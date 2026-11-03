#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用加密请求构造器

用途：把「明文参数」转成可直接粘贴进 Burp Repeater 的 HTTP 报文。
适合前端把密钥硬编码在 JS 里、请求体/请求头用对称加密包装的场景。

默认算法 DES-CBC-PKCS7；可用 --cipher aes 切换到 AES-CBC。

依赖：优先 pycryptodome（pip install pycryptodome）；Windows 上无库时自动
回退到 PowerShell(.NET) 实现，无需安装任何东西。

示例：
  # DES，加密 {"f":"GetToken","c":"Public"} 与 {}，输出完整报文
  python des_request.py --key 01234567 \\
      --func GetToken --class Public --payload '{}' \\
      --host app.example.com --path /api/gateway

  # 解密一段响应密文
  python des_request.py --key 01234567 --decrypt 'AAAA...'

  # AES-128-CBC
  python des_request.py --key 0123456789abcdef --cipher aes \\
      --func Method --class Cls --payload '{"a":1}'
"""
import argparse
import base64
import json
import subprocess
import sys

MODE_PAD = "pkcs7"


def _ps_crypt(data: bytes, key: bytes, iv: bytes, cipher: str, encrypt: bool) -> bytes:
    """Windows 回退实现：调用 .NET 完成 DES/AES-CBC-PKCS7。"""
    algo = "DES" if cipher == "des" else "AES"
    op = "E" if encrypt else "D"
    ps = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference='Stop'
$data=[Convert]::FromBase64String($env:DATA)
$key=[Text.Encoding]::UTF8.GetBytes($env:KEY)
$iv=[Text.Encoding]::UTF8.GetBytes($env:IV)
if($env:ALGO -eq 'DES'){
  $c=New-Object System.Security.Cryptography.DESCryptoServiceProvider
}else{
  $c=New-Object System.Security.Cryptography.AesCryptoServiceProvider
}
$c.Key=$key; $c.IV=$iv; $c.Mode='CBC'; $c.Padding='PKCS7'
if($env:OP -eq 'E'){ $t=$c.CreateEncryptor() } else { $t=$c.CreateDecryptor() }
$out=$t.TransformFinalBlock($data,0,$data.Length)
[Convert]::ToBase64String($out)
"""
    import os
    env = dict(os.environ)
    env.update({
        "DATA": base64.b64encode(data).decode(),
        "KEY": key.decode(),
        "IV": iv.decode(),
        "ALGO": algo,
        "OP": op,
    })
    for exe in ("powershell", "pwsh"):
        try:
            r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps],
                               capture_output=True, env=env, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                return base64.b64decode(r.stdout.strip())
        except FileNotFoundError:
            continue
    raise RuntimeError("无 pycryptodome 且找不到 PowerShell，无法加解密：pip install pycryptodome")


def _cipher(cipher: str, key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    try:
        if cipher == "des":
            from Crypto.Cipher import DES
            c = DES.new(key, DES.MODE_CBC, iv)
            block = 8
        else:
            from Crypto.Cipher import AES
            c = AES.new(key, AES.MODE_CBC, iv)
            block = 16
        if encrypt:
            pad = block - len(data) % block
            return c.encrypt(data + bytes([pad]) * pad)
        plain = c.decrypt(data)
        return plain[:-plain[-1]]
    except ImportError:
        return _ps_crypt(data, key, iv, cipher, encrypt)


def enc_b64(cipher: str, key: bytes, iv: bytes, text: str) -> str:
    return base64.b64encode(_cipher(cipher, key, iv, text.encode("utf-8"), True)).decode()


def dec_b64(cipher: str, key: bytes, iv: bytes, b64: str) -> str:
    return _cipher(cipher, key, iv, base64.b64decode(b64), False).decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description="通用加密请求构造器")
    ap.add_argument("--cipher", choices=["des", "aes"], default="des")
    ap.add_argument("--key", required=True, help="对称密钥（UTF-8 字符串）")
    ap.add_argument("--iv", help="IV，缺省与 key 相同")
    ap.add_argument("--func", default="GetToken", help="接口方法名")
    ap.add_argument("--class", dest="cls", default="Public", help="接口类名/命名空间")
    ap.add_argument("--payload", default="{}", help="业务入参（明文）")
    ap.add_argument("--host", default="app.example.com")
    ap.add_argument("--path", default="/api/gateway")
    ap.add_argument("--header-name", default="Authorization-Enc")
    ap.add_argument("--json-field", default="data_enc")
    ap.add_argument("--decrypt", help="解密给定的 Base64 密文后退出")
    args = ap.parse_args()

    key = args.key.encode("utf-8")
    iv = (args.iv or args.key).encode("utf-8")

    if args.decrypt:
        print(dec_b64(args.cipher, key, iv, args.decrypt))
        return

    auth_plain = json.dumps({"f": args.func, "c": args.cls}, separators=(",", ":"), ensure_ascii=False)
    auth = enc_b64(args.cipher, key, iv, auth_plain)
    body_cipher = enc_b64(args.cipher, key, iv, args.payload)
    body = json.dumps({args.json_field: body_cipher}, separators=(",", ":"), ensure_ascii=False)
    clen = len(body.encode("utf-8"))

    print("=== PLAINTEXT ===")
    print("auth  :", auth_plain)
    print("body  :", args.payload)
    print("\n=== VALUES ===")
    print(f"{args.header_name}: {auth}")
    print(f"{args.json_field}: {body_cipher}")
    print(f"Content-Length: {clen}")
    print("\n=== REQUEST (paste into Repeater) ===")
    print(f"POST {args.path} HTTP/1.1")
    print(f"Host: {args.host}")
    print("Content-Type: application/json")
    print(f"{args.header_name}: {auth}")
    print(f"Content-Length: {clen}")
    print()
    print(body)


if __name__ == "__main__":
    main()
