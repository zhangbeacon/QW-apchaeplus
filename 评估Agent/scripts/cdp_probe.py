#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浏览器取证包装器：把 browser_harness.js 的能力以 Python 命令行暴露。

要求：Node >= 21（原生 WebSocket），目标 Chrome 以
      --remote-debugging-port=<port> --user-data-dir=<隔离目录> 启动。

用法：
  python cdp_probe.py --port 9222 --list
  python cdp_probe.py --port 9222 --info    --target <id>
  python cdp_probe.py --port 9222 --cookies --target <id> --origin https://app.example.com
  python cdp_probe.py --port 9222 --hook    --target <id> --seconds 20
  python cdp_probe.py --port 9222 --eval    --target <id> --expr-file probe.js
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "browser_harness.js")


def node_bin():
    for name in ("node", "node.exe"):
        p = shutil.which(name)
        if p:
            return p
    raise RuntimeError("未找到 node（需要 Node >= 21）")


def run(args):
    proc = subprocess.run([node_bin(), HARNESS] + args, capture_output=True, timeout=900)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.exit(proc.returncode)
    return proc.stdout.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description="CDP 浏览器取证")
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--target", help="CDP targetId（--list 可查）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--info", action="store_true")
    g.add_argument("--cookies", action="store_true")
    g.add_argument("--hook", action="store_true")
    g.add_argument("--eval", action="store_true")
    ap.add_argument("--origin", default=None)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--expr-file", default=None)
    args = ap.parse_args()

    port = str(args.port)
    if args.list:
        print(run([port, "list"]), end="")
        return

    if not args.target:
        sys.exit("需要 --target")
    if args.info:
        print(run([port, "info", args.target]), end="")
    elif args.cookies:
        extra = [args.origin] if args.origin else []
        print(run([port, "cookies", args.target] + extra), end="")
    elif args.hook:
        out = run([port, "hook", args.target, str(args.seconds)])
        try:
            items = json.loads(out)
            for it in items:
                print(f"[{it.get('m', '')}] {it.get('u', '')}")
                if it.get("b"):
                    print("    body:", str(it["b"])[:300])
        except json.JSONDecodeError:
            print(out)
    elif args.eval:
        if not args.expr_file:
            sys.exit("--eval 需要 --expr-file")
        print(run([port, "eval", args.target, os.path.abspath(args.expr_file)]), end="")


if __name__ == "__main__":
    main()
