#!/usr/bin/env bash
# business 场景前置：声明 UDS 后端 + 回环 TCP 后端（业务契约探测所需）
set -euo pipefail
mkdir -p "$QW9_UDS_DIR"
rm -f "$QW9_UDS_DIR"/*.log "$QW9_UDS_DIR"/*.sock 2>/dev/null || true
: > "$QW9_OUT_DIR/backends.pid"
python3 "$QW9_SUPPORT/uds_backend.py" "$QW9_UDS_DIR/declared.sock" declared \
  > "$QW9_OUT_DIR/uds_declared.console" 2>&1 &
echo $! >> "$QW9_OUT_DIR/backends.pid"
python3 "$QW9_SUPPORT/tcp_backend.py" 8199 \
  > "$QW9_OUT_DIR/tcp_backend.console" 2>&1 &
echo $! >> "$QW9_OUT_DIR/backends.pid"
sleep 0.5
