#!/usr/bin/env bash
# business 场景收尾：只杀自己记录 PID 的后端
set -u
if [ -f "$QW9_OUT_DIR/backends.pid" ]; then
  while read -r pid; do kill "$pid" 2>/dev/null || true; done < "$QW9_OUT_DIR/backends.pid"
  rm -f "$QW9_OUT_DIR/backends.pid"
fi
