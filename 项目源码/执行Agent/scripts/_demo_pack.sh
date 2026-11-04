#!/usr/bin/env bash
# demo 打包：LF 检查 → stage → tar → sha256
set -euo pipefail
cd /mnt/e/强网拟态/03_platform/demo-target
chmod +x configure
STAGE=/tmp/demo-vuln-app-1.0
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp main.c configure Makefile "$STAGE/"
tar czf demo-vuln-app-1.0.tar.gz -C /tmp demo-vuln-app-1.0
sha256sum demo-vuln-app-1.0.tar.gz
tar tzf demo-vuln-app-1.0.tar.gz
