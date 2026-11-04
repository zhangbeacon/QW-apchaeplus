#!/usr/bin/env bash
# P0 可行性三问（实现方案 §8 的 P0 试制，一次性回答，输出 PASS/FAIL/INFO）
#   A. clang 能否用于 2.4.49 目标 + FORTIFY 是否真实生效（_chk 符号实证）
#   B. V2 完整构建（干净树 + 全 DSO + manifest + FORTIFY 覆盖率）——耗时数分钟
#   C. WSL 隔离可行性（WSL1/2 判别、chroot syscall、v3 隔离落地 + 可达性自检）
set -u
ROOT="${QW9_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"
PASS=0; FAIL=0
say() { printf '\n===== [P0-%s] %s =====\n' "$1" "$2"; }
res() { if [ "$1" = 0 ]; then echo "PASS: $2"; PASS=$((PASS+1)); else echo "FAIL: $2"; FAIL=$((FAIL+1)); fi; }

# ---------- A ----------
say A "编译器与 FORTIFY 可行性"
command -v clang >/dev/null 2>&1 && res 0 "clang 存在: $(clang --version | head -1)" \
  || { echo "FAIL: clang 不存在（apt install clang）"; FAIL=$((FAIL+1)); }
TD=$(mktemp -d /tmp/qw9-p0.XXXX)
cat > "$TD/t.c" <<'EOF'
#include <stdio.h>
#include <string.h>
int main(void) {
    char dst[8], src[8] = "abcdefgh";
    memcpy(dst, src, sizeof dst);
    char buf[8];
    snprintf(buf, sizeof buf, "x%s", "y");
    return (int) dst[0] + buf[0] - 'a' - 'x';
}
EOF
if cc_bin=$(command -v clang); then
  "$cc_bin" -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -o "$TD/t" "$TD/t.c" 2> "$TD/cc.err" \
    && readelf -W -s "$TD/t" | grep -q '__memcpy_chk\|__snprintf_chk\|__strcpy_chk' \
    && res 0 "FORTIFY _chk 符号实证存在" \
    || res 1 "FORTIFY 未生效（详见 $TD/cc.err / readelf）"
  readelf -W -s "$TD/t" | grep -q '__stack_chk_fail' \
    && res 0 "栈保护符号存在" || res 1 "栈保护符号缺失"
fi

# ---------- B ----------
say B "V2 完整构建（数分钟）"
if PYTHONPATH=src python3 -m qw9 build --recipe recipes/v2-hardened.yaml; then
  cov=$(python3 -c "import json;m=json.load(open('artifacts/v2-hardened/manifest.json'));print(m['summary']['fortify_coverage'])")
  echo "INFO: v2 fortify_coverage=$cov（httpd 自身 TU；APR 来自 /usr 不在覆盖内，如实标注）"
  res 0 "V2 构建闭环（干净树→manifest）"
else
  res 1 "V2 构建失败（artifacts/v2-hardened/build.log）"
fi

# ---------- C ----------
say C "WSL 隔离可行性"
KREL=$(uname -r)
case "$KREL" in
  *microsoft-standard*) echo "INFO: WSL2 ($KREL)——namespace/容器可用" ;;
  *microsoft*)          echo "INFO: WSL1 ($KREL)——无真实内核，namespace 不可靠（本方案不依赖）" ;;
  *)                    echo "INFO: 原生 Linux ($KREL)" ;;
esac
chroot / /bin/true >/dev/null 2>&1 && echo "INFO: chroot syscall 可用（可选增强）" \
  || echo "INFO: chroot 不可用——按权限矩阵口径执行（方案已兼容）"
if PYTHONPATH=src python3 -m qw9 isolate --recipe recipes/v3-isolated.yaml; then
  res 0 "V3 隔离落地 + 可达性自检（artifacts/v3-isolated/isolate-verify.json）"
else
  res 1 "V3 隔离失败（artifacts/v3-isolated/isolate.log）"
fi

printf '\n===== P0 汇总: PASS=%d FAIL=%d =====\n' "$PASS" "$FAIL"
echo "口径：A/B 全过 => V2 路线可行；C 过 => V3 路线可行；任何 FAIL 对应方案 §9 回退。"
[ "$FAIL" = 0 ]
