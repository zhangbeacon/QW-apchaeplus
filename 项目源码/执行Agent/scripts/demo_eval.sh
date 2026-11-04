#!/usr/bin/env bash
# demo 打靶评估：对 d1/d2/i1 跑三轴（功能/溢出表型/泄露），产出 demo-matrix.md
# 诚实口径：三变体的溢出漏洞全部仍在（都崩）；差异在"表型（信号）"与"泄露轴可达性"
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="${1:-demo01}"
EVAL="$ROOT/artifacts/$RUN_ID/eval"
MARK="/opt/qw9-demo/markers/root-only.txt"
USER_V3="demo-v3"
LONG=$(python3 -c "import sys; sys.stdout.write('A'*200)")
mkdir -p "$EVAL"

run_as() { # $1=user $2=cmd-string
  if [ "$1" = "root" ]; then eval "$2"; else su -s /bin/sh -c "$2" "$1"; fi
}

eval_variant() { # $1=id $2=prefix $3=user
  local id="$1" bin="$2/bin/demo_app" user="$3" out rc func pheno leak
  out=$(run_as "$user" "'$bin' --hello"); rc=$?
  func="FAIL"; { [ "$rc" = 0 ] && printf '%s' "$out" | grep -q DEMO_OK; } && func="PASS(exit0)"
  out=$(run_as "$user" "'$bin' '$LONG'"); rc=$?
  case $rc in
    139) pheno="触发:SIGSEGV(11) 段错误" ;;
    134) pheno="触发:SIGABRT(6) 栈破坏被检测(stack smashing)" ;;
    0)   pheno="未触发:正常返回" ;;
    *)   pheno="其他:rc=$rc" ;;
  esac
  out=$(run_as "$user" "'$bin' --read '$MARK'")
  leak="other"
  printf '%s' "$out" | grep -q DEMO_ROOT_ONLY_SECRET && leak="泄露成功(读到标记)"
  printf '%s' "$out" | grep -q "SECRET_READ=denied" && leak="泄露被拒(权限)"
  echo "$id|$func|$pheno|$leak"
}

R1=$(eval_variant d1 /opt/qw9/d1 root)
R2=$(eval_variant d2 /opt/qw9/d2 root)
R3=$(eval_variant i1 /opt/qw9/i1 "$USER_V3")

{
  echo "# demo 三版本差异矩阵（run_id=$RUN_ID，生成于 $(date '+%F %T')）"
  echo ""
  echo "| 候选 | 功能面(--hello) | 漏洞面(200B 栈溢出) | 泄露面(root-only 标记) |"
  echo "|---|---|---|---|"
  for r in "$R1" "$R2" "$R3"; do
    IFS='|' read -r a b c d <<< "$r"
    echo "| $a | $b | $c | $d |"
  done
  echo ""
  echo "## 诚实结论口径"
  echo ""
  echo "- 溢出漏洞（CWE-120）在三个变体上**全部仍然存在**——没有任何变体把它修掉；"
  echo "- V1→V2：同一攻击、同一根因，可观测表型从 SIGSEGV(11) 变为 SIGABRT(6)（栈破坏被运行时检测）——对应赛题 P029『均触发但表现不一致』；"
  echo "- V1/V2→V3：泄露轴被权限边界拦下（root-only 标记不可读）——『漏洞仍存在但该轴利用受抑制』，对应 P030；"
  echo "- 本 demo 只验证流水线，不是真实软件，不计入赛题漏洞分。"
} > "$EVAL/demo-matrix.md"

echo "$R1"; echo "$R2"; echo "$R3"
echo "matrix: $EVAL/demo-matrix.md"
