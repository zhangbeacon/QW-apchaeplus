#!/usr/bin/env bash
# demo 全链路：plan → expand → build(真实 gcc) → verify → 打靶评估 → deliver
set -euo pipefail
cd /mnt/e/强网拟态/03_platform
RUN=demo01
rm -rf "artifacts/$RUN" "recipes/gen/$RUN" "delivery/$RUN"

echo "===== [1/6] gen plan ====="
PYTHONPATH=src python3 -m qw9 gen plan --plan plans/demo4.yaml

echo "===== [2/6] gen expand ====="
PYTHONPATH=src python3 -m qw9 gen expand --plan plans/demo4.yaml --run-id "$RUN"

echo "===== [3/6] gen build（真实 gcc 构建 ×3） ====="
PYTHONPATH=src python3 -m qw9 gen build --run-id "$RUN" --jobs 2

echo "===== [4/6] gen verify（完整性自检） ====="
PYTHONPATH=src python3 -m qw9 gen verify --run-id "$RUN"

echo "===== [5/6] demo 打靶评估（三轴：功能/溢出/泄露） ====="
bash scripts/demo_eval.sh "$RUN"

echo "===== [6/6] gen deliver（评估分=打靶结果，挑 V2 + 预注册 V3） ====="
cat > "artifacts/$RUN/hde.json" <<'EOF'
{"schema": "qw9/scores/v1", "run_id": "demo01",
 "candidates": {
   "d1": {"score": "N/A", "detail": {"note": "baseline"}},
   "d2": {"score": 0.5, "detail": {"overflow_phenotype": "SIGSEGV->SIGABRT(stack smashing detected)", "evidence": "eval/demo-matrix.md"}},
   "i1": {"score": 0.9, "detail": {"note": "isolation axis, preregistered V3"}}}}
EOF
PYTHONPATH=src python3 -m qw9 gen deliver --run-id "$RUN" --scores "artifacts/$RUN/hde.json"

echo "===== 交付清单 ====="
ls -R "delivery/$RUN" | head -30
echo "===== demo-matrix.md ====="
cat "artifacts/$RUN/eval/demo-matrix.md"
