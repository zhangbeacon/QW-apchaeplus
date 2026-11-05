"""CLI: python -m evalkernel --raw <jsonl> --config <dir> --out <dir> [--B 200] [--seed N]"""

from __future__ import annotations

import argparse
import json
import sys

from .pipeline import run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="evalkernel")
    ap.add_argument("--raw", required=True, help="raw_trials.jsonl from the monitoring agent")
    ap.add_argument("--config", required=True, help="directory containing probes.json / variants.json")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--B", type=int, default=200, help="permutation replicates (default 200)")
    ap.add_argument("--seed", type=int, default=20261102)
    ap.add_argument("--deployment-model", default="M2", choices=["M1", "M2", "M3", "M4"])
    ap.add_argument("--journal", default=None,
                    help="append evaluation events to this journal.jsonl (supervisor contract)")
    ap.add_argument("--evidence-dir", default=None,
                    help="mirror key artifacts into the supervisor evidence tree")
    ap.add_argument("--run-id", default=None,
                    help="run id used in journal/evidence (defaults to input hash prefix)")
    ap.add_argument("--verdicts", default=None,
                    help="directory of qw9/verdict-v1 verdict.json files (alternative to --raw)")
    ap.add_argument("--summary", action="store_true", help="print a short JSON summary")
    args = ap.parse_args(argv)

    res = run(args.raw, args.config, args.out, B=args.B, seed=args.seed,
              deployment_model=args.deployment_model, journal_path=args.journal,
              evidence_dir=args.evidence_dir, run_id=args.run_id)
    if args.summary:
        hde = res["hde"]["gauges"].get("final_pure", {})
        print(json.dumps({
            "final_pure_HDE": hde.get("HDE"),
            "final_pure_DIV": hde.get("DIV"),
            "audit_verdict": res["audit"]["verdict"],
            "coverage": res["audit"]["coverage"]["rate"],
        }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
