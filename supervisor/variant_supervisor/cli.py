from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import SupervisorAgent
from .config import ConfigError, load_config
from .journal import Journal


def cmd_run(args) -> int:
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 3
    agent = SupervisorAgent(cfg, run_id=args.run_id, verbose=not args.quiet)
    verdict = agent.run()
    print(f"\nverdict: {verdict}")
    print(f"journal: {cfg.journal_path}")
    return {"PASS": 0, "FAIL": 1, "NEEDS_HUMAN": 2, "ABORTED": 130}.get(verdict, 3)


def cmd_report(args) -> int:
    journal = Journal(Path(args.journal), "report")
    entries = journal.tail(args.limit)
    if not entries:
        print("no journal entries")
        return 1
    for entry in entries:
        print(json.dumps(entry, ensure_ascii=False, indent=2))
    return 0


def cmd_audit(args) -> int:
    from .audit import audit_evidence

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 3
    issues = audit_evidence(
        cfg.evidence_dir,
        cfg.required_evidence,
        started_at=0,
        max_age_sec=cfg.evidence_max_age_sec,
        expected_json=cfg.expected_json,
    )
    if not issues:
        print("audit: OK")
        return 0
    for issue in issues:
        print(f"audit: {issue.kind}: {issue.detail}")
    return 2


def cmd_watch(args) -> int:
    from .watch import watch as watch_events

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 3
    return watch_events(cfg, Path(args.events), follow=args.follow, execute_clean=args.execute_clean)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="variant-supervisor")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="run a supervised pipeline")
    p.add_argument("--config", required=True)
    p.add_argument("--run-id")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("report", help="print the last journal entries")
    p.add_argument("--journal", required=True)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("audit", help="audit evidence without running stages")
    p.add_argument("--config", required=True)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("watch", help="watch a JSONL event stream from an external pipeline")
    p.add_argument("--config", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--follow", action="store_true")
    p.add_argument("--execute-clean", action="store_true")
    p.set_defaults(func=cmd_watch)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

