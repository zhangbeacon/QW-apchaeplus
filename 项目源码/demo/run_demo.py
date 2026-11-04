#!/usr/bin/env python3
"""A2 end-to-end demo: freeze -> request -> gate -> approve -> archive -> check."""
import json
import shutil
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
sys.path.insert(0, str(ROOT))

from a2_gatekeeper.cli import main  # noqa: E402

STATE = BASE / "state"
EVIDENCE = BASE / "evidence"
RULES = BASE / "rules.json"


def call(args, expect=0):
    print("\n$ a2 " + " ".join(args))
    rc = main(args)
    print(f"[exit {rc}]")
    if expect is not None and rc != expect:
        raise SystemExit(f"expected exit {expect}, got {rc}")


def run():
    shutil.rmtree(STATE, ignore_errors=True)
    shutil.rmtree(EVIDENCE, ignore_errors=True)

    call(["freeze", "--rules", str(RULES), "--state", str(STATE)])

    (STATE / "env.json").write_text(json.dumps(
        {"clean_tree": True, "ports_free": [8080, 8082, 8084], "host_mounts": []},
        ensure_ascii=False), encoding="utf-8")

    call(["request", "--rules", str(RULES), "--state", str(STATE),
          "--action", "build", "--target", "V2", "--eta", "300"], expect=0)

    call(["request", "--rules", str(RULES), "--state", str(STATE),
          "--action", "target", "--target", "V2"], expect=2)

    call(["gate", "--rules", str(RULES), "--state", str(STATE),
          "--functional", str(BASE / "functional.json"),
          "--results", str(BASE / "results.json")], expect=0)

    call(["request", "--rules", str(RULES), "--state", str(STATE),
          "--action", "target", "--target", "V2"], expect=0)

    call(["begin", "--state", str(STATE), "--evidence", str(EVIDENCE),
          "--run-id", "demo-run-001"])

    (EVIDENCE / "security.json").write_text(json.dumps(
        {"run_id": "demo-run-001", "verdict": "pass"}, ensure_ascii=False), encoding="utf-8")
    (EVIDENCE / "functional.ok").write_text("", encoding="utf-8")

    call(["check", "--state", str(STATE), "--run-id", "demo-run-001",
          "--evidence", str(EVIDENCE), "--binary", str(ROOT / "a2_gatekeeper" / "rules.py")])

    print("\n=== timeline ===")
    for line in (STATE / "timeline.jsonl").read_text(encoding="utf-8").splitlines():
        print(line)


if __name__ == "__main__":
    run()
