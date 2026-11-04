from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from . import rules as rules_mod
from .timeline import append as timeline_append

ALLOWED_ACTIONS = {"build", "isolate", "target", "expand"}


def decisions_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "decisions.jsonl"


def read_decisions(state_dir: str | Path) -> list[dict]:
    p = decisions_path(state_dir)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def g4_passed(state_dir: str | Path) -> bool:
    p = Path(state_dir) / "gates.json"
    if not p.exists():
        return False
    try:
        return bool(json.loads(p.read_text(encoding="utf-8")).get("G4", {}).get("pass"))
    except json.JSONDecodeError:
        return False


def _used(state_dir: str | Path, action: str, target: str) -> int:
    return sum(
        1 for d in read_decisions(state_dir)
        if d.get("decision") == "approve"
        and d.get("request", {}).get("action") == action
        and d.get("request", {}).get("target") == target
    )


def request(state_dir: str | Path, rules_path: str | Path, req: dict) -> dict:
    """A1 submits a request form; A2 returns approve / reject / need_evidence."""
    rules = rules_mod.load(rules_path)
    decision, reason = "approve", "ok"

    frozen, msg = rules_mod.status(rules_path, state_dir)
    action = str(req.get("action", "")).strip()
    target = str(req.get("target", "")).strip()

    if not frozen:
        decision, reason = "reject", msg
    elif action not in ALLOWED_ACTIONS:
        decision, reason = "reject", f"action not allowed: {action or '<empty>'}"
    elif not target:
        decision, reason = "reject", "missing target"
    elif any(k in req for k in ("rules", "rules_patch", "thresholds")):
        decision, reason = "reject", "A1 may not modify rules or thresholds"
    else:
        limit = int(rules.get("thresholds", {}).get("max_retries", 3))
        if action in {"build", "isolate"} and _used(state_dir, action, target) >= limit:
            decision, reason = "reject", f"retry limit reached ({limit})"
        elif action in {"target", "expand"} and not g4_passed(state_dir):
            decision, reason = "reject", "G4 not passed; target/expand is not allowed"

    rec = {
        "id": "dec-" + time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "request": req,
        "decision": decision,
        "reason": reason,
    }
    p = decisions_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    timeline_append(state_dir, "A2", "approval", target, decision,
                    {"request": req, "reason": reason, "id": rec["id"]})
    return rec
