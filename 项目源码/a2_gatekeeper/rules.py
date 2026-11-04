from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(obj: dict) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def freeze(rules_path: str | Path, state_dir: str | Path) -> dict:
    """G0: freeze the rule book; the hash is held by A2 only."""
    rules = load(rules_path)
    rec = {
        "hash": digest(rules),
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rules_path": str(Path(rules_path).resolve()),
        "rule_version": rules.get("version", "unknown"),
    }
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    (Path(state_dir) / "freeze.json").write_text(
        json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    return rec


def status(rules_path: str | Path, state_dir: str | Path) -> tuple[bool, str]:
    p = Path(state_dir) / "freeze.json"
    if not p.exists():
        return False, "G0 not frozen"
    rec = json.loads(p.read_text(encoding="utf-8"))
    current = digest(load(rules_path))
    if rec.get("hash") != current:
        return False, "G0 rules changed after freeze"
    return True, "ok"
