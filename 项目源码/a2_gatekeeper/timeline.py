from __future__ import annotations

import json
import time
from pathlib import Path


def append(state_dir: str | Path, actor: str, action: str, target: str = "",
           result: str = "", detail: dict | None = None) -> dict:
    p = Path(state_dir) / "timeline.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    seq = 0
    if p.exists():
        with p.open(encoding="utf-8") as f:
            seq = sum(1 for _ in f)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "seq": seq + 1,
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "detail": detail or {},
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def read(state_dir: str | Path) -> list[dict]:
    p = Path(state_dir) / "timeline.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out
