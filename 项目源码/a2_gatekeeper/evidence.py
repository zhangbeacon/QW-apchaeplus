from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from .timeline import append as timeline_append


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def begin(state_dir: str | Path, evidence_dir: str | Path, run_id: str) -> dict:
    """Archive old evidence, create a fresh evidence dir, bind the new run_id."""
    state_dir = Path(state_dir)
    evidence_dir = Path(evidence_dir)
    archive_root = state_dir / "archive"
    archive_root.mkdir(parents=True, exist_ok=True)

    if evidence_dir.exists():
        target = archive_root / time.strftime("%Y%m%d-%H%M%S")
        target.mkdir(parents=True, exist_ok=True)
        for item in evidence_dir.iterdir():
            shutil.move(str(item), str(target / item.name))
    evidence_dir.mkdir(parents=True, exist_ok=True)

    rec = {
        "run_id": run_id,
        "started_at": time.time(),
        "started_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "evidence_dir": str(evidence_dir.resolve()),
    }
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{run_id}.json").write_text(
        json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    timeline_append(state_dir, "A2", "archive", run_id, "fresh",
                    {"evidence_dir": str(evidence_dir)})
    return rec


def check(state_dir: str | Path, run_id: str, evidence_dir: str | Path,
          binary: str | Path | None = None) -> list[str]:
    """Before judging: run_id must match, binary must exist, evidence must be fresh."""
    issues: list[str] = []
    meta_path = Path(state_dir) / "runs" / f"{run_id}.json"
    if not meta_path.exists():
        return [f"run_id {run_id} has no begin record"]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    started = float(meta.get("started_at", 0))

    if binary:
        b = Path(binary)
        if not b.exists():
            issues.append(f"binary missing: {b}")
        else:
            meta["binary_sha256"] = sha256(b)

    ed = Path(evidence_dir)
    if not ed.exists():
        issues.append("evidence dir missing")
    else:
        files = [p for p in ed.rglob("*") if p.is_file()]
        if not files:
            issues.append("evidence dir empty")
        for p in files:
            if p.stat().st_mtime + 2 < started:
                issues.append(f"stale evidence: {p.name} predates run")

    if issues:
        timeline_append(state_dir, "A2", "evidence_check", run_id, "fail", {"issues": issues})
    else:
        timeline_append(state_dir, "A2", "evidence_check", run_id, "pass",
                        {"binary": str(binary) if binary else ""})
    return issues
