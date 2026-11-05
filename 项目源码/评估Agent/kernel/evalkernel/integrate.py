"""Integration adapters for the 监管 Agent (supervisor) conventions.

Repo contract (监管Agent-接口契约.md / 接入示例):
  * journal.jsonl  : append-only JSONL; event types include "diagnosis" and
                     the stage_event schema types {stage_fail, audit_fail};
  * evidence/      : marker files (*.ok with timestamp) + manifest.json
                     summarising each file's sha256;
  * results.json   : optional machine summary — path x status x summary.

This module never mutates supervisor state: it only appends journal lines and
writes into the evaluator's own evidence subdirectory.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path

ARTIFACT_FILES = ["hde.json", "safety.json", "audit.json", "status.json",
                  "matrix.json", "scores.json", "fitness.json", "report.md",
                  "manifest.json"]

# vendored copy of 接入示例/stage_event.schema.json (subset we enforce)
STAGE_EVENT_TYPES = {"stage_fail", "audit_fail"}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------- results.json


def write_results(out_dir: Path, run_id: str) -> Path:
    """Optional summary per supervisor contract: path x status x summary."""
    audit = {}
    ap = out_dir / "audit.json"
    if ap.exists():
        audit = json.loads(ap.read_text(encoding="utf-8"))
    verdict = audit.get("verdict", "unknown")
    items = []
    for name in ARTIFACT_FILES:
        f = out_dir / name
        if not f.exists():
            items.append({"path": name, "status": "missing", "summary": ""})
            continue
        summary = ""
        if name == "hde.json":
            g = json.loads(f.read_text(encoding="utf-8")).get("gauges", {})
            fp = g.get("final_pure", {})
            summary = f"HDE(final,pure)={fp.get('HDE')}"
        elif name == "safety.json":
            s = json.loads(f.read_text(encoding="utf-8"))
            tb = s.get("track_b", {})
            base = s.get("baselines", {})
            summary = (f"ASR={tb.get('ASR')} CMR={tb.get('CMR')} "
                       f"dCMR={base.get('dCMR')}")
        elif name == "audit.json":
            summary = f"coverage={audit.get('coverage', {}).get('rate')}"
        items.append({"path": name, "status": "ok", "summary": summary})
    results = {"run_id": run_id, "verdict": verdict, "items": items}
    (out_dir / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    return out_dir / "results.json"


# ---------------------------------------------------------------- journal


def journal_events(audit: dict, run_id: str) -> list[dict]:
    """Events required by the supervisor conventions for this evaluation run."""
    ts = _now()
    verdict = audit.get("verdict", "unknown")
    events = [{"ts": ts, "run_id": run_id, "type": "diagnosis",
               "stage": "evaluation", "attempt": 1,
               "cause": verdict.split(":")[0].upper(),
               "action": "report",
               "confidence": 1.0,
               "rationale": f"evaluator verdict={verdict}",
               "source": "evalkernel"}]
    if verdict.startswith("needs_retest"):
        issues = [{"kind": "coverage", "detail": f"{len(audit.get('retest_requests', []))} cells below half coverage"}
                  if "coverage" in verdict else
                  {"kind": "stale", "detail": verdict.split(":", 1)[-1]}]
        events.append({"ts": ts, "run_id": run_id, "type": "audit_fail",
                       "stage": "evaluation", "issues": issues,
                       "source": "evalkernel"})
    elif verdict.startswith("unusable"):
        n_conf = audit.get("conflicts", {}).get("count", 0)
        events.append({"ts": ts, "run_id": run_id, "type": "audit_fail",
                       "stage": "evaluation",
                       "issues": [{"kind": "conflict",
                                   "detail": f"{n_conf} state-vs-R contradictions"}],
                       "source": "evalkernel"})
    return events


def append_journal(journal_path: str | Path, events: list[dict]) -> int:
    """Append-only, one JSON object per line (supervisor convention)."""
    if not events:
        return 0
    p = Path(journal_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for e in events:
        _validate_stage_event(e)
        lines.append(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def _validate_stage_event(e: dict) -> None:
    """Enforce the vendored stage_event schema subset."""
    if not isinstance(e, dict):
        raise ValueError("event must be an object")
    if e.get("type") not in STAGE_EVENT_TYPES:
        return  # diagnosis-type events are journal-only, not stage events
    if not isinstance(e.get("stage"), str):
        raise ValueError(f"stage_event requires string stage: {e}")
    if not isinstance(e.get("issues", []), list):
        raise ValueError("issues must be an array")


# ---------------------------------------------------------------- evidence


def write_evidence(out_dir: Path, evidence_dir: str | Path, run_id: str) -> dict:
    """Mirror key artifacts into the supervisor evidence tree.

    evidence/<evidence_dir>/evaluation/<artifacts> + manifest.json (sha256 each)
    + evaluation.ok marker (usable runs only), mirroring functional.ok/negative.ok.
    """
    base = Path(evidence_dir) / "evaluation"
    base.mkdir(parents=True, exist_ok=True)
    copied = {}
    for name in ARTIFACT_FILES:
        if name == "manifest.json":
            continue  # evidence/manifest.json is the supervisor-side summary
        f = out_dir / name
        if f.exists():
            shutil.copy2(f, base / name)
            copied[name] = _sha(base / name)
    (base / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "files": copied},
                   ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    audit = json.loads((out_dir / "audit.json").read_text(encoding="utf-8"))
    verdict = audit.get("verdict", "unknown")
    ok_path = base / "evaluation.ok"
    if verdict == "usable":
        ok_path.write_text(f"verdict=usable\nts={_now()}\n", encoding="utf-8")
    elif ok_path.exists():
        ok_path.unlink()  # stale marker must not survive an unusable rerun
    return {"dir": str(base), "files": sorted(copied), "verdict": verdict,
            "ok_marker": ok_path.exists()}

