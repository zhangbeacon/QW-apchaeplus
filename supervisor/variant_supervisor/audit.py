from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class AuditIssue:
    kind: str
    detail: str


def audit_evidence(
    evidence_dir: Path,
    required: list[str],
    started_at: float,
    max_age_sec: int,
    expected_json: dict[str, dict[str, Any]] | None = None,
) -> list[AuditIssue]:
    issues: list[AuditIssue] = []
    now = time.time()

    for rel in required:
        path = evidence_dir / rel
        if not path.exists():
            issues.append(AuditIssue("missing", f"{rel} does not exist"))
            continue
        st = path.stat()
        if st.st_size == 0:
            issues.append(AuditIssue("empty", f"{rel} is empty"))
            continue
        age = now - st.st_mtime
        if age > max_age_sec:
            issues.append(AuditIssue("stale", f"{rel} is {int(age)}s old (max {max_age_sec}s)"))
        if st.st_mtime + 2 < started_at:
            issues.append(AuditIssue("old_run", f"{rel} predates this run"))

    for rel, wanted in (expected_json or {}).items():
        path = evidence_dir / rel
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            issues.append(AuditIssue("bad_json", f"{rel}: {exc}"))
            continue
        for key, value in wanted.items():
            if data.get(key) != value:
                issues.append(
                    AuditIssue("bad_value", f"{rel}: {key}={data.get(key)!r}, expected {value!r}")
                )
    return issues
