"""Verification of the generation agent's delivery (A1 §2/§7).

A1 delivers `artifacts/<run_id>/<id>/manifest.json` + build.log. The evaluator
only checks presence and internal consistency (required fields, hash format) —
it never judges build quality, and a missing manifest blocks that candidate
from being treated as delivered.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_REQUIRED = ["id", "sha256", "compiler"]


def verify_manifests(artifacts_dir: str | Path, variants: list[str],
                     required_fields: list[str] | None = None) -> dict:
    req = required_fields or DEFAULT_REQUIRED
    d = Path(artifacts_dir)
    if not d.is_dir():
        return {"checked": False, "reason": "MANIFEST_DIR_MISSING",
                "dir": str(d), "variants": {}}
    out: dict = {"checked": True, "dir": str(d), "variants": {}}
    n_ok = 0
    for vid in variants:
        mp = d / vid / "manifest.json"
        if not mp.exists():
            out["variants"][vid] = {"present": False, "valid": False,
                                    "reason": "MISSING_MANIFEST"}
            continue
        try:
            m = json.loads(mp.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - report, do not raise
            out["variants"][vid] = {"present": True, "valid": False,
                                    "reason": f"BAD_JSON:{exc}"}
            continue
        if not isinstance(m, dict):
            out["variants"][vid] = {"present": True, "valid": False,
                                    "reason": "NOT_AN_OBJECT"}
            continue
        missing = [k for k in req if k not in m]
        sha = m.get("sha256")
        sha_ok = (isinstance(sha, str) and len(sha) == 64
                  and all(c in "0123456789abcdef" for c in sha.lower()))
        valid = not missing and sha_ok
        out["variants"][vid] = {"present": True, "valid": valid,
                                "missing_fields": missing,
                                "sha256_format_ok": sha_ok}
        if valid:
            n_ok += 1
    out["n_ok"] = n_ok
    out["n_total"] = len(variants)
    return out
