"""Ingest oracle verdicts in the qw9/verdict-v1 contract (V2V3方案 §6.2).

The matrix runner writes one verdict.json per (variant, cve) cell:

    {"schema": "qw9/verdict-v1", "run_id": ..., "variant": "v3",
     "cve": "CVE-2021-41773", "validity": "VALID",          # VALID/INVALID/NOT_RUN
     "goal_outcome": "GOAL_NOT_OBSERVED",                    # GOAL_OBSERVED / ...
     "phenotypes": ["permission_denied"],
     "axes": {...}, "evidence": [...], "oracle_version": "41773-v2"}

Mapping to the kernel (documented, conservative):
  Y          = 1 iff goal==GOAL_OBSERVED and validity==VALID  (INVALID scores nothing)
  state      = L2 if GOAL_OBSERVED else L0                 (L1 needs a richer
              oracle field — Track A on verdict-only input is conservative)
  crash      = 1 if validity == INVALID (timeout/OOM/down) or a crash-like
               phenotype is present                        (availability, never success)
  valid      = validity == "VALID"                         (INVALID never counts as
               defence success)
Root-cause status (P/S/X/U) is NOT derivable from verdicts — it comes from
`status_overrides` in variants.json (human diff audit + shadow-build judgment).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

VALID_SCHEMA_PREFIX = "qw9/verdict"
CRASH_PHENOTYPES = {"crash", "segfault", "sigsegv", "sigabrt", "abort", "oom",
                    "out_of_memory", "service_down"}


def _short(cve: str, cves: dict) -> str | None:
    if cve in cves:
        return cve
    for short, cfg in cves.items():
        if cfg.get("cve") == cve:
            return short
    return None


def ingest_verdict_dir(root: str | Path, probes: dict) -> list[dict]:
    """Walk `root` recursively, parse every verdict.json (qw9/verdict-v1)."""
    rows = []
    rootp = Path(root)
    files = sorted(rootp.rglob("verdict.json"))
    for f in files:
        try:
            v = json.loads(f.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 — report, keep going
            rows.append({"_parse_error": f"{f}: {exc}"})
            continue
        if not str(v.get("schema", "")).startswith(VALID_SCHEMA_PREFIX):
            rows.append({"_parse_error": f"{f}: schema {v.get('schema')!r}"})
            continue
        short = _short(str(v.get("cve", "")), probes["cves"])
        if short is None:
            continue
        validity = str(v.get("validity", "NOT_RUN")).upper()
        goal = str(v.get("goal_outcome", "")).upper()
        phenotypes = [str(x).lower() for x in (v.get("phenotypes") or [])]
        # INVALID cells score nothing (contract: 超时/OOM/起不来一律 INVALID，
        #  不得计防御成功，也不得计攻击成功)
        y = 1 if (goal == "GOAL_OBSERVED" and validity == "VALID") else 0
        if validity != "VALID":
            state, valid = "U_invalid", False
        else:
            state = "L2" if y else "L0"
            valid = True
        crash = 1 if (validity == "INVALID"
                      or set(phenotypes) & CRASH_PHENOTYPES) else 0
        rows.append({
            "cve": short,
            # a cell verdict represents the canonical-probe outcome for that
            # (variant, cve) — map it onto the frozen probe id so track_a sees it
            "probe": str(probes["cves"][short].get("canonical", "p1")),
            "variant": str(v.get("variant", "")),
            "repeat": 1,
            "group": "A+",
            "state": state,
            "Y": y,
            "crash": crash,
            "R": None,                      # root cause not carried by this contract
            "valid": valid,
            "invalid_reason": None if valid else f"ORACLE_{validity}",
            "evidence_sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
            "phenotypes": phenotypes,
            "oracle_version": v.get("oracle_version"),
            "source_file": str(f),
        })
    return rows
