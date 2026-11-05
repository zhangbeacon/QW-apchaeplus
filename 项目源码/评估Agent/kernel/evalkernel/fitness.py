"""Fitness interface for the variant generation agent.

The generation agent may only read the calibration split (design doc §5.5).
This module turns the evaluation artifacts into a small, stable contract:

    {"split": "calibration", "eligible": bool, "HDE": float|null,
     "CMR": float|null, "score": float|null, "reasons": [...]}

`score` is null when the measurement is not usable: the generation agent must
not optimise a number the evaluator refuses to certify.
"""

from __future__ import annotations


def fitness(hde: dict, safety: dict, split: str = "calibration") -> dict:
    rec = (hde.get("splits") or {}).get(split, {})
    hde_val = rec.get("HDE")
    cmr = (safety.get("track_b") or {}).get("CMR")
    reasons = []
    if hde_val is None:
        reasons.append("SPLIT_HDE_NA")
    if not rec.get("cves"):
        reasons.append("SPLIT_EMPTY")
    verdict = ((hde.get("digest") or {}).get("verdict"))
    if verdict and str(verdict).startswith("unusable"):
        reasons.append("SESSION_UNUSABLE")
    eligible = not reasons
    return {
        "split": split,
        "eligible": eligible,
        "HDE": hde_val,
        "CMR": cmr,
        "score": hde_val if eligible else None,
        "reasons": reasons,
    }
