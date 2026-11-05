"""Two-stage chain metrics.

BlockRate   = P(stage2 fails | stage1 succeeds)
ChainSuccess = P(stage1 succeeds and stage2 succeeds)

Both stages are evaluated on the same (probe, variant, repeat) trial, i.e. one
session, one instance, one round — never stitched across runs.
"""

from __future__ import annotations

from collections import defaultdict

LEVEL = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}


def _ok(state: str, spec: dict) -> bool:
    if state not in LEVEL:
        return False
    lv = LEVEL[state]
    if "state" in spec:
        return state == spec["state"]
    lo = LEVEL.get(spec.get("min_state", "L0"), 0)
    hi = LEVEL.get(spec.get("max_state", "L3"), 3)
    return lo <= lv <= hi


def chain_metrics(classified: list[dict], chains: dict) -> dict:
    """Per-CVE chain success / block rate over A+ trials of the configured probes."""
    by_cve = defaultdict(lambda: {"stage1": 0, "both": 0, "total": 0})
    for r in classified:
        spec = chains.get(r["cve"])
        if not spec or r["group"] != "A+" or not r["valid"]:
            continue
        if r["probe"] not in spec.get("probes", []):
            continue
        s1 = _ok(r["state"], spec["stage1"])
        s2 = _ok(r["state"], spec["stage2"])
        acc = by_cve[r["cve"]]
        acc["total"] += 1
        if s1:
            acc["stage1"] += 1
            if s2:
                acc["both"] += 1
    out = {}
    for cve, acc in by_cve.items():
        total, stage1, both = acc["total"], acc["stage1"], acc["both"]
        out[cve] = {
            "ChainSuccess": (both / total) if total else None,
            "BlockRate": ((stage1 - both) / stage1) if stage1 else None,
            "stage1_rate": (stage1 / total) if total else None,
            "n": total,
        }
    for cve in chains:
        out.setdefault(cve, {"ChainSuccess": None, "BlockRate": None,
                             "reason": "NO_STAGE1_SUCCESS"})
    return out


def chain_deltas(b0: dict, b1: dict) -> dict:
    """Delta = chain success in B0 minus chain success in B1 (positive = better)."""
    out = {}
    for cve in sorted(set(b0) | set(b1)):
        a = (b0.get(cve) or {}).get("ChainSuccess")
        b = (b1.get(cve) or {}).get("ChainSuccess")
        out[cve] = {"dChainSuccess": (a - b) if (a is not None and b is not None) else None}
    return out
