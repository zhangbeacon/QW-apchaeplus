"""Axis matrix: within-group HDE per axis, matched pairwise contrasts, factorial guard.

HDE is not additive across variants, so the matrix deliberately reports
(a) within-group HDE for each axis group and (b) two-variant matched contrasts.
The 2x2x2 factorial is only reportable with >=2 independent builds per cell;
with one build it returns an explicit N/A instead of a fabricated interaction.
"""

from __future__ import annotations

from . import metrics as M
from . import stats as S


def axis_matrix(cells: dict, probes: dict, axis_groups: dict[str, list[str]],
                q_by_cve: dict) -> dict:
    """{axis: {cve: HDE within that axis group}}."""
    out = {}
    for axis, variants in axis_groups.items():
        if len(variants) < 2:
            out[axis] = {"reason": "GROUP_TOO_SMALL", "per_cve": {}}
            continue
        per = {}
        for short, cfg in probes["cves"].items():
            sub = {short: {pid: {v: pv[v] for v in variants if v in pv}
                           for pid, pv in cells.get(short, {}).items()}}
            if not sub[short]:
                per[short] = {"HDE": None, "reason": "NO_DATA"}
                continue
            full = {pid: d for pid, d in sub[short].items()
                    if len(d) == len(variants)}
            if not full:
                per[short] = {"HDE": None, "reason": "INCOMPLETE_GROUP"}
                continue
            r = M.track_a({short: full}, short, q_by_cve[short],
                          len(variants), cfg["family"])
            per[short] = {"HDE": r["HDE"], "DIV": r["DIV"],
                          "reason": r.get("reason")}
        vals = [v["HDE"] for v in per.values() if v.get("HDE") is not None]
        out[axis] = {
            "K": len(variants),
            "variants": variants,
            "HDE": (sum(vals) / len(vals)) if vals else None,
            "per_cve": per,
        }
    return out


def pairwise(cells: dict, probes: dict, contrasts: list[list[str]],
             q_by_cve: dict, B: int, seed: int) -> dict:
    """Matched two-variant contrasts: HDE over {a,b} per CVE + permutation p."""
    out = {}
    for pair in contrasts:
        if len(pair) != 2:
            continue
        a, b = pair
        key = f"{a}_vs_{b}"
        per = {}
        for short, cfg in probes["cves"].items():
            sub = {}
            for pid, pv in cells.get(short, {}).items():
                if a in pv and b in pv:
                    sub[pid] = {a: pv[a], b: pv[b]}
            if not sub:
                per[short] = {"HDE": None, "reason": "NO_PAIR_DATA"}
                continue
            r = M.track_a({short: sub}, short, q_by_cve[short], 2, cfg["family"])
            ps = []
            for pid, pv in sub.items():
                p = S.perm_p({v: pv[v]["states"] for v in pv}, 2, B=max(50, B // 4),
                             seed=seed)
                if p is not None:
                    ps.append(p)
            per[short] = {"HDE": r["HDE"], "DIV": r["DIV"],
                          "p": (sorted(ps)[len(ps) // 2] if ps else None),
                          "reason": r.get("reason")}
        vals = [v["HDE"] for v in per.values() if v.get("HDE") is not None]
        out[key] = {
            "pair": [a, b],
            "HDE": (sum(vals) / len(vals)) if vals else None,
            "per_cve": per,
        }
    return out


def factorial(cells: dict, probes: dict, factors: dict[str, dict], q_by_cve: dict,
              builds_per_cell: int = 1) -> dict:
    """2x2x2 compiler x opt x alloc guard.

    Requires >=2 independent builds per cell for an interaction term. With a single
    build we return N/A (single_build) rather than a number with no error estimate.
    """
    keys = ("compiler", "opt", "alloc")
    present = all(all(k in lv for k in keys) for lv in factors.values())
    if not present:
        return {"reason": "FACTORS_NOT_DECLARED"}
    cells_seen = {}
    for vid, levels in factors.items():
        cells_seen.setdefault(tuple(levels[k] for k in keys), []).append(vid)
    if builds_per_cell < 2:
        return {"reason": "SINGLE_BUILD_PER_CELL",
                "cells": {"/".join(k): v for k, v in cells_seen.items()},
                "main_effects": None, "interaction": None,
                "note": "interaction requires >=2 independent builds per cell"}
    # with replication, main effects are averages of cell HDE
    per_cell = {}
    for cell_key, vids in cells_seen.items():
        per = {}
        for short, cfg in probes["cves"].items():
            sub = {pid: {v: pv[v] for v in vids if v in pv}
                   for pid, pv in cells.get(short, {}).items()}
            sub = {pid: d for pid, d in sub.items() if len(d) == len(vids)}
            if not sub:
                per[short] = None
                continue
            r = M.track_a({short: sub}, short, q_by_cve[short], len(vids), cfg["family"])
            per[short] = r["HDE"]
        vals = [v for v in per.values() if v is not None]
        per_cell["/".join(cell_key)] = (sum(vals) / len(vals)) if vals else None
    return {"reason": "OK", "cells": per_cell,
            "main_effects": None, "interaction": None,
            "note": "main effects are reported by axis_matrix; interaction kept null "
                    "unless a proper replicated design is available"}
