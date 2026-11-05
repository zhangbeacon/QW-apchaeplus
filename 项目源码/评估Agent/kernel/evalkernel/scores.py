"""Per-candidate score cards for the variant generation agent (A1).

A1 §7/§8: the generation agent reads the evaluator's artifacts, ranks candidates,
and picks V2 — but the *decision and justification* stay with A1. This module
therefore emits ranked facts + gates, never a selection.

Score of candidate v = HDE over the two-variant set {V1, v}, aggregated over
eligible CVEs (equal weight). Per-CVE p is the minimum probe-level permutation
p (conservative: detects "any probe diverges").
"""

from __future__ import annotations

from . import metrics as M
from . import stats as S


def _axis_diff(factors: dict, a: str, b: str) -> list[str]:
    fa, fb = factors.get(a, {}), factors.get(b, {})
    return sorted(k for k in set(fa) & set(fb) if fa[k] != fb[k])


def candidate_scores(cells: dict, probes: dict, q_by_cve: dict,
                     baseline: str, candidates: list[str],
                     statuses: dict, classes: dict, factors: dict,
                     pool_cells: dict | None = None, pool_K: int | None = None,
                     B: int = 100, seed: int = 20261102) -> dict:
    out: dict = {"baseline": baseline, "candidates": {}}
    ranking: list[tuple[str, float]] = []

    pool_hde = None
    if pool_cells is not None and pool_K:
        pool_hde = S._agg(pool_cells, q_by_cve, pool_K, None)

    for v in candidates:
        if v == baseline:
            continue
        per: dict = {}
        for short, cfg in probes["cves"].items():
            sub = {}
            for pid, pv in cells.get(short, {}).items():
                if baseline in pv and v in pv:
                    sub[pid] = {baseline: pv[baseline], v: pv[v]}
            if not sub:
                per[short] = {"HDE": None, "DIV": None, "reason": "NO_PAIR_DATA",
                              "status": None}
                continue
            r = M.track_a({short: sub}, short, q_by_cve[short], 2, cfg["family"])
            pmin = None
            for pid, pv in sub.items():
                p = S.perm_p({x: pv[x]["states"] for x in pv}, 2,
                             B=max(50, B // 2), seed=seed)
                if p is not None:
                    pmin = p if pmin is None else min(pmin, p)
            per[short] = {
                "HDE": r["HDE"], "DIV": r["DIV"], "p": pmin,
                "status": {x: statuses.get(short, {}).get(x, {}).get("status")
                           for x in (baseline, v)},
            }

        vals = [x["HDE"] for x in per.values() if x.get("HDE") is not None]
        score = (sum(vals) / len(vals)) if vals else None

        st_all = [statuses.get(s, {}).get(v, {}).get("status")
                  for s in probes["cves"]]
        st_all = [x for x in st_all if x is not None]
        all_p = bool(st_all) and all(x == "P" for x in st_all)
        class_ok = classes.get(v) == "pure"
        entry = {
            "class": classes.get(v),
            "gates": {"status_all_P": all_p, "class_pure": class_ok,
                      "has_score": score is not None},
            "eligible": bool(all_p and class_ok and score is not None),
            "score": score,
            "per_cve": per,
            "axes_different_from_baseline": _axis_diff(factors, baseline, v),
        }
        if pool_hde is not None and pool_K:
            without = S._agg(
                {cve: {pid: {k: d for k, d in pv.items() if k != v}
                       for pid, pv in probes_set.items()}
                 for cve, probes_set in (pool_cells or {}).items()},
                q_by_cve, pool_K - 1, None)
            if without is not None:
                entry["loo_contribution"] = pool_hde - without
        out["candidates"][v] = entry
        if entry["eligible"] and score is not None:
            ranking.append((v, score))

    ranking.sort(key=lambda x: (-x[1], x[0]))
    out["ranking"] = [v for v, _ in ranking]
    out["note"] = ("ranking is informational; the V2 decision and its written "
                   "justification belong to A1 (select.py), and must cite fields "
                   "of this file")
    return out
