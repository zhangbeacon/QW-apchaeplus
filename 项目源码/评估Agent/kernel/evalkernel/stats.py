"""Statistical layer: permutation null, Holm, noise floor, LOO, split-half,
cluster bootstrap, FPR upper bound.

Deterministic given a seed. Only stdlib. No LLM.
"""

from __future__ import annotations

import math
import random

from .metrics import mi_raw, track_a


# ---------------------------------------------------------------- permutation


def perm_p(per_variant: dict[str, list[str]], K: int, B: int = 1000,
           seed: int = 20261102) -> float | None:
    """Paired permutation: within each repeat round, reassign the K outcomes."""
    obs = mi_raw(per_variant, K)
    if obs is None:
        return None
    _, I_obs = obs
    variants = sorted(per_variant)
    m = len(per_variant[variants[0]])
    rng = random.Random(seed)
    ge = 0
    for _ in range(B):
        permuted: dict[str, list[str]] = {v: [] for v in variants}
        for r in range(m):
            round_states = [per_variant[v][r] for v in variants]
            rng.shuffle(round_states)
            for v, s in zip(variants, round_states):
                permuted[v].append(s)
        res = mi_raw(permuted, K)
        if res is not None and res[1] >= I_obs - 1e-12:
            ge += 1
    return (ge + 1) / (B + 1)


def holm(pvals: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (family-wise error control)."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    n = len(items)
    adj = {}
    running = 0.0
    for i, (k, p) in enumerate(items):
        val = (n - i) * p
        running = max(running, val)
        adj[k] = min(1.0, running)
    return adj


def kendall_tau(a: dict[str, float], b: dict[str, float]) -> float | None:
    keys = sorted(set(a) & set(b))
    n = len(keys)
    if n < 2:
        return None
    conc = disc = 0
    for i in range(n):
        for j in range(i + 1, n):
            da = a[keys[i]] - a[keys[j]]
            db = b[keys[i]] - b[keys[j]]
            if da == 0 or db == 0:
                continue
            if da * db > 0:
                conc += 1
            else:
                disc += 1
    denom = conc + disc
    return None if denom == 0 else (conc - disc) / denom


# ---------------------------------------------------------------- LOO / split


def loo_probe(cells: dict, q_by_cve: dict, K: int) -> dict:
    """Delete one probe at a time, recompute aggregate HDE, report max shift."""
    base = _agg(cells, q_by_cve, K, None)
    if base is None:
        return {"max_delta": None, "per_probe": {}, "tau": None}
    per = {}
    for cve in sorted(cells):
        for pid in sorted(cells[cve]):
            v = _agg(cells, q_by_cve, K, (cve, pid))
            if v is not None:
                per[f"{cve}:{pid}"] = v
    max_delta = max((abs(v - base) for v in per.values()), default=None)
    return {"max_delta": max_delta, "base": base, "per_probe": per}


def loo_variant(cells: dict, q_by_cve: dict, K: int, variants: list[str]) -> dict:
    """Delete one variant at a time (K-1 set) and report the shift."""
    base = _agg(cells, q_by_cve, K, None)
    if base is None or len(variants) < 2:
        return {"max_delta": None, "per_variant": {}, "base": base}
    per = {}
    for drop in variants:
        keep = [v for v in variants if v != drop]
        sub = {}
        for cve, probes in cells.items():
            sub[cve] = {}
            for pid, pv in probes.items():
                if set(keep).issubset(pv):
                    sub[cve][pid] = {v: pv[v] for v in keep}
        val = _agg(sub, q_by_cve, len(keep), None)
        if val is not None:
            per[drop] = val
    deltas = [abs(v - base) for v in per.values()]
    return {"base": base, "per_variant": per,
            "max_delta": max(deltas) if deltas else None,
            "min": min(per.values()) if per else None,
            "max": max(per.values()) if per else None}


def _agg(cells: dict, q_by_cve: dict, K: int, drop: tuple | None) -> float | None:
    vals = []
    for cve, probes in cells.items():
        if cve not in q_by_cve:
            continue
        sub = {p: d for p, d in probes.items() if drop is None or (cve, p) != drop}
        if not sub:
            continue
        r = track_a({cve: sub}, cve, q_by_cve[cve], K, sorted(sub))
        if r["HDE"] is not None:
            vals.append(r["HDE"])
    if not vals:
        return None
    return sum(vals) / len(vals)


def split_half(per_variant: dict[str, list[str]], K: int) -> dict:
    """Stability across the two halves of the repeat rounds (K=3 friendly)."""
    variants = sorted(per_variant)
    if not variants:
        return {"reason": "NO_DATA", "delta": None}
    m = len(per_variant[variants[0]])
    if m < 4:
        return {"reason": "TOO_FEW_REPEATS", "delta": None}
    h = m // 2
    a = {v: per_variant[v][:h] for v in variants}
    b = {v: per_variant[v][h:] for v in variants}
    ra, rb = mi_raw(a, K), mi_raw(b, K)
    if ra is None or rb is None:
        return {"reason": "HALF_TOO_SMALL", "delta": None}
    return {"first": ra[1], "second": rb[1], "delta": abs(ra[1] - rb[1])}


# ---------------------------------------------------------------- bootstrap


def bootstrap_ci(cells: dict, q_by_cve: dict, variants: list[str], B: int = 2000,
                 seed: int = 20261102, alpha: float = 0.05) -> dict:
    """Cluster bootstrap over variants (pool gauges only; K=3 is not meaningful)."""
    if len(variants) < 3:
        return {"ci": None, "reason": "K_TOO_SMALL_FOR_VARIANT_BOOTSTRAP"}
    rng = random.Random(seed)
    stats = []
    for _ in range(B):
        picks = [rng.choice(variants) for _ in variants]
        sub = {}
        for cve, probes in cells.items():
            sub[cve] = {}
            for pid, pv in probes.items():
                renamed = {}
                for i, src in enumerate(picks):
                    if src in pv:
                        renamed[f"{src}#{i}"] = pv[src]
                if len(renamed) == len(variants):
                    sub[cve][pid] = renamed
        val = _agg(sub, q_by_cve, len(variants), None)
        if val is not None:
            stats.append(val)
    if len(stats) < 10:
        return {"ci": None, "reason": "EMPTY_BOOTSTRAP"}
    stats.sort()
    lo = stats[int(math.floor(alpha / 2 * (len(stats) - 1)))]
    hi = stats[int(math.ceil((1 - alpha / 2) * (len(stats) - 1)))]
    return {"ci": [lo, hi], "B": len(stats)}


# ---------------------------------------------------------------- FPR bound

def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes)."""
    MAXIT, EPS, FPMIN = 200, 3e-12, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return h


def betai(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a,b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def beta_ppf(p: float, a: float, b: float) -> float:
    """Inverse CDF of Beta(a,b) by bisection (enough precision for a CI bound)."""
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if betai(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def fpr_upper(n: int, k: int, alpha: float = 0.05) -> float | None:
    """One-sided (1-alpha) upper bound for a binomial proportion (Clopper-Pearson)."""
    if n <= 0:
        return None
    if k == 0:
        return 1.0 - alpha ** (1.0 / n)
    if k >= n:
        return 1.0
    return beta_ppf(1.0 - alpha, k + 1, n - k)


# ---------------------------------------------------------------- noise floor


def noise_floor(kh_cells: dict, q_by_cve: dict, K: int, probes_by_cve: dict,
                B: int = 200, seed: int = 20261102) -> dict:
    """Null distribution by permutation on homogeneous instances (v6.5 pin (3))."""
    variants = sorted({v for cve in kh_cells for p in kh_cells[cve]
                       for v in kh_cells[cve][p]})
    if len(variants) < K:
        return {"q95": None, "reason": "NOT_ENOUGH_INSTANCES", "B": B}
    rng = random.Random(seed)
    vals = []
    for _ in range(B):
        sel = rng.sample(variants, K) if len(variants) > K else list(variants)
        permuted = {}
        for cve in kh_cells:
            permuted[cve] = {}
            for pid, pv in kh_cells[cve].items():
                if not set(sel).issubset(pv):
                    continue
                m = len(pv[sel[0]]["states"]) if isinstance(pv[sel[0]], dict) else len(pv[sel[0]])
                stacks = {}
                for v in sel:
                    cell = pv[v]
                    stacks[v] = list(cell["states"]) if isinstance(cell, dict) else list(cell)
                for r in range(m):
                    round_states = [stacks[v][r] for v in sel]
                    rng.shuffle(round_states)
                    for v, s in zip(sel, round_states):
                        stacks[v][r] = s
                permuted[cve][pid] = {v: {"states": stacks[v]} for v in sel}
        r = _agg(permuted, q_by_cve, K, None)
        if r is not None:
            vals.append(r)
    if not vals:
        return {"q95": None, "reason": "EMPTY_NULL", "B": B}
    vals.sort()
    idx = min(len(vals) - 1, int(round(0.95 * (len(vals) - 1))))
    return {"q95": vals[idx], "null_mean": sum(vals) / len(vals),
            "null_max": vals[-1], "B": len(vals)}
