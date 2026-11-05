"""Track A (DIV/HDE/ATTR) and Track B (ASR/CMR/PSC/availability/transfer) metrics.

Pure functions over classified cells. No I/O, no randomness.
"""

from __future__ import annotations

import itertools
import math
from collections import Counter, defaultdict

# ---------------------------------------------------------------- primitives


def entropy(counts, n: int) -> float:
    if n <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            h -= p * math.log2(p)
    return h


def mi_raw(per_variant: dict[str, list[str]], K: int) -> tuple[float, float] | None:
    """Return (H(S|x), I(S;V|x)) in bits, or None if a variant is missing/insufficient."""
    if len(per_variant) != K:
        return None
    m = len(next(iter(per_variant.values())))
    if m == 0:
        return None
    probs: dict[str, float] = defaultdict(float)
    cond = 0.0
    for states in per_variant.values():
        if len(states) != m:
            return None
        cnt = Counter(states)
        for s, c in cnt.items():
            probs[s] += (c / m) / K
        cond += entropy(cnt.values(), m)
    H = entropy(probs.values(), 1)  # probs already sum to 1
    I = max(0.0, H - cond / K)
    return H, I


# ---------------------------------------------------------------- track A


def _states_map(pv: dict) -> dict[str, list[str]]:
    """Accept either {v: [states]} or {v: {'states': [...]}}."""
    out = {}
    for v, d in pv.items():
        out[v] = d if isinstance(d, list) else d.get("states", [])
    return out


def track_a(cells: dict, cve: str, q: int, K: int, probes: list[str],
            cell_mode: bool = False) -> dict:
    """DIV / HDE / ATTR for one CVE over its A+ probes.

    Weights are renormalised over probes with complete data, and the coverage
    ratio is disclosed explicitly (silent dilution is forbidden, v6.2).
    cell_mode=True means each observed probe is an oracle cell verdict that
    already aggregates the whole probe family (qw9/verdict-v1), so coverage is
    not applicable and each cell carries full weight.
    """
    per_probe = []
    for pid in probes:
        pv = cells.get(cve, {}).get(pid)
        if not pv:
            continue
        r = mi_raw(_states_map(pv), K)
        if r is None:
            continue
        H, I = r
        per_probe.append((pid, H, I))
    if not per_probe:
        return {"DIV": None, "HDE": None, "ATTR": None,
                "reason": "NO_PROBE_WITH_FULL_K", "per_probe": {}}

    k = math.log2(q)
    w = 1.0 / len(per_probe)
    DIV = w * sum(H for (_, H, _) in per_probe) / k
    HDE = w * sum(I for (_, _, I) in per_probe) / k
    ATTR = (HDE / DIV) if DIV > 1e-12 else None
    coverage = 1.0 if cell_mode else len(per_probe) / len(probes)
    return {
        "DIV": DIV,
        "HDE": HDE,
        "ATTR": ATTR,
        "reason": "OK",
        "coverage": coverage,
        "coverage_warning": (not cell_mode) and coverage < 0.5,
        "per_probe": {pid: {"DIV": H / k, "HDE": I / k} for pid, H, I in per_probe},
    }


def aggregate_track_a(per_cve: dict[str, dict]) -> dict:
    ok = {c: v for c, v in per_cve.items() if v["HDE"] is not None}
    if not ok:
        return {"DIV": None, "HDE": None, "ATTR": None, "n_cve": 0}
    DIV = sum(v["DIV"] for v in ok.values()) / len(ok)
    HDE = sum(v["HDE"] for v in ok.values()) / len(ok)
    return {
        "DIV": DIV,
        "HDE": HDE,
        "ATTR": (HDE / DIV) if DIV > 1e-12 else None,
        "n_cve": len(ok),
    }


# ---------------------------------------------------------------- track B helpers


def cell_profile(states: list[str], ys: list[int], crashes: list[int]) -> dict:
    n = len(states)
    if n == 0:
        return {"p": None, "Y": None, "cr": None, "state": None, "n": 0}
    p = sum(ys) / n
    cr = sum(crashes) / n
    modal = Counter(states).most_common(1)[0][0]
    return {"p": p, "Y": 1 if p >= 0.5 else 0, "cr": cr, "state": modal, "n": n}


def track_b(cells: dict, cves: dict, K: int) -> dict:
    """ASR / CMR / PSC / availability over the six CVEs (equal weight)."""
    asr_num, cmr_num, avail_num = 0.0, 0.0, 0.0
    n_cve = 0
    psc_by_cve: dict[str, dict] = {}
    per_cve: dict[str, dict] = {}

    for cve, cfg in cves.items():
        probes = cfg["family"]
        prof = {}
        for pid in probes:
            pv = cells.get(cve, {}).get(pid)
            if not pv:
                continue
            prof[pid] = {v: cell_profile(pv[v]["states"], pv[v]["ys"], pv[v]["crs"]) for v in pv}
        if not prof:
            per_cve[cve] = {"reason": "NO_DATA"}
            continue

        # ASR: mean over probes of mean over variants of p
        probe_asr = [sum(c["p"] for c in prof[pid].values()) / K
                     for pid in prof if len(prof[pid]) == K]
        # CMR: fraction of probes where every variant succeeds
        probe_cmr = [1.0 if all(c["Y"] == 1 for c in prof[pid].values()) else 0.0
                     for pid in prof if len(prof[pid]) == K]
        probe_av = [sum(c["cr"] for c in prof[pid].values()) / K
                    for pid in prof if len(prof[pid]) == K]

        if not probe_asr:
            per_cve[cve] = {"reason": "NO_FULL_K_PROBE"}
            continue

        asr = sum(probe_asr) / len(probe_asr)
        cmr = sum(probe_cmr) / len(probe_cmr)
        avail = sum(probe_av) / len(probe_av)
        psc = _psc(prof, K)
        per_cve[cve] = {"ASR": asr, "CMR": cmr, "availability": avail, "PSC": psc}
        asr_num += asr
        cmr_num += cmr
        avail_num += avail
        n_cve += 1

    if n_cve == 0:
        return {"ASR": None, "CMR": None, "availability": None,
                "PSC": {}, "per_cve": per_cve, "n_cve": 0}
    return {
        "ASR": asr_num / n_cve,
        "CMR": cmr_num / n_cve,
        "availability": avail_num / n_cve,
        "PSC": {c: v.get("PSC") for c, v in per_cve.items()},
        "per_cve": per_cve,
        "n_cve": n_cve,
    }


def _psc(prof: dict, K: int) -> dict:
    """Minimum probe subset that lands Y=1 on every variant; N/A when impossible."""
    variants = None
    for pid, cells in prof.items():
        if len(cells) != K:
            continue
        vs = set(cells)
        variants = vs if variants is None else (variants & vs)
    if not variants:
        return {"value": None, "reason": "NO_FULL_K_PROBE"}
    probes = sorted(prof)
    for r in range(1, len(probes) + 1):
        for combo in itertools.combinations(probes, r):
            if all(any(prof[p].get(v, {}).get("Y") == 1 for p in combo) for v in variants):
                return {"value": r, "witness": list(combo)}
    return {"value": None, "reason": "NO_COVERING_SET"}


def transfer(cells: dict, cve: str, cfg: dict, K: int) -> dict:
    """T over a same-CVE selection/test split (v6.5 pin)."""
    sel, test = cfg.get("selection", []), cfg.get("test", [])
    if not sel or not test:
        return {"value": None, "reason": "NO_SELECTION_SPLIT"}
    cve_cells = cells.get(cve, {})
    variants = sorted({v for pid in list(sel) + list(test) for v in cve_cells.get(pid, {})})
    if len(variants) < 2:
        return {"value": None, "reason": "TOO_FEW_VARIANTS"}
    ok = total = 0
    for u in variants:
        best_pid, best_p = None, -1.0
        for pid in sel:
            c = cve_cells.get(pid, {}).get(u)
            if not c:
                continue
            prof = cell_profile(c["states"], c["ys"], c["crs"])
            if prof["p"] is not None and prof["p"] > best_p:
                best_pid, best_p = pid, prof["p"]
        if best_pid is None:
            continue
        for v in variants:
            if v == u:
                continue
            c = cve_cells.get(best_pid, {}).get(v)
            if not c:
                continue
            total += 1
            if cell_profile(c["states"], c["ys"], c["crs"])["Y"] == 1:
                ok += 1
    if total == 0:
        return {"value": None, "reason": "NO_TRANSFER_PAIRS"}
    return {"value": ok / total, "n_pairs": total}


# ---------------------------------------------------------------- deltas


def baselines(cells: dict, cves: dict, b0: list[str], b1: list[str]) -> dict:
    """B0 vs B1 deltas for ASR/CMR/availability."""
    def subset(vs: list[str]) -> dict:
        out = {}
        for cve, cfg in cves.items():
            prof = {}
            for pid in cfg["family"]:
                pv = cells.get(cve, {}).get(pid)
                if not pv:
                    continue
                if not set(vs).issubset(pv):
                    continue
                prof[pid] = {v: pv[v] for v in vs}
            out[cve] = prof
        return out

    def summarize(sub: dict, K: int) -> dict:
        asr, cmr, av, n = 0.0, 0.0, 0.0, 0
        for cve, prof in sub.items():
            if not prof:
                continue
            a, c, v = [], [], []
            for pid, pv in prof.items():
                if len(pv) != K:
                    continue
                profs = {k: cell_profile(pvv["states"], pvv["ys"], pvv["crs"]) for k, pvv in pv.items()}
                a.append(sum(x["p"] for x in profs.values()) / K)
                c.append(1.0 if all(x["Y"] == 1 for x in profs.values()) else 0.0)
                v.append(sum(x["cr"] for x in profs.values()) / K)
            if not a:
                continue
            asr += sum(a) / len(a)
            cmr += sum(c) / len(c)
            av += sum(v) / len(v)
            n += 1
        if n == 0:
            return {"ASR": None, "CMR": None, "availability": None, "n_cve": 0}
        return {"ASR": asr / n, "CMR": cmr / n, "availability": av / n, "n_cve": n}

    sub0, sub1 = subset(b0), subset(b1)
    s0, s1 = summarize(sub0, len(b0)), summarize(sub1, len(b1))
    d = {}
    for k in ("ASR", "CMR", "availability"):
        if s0.get(k) is None or s1.get(k) is None:
            d["d" + k] = None
        else:
            d["d" + k] = s0[k] - s1[k]
    return {"B0": s0, "B1": s1, **d}
