"""Pipeline: raw trials -> classification -> status -> Track A/B -> matrix ->
scores -> report. Evaluation side of the A1 handoff (design doc §7)."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path

from . import chains as CH
from . import fitness as FIT
from . import integrate as IG
from . import manifests as MF
from . import matrix as MX
from . import metrics as M
from . import qw9port as QP
from . import repro as RP
from . import report as RPT
from . import scores as SC
from . import stats as S
from . import verdicts as VD
from .predicates import (crash_of, derive_status, eligibility,
                         eligibility_classes, extract_features, state_of, y_of)
from .schema import (RawTrial, canon, dump_json, dump_jsonl, load_config,
                     load_trials, sha256_text)


# ---------------------------------------------------------------- classify


def classify(trials: list[RawTrial], probes: dict) -> list[dict]:
    cves = probes["cves"]
    out = []
    for t in trials:
        short = _short(t.cve, cves)
        cfg = cves[short]
        f = extract_features(t, cfg)
        state = state_of(short, f) if t.group == "A+" else "L0"
        y = y_of(short, f, state) if t.group == "A+" else 0
        valid = state != "U_invalid"
        out.append({
            "cve": short, "probe": t.probe, "variant": t.variant,
            "repeat": t.repeat, "group": t.group, "state": state, "Y": y,
            "crash": crash_of(f), "R": f["rc_R"], "valid": valid,
            "invalid_reason": None if valid else "EVIDENCE_INCOMPLETE",
            "evidence_sha256": t.evidence_sha(),
        })
    return out


def _short(cve: str, cves: dict) -> str:
    if cve in cves:
        return cve
    for short, cfg in cves.items():
        if cfg.get("cve") == cve:
            return short
    raise KeyError(f"unknown cve: {cve}")


def build_cells(classified: list[dict], variants: list[str]) -> dict:
    acc = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    for r in classified:
        if r["group"] != "A+" or not r["valid"] or r["variant"] not in variants:
            continue
        acc[r["cve"]][r["probe"]][r["variant"]]["states"].append((r["repeat"], r["state"]))
        acc[r["cve"]][r["probe"]][r["variant"]]["ys"].append((r["repeat"], r["Y"]))
        acc[r["cve"]][r["probe"]][r["variant"]]["crs"].append((r["repeat"], r["crash"]))
    cells: dict = {}
    for cve, probes_ in acc.items():
        cells[cve] = {}
        for pid, vs in probes_.items():
            cells[cve][pid] = {}
            for v, d in vs.items():
                cells[cve][pid][v] = {
                    "states": [s for _, s in sorted(d["states"])],
                    "ys": [y for _, y in sorted(d["ys"])],
                    "crs": [c for _, c in sorted(d["crs"])],
                }
    return cells


def status_table(classified: list[dict], probes: dict, variants_cfg: dict,
                 variant_set: list[str]) -> dict:
    rc = defaultdict(dict)
    for r in classified:
        if r["group"] != "A+" or r["variant"] not in variant_set:
            continue
        rc[(r["cve"], r["variant"])].setdefault(r["probe"], r["R"])
    hunks = variants_cfg.get("hunks_overlap", {})
    overrides = variants_cfg.get("status_overrides", {})  # {cve: {variant: "P"}}
    table = {}
    for short, cfg in probes["cves"].items():
        table[short] = {}
        for v in variant_set:
            obs = rc.get((short, v), {})
            override = overrides.get(short, {}).get(v)
            if override:
                table[short][v] = {"status": override,
                                   "reason": "STATUS_OVERRIDE",
                                   "R": dict(sorted(obs.items()))}
                continue
            overlap = short in hunks.get(v, [])
            st, reason = derive_status(obs, cfg["canonical"], overlap)
            table[short][v] = {"status": st, "reason": reason,
                               "R": dict(sorted(obs.items()))}
    return table


def resolve_classes(variants_cfg: dict) -> dict:
    """Explicit 'classes' wins; otherwise infer from group membership."""
    explicit = variants_cfg.get("classes", {})
    out = {}
    for vid, meta in variants_cfg["variants"].items():
        if vid in explicit:
            out[vid] = explicit[vid]
        else:
            group = meta.get("group", "")
            out[vid] = {"T": "struct"}.get(group, "pure")
    return out


# ---------------------------------------------------------------- gauges


def gauge_report(cells: dict, probes: dict, statuses: dict, variant_set: list[str],
                 kind: str, K: int, m: int, B: int, seed: int,
                 classes: dict | None = None, with_p: bool = True,
                 cell_mode: bool = False) -> dict:
    if K < 2:
        return {"K": K, "m": m, "DIV": None, "HDE": None, "ATTR": None,
                "n_cve": 0, "reason": "SET_TOO_SMALL", "per_cve": {}}
    per_cve = {}
    pvals = {}
    for short, cfg in probes["cves"].items():
        st = {v: statuses.get(short, {}).get(v, {}).get("status", "U_disputed")
              for v in variant_set}
        if classes is None:
            ok, why = eligibility(st, kind)
        else:
            ok, why = eligibility_classes(
                st, {v: classes.get(v, "pure") for v in variant_set}, kind)
        if not ok:
            per_cve[short] = {"DIV": None, "HDE": None, "ATTR": None, "reason": why}
            continue
        sub = {short: cells.get(short, {})}
        r = M.track_a(sub, short, int(cfg.get("q", 4)), K, cfg["family"],
                      cell_mode=cell_mode)
        r["eligibility"] = why
        per_cve[short] = r
        if with_p and r["HDE"] is not None:
            ps = []
            for pid in cfg["family"]:
                pv = cells.get(short, {}).get(pid)
                if pv and len(pv) == K:
                    p = S.perm_p({v: pv[v]["states"] for v in pv}, K,
                                 B=max(50, B // 2), seed=seed)
                    if p is not None:
                        ps.append(p)
            if ps:
                pvals[short] = min(ps)
    agg = M.aggregate_track_a({k: v for k, v in per_cve.items() if v.get("HDE") is not None})
    if pvals:
        adj = S.holm(pvals)
        for short, p in pvals.items():
            per_cve[short]["p"] = p
            per_cve[short]["p_holm"] = adj.get(short)
    return {"K": K, "m": m, "DIV": agg["DIV"], "HDE": agg["HDE"],
            "ATTR": agg["ATTR"], "n_cve": agg["n_cve"], "per_cve": per_cve}


def _override(statuses: dict, target: str, to: str) -> dict:
    out = {}
    for cve, vs in statuses.items():
        out[cve] = {}
        for v, rec in vs.items():
            rec2 = dict(rec)
            if rec2.get("status") == target:
                rec2["status"] = to
                rec2["reason"] = f"SCENARIO_{to}"
            out[cve][v] = rec2
    return out


def scenario_range(cells: dict, probes: dict, statuses: dict, vset: list[str],
                   K: int, m: int, classes: dict) -> dict:
    has_u = any(rec.get("status") == "U_disputed"
                for vs in statuses.values() for rec in vs.values())
    if not has_u:
        return {"applicable": False, "reason": "NO_U_DISPUTED"}
    g_p = gauge_report(cells, probes, _override(statuses, "U_disputed", "P"),
                       vset, "pure", K, m, B=1, seed=0, classes=classes, with_p=False)
    g_s = gauge_report(cells, probes, _override(statuses, "U_disputed", "S"),
                       vset, "shift", K, m, B=1, seed=0, classes=classes, with_p=False)
    vals = [x for x in (g_p.get("HDE"), g_s.get("HDE")) if x is not None]
    return {"applicable": True, "HDE_P": g_p.get("HDE"), "HDE_S": g_s.get("HDE"),
            "range": [min(vals), max(vals)] if vals else [None, None]}


# ---------------------------------------------------------------- audit


def audit(classified: list[dict], m_planned: int) -> dict:
    total = len(classified)
    valid = sum(1 for r in classified if r["valid"])
    conflicts = []
    for r in classified:
        if r["group"] != "A+" or not r["valid"]:
            continue
        if r["R"] == 0 and r["state"] in ("L2", "L3"):
            conflicts.append({"cve": r["cve"], "probe": r["probe"],
                              "variant": r["variant"], "state": r["state"]})
    neg = [r for r in classified if r["group"] == "A-"]
    probes_neg = {(r["cve"], r["probe"]) for r in neg}
    fpr_probe_level = len({(r["cve"], r["probe"]) for r in neg
                           if r["state"] in ("L2", "L3")})
    counts = Counter((r["cve"], r["probe"], r["variant"], r["group"])
                     for r in classified if r["valid"])
    retest = []
    for (cve, probe, variant, group), c in sorted(counts.items()):
        if group == "A+" and c < max(1, m_planned // 2):
            retest.append({"cve": cve, "probe": probe, "variant": variant,
                           "valid": c, "reason": "COVERAGE_BELOW_HALF"})
    return {
        "coverage": {"planned": total, "valid": valid,
                     "rate": (valid / total) if total else None},
        "conflicts": {"count": len(conflicts), "details": conflicts[:50]},
        "negative_controls": {
            "n_probes": len(probes_neg), "n_trials": len(neg),
            "probe_level_false_positives": fpr_probe_level,
            "trial_level_false_positives": sum(1 for r in neg if r["state"] in ("L2", "L3")),
            "fpr_upper_95_one_sided": S.fpr_upper(len(probes_neg), fpr_probe_level),
        },
        "invalid": {"count": total - valid,
                    "reasons": dict(Counter(r["invalid_reason"] for r in classified
                                            if not r["valid"]))},
        "retest_requests": retest,
    }


def _verdict(audit_obj: dict) -> str:
    if audit_obj["conflicts"]["count"] > 0:
        return "unusable:evidence_conflict"
    rate = audit_obj["coverage"]["rate"]
    if rate is not None and rate < 0.95:
        return "needs_retest:coverage_below_0.95"
    if audit_obj["retest_requests"]:
        return "needs_retest:probe_variant_coverage"
    return "usable"


# ---------------------------------------------------------------- run


def run(raw_path: str, config_dir: str, out_dir: str, B: int = 200,
        seed: int = 20261102, deployment_model: str = "M2",
        journal_path: str | None = None, evidence_dir: str | None = None,
        run_id: str | None = None, verdicts_dir: str | None = None) -> dict:
    cfg = load_config(config_dir)
    probes, vcfg = cfg["probes"], cfg["variants"]
    if verdicts_dir:
        # qw9/verdict-v1 contract (matrix runner oracle output)
        classified = VD.ingest_verdict_dir(verdicts_dir, probes)
        errors = [r for r in classified if "_parse_error" in r]
        if errors:
            raise ValueError(f"verdict ingest errors: {errors[:3]}")
        trials = []          # evidence hashes live in the verdict rows
    else:
        trials = load_trials(raw_path)
        classified = classify(trials, probes)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    dump_jsonl(out / "classified_trials.jsonl", classified)

    classes = resolve_classes(vcfg)
    h_group = vcfg["h_group"]
    t_group = vcfg["t_group"]
    final_set = vcfg["final"]
    pure_final = [v for v in final_set if classes.get(v) == "pure"]
    shift_final = [v for v in final_set if classes.get(v) in ("pure", "struct")]

    gauges_spec = {
        "pool_pure": (h_group, "pure"),
        "pool_shift": (h_group + t_group, "shift"),
        "final_pure": (pure_final, "pure"),
        "final_shift": (shift_final, "shift"),
    }
    q_by_cve = {k: int(v.get("q", 4)) for k, v in probes["cves"].items()}
    m_planned = max((r["repeat"] for r in classified), default=1)

    gauges, statuses_by_gauge, cells_by_gauge = {}, {}, {}
    for name, (vset, kind) in gauges_spec.items():
        if not vset:
            gauges[name] = {"K": 0, "m": 0, "DIV": None, "HDE": None,
                            "ATTR": None, "n_cve": 0, "reason": "EMPTY_SET",
                            "per_cve": {}}
            continue
        cells = build_cells(classified, vset)
        st = status_table(classified, probes, vcfg, vset)
        cells_by_gauge[name] = cells
        statuses_by_gauge[name] = st
        m = max((len(d["states"]) for cve in cells for p in cells[cve]
                 for d in cells[cve][p].values()), default=0)
        gauges[name] = gauge_report(cells, probes, st, vset, kind, len(vset), m,
                                    B, seed, classes=classes,
                                    cell_mode=(verdicts_dir is not None))
        if name == "final_pure":
            excluded = [{"variant": v, "class": classes.get(v)}
                        for v in final_set if classes.get(v) != "pure"]
            if excluded:
                gauges[name]["excluded_by_class"] = excluded

    ci = {}
    for name in ("pool_pure", "pool_shift"):
        vset = gauges_spec[name][0]
        if vset and len(vset) >= 3:
            ci[name] = S.bootstrap_ci(cells_by_gauge[name], q_by_cve, vset,
                                      B=min(300, max(60, B)), seed=seed)

    kh_cells = build_cells(classified, vcfg["kh_group"])
    floors = {}
    for name, (vset, _kind) in gauges_spec.items():
        if not vset:
            continue
        floors[name] = S.noise_floor(kh_cells, q_by_cve, len(vset),
                                     {k: v["family"] for k, v in probes["cves"].items()},
                                     B=max(50, B // 4), seed=seed)

    # Track B / chains / transfer / baselines: over the *delivered* set (V1,V2,V3),
    # including class-isolation members. Class never gates Track B.
    cells_delivered = build_cells(classified, final_set)
    tb = M.track_b(cells_delivered, probes["cves"], len(final_set))
    cells_base = build_cells(classified, vcfg["b0"] + final_set)
    base = M.baselines(cells_base, probes["cves"], vcfg["b0"], final_set)

    chains_cfg = probes.get("chains", {})
    delivered_only = [r for r in classified if r["variant"] in set(final_set)]
    chains_final = CH.chain_metrics(delivered_only, chains_cfg) if chains_cfg else {}
    b0_set = set(vcfg["b0"])
    chains_b0 = CH.chain_metrics([r for r in classified if r["variant"] in b0_set],
                                 chains_cfg) if chains_cfg else {}
    chain_deltas = CH.chain_deltas(chains_b0, chains_final) if chains_cfg else {}

    transfers = {c: M.transfer(cells_delivered, c, cfg_probe, len(final_set))
                 for c, cfg_probe in probes["cves"].items()}

    # per-candidate score cards for A1 (its flow steps 8-10)
    pool_statuses = statuses_by_gauge.get("pool_shift",
                                          statuses_by_gauge.get("pool_pure", {}))
    pool_set = h_group + t_group
    cells_pool = build_cells(classified, pool_set)
    baseline = final_set[0]
    cells_for_scores = build_cells(classified, pool_set + [baseline])
    scores = SC.candidate_scores(
        cells_for_scores, probes, q_by_cve, baseline=baseline,
        candidates=pool_set, statuses=pool_statuses,
        classes=classes, factors=vcfg.get("factors", {}),
        pool_cells=cells_pool, pool_K=len(pool_set),
        B=B, seed=seed)

    # sensitivity on the pure delivered gauge
    cells_pure_final = cells_by_gauge.get("final_pure", {})
    loo_p = S.loo_probe(cells_pure_final, q_by_cve, len(pure_final))
    loo_v = S.loo_variant(cells_delivered, q_by_cve, len(final_set), final_set)
    scenario = scenario_range(cells_pure_final, probes,
                              statuses_by_gauge.get("final_pure", {}),
                              pure_final, len(pure_final), m_planned, classes)

    # matrix over the whole pool (H+T)
    axes = MX.axis_matrix(cells_pool, probes, vcfg.get("axis_groups", {}), q_by_cve)
    pairs = MX.pairwise(cells_pool, probes, vcfg.get("contrasts", []), q_by_cve,
                        B=max(50, B // 2), seed=seed)
    fact = MX.factorial(cells_pool, probes, vcfg.get("factors", {}), q_by_cve,
                        builds_per_cell=vcfg.get("builds_per_cell", 1))

    audit_obj = audit(classified, m_planned)
    audit_obj["noise_floor"] = floors
    audit_obj["verdict"] = _verdict(audit_obj)

    # A1 delivery check (optional until artifacts/<run_id> exists)
    mcfg = vcfg.get("manifests", {})
    mdir = mcfg.get("dir")
    if mdir:
        audit_obj["manifest_check"] = MF.verify_manifests(
            mdir, pool_set, mcfg.get("required_fields"))
    else:
        audit_obj["manifest_check"] = {"checked": False,
                                       "reason": "MANIFEST_DIR_NOT_CONFIGURED"}

    if verdicts_dir:
        input_sha = sha256_text("\n".join(r["evidence_sha256"] for r in classified))
    else:
        input_sha = sha256_text("\n".join(t.evidence_sha() for t in trials))
    script_sha = sha256_text(canon({"module": "evalkernel", "seed": seed, "B": B,
                                    "config": canon({"p": probes, "v": vcfg})}))
    digest = {"raw_trials_sha256": input_sha, "script_sha256": script_sha,
              "seed": seed, "B": B, "verdict": audit_obj["verdict"]}

    repro = RP.reproducibility(classified)

    # scores.json 装饰为 qw9/scores/v1（执行 Agent deliver --scores 的输入形状）。
    # run_id 缺省取输入哈希前 12 位 —— 确定性不破坏（同输入同 run_id）。
    rid_for_scores = run_id or digest["raw_trials_sha256"][:12]
    scores = QP.decorate(scores, rid_for_scores, repro)

    hde = {
        "reproducibility": repro,
        "gauges": gauges,
        "status": statuses_by_gauge,
        "noise_floor": floors,
        "ci": ci,
        "sensitivity": {"loo": loo_p, "loo_variant": loo_v, "scenario": scenario},
        "splits": _split_reports(classified, probes, vcfg, q_by_cve, pure_final),
        "digest": digest,
    }
    safety = {
        "deployment_model": deployment_model,
        "track_b": tb,
        "baselines": base,
        "chains": chains_final,
        "chain_deltas": chain_deltas,
        "transfer": transfers,
        "matrix": {"axes": axes, "pairwise": pairs, "factorial": fact},
        "note": "CMR is a common-mode-risk indicator; only comparable to system "
                "gain under M2 (parallel arbitration).",
    }

    dump_json(out / "hde.json", hde)
    dump_json(out / "safety.json", safety)
    dump_json(out / "audit.json", audit_obj)
    dump_json(out / "status.json", statuses_by_gauge)
    dump_json(out / "matrix.json", {"axes": axes, "pairwise": pairs, "factorial": fact})
    dump_json(out / "scores.json", scores)
    dump_json(out / "fitness.json", FIT.fitness(hde, safety))

    report_md = RPT.render(hde, safety, audit_obj,
                           statuses_by_gauge.get("final_pure", {}),
                           meta={"deployment_model": deployment_model})
    (out / "report.md").write_text(report_md, encoding="utf-8")

    manifest = {}
    for f in sorted(out.iterdir()):
        if f.is_file() and f.name != "manifest.json":
            manifest[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    dump_json(out / "manifest.json", {"files": manifest, "digest": digest})

    integration = None
    if journal_path or evidence_dir:
        rid = run_id or digest["raw_trials_sha256"][:12]
        integration = {"run_id": rid}
        if journal_path:
            events = IG.journal_events(audit_obj, rid)
            IG.append_journal(journal_path, events)
            integration["journal_events"] = len(events)
        if evidence_dir:
            integration["evidence"] = IG.write_evidence(out, evidence_dir, rid)
        IG.write_results(out, rid)
        integration["results"] = str(out / "results.json")

    return {"hde": hde, "safety": safety, "audit": audit_obj, "scores": scores,
            "integration": integration}


def _split_reports(classified: list[dict], probes: dict, vcfg: dict,
                   q_by_cve: dict, variant_set: list[str]) -> dict:
    splits = vcfg.get("splits", {})
    out = {}
    resolved = resolve_classes(vcfg)
    for name, cves in splits.items():
        if not cves:
            continue
        sub_cfg = {"cves": {k: v for k, v in probes["cves"].items() if k in cves},
                   "variants": vcfg}
        sub = [r for r in classified if r["cve"] in cves]
        cells = build_cells(sub, variant_set)
        st = status_table(sub, sub_cfg, vcfg, variant_set)
        per = {}
        for short, c in sub_cfg["cves"].items():
            ok, why = eligibility_classes(
                {v: st[short][v]["status"] for v in variant_set},
                {v: resolved.get(v, "pure") for v in variant_set}, "pure")
            if not ok:
                per[short] = {"DIV": None, "HDE": None, "ATTR": None, "reason": why}
                continue
            per[short] = M.track_a(cells, short, q_by_cve[short],
                                   len(variant_set), c["family"])
        agg = M.aggregate_track_a({k: v for k, v in per.items() if v.get("HDE") is not None})
        out[name] = {"cves": cves, "DIV": agg["DIV"], "HDE": agg["HDE"],
                     "ATTR": agg["ATTR"], "n_cve": agg["n_cve"], "per_cve": per}
    return out
