"""Deterministic Markdown report renderer.

Numbers come only from the JSON artifacts. Section 9 is a template with explicit
placeholders: an LLM may fill the prose, but it must not introduce new numbers
(every number must already appear in sections 1-8).
"""

from __future__ import annotations


def f3(x) -> str:
    if x is None:
        return "N/A"
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (int,)):
        return str(x)
    return f"{x:.3f}"


def _pct(x) -> str:
    return "N/A" if x is None else f"{x:.3f}"


def render(hde: dict, safety: dict, audit: dict, status: dict, meta: dict | None = None) -> str:
    meta = meta or {}
    L: list[str] = []
    add = L.append

    add("# 评估报告（自动生成）\n")
    add(f"- 数据哈希：`{hde.get('digest', {}).get('raw_trials_sha256', 'N/A')}`")
    add(f"- 脚本哈希：`{hde.get('digest', {}).get('script_sha256', 'N/A')}`")
    add(f"- 置换次数 B={hde.get('digest', {}).get('B')}，种子={hde.get('digest', {}).get('seed')}")
    add(f"- 部署模型：{safety.get('deployment_model', 'N/A')}\n")

    # 1. session eligibility
    cov = audit.get("coverage", {})
    add("## 1. 会话资格\n")
    add("| 项 | 值 |")
    add("|---|---|")
    add(f"| 有效覆盖率 | {_pct(cov.get('rate'))}（{cov.get('valid')}/{cov.get('planned')}） |")
    add(f"| 证据冲突 | {audit.get('conflicts', {}).get('count')} |")
    for name, nf in (audit.get("noise_floor") or {}).items():
        add(f"| 噪声地板 `{name}` Q95 | {f3(nf.get('q95'))} |")
    nc = audit.get("negative_controls", {})
    add(f"| 阴性对照 | {nc.get('n_probes') or 0} 条独立探针 / {nc.get('n_trials') or 0} 次试验，"
        f"误报 {nc.get('probe_level_false_positives') or 0}，"
        f"单侧 95% 上界 {f3(nc.get('fpr_upper_95_one_sided'))} |")
    add(f"| 判定 | **{audit.get('verdict')}** |\n")

    # 2. root-cause matrix
    add("## 2. 根因矩阵（P/S/X/U）\n")
    counts: dict[str, int] = {}
    for cve, vs in status.items():
        for v, rec in vs.items():
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    add("| 状态 | 计数 |")
    add("|---|---|")
    for k in ("P", "S", "X_obs", "U_disputed"):
        add(f"| {k} | {counts.get(k, 0)} |")
    add("")

    # 3. track A main
    add("## 3. 轨道 A 主结果\n")
    g = (hde.get("gauges") or {}).get("final_pure", {})
    add("| 口径 | K | m | DIV | HDE | ATTR | n_cve |")
    add("|---|---|---|---|---|---|---|")
    for name in ("pool_pure", "pool_shift", "final_pure", "final_shift"):
        gg = (hde.get("gauges") or {}).get(name)
        if not gg:
            continue
        add(f"| `{name}` | {gg.get('K')} | {gg.get('m')} | {f3(gg.get('DIV'))} | "
            f"{f3(gg.get('HDE'))} | {f3(gg.get('ATTR'))} | {gg.get('n_cve')} |")
    add("")
    if g.get("per_cve"):
        add("**逐 CVE（final_pure）**\n")
        add("| CVE | DIV | HDE | ATTR | p | p(Holm) | 资格 |")
        add("|---|---|---|---|---|---|---|")
        for cve, r in g["per_cve"].items():
            add(f"| {cve} | {f3(r.get('DIV'))} | {f3(r.get('HDE'))} | {f3(r.get('ATTR'))} | "
                f"{f3(r.get('p'))} | {f3(r.get('p_holm'))} | {r.get('reason') or r.get('eligibility') or 'OK'} |")
        add("")

    # 4. splits
    add("## 4. 校准 / 验证集\n")
    add("| 分集 | CVE | DIV | HDE | ATTR |")
    add("|---|---|---|---|---|")
    for name, rec in (hde.get("splits") or {}).items():
        add(f"| `{name}` | {', '.join(rec.get('cves', []))} | {f3(rec.get('DIV'))} | "
            f"{f3(rec.get('HDE'))} | {f3(rec.get('ATTR'))} |")
    add("")

    # 5. track B
    tb = safety.get("track_b", {})
    add("## 5. 轨道 B（安全后果）\n")
    add("| 指标 | 值 |")
    add("|---|---|")
    add(f"| ASR | {f3(tb.get('ASR'))} |")
    add(f"| CMR | {f3(tb.get('CMR'))} |")
    add(f"| 可用性损失 | {f3(tb.get('availability'))} |")
    b = safety.get("baselines", {})
    add(f"| ΔASR (B0−B1) | {f3(b.get('dASR'))} |")
    add(f"| ΔCMR (B0−B1) | {f3(b.get('dCMR'))} |")
    add(f"| ΔAvail (B1−B0) | {f3(b.get('davailability'))} |")
    add("")
    tb_chains = safety.get("chains") or {}
    if tb_chains:
        add("**两阶段链**\n")
        add("| CVE | ChainSuccess | BlockRate | n |")
        add("|---|---|---|---|")
        for cve, r in tb_chains.items():
            add(f"| {cve} | {f3(r.get('ChainSuccess'))} | {f3(r.get('BlockRate'))} | {r.get('n')} |")
        add("")

    # 6. axes
    ax = (safety.get("matrix") or {}).get("axes") or {}
    add("## 6. 轴分析\n")
    if ax:
        add("| 轴 | K | HDE |")
        add("|---|---|---|")
        for name, rec in ax.items():
            add(f"| `{name}` | {rec.get('K')} | {f3(rec.get('HDE'))} |")
        add("")
        add("配对对照见 `matrix.json`（含每对 HDE 与置换 p）。\n")
    else:
        add("无轴数据（未配置 `axis_groups` 或数据不足）。\n")

    # 7. probes
    add("## 7. 探针诊断\n")
    add(f"- 无效试验：{audit.get('invalid', {}).get('count', 0)}")
    add(f"- 冲突明细：{len(audit.get('conflicts', {}).get('details', []))} 条")
    add("")

    # 8. sensitivity
    sens = hde.get("sensitivity") or {}
    add("## 8. 敏感性\n")
    add(f"- 留一探针最大偏移：{f3((sens.get('loo') or {}).get('max_delta'))}")
    add(f"- 留一变体范围：{f3((sens.get('loo_variant') or {}).get('min'))} ~ "
        f"{f3((sens.get('loo_variant') or {}).get('max'))}")
    sc = sens.get("scenario") or {}
    if sc:
        add(f"- U_disputed 情景区间：{f3(sc.get('range', [None, None])[0])} ~ "
            f"{f3(sc.get('range', [None, None])[1])}（scenario_P={f3(sc.get('HDE_P'))}, "
            f"scenario_S={f3(sc.get('HDE_S'))}）")
    add("")

    # 9. prose template
    add("## 9. 结论（文字由 LLM 填写，禁止引入新数字）\n")
    add("> 只能引用第 1–8 节已出现的数字；任何新数字视为幻觉，退回重写。\n")
    add("<在此处填写：哪类缺陷对哪类异构敏感、安全后果是否相对基线下降、代价是什么>\n")

    add("---\n")
    add("*本报告由 `evalkernel.report` 确定性生成；数字均可在 `hde.json` / "
        "`safety.json` / `audit.json` 中逐项追溯。*")
    return "\n".join(L) + "\n"
