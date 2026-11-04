"""A1 · V2 初筛：读评估分数（只读，不改），过三条硬约束，产出短名单 + 取舍理由。

三条硬约束（设计文档 §4.2）：
1. 必须有分（分数缺失 / N/A / 非数值 → 淘汰）；
2. 不能和基线同参数（等于没变）；
3. 轴必须在 v2_axes 内（默认排除隔离轴——V3 是预注册的，V2 不得与之撞轴）。

铁律：理由必须能溯源到分数文件的具体字段（detail 非空），写不出来就退回——
本模块直接报错，不产出含糊理由。
"""

import json


class SelectError(ValueError):
    pass


def load_scores(path, score_key="score"):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cands = data.get("candidates")
    if not isinstance(cands, dict) or not cands:
        raise SelectError(f"分数文件缺 candidates 映射: {path}")
    return data, cands


def _axis_diff(params, baseline_params):
    return [k for k in params
            if params.get(k) != (baseline_params or {}).get(k)]


def shortlist(state, scores_map, score_key="score"):
    delivery = state.get("delivery", {})
    v2_axes = set(delivery.get("v2_axes") or ["compile", "harden", "thread"])
    baseline_id = delivery.get("baseline_id", "c1")
    by_id = {e["id"]: e for e in state["candidates"]}
    base_params = (by_id.get(baseline_id) or {}).get("params", {})

    rows, rejected = [], {}
    for e in state["candidates"]:
        cid = e["id"]
        if e["axis"] not in v2_axes:
            rejected[cid] = f"轴不在 v2_axes（{e['axis']}，V3 预注册轴不参与挑选）"
            continue
        if e["status"] != "VERIFIED":
            rejected[cid] = f"状态 {e['status']}（需 VERIFIED）"
            continue
        sc = scores_map.get(cid)
        if not isinstance(sc, dict):
            rejected[cid] = "分数文件中无此候选"
            continue
        val = sc.get(score_key)
        if isinstance(val, str) and val.upper() == "N/A":
            rejected[cid] = "分数 N/A"
            continue
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            rejected[cid] = f"分数字段 {score_key} 缺失或非数值"
            continue
        diff = _axis_diff(e.get("params", {}), base_params)
        if cid == baseline_id or not diff:
            rejected[cid] = "与基线同参数（等于没变）"
            continue
        rows.append({"id": cid, "score": float(val), "axis": e["axis"],
                     "diff_axes": diff, "detail": sc.get("detail", {}) or {}})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows, rejected


def pick_v2(state, scores_map, score_key="score", min_margin=0.0):
    rows, rejected = shortlist(state, scores_map, score_key)
    if not rows:
        raise SelectError("短名单为空 → BLOCKED，不硬选。落选原因: "
                          + json.dumps(rejected, ensure_ascii=False))
    top = rows[0]
    runner = rows[1] if len(rows) > 1 else None
    margin = round(top["score"] - runner["score"], 6) if runner else None
    risks = []
    if runner is not None and margin is not None and margin < min_margin:
        risks.append(f"与前名分差仅 {margin}（< {min_margin}），优势可能来自单点探针")
    if not (top.get("detail") or {}):
        raise SelectError(
            f"{top['id']}: 分数记录无 detail 字段，理由无法溯源到具体差异维度 → 退回重写")
    return {"chosen": top, "runner_up": runner, "margin": margin,
            "risks": risks, "rejected": rejected, "rows": rows}


def render_selection_md(pick, state, scores_path, score_key):
    top, run = pick["chosen"], pick["runner_up"]
    baseline = state.get("delivery", {}).get("baseline_id", "c1")
    lines = [
        f"# V2 选择理由（run_id={state.get('run_id', '')}）",
        "",
        f"- 分数来源：`{scores_path}`（字段 `{score_key}`，评估 Agent 产出，A1 只读）",
        f"- 选择：**{top['id']}**（{top['axis']} 轴）score={top['score']}",
        f"- 与基线 `{baseline}` 的差异轴：{', '.join(top['diff_axes']) or '（无）'}",
    ]
    if run:
        lines.append(
            f"- 次名：{run['id']} score={run['score']}（分差 {pick['margin']}）；"
            f"未选原因：分数低一位，其差异轴为 {', '.join(run['diff_axes'])}")
    for r in pick["risks"]:
        lines.append(f"- 风险：{r}")
    lines += [
        "",
        "## 分数溯源",
        "",
        f"- 选中候选 detail 字段：{', '.join(sorted((top.get('detail') or {}).keys()))}",
        "",
        "## 落选原因一览",
        "",
    ]
    for cid, why in sorted(pick["rejected"].items()):
        lines.append(f"- {cid}: {why}")
    lines += ["", "> 声明：本文件由 A1 依据机器分数整理，不含任何由 A1 产生的判定结论。"]
    return "\n".join(lines) + "\n"
