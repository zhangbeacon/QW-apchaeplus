"""qw9/scores/v1 适配层 —— 让执行 Agent（qw9）的 `deliver --scores` 直接消费评估产物。

仓库契约（QW-apchaeplus · 项目源码/执行Agent/接入示例 scores.example.json）：

    {"schema": "qw9/scores/v1", "run_id": ...,
     "candidates": {id: {"score": float | "N/A", "detail": {...}}}}

与设计文档的对应（千相设计文档 §3.3 / §2.9，异构分化熵口径）：

  * scores.json 是 A1 第 8–10 步的直接输入：与基准配对的差异分、逐漏洞分解、
    三道资格门（状态全 P、类别 pure、有分）与相对 V1 的轴差清单 —— 这些具体
    字段全部进入 detail，因为仓库契约规定 detail 是 A1 选择理由唯一合法的
    溯源目标（A1 的 selection.md 必须引用该文件的具体字段）；
  * 资格门语义不变：eligibility 由 scores.candidate_scores 判定，本模块只做
    形状映射，不重新打分、不改变任何数值；
  * 隔离轴候选（V3）：仓库示例约定 score=0.0 + note "隔离轴不参与 V2 挑选，
    仅留档"。0.0 是占位不是测量值，与设计文档"V3 预注册、不计分"一致；
  * 不合格候选 score="N/A"（无有效分，不参与挑选），reason 给出第一道未过的门；
  * 稳定性门事实（K 轮行为指纹熵，阈值 0.15）随 detail.stability 输出 ——
    设计文档 §2.9：计算与门禁结论由 A3 给出，执行权在 A2，本模块不执行门禁。

本模块是纯函数：同输入同输出，无时间戳、无随机数，不破坏产物逐字节一致性。
"""

from __future__ import annotations

import copy

SCHEMA = "qw9/scores/v1"

# 资格门 -> N/A 原因码（顺序即检查顺序，报第一道未过的门）
_GATE_REASONS = (("status_all_P", "STATUS_NOT_ALL_P"),
                 ("class_pure", "CLASS_NOT_PURE"),
                 ("has_score", "NO_VALID_SCORE"))


def _first_gate_fail(gates: dict) -> str:
    for key, reason in _GATE_REASONS:
        if not gates.get(key):
            return reason
    return "NOT_ELIGIBLE"


def _stability_fact(repro_entry: dict | None) -> dict | None:
    """稳定性门事实：只搬运 A3 已算出的数，不做任何判定。"""
    if not isinstance(repro_entry, dict):
        return None
    out = {"K": repro_entry.get("K"), "distinct": repro_entry.get("distinct"),
           "H": repro_entry.get("H"), "gate_pass": repro_entry.get("gate_pass"),
           "threshold": repro_entry.get("threshold")}
    if repro_entry.get("H") is None:
        out["note"] = "重复次数不足两次，稳定性不可算"
    return out


def decorate(scores: dict, run_id: str,
             stability: dict | None = None) -> dict:
    """把 candidate_scores 的输出装饰成 qw9/scores/v1 形状（返回新 dict）。"""
    out = copy.deepcopy(scores)
    out["schema"] = SCHEMA
    out["run_id"] = run_id
    st = stability or {}

    for vid, entry in out.get("candidates", {}).items():
        cls = entry.get("class")
        if cls == "isolation":
            entry["score"] = 0.0
            entry["detail"] = {"note": "隔离轴不参与 V2 挑选，仅留档", "class": cls}
            continue

        gates = entry.get("gates", {})
        raw = entry.get("score")
        if not entry.get("eligible") or not isinstance(raw, (int, float)):
            entry["score"] = "N/A"
            entry["detail"] = {"reason": _first_gate_fail(gates),
                               "gates": gates, "score_raw": raw}
            continue

        per_cve = {}
        for short, d in (entry.get("per_cve") or {}).items():
            per_cve[short] = {"hde": d.get("HDE"), "p": d.get("p")}
        detail = {"hde": raw, "per_cve": per_cve, "gates": gates,
                  "axes_different_from_baseline":
                      entry.get("axes_different_from_baseline", [])}
        if "loo_contribution" in entry:
            detail["loo_contribution"] = entry["loo_contribution"]
        fact = _stability_fact(st.get(vid))
        if fact is not None:
            detail["stability"] = fact
        entry["detail"] = detail
    return out
