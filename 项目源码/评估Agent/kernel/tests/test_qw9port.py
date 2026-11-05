"""Tests for the qw9/scores/v1 adapter (evalkernel.qw9port).

对应执行 Agent 接入契约（scores.example.json）与设计文档 §3.3 的字段要求：
  * 三道资格门 → "N/A" + 第一道未过门的原因码；
  * 合格候选 → float score + detail（per_cve / gates / 轴差 / 稳定性门事实）；
  * 隔离轴 → score=0.0 + note（仓库示例约定，非测量值）；
  * schema/run_id 注入且确定性（同输入同输出）。
"""

from __future__ import annotations

import unittest

from evalkernel.qw9port import SCHEMA, decorate


def entry(cls="pure", eligible=True, score=0.42, gates=None):
    g = {"status_all_P": True, "class_pure": cls == "pure",
         "has_score": score is not None}
    if gates:
        g.update(gates)
    return {
        "class": cls,
        "gates": g,
        "eligible": bool(g["status_all_P"] and g["class_pure"]
                         and g["has_score"]),
        "score": score,
        "per_cve": {"44790": {"HDE": score, "DIV": None if score is None else score * 2,
                              "p": 0.03}},
        "axes_different_from_baseline": ["allocator"],
    }


class TestDecorate(unittest.TestCase):
    def test_schema_and_run_id_injected(self):
        out = decorate({"baseline": "V1", "candidates": {}}, "gen01")
        self.assertEqual(out["schema"], SCHEMA)
        self.assertEqual(out["run_id"], "gen01")
        self.assertEqual(out["baseline"], "V1")

    def test_eligible_candidate_carries_doc_fields_in_detail(self):
        scores = {"candidates": {"c3": entry()}}
        st = {"c3": {"K": 3, "distinct": 1, "H": 0.0, "gate_pass": True,
                     "threshold": 0.15}}
        out = decorate(scores, "r1", st)
        c = out["candidates"]["c3"]
        self.assertIsInstance(c["score"], float)
        d = c["detail"]
        self.assertEqual(d["hde"], 0.42)
        self.assertEqual(d["per_cve"]["44790"]["hde"], 0.42)
        self.assertEqual(d["per_cve"]["44790"]["p"], 0.03)
        self.assertEqual(d["axes_different_from_baseline"], ["allocator"])
        self.assertEqual(d["stability"]["H"], 0.0)
        self.assertTrue(d["stability"]["gate_pass"])

    def test_status_gate_fail_maps_to_na_with_reason(self):
        scores = {"candidates": {"c2": entry(gates={"status_all_P": False})}}
        out = decorate(scores, "r1")
        c = out["candidates"]["c2"]
        self.assertEqual(c["score"], "N/A")
        self.assertEqual(c["detail"]["reason"], "STATUS_NOT_ALL_P")
        self.assertEqual(c["detail"]["gates"]["status_all_P"], False)

    def test_class_gate_fail_reason(self):
        scores = {"candidates": {"s1": entry(cls="struct")}}
        out = decorate(scores, "r1")
        self.assertEqual(out["candidates"]["s1"]["detail"]["reason"],
                         "CLASS_NOT_PURE")

    def test_no_score_reason(self):
        scores = {"candidates": {"c9": entry(score=None)}}
        out = decorate(scores, "r1")
        c = out["candidates"]["c9"]
        self.assertEqual(c["score"], "N/A")
        self.assertEqual(c["detail"]["reason"], "NO_VALID_SCORE")
        self.assertIsNone(c["detail"]["score_raw"])

    def test_isolation_zero_with_note_not_measured(self):
        scores = {"candidates": {"i1": entry(cls="isolation", score=None)}}
        out = decorate(scores, "r1")
        c = out["candidates"]["i1"]
        self.assertEqual(c["score"], 0.0)
        self.assertIn("隔离轴不参与 V2 挑选", c["detail"]["note"])
        self.assertEqual(c["detail"]["class"], "isolation")

    def test_stability_insufficient_repeats_gets_note(self):
        scores = {"candidates": {"c5": entry()}}
        st = {"c5": {"K": 1, "distinct": 1, "H": None, "gate_pass": None}}
        out = decorate(scores, "r1", st)
        self.assertIn("不可算", out["candidates"]["c5"]["detail"]["stability"]["note"])

    def test_missing_stability_omits_key(self):
        scores = {"candidates": {"c3": entry()}}
        out = decorate(scores, "r1", {})
        self.assertNotIn("stability", out["candidates"]["c3"]["detail"])

    def test_deterministic_and_input_not_mutated(self):
        scores = {"baseline": "V1",
                  "candidates": {"c3": entry(), "i1": entry(cls="isolation")}}
        snapshot = repr(scores)
        a = repr(decorate(scores, "r1"))
        b = repr(decorate(scores, "r1"))
        self.assertEqual(a, b)
        self.assertEqual(repr(scores), snapshot)  # 输入不被改动


if __name__ == "__main__":
    unittest.main()
