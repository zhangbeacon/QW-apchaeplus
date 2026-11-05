"""Tests for 异构分化熵的稳定性门（行为指纹熵 H(i)，千相设计文档 §2.9/§5.4）."""

from __future__ import annotations

import unittest

from evalkernel.repro import entropy_h, reproducibility, round_fingerprints


def row(variant, repeat, state):
    return {"variant": variant, "repeat": repeat, "cve": "44790", "probe": "p1",
            "state": state, "Y": state in ("L2", "L3"), "crash": state == "L2",
            "valid": True, "phenotypes": [], "validity": "VALID",
            "goal_outcome": "GOAL_OBSERVED" if state == "L2" else "GOAL_NOT_OBSERVED"}


class TestEntropyH(unittest.TestCase):
    def test_identical_rounds_zero(self):
        out = entropy_h(["aa", "aa", "aa"])
        self.assertEqual(out["H"], 0.0)
        self.assertTrue(out["gate_pass"])

    def test_all_distinct_is_one(self):
        out = entropy_h(["aa", "bb", "cc"])
        self.assertAlmostEqual(out["H"], 1.0, places=6)
        self.assertFalse(out["gate_pass"])

    def test_partial_two_of_three(self):
        out = entropy_h(["aa", "aa", "bb"])
        self.assertAlmostEqual(out["H"], 0.579, places=3)
        self.assertFalse(out["gate_pass"])

    def test_k_one_not_computable(self):
        out = entropy_h(["aa"])
        self.assertIsNone(out["H"])
        self.assertEqual(out["reason"], "K_LESS_THAN_2")


class TestReproducibility(unittest.TestCase):
    def test_stable_candidate_passes_gate(self):
        rows = [row("c5", r, "L1") for r in range(1, 6)]
        out = reproducibility(rows)
        self.assertEqual(out["c5"]["H"], 0.0)
        self.assertTrue(out["c5"]["gate_pass"])

    def test_jittery_candidate_fails_gate(self):
        rows = [row("V2", r, "L2" if r % 2 else "L1") for r in range(1, 7)]
        out = reproducibility(rows)
        self.assertGreater(out["V2"]["H"], 0.15)
        self.assertFalse(out["V2"]["gate_pass"])

    def test_variant_filter(self):
        rows = ([row("c5", r, "L1") for r in range(1, 4)]
                + [row("V2", r, "L2" if r % 2 else "L1") for r in range(1, 4)])
        out = reproducibility(rows, variants=["c5"])
        self.assertIn("c5", out)
        self.assertNotIn("V2", out)


if __name__ == "__main__":
    unittest.main()
