"""Tests for the offline evaluation kernel.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path

from evalkernel import metrics as M
from evalkernel import stats as S
from evalkernel.predicates import (derive_status, eligibility, extract_features,
                                   state_of, y_of)
from evalkernel.pipeline import run
from evalkernel.schema import RawTrial

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def cells_for(states_by_variant: dict[str, list[str]]) -> dict:
    return {"c1": {"p1": {v: {"states": s, "ys": [0] * len(s), "crs": [0] * len(s)}
                          for v, s in states_by_variant.items()}}}


class TestGoldenVectors(unittest.TestCase):
    """Hand-computed: H, I, HDE must match to 6 decimals."""

    def test_two_two_split_gives_half(self):
        # 2x L3 vs 2x L1 -> H = 1 bit, q=4 -> HDE = 1/log2(4) = 0.5
        c = cells_for({"a": ["L3", "L3"], "b": ["L3", "L3"],
                       "c": ["L1", "L1"], "d": ["L1", "L1"]})
        r = M.track_a(c, "c1", 4, 4, ["p1"])
        self.assertAlmostEqual(r["DIV"], 0.5, places=6)
        self.assertAlmostEqual(r["HDE"], 0.5, places=6)
        self.assertAlmostEqual(r["ATTR"], 1.0, places=6)

    def test_three_one_split(self):
        # 3x L3 vs 1x L1 -> H = 0.811278..., HDE = 0.405639...
        c = cells_for({"a": ["L3", "L3"], "b": ["L3", "L3"],
                       "c": ["L3", "L3"], "d": ["L1", "L1"]})
        r = M.track_a(c, "c1", 4, 4, ["p1"])
        self.assertAlmostEqual(r["DIV"], 0.405639, places=6)
        self.assertAlmostEqual(r["HDE"], 0.405639, places=6)

    def test_all_same_gives_zero(self):
        c = cells_for({v: ["L3", "L3"] for v in "abcd"})
        r = M.track_a(c, "c1", 4, 4, ["p1"])
        self.assertAlmostEqual(r["HDE"], 0.0, places=6)
        self.assertIsNone(r["ATTR"])

    def test_four_distinct_gives_one(self):
        c = cells_for({"a": ["L0", "L0"], "b": ["L1", "L1"],
                       "c": ["L2", "L2"], "d": ["L3", "L3"]})
        r = M.track_a(c, "c1", 4, 4, ["p1"])
        self.assertAlmostEqual(r["HDE"], 1.0, places=6)

    def test_three_variant_table_matches_doc(self):
        # design doc §2.9 example 4: K=3, q=4 -> 2:1 => 0.459, 1:1:1 => 0.792
        two_one = cells_for({"V1": ["L3", "L3"], "V2": ["L3", "L3"], "V3": ["L1", "L1"]})
        r = M.track_a(two_one, "c1", 4, 3, ["p1"])
        self.assertAlmostEqual(r["HDE"], 0.459, places=3)
        all_diff = cells_for({"V1": ["L3", "L3"], "V2": ["L1", "L1"], "V3": ["L2", "L2"]})
        r2 = M.track_a(all_diff, "c1", 4, 3, ["p1"])
        self.assertAlmostEqual(r2["HDE"], 0.792, places=3)

    def test_within_variant_noise_lowers_attr(self):
        # each variant flips L1/L3 -> H=1, I=0 -> HDE=0, DIV=0.5, ATTR=0
        c = cells_for({"a": ["L3", "L1"], "b": ["L3", "L1"],
                       "c": ["L3", "L1"], "d": ["L3", "L1"]})
        r = M.track_a(c, "c1", 4, 4, ["p1"])
        self.assertAlmostEqual(r["HDE"], 0.0, places=6)
        self.assertAlmostEqual(r["DIV"], 0.5, places=6)
        self.assertAlmostEqual(r["ATTR"], 0.0, places=6)


class TestPredicates(unittest.TestCase):
    def _trial(self, **kw) -> RawTrial:
        base = dict(cve="CVE-2021-44790", probe="p1", variant="c1", repeat=1)
        base.update(kw)
        return RawTrial.from_dict(base)

    def test_44790_asan_never_counts(self):
        t = self._trial(asan={"report": "negative-size-param"})
        f = extract_features(t, {"markers": [], "log_patterns": ["block too big"]})
        st = state_of("44790", f)
        self.assertNotEqual(st, "L2")
        self.assertEqual(y_of("44790", f, st), 0)

    def test_44790_native_crash_with_backtrace(self):
        t = self._trial(process={"signal": "SIGSEGV"}, rc={"R": 1, "backtrace_hit": True})
        f = extract_features(t, {"markers": [], "log_patterns": []})
        st = state_of("44790", f)
        self.assertEqual(st, "L2")
        self.assertEqual(y_of("44790", f, st), 1)

    def test_44790_crash_without_backtrace_is_availability_only(self):
        t = self._trial(process={"signal": "SIGSEGV"}, rc={"R": 1, "backtrace_hit": False})
        f = extract_features(t, {"markers": [], "log_patterns": []})
        st = state_of("44790", f)
        self.assertNotEqual(st, "L2")
        self.assertEqual(y_of("44790", f, st), 0)

    def test_status_derivation(self):
        self.assertEqual(derive_status({"p1": 1}, "p1", False)[0], "P")
        self.assertEqual(derive_status({"p1": 0, "p2": 1}, "p1", False)[0], "S")
        self.assertEqual(derive_status({"p1": 0, "p2": 0}, "p1", False)[0], "X_obs")
        self.assertEqual(derive_status({"p1": 1}, "p1", True)[0], "U_disputed")
        self.assertEqual(derive_status({}, "p1", False)[0], "U_disputed")

    def test_eligibility(self):
        self.assertTrue(eligibility({"a": "P", "b": "P"}, "pure")[0])
        self.assertFalse(eligibility({"a": "P", "b": "S"}, "pure")[0])
        self.assertTrue(eligibility({"a": "P", "b": "S"}, "shift")[0])
        self.assertFalse(eligibility({"a": "P", "b": "P"}, "shift")[0])
        self.assertFalse(eligibility({"a": "X_obs", "b": "S"}, "shift")[0])


class TestStats(unittest.TestCase):
    def test_perm_p_is_probability(self):
        pv = {"a": ["L3", "L3"], "b": ["L3", "L3"], "c": ["L1", "L1"], "d": ["L1", "L1"]}
        p = S.perm_p(pv, 4, B=100, seed=1)
        self.assertIsNotNone(p)
        self.assertTrue(0.0 <= p <= 1.0)

    def test_all_same_is_not_significant(self):
        pv = {v: ["L3", "L3"] for v in "abcd"}
        p = S.perm_p(pv, 4, B=100, seed=1)
        self.assertGreater(p, 0.05)

    def test_holm_monotone(self):
        adj = S.holm({"a": 0.01, "b": 0.04, "c": 0.03})
        self.assertLessEqual(adj["a"], adj["b"])
        self.assertLessEqual(adj["a"], adj["c"])
        self.assertGreaterEqual(adj["b"], 0.04)


def _synthetic_dataset(path: Path, variants: list[str], repeats: int = 2) -> None:
    """44790, probe p1: first half of variants crash (L2), rest are L1. R=1 everywhere."""
    lines = []
    for i, v in enumerate(variants):
        crash = i % 2 == 0
        for r in range(1, repeats + 1):
            trial = {
                "cve": "CVE-2021-44790", "probe": "p1", "variant": v, "repeat": r,
                "group": "A+",
                "resp": {"status": 500 if crash else 200,
                         "body": "" if crash else "parsebody-done"},
                "logs": {"error": "" if crash else "memory allocation error: block too big"},
                "process": {"signal": "SIGABRT" if crash else None},
                "rc": {"R": 1, "backtrace_hit": crash},
            }
            lines.append(json.dumps(trial, ensure_ascii=False))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="evalkernel_test_"))
        self.raw = self.tmp / "raw_trials.jsonl"
        self.cfg = self.tmp / "config"
        shutil.copytree(CONFIG, self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_deterministic_output(self):
        variants = ["V1", "V2", "V3", "b0_1", "b0_2", "b0_3",
                    "c1", "c2", "c3", "k1", "k2", "k3", "k4"]
        _synthetic_dataset(self.raw, variants)
        out1, out2 = self.tmp / "o1", self.tmp / "o2"
        run(str(self.raw), str(self.cfg), str(out1), B=50, seed=7)
        run(str(self.raw), str(self.cfg), str(out2), B=50, seed=7)
        for name in ("classified_trials.jsonl", "hde.json", "safety.json",
                     "audit.json", "status.json"):
            self.assertEqual((out1 / name).read_bytes(), (out2 / name).read_bytes(), name)

    def test_missing_variant_yields_na(self):
        # V3 is class=isolation (never in final_pure); final_pure = {V1, V2}.
        # With data only for V1, the pure gauge is N/A — not silently computed.
        _synthetic_dataset(self.raw, ["V1"])
        out = self.tmp / "o3"
        res = run(str(self.raw), str(self.cfg), str(out), B=50, seed=7)
        gauge = res["hde"]["gauges"].get("final_pure", {})
        self.assertIsNone(gauge.get("HDE"))
        self.assertEqual(gauge.get("K"), 2)

    def test_asan_does_not_change_safety_metrics(self):
        variants = ["V1", "V2", "V3", "b0_1", "b0_2", "b0_3"]
        _synthetic_dataset(self.raw, variants)
        out_a = self.tmp / "a"
        res_a = run(str(self.raw), str(self.cfg), str(out_a), B=50, seed=7)

        # rewrite with ASan reports on every trial
        rows = [json.loads(l) for l in self.raw.read_text(encoding="utf-8").splitlines() if l]
        for r in rows:
            r["asan"] = {"report": "heap-buffer-overflow"}
        self.raw.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        out_b = self.tmp / "b"
        res_b = run(str(self.raw), str(self.cfg), str(out_b), B=50, seed=7)

        self.assertEqual(res_a["safety"]["track_b"]["ASR"],
                         res_b["safety"]["track_b"]["ASR"])
        self.assertEqual(res_a["safety"]["track_b"]["CMR"],
                         res_b["safety"]["track_b"]["CMR"])


if __name__ == "__main__":
    unittest.main()
