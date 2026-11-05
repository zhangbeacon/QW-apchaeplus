"""Tests for Phase 2/3: matrix, chains, report, fitness, FPR bound, bootstrap."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evalkernel import chains as CH
from evalkernel import matrix as MX
from evalkernel import stats as S
from evalkernel.fitness import fitness
from evalkernel.pipeline import run
from evalkernel.report import render

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"

Q = {"41773": 4, "44224": 4, "44790": 3, "22720": 4, "25690": 4, "38474": 4}


def cells(states_by_variant, cve="41773", probe="p1"):
    return {cve: {probe: {v: {"states": s, "ys": [0] * len(s), "crs": [0] * len(s)}
                          for v, s in states_by_variant.items()}}}


class TestFprBound(unittest.TestCase):
    def test_zero_events_formula(self):
        self.assertAlmostEqual(S.fpr_upper(6, 0), 1 - 0.05 ** (1 / 6), places=6)
        self.assertAlmostEqual(S.fpr_upper(29, 0), 0.099, places=2)

    def test_monotone_in_k(self):
        vals = [S.fpr_upper(50, k) for k in range(0, 6)]
        self.assertEqual(vals, sorted(vals))

    def test_edge_cases(self):
        self.assertIsNone(S.fpr_upper(0, 0))
        self.assertEqual(S.fpr_upper(5, 5), 1.0)


class TestChains(unittest.TestCase):
    def _row(self, cve, probe, state, variant="V1", repeat=1):
        return {"cve": cve, "probe": probe, "variant": variant, "repeat": repeat,
                "group": "A+", "state": state, "valid": True}

    def test_block_and_success(self):
        cfg = {"41773": {"probes": ["p1"], "stage1": {"min_state": "L2"},
                         "stage2": {"state": "L3"}}}
        rows = [self._row("41773", "p1", "L2", "V1", 1),
                self._row("41773", "p1", "L3", "V1", 2)]
        out = CH.chain_metrics(rows, cfg)["41773"]
        self.assertAlmostEqual(out["ChainSuccess"], 0.5)
        self.assertAlmostEqual(out["BlockRate"], 0.5)
        self.assertEqual(out["n"], 2)

    def test_no_stage1_success_is_na(self):
        cfg = {"41773": {"probes": ["p1"], "stage1": {"min_state": "L2"},
                         "stage2": {"state": "L3"}}}
        out = CH.chain_metrics([self._row("41773", "p1", "L0")], cfg)["41773"]
        self.assertAlmostEqual(out["ChainSuccess"], 0.0)
        self.assertIsNone(out["BlockRate"])


class TestMatrix(unittest.TestCase):
    def test_axis_group_hde(self):
        c = cells({"a": ["L3", "L3"], "b": ["L3", "L3"],
                   "c": ["L1", "L1"], "d": ["L1", "L1"]})
        probes = {"cves": {"41773": {"family": ["p1"], "canonical": "p1", "q": 4}}}
        out = MX.axis_matrix(c, probes, {"grp": ["a", "b", "c", "d"]}, Q)
        self.assertAlmostEqual(out["grp"]["HDE"], 0.5, places=6)

    def test_small_group_is_na(self):
        c = cells({"a": ["L3"], "b": ["L3"]})
        probes = {"cves": {"41773": {"family": ["p1"], "canonical": "p1", "q": 4}}}
        out = MX.axis_matrix(c, probes, {"one": ["a"]}, Q)
        self.assertEqual(out["one"]["reason"], "GROUP_TOO_SMALL")

    def test_pairwise_contrast(self):
        c = cells({"a": ["L3", "L3"], "b": ["L1", "L1"]})
        probes = {"cves": {"41773": {"family": ["p1"], "canonical": "p1", "q": 4}}}
        out = MX.pairwise(c, probes, [["a", "b"]], Q, B=50, seed=1)
        self.assertAlmostEqual(out["a_vs_b"]["HDE"], 0.5, places=6)

    def test_factorial_needs_replication(self):
        probes = {"cves": {"41773": {"family": ["p1"], "canonical": "p1", "q": 4}}}
        factors = {"c1": {"compiler": "gcc", "opt": "O2", "alloc": "ptmalloc"}}
        out = MX.factorial({}, probes, factors, Q, builds_per_cell=1)
        self.assertEqual(out["reason"], "SINGLE_BUILD_PER_CELL")
        self.assertIsNone(out["interaction"])


class TestSensitivity(unittest.TestCase):
    def test_loo_variant_moves_value(self):
        c = cells({"a": ["L3", "L3"], "b": ["L3", "L3"],
                   "c": ["L3", "L3"], "d": ["L1", "L1"]})
        out = S.loo_variant(c, Q, 4, ["a", "b", "c", "d"])
        self.assertIsNotNone(out["max_delta"])
        self.assertGreater(out["max_delta"], 0.0)

    def test_bootstrap_ci_bounds(self):
        c = cells({"a": ["L3", "L3"], "b": ["L3", "L3"],
                   "c": ["L1", "L1"], "d": ["L1", "L1"]})
        out = S.bootstrap_ci(c, Q, ["a", "b", "c", "d"], B=60, seed=3)
        self.assertIn("ci", out)
        if out["ci"]:
            lo, hi = out["ci"]
            self.assertLessEqual(lo, hi)
            self.assertGreaterEqual(lo, 0.0)
            self.assertLessEqual(hi, 1.0)


class TestReportAndFitness(unittest.TestCase):
    def test_render_has_all_sections(self):
        hde = {"gauges": {"final_pure": {"K": 3, "m": 20, "DIV": 0.4, "HDE": 0.4,
                                        "ATTR": 1.0, "n_cve": 6, "per_cve": {}}},
               "splits": {}, "sensitivity": {}, "noise_floor": {},
               "digest": {"raw_trials_sha256": "x", "script_sha256": "y",
                          "seed": 1, "B": 10}}
        safety = {"deployment_model": "M2", "track_b": {"ASR": 0.5, "CMR": 0.4,
                                                        "availability": 0.0},
                  "baselines": {"dASR": 0.1, "dCMR": 0.2, "davailability": 0.0}}
        audit = {"coverage": {"planned": 10, "valid": 10, "rate": 1.0},
                 "conflicts": {"count": 0, "details": []},
                 "negative_controls": {"n_probes": 6, "n_trials": 6,
                                       "probe_level_false_positives": 0,
                                       "fpr_upper_95_one_sided": 0.393},
                 "invalid": {"count": 0}, "verdict": "usable"}
        md = render(hde, safety, audit, {"41773": {"V1": {"status": "P"}}})
        for i in range(1, 10):
            self.assertIn(f"## {i}.", md)
        self.assertIn("0.400", md)

    def test_fitness_ineligible_without_split(self):
        out = fitness({"splits": {}, "digest": {}}, {"track_b": {"CMR": 0.4}})
        self.assertFalse(out["eligible"])
        self.assertIsNone(out["score"])


class TestPipelineArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="evalkernel_p2_"))
        self.cfg = self.tmp / "config"
        shutil.copytree(CONFIG, self.cfg)
        self.raw = self.tmp / "raw.jsonl"
        rows = []
        for v in ["V1", "V2", "V3", "b0_1", "b0_2", "b0_3"]:
            for r in range(1, 4):
                crash = v == "V2" and r % 2 == 1
                rows.append({
                    "cve": "CVE-2021-44790", "probe": "p1", "variant": v,
                    "repeat": r, "group": "A+",
                    "resp": {"status": 500 if crash else 200,
                             "body": "" if crash else "parsebody-done"},
                    "logs": {"error": "" if crash else "memory allocation error: block too big"},
                    "process": {"signal": "SIGABRT" if crash else None},
                    "rc": {"R": 1, "backtrace_hit": crash},
                })
        self.raw.write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_artifacts_written(self):
        out = self.tmp / "out"
        run(str(self.raw), str(self.cfg), str(out), B=60, seed=5)
        for name in ("classified_trials.jsonl", "hde.json", "safety.json",
                     "audit.json", "status.json", "matrix.json", "fitness.json",
                     "report.md", "manifest.json"):
            self.assertTrue((out / name).exists(), name)
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("hde.json", manifest["files"])


if __name__ == "__main__":
    unittest.main()
