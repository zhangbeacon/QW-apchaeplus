"""Tests for the A1 handoff: per-candidate scores, class-gated gauges,
manifest verification, and scores.json emission."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evalkernel import manifests as MF
from evalkernel import scores as SC
from evalkernel.pipeline import run
from evalkernel.predicates import eligibility_classes

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"

Q = {"41773": 4, "44224": 4, "44790": 3, "22720": 4, "25690": 4, "38474": 4}
PROBES = {"cves": {"41773": {"family": ["p1"], "canonical": "p1", "q": 4}}}


def cells(states_by_variant, cve="41773", probe="p1"):
    return {cve: {probe: {v: {"states": s, "ys": [0] * len(s), "crs": [0] * len(s)}
                          for v, s in states_by_variant.items()}}}


class TestCandidateScores(unittest.TestCase):
    def test_hand_value_and_eligible(self):
        # V1 = L3 always, candidate = L1 always -> pair HDE = 1/log2(4) = 0.5
        c = cells({"V1": ["L3", "L3"], "c5": ["L1", "L1"]})
        statuses = {"41773": {"V1": {"status": "P"}, "c5": {"status": "P"}}}
        classes = {"V1": "pure", "c5": "pure"}
        factors = {"V1": {"compiler": "gcc", "alloc": "ptmalloc"},
                   "c5": {"compiler": "gcc", "alloc": "jemalloc"}}
        out = SC.candidate_scores(c, PROBES, Q, "V1", ["c5"], statuses,
                                  classes, factors, B=50, seed=1)
        e = out["candidates"]["c5"]
        self.assertAlmostEqual(e["score"], 0.5, places=6)
        self.assertTrue(e["eligible"])
        self.assertEqual(e["axes_different_from_baseline"], ["alloc"])
        self.assertEqual(out["ranking"], ["c5"])

    def test_struct_candidate_not_eligible_for_pure_ranking(self):
        c = cells({"V1": ["L3", "L3"], "s1": ["L0", "L0"]})
        statuses = {"41773": {"V1": {"status": "P"}, "s1": {"status": "S"}}}
        classes = {"V1": "pure", "s1": "struct"}
        out = SC.candidate_scores(c, PROBES, Q, "V1", ["s1"], statuses,
                                  classes, {}, B=50, seed=1)
        e = out["candidates"]["s1"]
        self.assertFalse(e["eligible"])
        self.assertFalse(e["gates"]["status_all_P"])
        self.assertFalse(e["gates"]["class_pure"])
        self.assertEqual(out["ranking"], [])

    def test_baseline_excluded_from_candidates(self):
        c = cells({"V1": ["L3", "L3"]})
        statuses = {"41773": {"V1": {"status": "P"}}}
        out = SC.candidate_scores(c, PROBES, Q, "V1", ["V1"], statuses,
                                  {"V1": "pure"}, {}, B=50, seed=1)
        self.assertEqual(out["candidates"], {})
        self.assertEqual(out["ranking"], [])


class TestClassGates(unittest.TestCase):
    def test_isolation_excluded_from_both_gauges(self):
        st = {"V1": "P", "V2": "P", "V3": "P"}
        cls = {"V1": "pure", "V2": "pure", "V3": "isolation"}
        ok, why = eligibility_classes(st, cls, "pure")
        self.assertFalse(ok)  # isolation member breaks the pure class rule
        self.assertTrue(why.startswith("NOT_ALL_PURE"))
        ok2, why2 = eligibility_classes(st, cls, "shift")
        self.assertFalse(ok2)
        self.assertTrue(why2.startswith("CLASS_MIX"))

    def test_struct_plus_pure_passes_shift(self):
        st = {"V1": "P", "s1": "S"}
        cls = {"V1": "pure", "s1": "struct"}
        ok, why = eligibility_classes(st, cls, "shift")
        self.assertTrue(ok)


class TestManifests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mf_"))
        for vid, body in {
            "c1": {"id": "c1", "sha256": "a" * 64, "compiler": "gcc"},
            "c2": {"id": "c2", "compiler": "gcc"},  # sha256 missing
        }.items():
            d = self.tmp / vid
            d.mkdir()
            (d / "manifest.json").write_text(json.dumps(body), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_and_invalid_flagged(self):
        out = MF.verify_manifests(self.tmp, ["c1", "c2", "c3"])
        self.assertTrue(out["variants"]["c1"]["valid"])
        self.assertFalse(out["variants"]["c2"]["valid"])
        self.assertIn("sha256", out["variants"]["c2"]["missing_fields"])
        self.assertEqual(out["variants"]["c3"]["reason"], "MISSING_MANIFEST")
        self.assertEqual(out["n_ok"], 1)

    def test_missing_dir_reported(self):
        out = MF.verify_manifests(self.tmp / "nope", ["c1"])
        self.assertFalse(out["checked"])
        self.assertEqual(out["reason"], "MANIFEST_DIR_MISSING")


class TestPipelineHandoff(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="handoff_"))
        self.cfg = self.tmp / "config"
        shutil.copytree(CONFIG, self.cfg)
        self.raw = self.tmp / "raw.jsonl"
        rows = []
        for v in ["V1", "V2", "V3", "b0_1", "b0_2", "b0_3",
                  "c1", "c5", "m1", "s1", "k1", "k2"]:
            for r in range(1, 4):
                crash = v in ("V2", "c5") and r % 2 == 1     # jemalloc-ish L2
                desync = v in ("m1", "V3")                   # MPM-ish desync
                rows.append({
                    "cve": "CVE-2021-44790", "probe": "p1", "variant": v,
                    "repeat": r, "group": "A+",
                    "resp": {"status": 500 if crash else 200,
                             "body": "" if crash else "parsebody-done"},
                    "logs": {"error": "" if crash else "memory allocation error: block too big"},
                    "process": {"signal": "SIGABRT" if crash else None},
                    "rc": {"R": 1, "backtrace_hit": crash},
                })
                rows.append({
                    "cve": "CVE-2022-22720", "probe": "p1", "variant": v,
                    "repeat": r, "group": "A+",
                    "resp": ({"resp_count": 2, "second_hit_marker": True,
                              "status": 200, "body": "PROTECTED_SECRET"}
                             if desync else {"resp_count": 1, "status": 400}),
                    "logs": {"error": ""}, "process": {"signal": None},
                    "rc": {"R": 1},
                })
        self.raw.write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_final_pure_excludes_isolation_and_scores_written(self):
        out = self.tmp / "out"
        res = run(str(self.raw), str(self.cfg), str(out), B=60, seed=5)
        hde = res["hde"]
        fp = hde["gauges"]["final_pure"]
        self.assertEqual(fp["K"], 2)                      # V3 excluded by class
        excluded = [e["variant"] for e in fp.get("excluded_by_class", [])]
        self.assertEqual(excluded, ["V3"])
        # delivered Track B still covers all three
        # (track_b has no explicit K, so assert via manifest instead)
        scores = res["scores"]
        self.assertIn("c5", scores["candidates"])
        self.assertIn("s1", scores["candidates"])
        self.assertFalse(scores["candidates"]["s1"]["eligible"])
        # 44790: V2 (jemalloc-ish) diverges from V1 -> score > 0
        self.assertGreater(scores["candidates"]["c5"]["per_cve"]["44790"]["HDE"], 0.0)
        # 22720 diverges only via m1/V3, neither is a pure candidate of {V1,x}
        self.assertTrue((out / "scores.json").exists())

    def test_final_shift_na_when_no_struct_member(self):
        res = run(str(self.raw), str(self.cfg), str(self.tmp / "o2"), B=60, seed=5)
        fs = res["hde"]["gauges"]["final_shift"]
        # shift_final = [V1, V2] (V3 excluded by class); both P -> NO_S -> N/A
        self.assertIsNone(fs["HDE"])


if __name__ == "__main__":
    unittest.main()
