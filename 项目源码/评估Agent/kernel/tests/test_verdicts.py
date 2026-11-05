"""Tests for qw9/verdict-v1 ingestion and status_overrides (initial-doc alignment)."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evalkernel import verdicts as VD
from evalkernel.pipeline import run
from evalkernel.predicates import eligibility_classes

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def make_verdict(tmp: Path, variant: str, cve: str, *, validity="VALID",
                 goal="GOAL_NOT_OBSERVED", phenotypes=None, run_id="r1") -> Path:
    d = tmp / "runs" / run_id / variant / cve
    d.mkdir(parents=True, exist_ok=True)
    body = {
        "schema": "qw9/verdict-v1", "run_id": run_id,
        "variant": variant, "cve": cve,
        "validity": validity, "goal_outcome": goal,
        "phenotypes": phenotypes or [],
        "axes": {}, "evidence": [], "oracle_version": "41773-v1",
    }
    f = d / "verdict.json"
    f.write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
    return f


class TestIngest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vd_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_goal_observed_maps_to_y1_l2(self):
        make_verdict(self.tmp, "V2", "CVE-2021-41773", goal="GOAL_OBSERVED")
        rows = VD.ingest_verdict_dir(self.tmp, CONFIG.parent.joinpath("config") / "probes.json"
                                     and json_probe_cfg())
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["cve"], "41773")
        self.assertEqual(r["Y"], 1)
        self.assertEqual(r["state"], "L2")
        self.assertTrue(r["valid"])

    def test_invalid_never_counts_as_defence_or_success(self):
        make_verdict(self.tmp, "V3", "CVE-2021-44790", validity="INVALID",
                     goal="GOAL_OBSERVED", phenotypes=["oom"])
        rows = VD.ingest_verdict_dir(self.tmp, json_probe_cfg())
        r = rows[0]
        self.assertEqual(r["Y"], 0)          # INVALID never counts as success
        self.assertFalse(r["valid"])
        self.assertEqual(r["state"], "U_invalid")
        self.assertEqual(r["crash"], 1)      # but IS availability loss

    def test_crash_phenotype_is_availability_not_success(self):
        make_verdict(self.tmp, "V1", "CVE-2021-44790", phenotypes=["crash"])
        rows = VD.ingest_verdict_dir(self.tmp, json_probe_cfg())
        r = rows[0]
        self.assertEqual(r["Y"], 0)
        self.assertEqual(r["crash"], 1)

    def test_unknown_schema_flagged(self):
        make_verdict(self.tmp, "V1", "CVE-2021-41773")
        f = self.tmp / "runs" / "r1" / "V1" / "CVE-2021-41773" / "verdict.json"
        body = json.loads(f.read_text(encoding="utf-8"))
        body["schema"] = "other/v9"
        f.write_text(json.dumps(body), encoding="utf-8")
        rows = VD.ingest_verdict_dir(self.tmp, json_probe_cfg())
        self.assertTrue(all("_parse_error" in r for r in rows))


def json_probe_cfg():
    return json.loads((ROOT / "config" / "probes.json").read_text(encoding="utf-8"))


class TestStatusOverridesAndVerdictRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vd_run_"))
        self.cfg = self.tmp / "config"
        shutil.copytree(CONFIG, self.cfg)
        # pre-register statuses (human diff audit + shadow judgment)
        vcfg = json.loads((self.cfg / "variants.json").read_text(encoding="utf-8"))
        vcfg["status_overrides"] = {
            cve: {"V1": "P", "V2": "P", "V3": "P"}
            for cve in ("41773", "44224", "44790", "22720", "25690", "38474")
        }
        (self.cfg / "variants.json").write_text(
            json.dumps(vcfg, ensure_ascii=False, indent=2), encoding="utf-8")
        # verdict data: V2 goal observed (jemalloc-ish crash), V1/V3 not
        self.vd = self.tmp / "verdicts"
        make_verdict(self.vd, "V1", "CVE-2021-44790")
        make_verdict(self.vd, "V2", "CVE-2021-44790", goal="GOAL_OBSERVED",
                     phenotypes=["crash"])
        make_verdict(self.vd, "V3", "CVE-2021-44790")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_verdict_run_computes_hde_with_overrides(self):
        res = run(str(self.tmp / "unused.jsonl"), str(self.cfg),
                  str(self.tmp / "out"), B=50, seed=7,
                  verdicts_dir=str(self.vd), run_id="vd1")
        gauge = res["hde"]["gauges"]["final_pure"]
        # pure members {V1,V2}: V1=L0, V2=L2 -> 1:1 split, q=3
        # H = 1.0 bit -> HDE = 1.0/log2(3) = 0.631
        self.assertAlmostEqual(gauge["HDE"], 0.631, places=3)
        per = gauge["per_cve"]["44790"]
        self.assertEqual(per["eligibility"], "ALL_PURE_P")
        # every status came from the override
        st = res["hde"]["status"]["final_pure"]["44790"]
        self.assertTrue(all(rec["reason"] == "STATUS_OVERRIDE"
                            for rec in st.values()))

    def test_eligibility_classes_rejects_isolation(self):
        st = {"V1": "P", "V2": "P", "V3": "P"}
        cls = {"V1": "pure", "V2": "pure", "V3": "isolation"}
        ok, why = eligibility_classes(st, cls, "pure")
        self.assertFalse(ok)
        self.assertTrue(why.startswith("NOT_ALL_PURE"))


if __name__ == "__main__":
    unittest.main()
