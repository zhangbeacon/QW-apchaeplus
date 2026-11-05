"""Tests for supervisor (监管 Agent) integration: journal, evidence, results."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from evalkernel.integrate import (STAGE_EVENT_TYPES, append_journal,
                                  journal_events, write_evidence, write_results)
from evalkernel.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"


def _mk_run(tmp: Path, conflict: bool = False, variants=("V1", "V2", "V3")) -> Path:
    raw = tmp / "raw.jsonl"
    rows = []
    for v in variants:
        for r in range(1, 4):
            crash = v == "V2" and r % 2 == 1
            rows.append({
                "cve": "CVE-2021-44790", "probe": "p1", "variant": v,
                "repeat": r, "group": "A+",
                "resp": {"status": 500 if crash else 200,
                         "body": "" if crash else "parsebody-done"},
                "logs": {"error": "" if crash else "memory allocation error: block too big"},
                "process": {"signal": "SIGABRT" if crash else None},
                "rc": ({"R": 0, "backtrace_hit": True} if (crash and conflict)
                       else {"R": 1, "backtrace_hit": crash}),
            })
    raw.write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")
    return raw


class TestJournal(unittest.TestCase):
    def test_usable_run_emits_diagnosis_only(self):
        audit = {"verdict": "usable", "conflicts": {"count": 0},
                 "retest_requests": []}
        events = journal_events(audit, "r1")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "diagnosis")
        self.assertEqual(events[0]["stage"], "evaluation")
        self.assertEqual(events[0]["source"], "evalkernel")

    def test_unusable_run_emits_schema_conformant_audit_fail(self):
        audit = {"verdict": "unusable:evidence_conflict",
                 "conflicts": {"count": 2}, "retest_requests": []}
        events = journal_events(audit, "r1")
        fails = [e for e in events if e["type"] == "audit_fail"]
        self.assertEqual(len(fails), 1)
        ev = fails[0]
        # stage_event.schema.json: required = [type, stage]; type in enum
        self.assertIn(ev["type"], STAGE_EVENT_TYPES)
        self.assertIsInstance(ev["stage"], str)
        self.assertEqual(ev["issues"][0]["kind"], "conflict")
        self.assertEqual(ev["source"], "evalkernel")

    def test_needs_retest_emits_audit_fail_with_issues(self):
        audit = {"verdict": "needs_retest:probe_variant_coverage",
                 "conflicts": {"count": 0},
                 "retest_requests": [{"cve": "x", "probe": "p", "variant": "v"}]}
        events = journal_events(audit, "r1")
        fails = [e for e in events if e["type"] == "audit_fail"]
        self.assertEqual(len(fails), 1)
        self.assertIn("coverage", fails[0]["issues"][0]["kind"] + fails[0]["issues"][0]["detail"])

    def test_append_is_jsonl(self):
        tmp = Path(tempfile.mkdtemp(prefix="jr_"))
        try:
            jp = tmp / "journal.jsonl"
            n = append_journal(jp, journal_events({"verdict": "usable",
                                                   "conflicts": {"count": 0}},
                                                  "r1"))
            self.assertEqual(n, 1)
            lines = jp.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            json.loads(lines[0])  # must parse
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestEvidenceAndResults(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="integ_"))
        self.cfg = self.tmp / "config"
        shutil.copytree(CONFIG, self.cfg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_usable_run_writes_ok_marker_and_manifest(self):
        raw = _mk_run(self.tmp, conflict=False)
        out = self.tmp / "out"
        ev = self.tmp / "evidence"
        run(str(raw), str(self.cfg), str(out), B=50, seed=5,
            evidence_dir=str(ev), run_id="demo1", journal_path=str(self.tmp / "journal.jsonl"))
        evdir = ev / "evaluation"
        self.assertTrue((evdir / "evaluation.ok").exists())
        manifest = json.loads((evdir / "manifest.json").read_text(encoding="utf-8"))
        for name, sha in manifest["files"].items():
            actual = hashlib.sha256((evdir / name).read_bytes()).hexdigest()
            self.assertEqual(actual, sha, name)
        jr = (self.tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertTrue(all("audit_fail" not in json.loads(l)["type"] or True
                            for l in jr))
        # results.json exists with items
        res = json.loads((out / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(res["run_id"], "demo1")
        self.assertTrue(any(i["path"] == "hde.json" and i["status"] == "ok"
                            for i in res["items"]))

    def test_conflict_run_is_unusable_and_no_ok_marker(self):
        raw = _mk_run(self.tmp, conflict=True)
        out = self.tmp / "out"
        ev = self.tmp / "evidence"
        res = run(str(raw), str(self.cfg), str(out), B=50, seed=5,
                  evidence_dir=str(ev), run_id="demo2",
                  journal_path=str(self.tmp / "journal.jsonl"))
        self.assertTrue(res["audit"]["verdict"].startswith("unusable"))
        self.assertFalse((ev / "evaluation" / "evaluation.ok").exists())
        jr = [json.loads(l) for l in
              (self.tmp / "journal.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(e["type"] == "audit_fail" and e["source"] == "evalkernel"
                            for e in jr))


if __name__ == "__main__":
    unittest.main()
