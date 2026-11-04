from __future__ import annotations

import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from a2_gatekeeper import approvals, evidence, gate, rules  # noqa: E402

WORK = Path(__file__).resolve().parent / "_work"


def fresh(name: str) -> Path:
    p = WORK / name
    shutil.rmtree(p, ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_rules(p: Path) -> Path:
    rules = {
        "version": "1.0",
        "thresholds": {"max_retries": 3},
        "functional": {"capabilities": [{"id": f"c{i}"} for i in range(7)]},
    }
    f = p / "rules.json"
    f.write_text(json.dumps(rules), encoding="utf-8")
    return f


def functional(p: Path, run_id: str = "r1", fail: str | None = None) -> Path:
    caps = [{"id": cid, "pass": cid != fail}
            for cid in ["static", "cgi", "lua", "forward_proxy", "reverse_proxy", "rewrite", "headers"]]
    f = p / "functional.json"
    f.write_text(json.dumps({"run_id": run_id, "capabilities": caps}), encoding="utf-8")
    return f


def results(p: Path, n: int = 3) -> Path:
    f = p / "results.json"
    f.write_text(json.dumps({
        "v1_positive": True,
        "fixed_negative": True,
        "vulns": [{"cve": f"CVE-{i}", "difference": True} for i in range(n)],
    }), encoding="utf-8")
    return f


class A2Test(unittest.TestCase):
    def test_freeze_tamper_detected(self):
        d = fresh("freeze")
        r = write_rules(d)
        rules.freeze(r, d / "state")
        self.assertTrue(rules.status(r, d / "state")[0])
        data = json.loads(r.read_text(encoding="utf-8"))
        data["thresholds"]["max_retries"] = 99
        r.write_text(json.dumps(data), encoding="utf-8")
        ok, msg = rules.status(r, d / "state")
        self.assertFalse(ok)
        self.assertIn("changed after freeze", msg)

    def test_retry_limit(self):
        d = fresh("retry")
        r = write_rules(d)
        state = d / "state"
        rules.freeze(r, state)
        for i in range(3):
            rec = approvals.request(state, r, {"action": "build", "target": "V2"})
            self.assertEqual(rec["decision"], "approve", f"round {i}")
        rec = approvals.request(state, r, {"action": "build", "target": "V2"})
        self.assertEqual(rec["decision"], "reject")
        self.assertIn("retry limit", rec["reason"])

    def test_g4_blocks_target(self):
        d = fresh("g4")
        r = write_rules(d)
        state = d / "state"
        rules.freeze(r, state)
        rec = approvals.request(state, r, {"action": "target", "target": "V2"})
        self.assertEqual(rec["decision"], "reject")
        gate.evaluate(state, r, functional(d), results(d))
        rec = approvals.request(state, r, {"action": "target", "target": "V2"})
        self.assertEqual(rec["decision"], "approve")

    def test_functional_gate_needs_seven(self):
        d = fresh("functional")
        r = write_rules(d)
        state = d / "state"
        rules.freeze(r, state)
        g = gate.evaluate(state, r, functional(d, fail="lua"), results(d))
        self.assertFalse(g["G2"]["pass"])
        g = gate.evaluate(state, r, functional(d), results(d))
        self.assertTrue(g["G2"]["pass"])

    def test_stale_evidence(self):
        d = fresh("stale")
        state = d / "state"
        ev = d / "evidence"
        evidence.begin(state, ev, "run-1")
        f = ev / "security.json"
        f.write_text("{}", encoding="utf-8")
        old = time.time() - 3600
        os.utime(f, (old, old))
        issues = evidence.check(state, "run-1", ev)
        self.assertTrue(any("stale evidence" in i for i in issues))

    def test_missing_binary(self):
        d = fresh("binary")
        state = d / "state"
        ev = d / "evidence"
        evidence.begin(state, ev, "run-1")
        (ev / "security.json").write_text("{}", encoding="utf-8")
        issues = evidence.check(state, "run-1", ev, binary=d / "nope")
        self.assertTrue(any("binary missing" in i for i in issues))


if __name__ == "__main__":
    unittest.main(verbosity=2)
