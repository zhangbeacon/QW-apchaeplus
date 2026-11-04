import os
import tempfile
import time
import unittest
from pathlib import Path

from variant_supervisor.audit import audit_evidence


class AuditTest(unittest.TestCase):
    def test_missing_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            issues = audit_evidence(Path(d), ["security.json"], time.time(), 60)
            self.assertTrue(any(i.kind == "missing" for i in issues))

    def test_stale_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "security.json"
            p.write_text('{"verdict": "pass"}', encoding="utf-8")
            old = time.time() - 3600
            os.utime(p, (old, old))
            issues = audit_evidence(Path(d), ["security.json"], time.time() - 10, 60)
            self.assertTrue(any(i.kind in {"stale", "old_run"} for i in issues))

    def test_expected_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "security.json"
            p.write_text('{"verdict": "fail"}', encoding="utf-8")
            issues = audit_evidence(
                Path(d), ["security.json"], time.time() - 1, 60, {"security.json": {"verdict": "pass"}}
            )
            self.assertTrue(any(i.kind == "bad_value" for i in issues))


if __name__ == "__main__":
    unittest.main()
