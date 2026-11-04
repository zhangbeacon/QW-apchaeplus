import unittest

from variant_supervisor.policy import coerce_llm_diagnosis, diagnose
from variant_supervisor.watchdog import RunResult
from pathlib import Path


def result(**kw):
    base = dict(
        exit_code=1,
        timed_out=False,
        log_too_big=False,
        rss_exceeded=False,
        duration_sec=1.0,
        peak_rss_mb=10.0,
        log_path=Path("x.log"),
    )
    base.update(kw)
    return RunResult(**base)


class PolicyTest(unittest.TestCase):
    def test_port_conflict_cleans(self):
        d = diagnose(result(), "AH00072: Address already in use", 0, 2)
        self.assertEqual(d.cause, "PORT_CONFLICT")
        self.assertEqual(d.action, "clean")

    def test_timeout_retries_then_escalates(self):
        d = diagnose(result(timed_out=True), "", 0, 2)
        self.assertEqual(d.action, "retry")
        d2 = diagnose(result(timed_out=True), "", 2, 2)
        self.assertEqual(d2.action, "escalate")

    def test_missing_dep_escalates(self):
        d = diagnose(result(), "No such file or directory: gcc", 0, 2)
        self.assertEqual(d.action, "escalate")

    def test_llm_low_confidence_rejected(self):
        fallback = diagnose(result(), "Address already in use", 0, 2)
        d = coerce_llm_diagnosis(
            {"cause": "X", "action": "abort", "confidence": 0.2, "rationale": "?"}, fallback
        )
        self.assertEqual(d.source, "rule")

    def test_llm_high_confidence_accepted(self):
        fallback = diagnose(result(), "Address already in use", 0, 2)
        d = coerce_llm_diagnosis(
            {"cause": "PORT_CONFLICT", "action": "clean", "confidence": 0.9, "rationale": "stale listener"},
            fallback,
        )
        self.assertEqual(d.source, "llm")


if __name__ == "__main__":
    unittest.main()
