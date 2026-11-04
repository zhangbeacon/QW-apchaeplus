import tempfile
import unittest
from pathlib import Path

from variant_supervisor.policy import diagnose
from variant_supervisor.watchdog import run_command


class WatchdogTest(unittest.TestCase):
    def test_spawn_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "run.log"
            result = run_command(
                ["definitely-not-a-real-binary-xyz"],
                cwd=Path(d),
                log_path=log,
                timeout=5,
                max_log_mb=1,
                max_rss_mb=64,
            )
            self.assertIsNone(result.exit_code)
            self.assertIn("failed to start command", log.read_text(encoding="utf-8"))
            diag = diagnose(result, log.read_text(encoding="utf-8"), 0, 2)
            self.assertEqual(diag.action, "escalate")


if __name__ == "__main__":
    unittest.main()
