import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from variant_supervisor.agent import SupervisorAgent
from variant_supervisor.config import load_config


class AgentAuditTest(unittest.TestCase):
    def test_old_evidence_escalates(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            evidence = root / "evidence"
            evidence.mkdir()
            old = evidence / "functional.ok"
            old.write_text("stale pass from a previous run\n", encoding="utf-8")
            stamp = time.time() - 3600
            os.utime(old, (stamp, stamp))

            cfg_path = root / "pipeline.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "project": "t",
                        "stages": [
                            {"name": "build", "cmd": ["{python}", "-c", "print('ok')"]}
                        ],
                        "audit": {"required": ["functional.ok"], "max_age_sec": 300},
                    }
                ),
                encoding="utf-8",
            )
            agent = SupervisorAgent(load_config(cfg_path), run_id="test-run", verbose=False)
            verdict = agent.run()
            self.assertEqual(verdict, "NEEDS_HUMAN")
            journal = (root / "logs" / "journal.jsonl").read_text(encoding="utf-8")
            self.assertIn("old_run", journal)


if __name__ == "__main__":
    unittest.main()
