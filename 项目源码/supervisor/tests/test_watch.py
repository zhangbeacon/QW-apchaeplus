import json
import tempfile
import unittest
from pathlib import Path

from variant_supervisor.config import load_config
from variant_supervisor.watch import watch


class WatchTest(unittest.TestCase):
    def test_stage_fail_event_is_diagnosed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            log = root / "build.log"
            log.write_text("Address already in use\n", encoding="utf-8")
            events = root / "events.jsonl"
            events.write_text(
                json.dumps(
                    {
                        "type": "stage_fail",
                        "stage": "build",
                        "exit_code": 1,
                        "log": str(log),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cfg_path = root / "pipeline.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "project": "t",
                        "stages": [{"name": "build", "cmd": ["echo"]}],
                        "log_dir": "logs",
                        "evidence_dir": "evidence",
                    }
                ),
                encoding="utf-8",
            )
            cfg = load_config(cfg_path)
            self.assertEqual(watch(cfg, events, follow=False), 0)
            text = (root / "logs" / "journal.jsonl").read_text(encoding="utf-8")
            self.assertIn("watch_diagnosis", text)
            self.assertIn("PORT_CONFLICT", text)


if __name__ == "__main__":
    unittest.main()
