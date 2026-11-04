import json
import tempfile
import unittest
from pathlib import Path

from variant_supervisor.config import ConfigError, load_config


def write_config(root: Path, payload: dict) -> Path:
    path = root / "pipeline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


BASE = {
    "project": "t",
    "stages": [{"name": "build", "cmd": ["{python}", "x.py"]}],
}


class ConfigTest(unittest.TestCase):
    def test_minimal(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(write_config(Path(d), BASE))
            self.assertEqual(cfg.stages[0].name, "build")
            self.assertTrue(cfg.stages[0].cmd[0].endswith("python.exe") or "python" in cfg.stages[0].cmd[0])

    def test_duplicate_stage(self):
        with tempfile.TemporaryDirectory() as d:
            payload = dict(BASE)
            payload["stages"] = [
                {"name": "build", "cmd": ["echo"]},
                {"name": "build", "cmd": ["echo"]},
            ]
            with self.assertRaises(ConfigError):
                load_config(write_config(Path(d), payload))

    def test_empty_cmd(self):
        with tempfile.TemporaryDirectory() as d:
            payload = dict(BASE)
            payload["stages"] = [{"name": "build", "cmd": []}]
            with self.assertRaises(ConfigError):
                load_config(write_config(Path(d), payload))

    def test_no_stages(self):
        with tempfile.TemporaryDirectory() as d:
            payload = dict(BASE)
            payload["stages"] = []
            with self.assertRaises(ConfigError):
                load_config(write_config(Path(d), payload))


if __name__ == "__main__":
    unittest.main()
