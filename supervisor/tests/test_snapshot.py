import tempfile
import unittest
from pathlib import Path

from variant_supervisor.snapshot import SnapshotManager


class SnapshotTest(unittest.TestCase):
    def test_create_and_restore(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            src = root / "src"
            src.mkdir()
            (src / "app.c").write_text("v1", encoding="utf-8")

            mgr = SnapshotManager(root / "snaps", [src], "run1")
            snap = mgr.create("before-edit")
            self.assertIsNotNone(snap)

            (src / "app.c").write_text("v2", encoding="utf-8")
            mgr.restore(snap)
            self.assertEqual((src / "app.c").read_text(encoding="utf-8"), "v1")

    def test_missing_source_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mgr = SnapshotManager(root / "snaps", [root / "missing"], "run1")
            self.assertIsNone(mgr.create("x"))


if __name__ == "__main__":
    unittest.main()
