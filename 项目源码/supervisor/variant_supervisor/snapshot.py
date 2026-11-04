from __future__ import annotations

import shutil
from pathlib import Path


class SnapshotManager:
    """Copy configured source dirs so a failed transform can be rolled back."""

    def __init__(self, root: Path, source_dirs: list[Path], run_id: str):
        self.root = root
        self.source_dirs = [p for p in source_dirs if p.is_dir()]
        self.run_id = run_id
        self.base = root / run_id
        self._index = 0

    def _dest_name(self, index: int, src: Path) -> str:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in src.name)
        return f"{index:02d}-{safe}"

    def create(self, label: str = "") -> Path | None:
        if not self.source_dirs:
            return None
        self._index += 1
        safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in (label or "snap"))
        target = self.base / f"{self._index:02d}-{safe_label}"
        target.mkdir(parents=True, exist_ok=True)
        for index, src in enumerate(self.source_dirs):
            dest = target / self._dest_name(index, src)
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(
                src,
                dest,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "node_modules"),
            )
        return target

    def restore(self, snap: Path) -> None:
        for index, src in enumerate(self.source_dirs):
            saved = snap / self._dest_name(index, src)
            if not saved.is_dir():
                continue
            if src.exists():
                shutil.rmtree(src)
            shutil.copytree(saved, src)
