from pathlib import Path

base = Path(__file__).resolve().parent
work = base / "work"
work.mkdir(parents=True, exist_ok=True)
(work / "clean.marker").write_text("cleaned stale listener\n", encoding="utf-8")
print("clean ok: stale listener marker created")
