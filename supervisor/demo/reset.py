from pathlib import Path
import shutil

base = Path(__file__).resolve().parent
for name in ("work/state.json", "work/clean.marker", "work/security_seen.marker"):
    p = base / name
    if p.exists():
        p.unlink()
for d in ("evidence", "logs"):
    p = base / d
    if p.exists():
        shutil.rmtree(p)
(base / "work" / "src").mkdir(parents=True, exist_ok=True)
(base / "work" / "src" / "app.txt").write_text("demo source\n", encoding="utf-8")
print("demo reset")

