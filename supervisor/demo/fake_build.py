from pathlib import Path
import os
import sys

base = Path(__file__).resolve().parent
work = base / "work"
work.mkdir(parents=True, exist_ok=True)
marker = work / "clean.marker"

if os.environ.get("DEMO_BUILD_ALWAYS_FAIL") == "1":
    print("No such file or directory: missing-tool", file=sys.stderr)
    sys.exit(1)

if not marker.exists():
    print("AH00072: make_sock: could not bind to address 0.0.0.0:8080", file=sys.stderr)
    print("(98)Address already in use: AH00072: make_sock: could not bind to address", file=sys.stderr)
    sys.exit(1)

(work / "state.json").write_text('{"built": true}\n', encoding="utf-8")
print("build ok: demo artifact produced")
