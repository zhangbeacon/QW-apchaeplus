from pathlib import Path
import json
import os
import time

base = Path(__file__).resolve().parent
evidence = base / "evidence"
work = base / "work"
evidence.mkdir(parents=True, exist_ok=True)
work.mkdir(parents=True, exist_ok=True)

payload = {
    "verdict": "pass",
    "cves": ["CVE-2021-44224"],
    "generated_at": time.time(),
    "negative_control": True,
}
(evidence / "security.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

seen = work / "security_seen.marker"
skip_once = os.environ.get("DEMO_SECURITY_SKIP_NEGATIVE_ONCE") == "1"
if skip_once and not seen.exists():
    seen.write_text("first run: negative control omitted on purpose\n", encoding="utf-8")
    print("security partial: positive evidence only (negative control omitted)")
    raise SystemExit(0)

(evidence / "negative.ok").write_text("fixed build rejected the same request\n", encoding="utf-8")
print("security ok: positive + negative evidence written")
