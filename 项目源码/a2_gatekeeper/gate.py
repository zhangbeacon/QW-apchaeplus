from __future__ import annotations

import json
from pathlib import Path

from . import rules as rules_mod
from .timeline import append as timeline_append

REQUIRED_CAPABILITIES = {
    "static", "cgi", "lua", "forward_proxy", "reverse_proxy",
    "rewrite", "headers",
}


def evaluate(state_dir: str | Path, rules_path: str | Path,
             functional: str | Path | None = None,
             results: str | Path | None = None) -> dict:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    gates: dict[str, dict] = {}

    frozen, msg = rules_mod.status(rules_path, state_dir)
    gates["G0"] = {"pass": frozen, "reason": "spec frozen" if frozen else msg}

    env = state_dir / "env.json"
    gates["G1"] = {"pass": env.exists(),
                   "reason": "clean build/env manifest present" if env.exists() else "G1 env manifest missing"}

    caps = []
    run_id = ""
    if functional and Path(functional).exists():
        data = json.loads(Path(functional).read_text(encoding="utf-8"))
        caps = data.get("capabilities", [])
        run_id = data.get("run_id", "")
    ids = {c.get("id") for c in caps if c.get("pass")}
    missing = sorted(REQUIRED_CAPABILITIES - ids)
    g2 = len(caps) >= 7 and not missing and bool(run_id)
    gates["G2"] = {"pass": g2,
                   "reason": "7/7 capabilities pass" if g2 else f"missing/failed: {missing or 'run_id'}",
                   "run_id": run_id}

    res = {}
    if results and Path(results).exists():
        res = json.loads(Path(results).read_text(encoding="utf-8"))
    g3 = bool(res.get("v1_positive")) and bool(res.get("fixed_negative"))
    gates["G3"] = {"pass": g3,
                   "reason": "V1 positive + fixed negative present" if g3 else "G3 control missing"}

    vulns = [v for v in res.get("vulns", []) if v.get("difference")]
    g4 = len(vulns) >= 3
    gates["G4"] = {"pass": g4,
                   "reason": f"{len(vulns)} independent differences" if g4 else f"only {len(vulns)}/3 differences"}

    (state_dir / "gates.json").write_text(
        json.dumps(gates, ensure_ascii=False, indent=2), encoding="utf-8")
    timeline_append(state_dir, "A2", "gate", "", "evaluated",
                    {k: v["pass"] for k, v in gates.items()})
    return gates


def status(state_dir: str | Path) -> dict:
    p = Path(state_dir) / "gates.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))
