"""Generate a synthetic dataset for smoke-testing the kernel end to end.

This is NOT experimental data. It encodes the pre-registered expectations from
the design doc so the pipeline can be exercised before the real rig exists:

  * 41773/44224/25690/38474 : pure heterogeneity -> no divergence (HDE = 0)
  * 44790                   : jemalloc variants crash (L2), ptmalloc ones only
                              log the Lua error (L1) -> HDE > 0
  * 22720                   : prefork/worker variants desync (L2), others L0
  * s1 on 41773             : canonical payload dead, p3 still crosses -> S

Usage: python tools/make_synthetic.py --out data/synthetic/raw_trials.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

H_GROUP = ["c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "h1", "h2", "m1", "m2"]
T_GROUP = ["s1", "s2", "s3", "s4"]
FINAL = ["V1", "V2", "V3"]
B0 = ["b0_1", "b0_2", "b0_3"]
KH = [f"k{i}" for i in range(1, 17)]

CVES = ["41773", "44224", "44790", "22720", "25690", "38474"]
CVE_ID = {
    "41773": "CVE-2021-41773", "44224": "CVE-2021-44224", "44790": "CVE-2021-44790",
    "22720": "CVE-2022-22720", "25690": "CVE-2023-25690", "38474": "CVE-2024-38474",
}
PROBES = {"41773": ["p1", "p2", "p3", "p4"], "44224": ["p1", "p2", "p3"],
          "44790": ["p1", "p2", "p3", "p4"], "22720": ["p1", "p2", "p3"],
          "25690": ["p1", "p2", "p3"], "38474": ["p1", "p2", "p3"]}


def desired_state(cve: str, variant: str, probe: str) -> str:
    """Encode the pre-registered expectation matrix."""
    if cve == "41773":
        if variant == "s1" and probe in ("p1", "p2"):
            return "L0"
        return "L3" if probe in ("p1", "p3") else ("L2" if probe == "p2" else "L0")
    if cve == "44224":
        return "L2" if probe == "p1" else ("L2" if probe == "p2" else "L1")
    if cve == "44790":
        jemalloc = variant in ("c5", "c6", "c7", "c8", "V2")
        if probe in ("p1", "p2"):
            return "L2" if jemalloc else "L1"
        return "L1"
    if cve == "22720":
        mpm = variant in ("m1", "m2", "V3")
        return "L2" if (mpm and probe == "p1") else "L0"
    if cve == "25690":
        return "L2" if probe in ("p1", "p2") else "L1"
    if cve == "38474":
        return "L2" if probe == "p1" else "L0"
    raise ValueError(cve)


def trial(cve: str, probe: str, variant: str, repeat: int, state: str,
          canonical: str, group: str = "A+") -> dict:
    base = {"cve": CVE_ID[cve], "probe": probe, "variant": variant,
            "repeat": repeat, "group": group}
    resp, logs, proc, rc = {"status": 200}, {}, {"signal": None}, {"R": 1}

    if cve == "41773":
        if state == "L3":
            resp["body"] = "root:x:0:0:root:/root:/bin/bash\nuid=1000(kali) gid=1000(kali)"
        elif state == "L2":
            resp["body"] = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/"
        elif state == "L1":
            resp["status"] = 500
            logs["error"] = "AH01241: exec of '/var/www/cgi-bin/../../bin/sh' failed"
        else:
            resp["status"] = 404
    elif cve == "44224":
        if state == "L2":
            base["uds"] = {"request_lines": 1, "bytes": 74}
        elif state == "L1":
            logs["error"] = "AH00957: HTTP: attempt to connect to unix:/tmp/x.sock failed"
            resp["status"] = 502
        else:
            resp["status"] = 503
    elif cve == "44790":
        if state == "L2":
            resp["status"] = 500
            proc["signal"] = "SIGABRT"
            rc["backtrace_hit"] = True
        elif state == "L1":
            logs["error"] = "lua: memory allocation error: block too big"
        else:
            resp["body"] = "parsebody-done"
    elif cve == "22720":
        if state == "L2":
            resp["resp_count"] = 2
            resp["second_hit_marker"] = True
            resp["body"] = "PROTECTED_SECRET"
        else:
            resp["resp_count"] = 1
            resp["status"] = 400
    elif cve == "25690":
        if state == "L2":
            base["backend"] = {"lines": 2, "second_is_injected": True,
                               "injected_found": True}
        else:
            base["backend"] = {"lines": 1, "second_is_injected": False,
                               "injected_found": False}
    elif cve == "38474":
        if state == "L2":
            resp["body"] = "SECRET_MARKER"
        else:
            resp["status"] = 404

    # s1 kills the canonical trigger on 41773 but p3 still crosses
    if cve == "41773" and variant == "s1":
        rc["R"] = 0 if probe in ("p1", "p2") else 1
    base.update({"resp": resp, "logs": logs, "process": proc, "rc": rc,
                 "latency_ms": 15})
    return base


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/synthetic/raw_trials.jsonl")
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    variants = H_GROUP + T_GROUP + FINAL + B0 + KH
    rows = []
    for v in variants:
        for cve in CVES:
            for probe in PROBES[cve]:
                for r in range(1, args.repeats + 1):
                    st = desired_state(cve, v, probe) if v in (H_GROUP + T_GROUP + FINAL) else desired_state(cve, "c1", probe)
                    rows.append(trial(cve, probe, v, r, st, "p1"))

    # negative controls: one per (cve, variant), must classify as L0
    for v in variants:
        for cve in CVES:
            rows.append(trial(cve, "n1", v, 1, "L0", "p1", group="A-"))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")
    print(f"wrote {len(rows)} trials -> {out}")


if __name__ == "__main__":
    main()
