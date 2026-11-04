from __future__ import annotations

import argparse
import json
import sys

from . import approvals, evidence, gate, rules
from .timeline import read as read_timeline


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="a2", description="A2 监管 Agent: rules, approvals, gates, evidence.")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("freeze", help="G0: freeze the rule book")
    f.add_argument("--rules", required=True)
    f.add_argument("--state", default="state")

    s = sub.add_parser("status", help="show G0 status")
    s.add_argument("--rules", required=True)
    s.add_argument("--state", default="state")

    r = sub.add_parser("request", help="A1 submits a request form")
    r.add_argument("--rules", required=True)
    r.add_argument("--state", default="state")
    r.add_argument("--action", required=True, choices=sorted(approvals.ALLOWED_ACTIONS))
    r.add_argument("--target", required=True)
    r.add_argument("--eta", default="")
    r.add_argument("--param", action="append", default=[], help="key=value, repeatable")

    fn = sub.add_parser("functional", help="validate the 7-capability functional result")
    fn.add_argument("--state", default="state")
    fn.add_argument("--results", required=True)

    g = sub.add_parser("gate", help="evaluate G0-G4")
    g.add_argument("--rules", required=True)
    g.add_argument("--state", default="state")
    g.add_argument("--functional")
    g.add_argument("--results")

    b = sub.add_parser("begin", help="archive old evidence and bind a run_id")
    b.add_argument("--state", default="state")
    b.add_argument("--evidence", required=True)
    b.add_argument("--run-id", required=True)

    c = sub.add_parser("check", help="verify run_id / binary / evidence freshness")
    c.add_argument("--state", default="state")
    c.add_argument("--run-id", required=True)
    c.add_argument("--evidence", required=True)
    c.add_argument("--binary")

    t = sub.add_parser("timeline", help="print the append-only timeline")
    t.add_argument("--state", default="state")

    a = p.parse_args(argv)

    if a.cmd == "freeze":
        rec = rules.freeze(a.rules, a.state)
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return 0
    if a.cmd == "status":
        ok, msg = rules.status(a.rules, a.state)
        print(json.dumps({"frozen": ok, "reason": msg}, ensure_ascii=False))
        return 0 if ok else 1
    if a.cmd == "request":
        params = {}
        for item in a.param:
            if "=" in item:
                k, v = item.split("=", 1)
                params[k] = v
        req = {"action": a.action, "target": a.target, "params": params, "eta": a.eta, "requester": "A1"}
        rec = approvals.request(a.state, a.rules, req)
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return 0 if rec["decision"] == "approve" else 2
    if a.cmd == "functional":
        data = json.loads(open(a.results, encoding="utf-8").read())
        caps = data.get("capabilities", [])
        ids = {c.get("id") for c in caps if c.get("pass")}
        missing = sorted(gate.REQUIRED_CAPABILITIES - ids)
        ok = len(caps) >= 7 and not missing and bool(data.get("run_id"))
        print(json.dumps({"pass": ok, "missing": missing, "count": len(caps),
                          "run_id": data.get("run_id", "")}, ensure_ascii=False))
        return 0 if ok else 2
    if a.cmd == "gate":
        res = gate.evaluate(a.state, a.rules, a.functional, a.results)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if all(v["pass"] for v in res.values()) else 2
    if a.cmd == "begin":
        rec = evidence.begin(a.state, a.evidence, a.run_id)
        print(json.dumps(rec, ensure_ascii=False, indent=2))
        return 0
    if a.cmd == "check":
        issues = evidence.check(a.state, a.run_id, a.evidence, a.binary)
        print(json.dumps({"pass": not issues, "issues": issues}, ensure_ascii=False, indent=2))
        return 0 if not issues else 2
    if a.cmd == "timeline":
        for rec in read_timeline(a.state):
            print(json.dumps(rec, ensure_ascii=False))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
