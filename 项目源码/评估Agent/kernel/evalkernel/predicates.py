"""Judgment functions: features -> state -> Y_i; and per-(CVE, variant) status.

All rules are pure functions of the trial payload. ASan evidence is deliberately
ignored here: it is only allowed in status evidence, never in state/Y_i.
"""

from __future__ import annotations

from .schema import RawTrial

# ---------------------------------------------------------------- features


def extract_features(trial: RawTrial, probe_cfg: dict) -> dict:
    """Deterministic extraction of machine-checkable features from raw evidence."""
    body = str(trial.resp.get("body", "") or "")
    err = str((trial.logs or {}).get("error", "") or "")
    acc = str((trial.logs or {}).get("access", "") or "")

    def hits(text: str, needles: list[str]) -> list[str]:
        return [n for n in needles if n and n in text]

    return {
        "status": int(trial.resp.get("status", 0) or 0),
        "body": body,
        "error_log": err,
        "access_log": acc,
        "markers": hits(body, probe_cfg.get("markers", [])),
        "log_hits": hits(err, probe_cfg.get("log_patterns", [])),
        "signal": (trial.process or {}).get("signal"),
        "timeout": bool((trial.process or {}).get("timeout", False)),
        "alive": bool((trial.process or {}).get("alive", True)),
        "rc_R": int((trial.rc or {}).get("R", 0) or 0),
        "rc_fields": dict((trial.rc or {}).get("fields", {}) or {}),
        "backtrace_hit": bool((trial.rc or {}).get("backtrace_hit", False)),
        "resp_count": int(trial.resp.get("resp_count", 1) or 1),
        "second_hit_marker": bool(trial.resp.get("second_hit_marker", False)),
        "backend": trial.backend or {},
        "uds": trial.uds or {},
    }


# ---------------------------------------------------------------- state ladder

CRASH_SIGNALS = {"SIGSEGV", "SIGABRT", "SIGBUS"}


def state_of(short: str, f: dict) -> str:
    """Return 'L0'..'L3' or 'U_invalid' (evidence incomplete)."""
    status = f["status"]
    markers = set(f["markers"])
    logs = set(f["log_hits"])

    if short == "41773":
        if "uid=" in markers and "gid=" in markers:
            return "L3"
        if "root:x:0:0" in markers:
            return "L2"
        if status == 500 and ({"AH01241", "End of script output before headers"} & logs):
            return "L1"
        if status == 0:
            return "U_invalid"
        return "L0"

    if short == "44224":
        uds = f["uds"]
        if bool(uds.get("protected_content", False)):
            return "L3"
        if int(uds.get("request_lines", 0) or 0) >= 1:
            return "L2"
        if ({"AH00957", "AH01114"} & logs) and int(uds.get("bytes", 0) or 0) == 0:
            return "L1"
        if status == 0:
            return "U_invalid"
        return "L0"

    if short == "44790":
        # Native evidence only. ASan is never consulted here.
        if f["signal"] in CRASH_SIGNALS and f["backtrace_hit"]:
            return "L2"
        if "block too big" in logs:
            return "L1"
        if f["signal"] in CRASH_SIGNALS:
            # path executed, crash observed, but not attributable to the bug
            return "L1"
        if status == 200 and "parsebody-done" in f["body"]:
            return "L0"
        if status == 0:
            return "U_invalid"
        return "L1"

    if short == "22720":
        if f["resp_count"] >= 2 and f["second_hit_marker"]:
            return "L3" if status == 200 else "L2"
        if f["resp_count"] >= 2:
            return "L1"
        if "discard" in logs or "AH" in "".join(logs):
            pass
        if status in (400, 408) or f["resp_count"] <= 1:
            return "L0"
        return "U_invalid"

    if short == "25690":
        b = f["backend"]
        if bool(b.get("protected_forwarded", False)):
            return "L3"
        if int(b.get("lines", 0) or 0) >= 2 and bool(b.get("second_is_injected", False)):
            return "L2"
        if int(b.get("lines", 0) or 0) >= 1 and bool(b.get("injected_found", False)):
            return "L1"
        if status == 0:
            return "U_invalid"
        return "L0"

    if short == "38474":
        if "EXEC_MARKER" in markers:
            return "L3"
        if "SECRET_MARKER" in markers:
            return "L2"
        if "decoded_question" in logs:
            return "L1"
        if status == 0:
            return "U_invalid"
        return "L0"

    raise ValueError(f"unknown cve short id: {short}")


# ---------------------------------------------------------------- Y_i

def y_of(short: str, f: dict, state: str) -> int:
    """Pre-registered success predicate. ASan never contributes."""
    if state == "U_invalid":
        return 0
    if short == "41773":
        return 1 if state in ("L2", "L3") else 0
    if short == "44224":
        return 1 if state in ("L2", "L3") else 0
    if short == "44790":
        # Native crash attributable to req_parsebody only.
        return 1 if state == "L2" else 0
    if short == "22720":
        return 1 if (state in ("L2", "L3") and f["second_hit_marker"]) else 0
    if short == "25690":
        if state == "L3":
            return 1
        return 1 if (state == "L2" and f["backend"].get("second_is_injected")) else 0
    if short == "38474":
        return 1 if state in ("L2", "L3") else 0
    raise ValueError(f"unknown cve short id: {short}")


def crash_of(f: dict) -> int:
    if f["timeout"]:
        return 1
    return 1 if f["signal"] in CRASH_SIGNALS else 0


# ---------------------------------------------------------------- status

def derive_status(rc_by_probe: dict[str, int], canonical: str,
                  hunks_overlap: bool) -> tuple[str, str]:
    """Derive P / S / X_obs / U_disputed from root-cause observations.

    rc_by_probe: probe_id -> R (0/1). Missing canonical -> U_disputed.
    """
    if canonical not in rc_by_probe:
        return "U_disputed", "MISSING_CANONICAL_R"
    r_c = rc_by_probe[canonical]
    r_other = any(v for k, v in rc_by_probe.items() if k != canonical)

    if r_c == 1 and not hunks_overlap:
        return "P", "CANONICAL_R1_NO_FIX_HUNK"
    if r_c == 1 and hunks_overlap:
        return "U_disputed", "CANONICAL_R1_BUT_FIX_HUNK"
    if r_c == 0 and r_other:
        return "S", "CANONICAL_R0_OTHER_R1"
    if r_c == 0 and not r_other:
        return "X_obs", "ALL_R0"
    return "U_disputed", "UNKNOWN"


def eligibility(statuses: dict[str, str], kind: str) -> tuple[bool, str]:
    """kind in {'pure','shift'}."""
    vals = list(statuses.values())
    if not vals:
        return False, "NO_VARIANTS"
    if kind == "pure":
        if all(s == "P" for s in vals):
            return True, "ALL_P"
        bad = sorted({s for s in vals if s != "P"})
        return False, "NOT_ALL_P:" + ",".join(bad)
    if kind == "shift":
        if any(s == "X_obs" for s in vals):
            return False, "HAS_X_OBS"
        if not any(s in ("P", "S") for s in vals):
            return False, "NO_P_OR_S"
        if not any(s == "S" for s in vals):
            return False, "NO_S"
        return True, "P_AND_S"
    raise ValueError(kind)


def eligibility_classes(statuses: dict[str, str], classes: dict[str, str],
                        kind: str) -> tuple[bool, str]:
    """Gates that also enforce variant class (v6.5 handoff with A1).

    pure  : every member class == 'pure' AND every status == P
    shift : every member class in {pure, struct}, status in {P, S}, at least one S

    'isolation' class members (the pre-registered V3) never enter either gauge;
    they are measured only in Track B on the delivered set.
    """
    vals = list(statuses.values())
    if not vals:
        return False, "NO_VARIANTS"
    if kind == "pure":
        bad_class = sorted({v for v in statuses if classes.get(v) != "pure"})
        if bad_class:
            return False, "NOT_ALL_PURE:" + ",".join(bad_class)
        bad = sorted({s for s in vals if s != "P"})
        if bad:
            return False, "NOT_ALL_P:" + ",".join(bad)
        return True, "ALL_PURE_P"
    if kind == "shift":
        bad_class = sorted({v for v in statuses
                            if classes.get(v) not in ("pure", "struct")})
        if bad_class:
            return False, "CLASS_MIX:" + ",".join(bad_class)
        if any(s == "X_obs" for s in vals):
            return False, "HAS_X_OBS"
        if not any(s in ("P", "S") for s in vals):
            return False, "NO_P_OR_S"
        if not any(s == "S" for s in vals):
            return False, "NO_S"
        return True, "P_AND_S"
    raise ValueError(kind)
