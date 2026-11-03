from __future__ import annotations

import re
from dataclasses import dataclass

from .watchdog import RunResult

ACTIONS = {"retry", "clean", "rollback", "abort", "escalate"}


@dataclass
class Diagnosis:
    cause: str
    action: str
    confidence: float
    rationale: str
    source: str = "rule"


RULES: list[tuple[str, str, str, float]] = [
    (r"address already in use", "PORT_CONFLICT", "clean", 0.95),
    (r"failed to start command", "SPAWN_ERROR", "escalate", 0.95),
    (r"no such file or directory", "MISSING_DEP", "escalate", 0.85),
    (r"permission denied", "PERMISSION", "escalate", 0.85),
    (r"cannot find -l|undefined reference", "LINK_ERROR", "retry", 0.8),
    (r"fatal error:.*no such file", "MISSING_HEADER", "escalate", 0.9),
    (r"out of memory|cannot allocate memory", "OOM", "escalate", 0.9),
    (r"checksum mismatch|patch does not apply|corrupt", "PATCH_FAILED", "rollback", 0.8),
    (r"assertionerror|assertion failed|mismatch", "TEST_FAIL", "retry", 0.75),
    (r"error:|error\[", "BUILD_ERROR", "retry", 0.7),
]


def diagnose(result: RunResult, log_text: str, attempts: int, max_retries: int) -> Diagnosis:
    if result.timed_out:
        diag = Diagnosis("TIMEOUT", "retry", 0.95, "stage exceeded its time budget")
    elif result.log_too_big:
        diag = Diagnosis("LOG_OVERFLOW", "clean", 0.9, "log exceeded the size budget")
    elif result.rss_exceeded:
        diag = Diagnosis("OOM", "escalate", 0.9, "RSS exceeded the memory budget")
    elif result.exit_code == 137:
        diag = Diagnosis("OOM", "escalate", 0.85, "process killed with SIGKILL/137")
    elif result.exit_code is None:
        diag = Diagnosis("SPAWN_ERROR", "escalate", 0.9, "command could not be started")
    else:
        lowered = log_text.lower()
        diag = Diagnosis("UNKNOWN", "retry", 0.4, "no known signature in the log")
        for pattern, cause, action, confidence in RULES:
            if re.search(pattern, lowered):
                diag = Diagnosis(cause, action, confidence, f"matched /{pattern}/")
                break

    # Budget-aware downgrade: retrying forever is worse than asking a human.
    if diag.action in {"retry", "clean", "rollback"} and attempts >= max_retries:
        return Diagnosis(
            diag.cause,
            "escalate",
            diag.confidence,
            diag.rationale + f"; retry budget exhausted ({attempts}/{max_retries})",
        )
    return diag


def coerce_llm_diagnosis(payload: dict, fallback: Diagnosis) -> Diagnosis:
    """Accept an LLM answer only when it is well-formed and confident enough."""
    try:
        action = str(payload.get("action", "")).strip().lower()
        cause = str(payload.get("cause", fallback.cause)).strip()[:80]
        confidence = float(payload.get("confidence", 0))
        rationale = str(payload.get("rationale", ""))[:500]
    except Exception:  # noqa: BLE001
        return fallback
    if action not in ACTIONS or confidence < 0.65:
        return fallback
    return Diagnosis(cause or fallback.cause, action, confidence, rationale or fallback.rationale, "llm")
