from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

SYSTEM_PROMPT = """You are a build/test supervisor for an Apache variant pipeline.
You receive a failed stage, its exit status, budget flags and the tail of its log.
Return ONE JSON object only, no markdown, with keys:
  cause: short upper-snake identifier
  action: one of retry, clean, rollback, abort, escalate
  confidence: number in [0,1]
  rationale: one sentence, concrete and evidence-based
Rules:
- Never claim a vulnerability was fixed or a test passed; you only propose handling.
- Prefer clean for stale ports/locks, retry for transient build errors,
  escalate for missing dependencies or permissions.
"""


def _log_tail(path, limit=4000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", "replace")


def diagnose_with_llm(config, stage_name: str, cmd: list[str], result, log_path, timeout=30):
    """Return (payload, error). payload is None when the LLM is disabled/unavailable."""
    if not config.llm_enabled:
        return None, "disabled"
    key = os.environ.get(config.llm_api_key_env, "").strip()
    if not key:
        return None, f"missing env {config.llm_api_key_env}"

    body = {
        "model": config.llm_model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "stage": stage_name,
                        "command": cmd,
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                        "log_too_big": result.log_too_big,
                        "rss_exceeded": result.rss_exceeded,
                        "peak_rss_mb": result.peak_rss_mb,
                        "duration_sec": result.duration_sec,
                        "log_tail": _log_tail(log_path),
                    },
                    ensure_ascii=False,
                ),
            },
        ],
    }
    req = urllib.request.Request(
        config.llm_base.rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.strip("`")
            if content.lower().startswith("json"):
                content = content[4:]
            content = content.strip()
        return json.loads(content), None
    except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError) as exc:
        return None, str(exc)[:300]

