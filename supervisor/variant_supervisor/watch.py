from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from .config import Config, StageConfig
from .journal import Journal
from .policy import diagnose
from .watchdog import RunResult, run_command, tail_text


def _stage_for(cfg: Config, name: str) -> StageConfig:
    for stage in cfg.stages:
        if stage.name == name:
            return stage
    return StageConfig(name=name, cmd=[], timeout=60, retries=1)


def _handle(cfg: Config, journal: Journal, event: dict, execute_clean: bool) -> None:
    kind = event.get("type")
    if kind not in {"stage_fail", "audit_fail"}:
        return

    if kind == "audit_fail":
        journal.write("watch_audit_fail", issues=event.get("issues", []), source=event.get("source"))
        print("[watch] audit failure observed:", event.get("issues"))
        return

    stage = _stage_for(cfg, str(event.get("stage", "unknown")))
    log = Path(str(event.get("log", "")))
    if not log.is_absolute():
        log = (cfg.base_dir / log).resolve()
    result = RunResult(
        exit_code=event.get("exit_code"),
        timed_out=bool(event.get("timed_out", False)),
        log_too_big=bool(event.get("log_too_big", False)),
        rss_exceeded=bool(event.get("rss_exceeded", False)),
        duration_sec=float(event.get("duration_sec", 0)),
        peak_rss_mb=float(event.get("peak_rss_mb", 0)),
        log_path=log,
    )
    diag = diagnose(result, tail_text(log), 0, stage.retries)
    journal.write(
        "watch_diagnosis",
        stage=stage.name,
        cause=diag.cause,
        action=diag.action,
        confidence=diag.confidence,
        rationale=diag.rationale,
        source=diag.source,
        exit_code=result.exit_code,
        log=str(log),
    )
    print(f"[watch] {stage.name} FAIL cause={diag.cause} action={diag.action}")

    if execute_clean and diag.action == "clean" and cfg.clean_cmd:
        clean_log = cfg.log_dir / "watch-clean.log"
        clean = run_command(cfg.clean_cmd, cfg.base_dir, clean_log, 30, cfg.max_log_mb, cfg.max_rss_mb)
        journal.write("watch_clean", stage=stage.name, exit_code=clean.exit_code, log=str(clean_log))
        print(f"[watch] clean exit={clean.exit_code}")


def watch(cfg: Config, events_path: Path, follow: bool = False, execute_clean: bool = False) -> int:
    events_path = events_path if events_path.is_absolute() else (cfg.base_dir / events_path).resolve()
    journal = Journal(cfg.journal_path, "watch-" + time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2))
    journal.write("watch_start", events=str(events_path), follow=follow, execute_clean=execute_clean)

    if not events_path.exists():
        print(f"[watch] events file not found: {events_path}")
        return 2

    offset = 0
    while True:
        with events_path.open("r", encoding="utf-8") as f:
            f.seek(offset)
            while True:
                line = f.readline()
                if not line:
                    break
                offset = f.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    journal.write("watch_bad_event", line=line[:500])
                    continue
                try:
                    _handle(cfg, journal, event, execute_clean)
                except Exception as exc:  # noqa: BLE001
                    journal.write("watch_error", event=event, error=repr(exc))
        if not follow:
            break
        try:
            if events_path.stat().st_size < offset:
                offset = 0
        except OSError:
            pass
        time.sleep(0.5)
    return 0


