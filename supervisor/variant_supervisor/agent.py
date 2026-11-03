from __future__ import annotations

import secrets
import time
from pathlib import Path

from .audit import audit_evidence
from .config import Config, StageConfig
from .journal import Journal
from .llm import diagnose_with_llm
from .policy import Diagnosis, coerce_llm_diagnosis, diagnose
from .snapshot import SnapshotManager
from .watchdog import RunResult, run_command, tail_text


class SupervisorAgent:
    """Run a pipeline, diagnose failures, apply bounded remediation, audit evidence."""

    def __init__(self, config: Config, run_id: str | None = None, verbose: bool = True):
        self.cfg = config
        self.run_id = run_id or time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)
        self.verbose = verbose

        for directory in (config.log_dir, config.evidence_dir, config.workdir):
            directory.mkdir(parents=True, exist_ok=True)

        self.journal = Journal(config.journal_path, self.run_id)
        self.snapshots = SnapshotManager(config.log_dir / "snapshots", config.snapshot_dirs, self.run_id)
        self.total_retries = 0
        self.needs_human = False
        self.aborted = False
        self.last_snapshot: Path | None = None
        self.stage_results: dict[str, dict] = {}
        self.started_at = time.time()

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"[supervisor] {message}")

    def run(self) -> str:
        try:
            return self._run_pipeline()
        except KeyboardInterrupt:
            self.journal.write("run_crash", error="KeyboardInterrupt")
            return self._finish("ABORTED")
        except Exception as exc:  # noqa: BLE001
            import traceback

            traceback.print_exc()
            self.journal.write("run_crash", error=repr(exc), traceback=traceback.format_exc()[-4000:])
            return self._finish("FAIL")

    def _run_pipeline(self) -> str:
        cfg = self.cfg
        self.started_at = time.time()
        self.journal.write(
            "run_start",
            project=cfg.project,
            base_dir=str(cfg.base_dir),
            stages=[s.name for s in cfg.stages],
            budgets={
                "max_stage_retries": cfg.max_stage_retries,
                "max_total_retries": cfg.max_total_retries,
                "max_log_mb": cfg.max_log_mb,
                "max_rss_mb": cfg.max_rss_mb,
            },
        )
        self.log(f"run {self.run_id} project={cfg.project}")

        self.last_snapshot = self.snapshots.create("initial")
        if self.last_snapshot:
            self.journal.write("snapshot", path=str(self.last_snapshot), label="initial")

        for stage in cfg.stages:
            if not self._run_stage(stage):
                return self._finish("NEEDS_HUMAN" if self.needs_human else "FAIL")

        return self._finish(self._audit_or_repair())

    # ------------------------------------------------------------------ stage
    def _stage_log(self, stage: StageConfig) -> Path:
        if stage.log:
            p = Path(stage.log)
            return p if p.is_absolute() else self.cfg.log_dir / p
        return self.cfg.log_dir / f"{stage.name}.log"

    def _run_stage(self, stage: StageConfig) -> bool:
        log_path = self._stage_log(stage)
        max_attempts = stage.retries + 1
        attempt = 0
        self.stage_results[stage.name] = {"status": "pending", "attempts": 0}

        while attempt < max_attempts:
            attempt += 1
            if attempt > 1 and self.total_retries >= self.cfg.max_total_retries:
                self.journal.write("budget_exhausted", stage=stage.name, total_retries=self.total_retries)
                self.needs_human = True
                self.stage_results[stage.name].update(status="budget_exhausted", attempts=attempt)
                return False

            snap = self.snapshots.create(f"before-{stage.name}-{attempt}") if stage.snapshot else None
            if snap:
                self.last_snapshot = snap
                self.journal.write("snapshot", path=str(snap), label=f"before-{stage.name}-{attempt}")

            self.journal.write("stage_start", stage=stage.name, attempt=attempt, cmd=stage.cmd)
            self.log(f"{stage.name} attempt {attempt}/{max_attempts}")
            result = run_command(
                stage.cmd,
                cwd=self.cfg.base_dir,
                log_path=log_path,
                timeout=stage.timeout,
                max_log_mb=self.cfg.max_log_mb,
                max_rss_mb=self.cfg.max_rss_mb,
            )
            record = {
                "stage": stage.name,
                "attempt": attempt,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "log_too_big": result.log_too_big,
                "rss_exceeded": result.rss_exceeded,
                "duration_sec": result.duration_sec,
                "peak_rss_mb": result.peak_rss_mb,
                "log": str(log_path),
            }
            self.journal.write("stage_result", **record)

            if result.ok:
                self.journal.write("stage_ok", stage=stage.name, attempt=attempt)
                self.stage_results[stage.name].update(status="ok", attempts=attempt)
                self.log(f"{stage.name} OK ({result.duration_sec}s, {result.peak_rss_mb} MB)")
                return True

            diag = self._diagnose(stage, result, log_path, attempt)
            self.journal.write(
                "diagnosis",
                stage=stage.name,
                attempt=attempt,
                cause=diag.cause,
                action=diag.action,
                confidence=diag.confidence,
                rationale=diag.rationale,
                source=diag.source,
            )
            self.log(f"{stage.name} FAIL cause={diag.cause} action={diag.action} ({diag.source})")

            if diag.action == "retry":
                self.total_retries += 1
                continue
            if diag.action == "clean":
                self.total_retries += 1
                if self._clean(stage):
                    continue
                self.needs_human = True
                self.stage_results[stage.name].update(status="clean_failed", attempts=attempt)
                return False
            if diag.action == "rollback":
                self.total_retries += 1
                self._rollback()
                continue
            if diag.action == "abort":
                self.aborted = True
                self.stage_results[stage.name].update(status="aborted", attempts=attempt)
                return False
            self.needs_human = True
            self.stage_results[stage.name].update(status="escalated", attempts=attempt)
            return False

        self.needs_human = True
        self.stage_results[stage.name].update(status="retries_exhausted", attempts=attempt)
        return False

    def _diagnose(self, stage: StageConfig, result: RunResult, log_path: Path, attempt: int) -> Diagnosis:
        rule = diagnose(result, tail_text(log_path), attempt - 1, stage.retries)
        if not self.cfg.llm_enabled:
            return rule

        payload, error = diagnose_with_llm(self.cfg, stage.name, stage.cmd, result, log_path)
        if error:
            self.journal.write("llm_unavailable", stage=stage.name, error=error)
            return rule
        llm = coerce_llm_diagnosis(payload or {}, rule)
        self.journal.write("llm_diagnosis", stage=stage.name, payload=payload, accepted=llm.source == "llm")
        return llm

    def _clean(self, stage: StageConfig) -> bool:
        if not self.cfg.clean_cmd:
            self.journal.write("clean_skipped", stage=stage.name, reason="no clean_cmd")
            return False
        log = self.cfg.log_dir / "clean.log"
        self.journal.write("action", stage=stage.name, action="clean", cmd=self.cfg.clean_cmd)
        result = run_command(self.cfg.clean_cmd, self.cfg.base_dir, log, 30, self.cfg.max_log_mb, self.cfg.max_rss_mb)
        self.journal.write(
            "clean_result",
            stage=stage.name,
            exit_code=result.exit_code,
            log=str(log),
        )
        return result.ok

    def _rollback(self) -> None:
        if self.last_snapshot and self.last_snapshot.exists():
            self.snapshots.restore(self.last_snapshot)
            self.journal.write("action", action="rollback", path=str(self.last_snapshot))
            self.log(f"rolled back to {self.last_snapshot.name}")
        else:
            self.journal.write("action", action="rollback", path=None, note="no snapshot")

    # ------------------------------------------------------------------ audit
    def _audit_or_repair(self) -> str:
        cfg = self.cfg
        issues = audit_evidence(
            cfg.evidence_dir,
            cfg.required_evidence,
            started_at=self.started_at,
            max_age_sec=cfg.evidence_max_age_sec,
            expected_json=cfg.expected_json,
        )
        self.journal.write("audit", ok=not issues, issues=[i.__dict__ for i in issues])

        if issues and self.total_retries < cfg.max_total_retries:
            security = next((s for s in cfg.stages if s.name == "security"), None)
            if security:
                self.total_retries += 1
                self.journal.write(
                    "action",
                    action="rerun",
                    stage="security",
                    reason="evidence audit failed",
                    issues=[i.__dict__ for i in issues],
                )
                self.log("audit failed; rerunning security stage once")
                rerun_started = time.time()
                if self._run_stage(security):
                    issues = audit_evidence(
                        cfg.evidence_dir,
                        cfg.required_evidence,
                        started_at=rerun_started,
                        max_age_sec=cfg.evidence_max_age_sec,
                        expected_json=cfg.expected_json,
                    )
                    self.journal.write("audit", ok=not issues, issues=[i.__dict__ for i in issues])

        if issues:
            self.needs_human = True
            return "NEEDS_HUMAN"
        self.log("audit OK")
        return "PASS"

    # ------------------------------------------------------------------ finish
    def _finish(self, verdict: str) -> str:
        self.journal.write(
            "run_end",
            verdict=verdict,
            total_retries=self.total_retries,
            stages=self.stage_results,
            journal=str(self.cfg.journal_path),
        )
        self.log(f"verdict={verdict} retries={self.total_retries}")
        return verdict





