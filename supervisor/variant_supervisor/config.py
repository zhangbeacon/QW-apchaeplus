from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when the pipeline config is structurally invalid."""


@dataclass
class StageConfig:
    name: str
    cmd: list[str]
    timeout: int = 60
    retries: int = 1
    log: str | None = None
    description: str = ""
    snapshot: bool = True


@dataclass
class Config:
    base_dir: Path
    project: str
    workdir: Path
    log_dir: Path
    evidence_dir: Path
    snapshot_dirs: list[Path]
    stages: list[StageConfig]
    clean_cmd: list[str] | None
    required_evidence: list[str]
    evidence_max_age_sec: int
    expected_json: dict[str, dict[str, Any]]
    max_stage_retries: int
    max_total_retries: int
    max_log_mb: float
    max_rss_mb: int
    llm_enabled: bool
    llm_model: str
    llm_base: str
    llm_api_key_env: str

    @property
    def journal_path(self) -> Path:
        return self.log_dir / "journal.jsonl"


def _expand(cmd: list[str] | None, python: str) -> list[str] | None:
    if not cmd:
        return None
    return [python if part == "{python}" else part for part in cmd]


def _as_cmd(value: Any, what: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise ConfigError(f"{what} must be a non-empty list of strings")
    return value


def _positive_int(value: Any, what: str, minimum: int = 1) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{what} must be an integer") from exc
    if number < minimum:
        raise ConfigError(f"{what} must be >= {minimum}")
    return number


def _positive_float(value: Any, what: str, minimum: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{what} must be a number") from exc
    if number < minimum:
        raise ConfigError(f"{what} must be >= {minimum}")
    return number


def load_config(path: str | Path) -> Config:
    path = Path(path).resolve()
    if not path.is_file():
        raise ConfigError(f"config not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be an object")

    base = (path.parent / raw.get("base_dir", ".")).resolve()

    def p(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (base / candidate).resolve()

    python = raw.get("python") or sys.executable
    raw_stages = raw.get("stages")
    if not isinstance(raw_stages, list) or not raw_stages:
        raise ConfigError("stages must be a non-empty list")

    stages: list[StageConfig] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_stages):
        if not isinstance(item, dict):
            raise ConfigError(f"stages[{index}] must be an object")
        name = str(item.get("name", "")).strip()
        if not name:
            raise ConfigError(f"stages[{index}].name is required")
        if name in seen:
            raise ConfigError(f"duplicate stage name: {name}")
        seen.add(name)
        log_value = item.get("log")
        if log_value is not None and not isinstance(log_value, str):
            raise ConfigError(f"stages[{index}].log must be a string")
        stages.append(
            StageConfig(
                name=name,
                cmd=_expand(_as_cmd(item.get("cmd"), f"stages[{index}].cmd"), python) or [],
                timeout=_positive_int(item.get("timeout", 60), f"stages[{index}].timeout"),
                retries=_positive_int(item.get("retries", 1), f"stages[{index}].retries", minimum=0),
                log=log_value,
                description=str(item.get("description", "")),
                snapshot=bool(item.get("snapshot", True)),
            )
        )

    audit = raw.get("audit", {})
    if not isinstance(audit, dict):
        raise ConfigError("audit must be an object")
    budgets = raw.get("budgets", {})
    if not isinstance(budgets, dict):
        raise ConfigError("budgets must be an object")
    llm = raw.get("llm", {})
    if not isinstance(llm, dict):
        raise ConfigError("llm must be an object")

    expected = audit.get("expected_json", {})
    if not isinstance(expected, dict):
        raise ConfigError("audit.expected_json must be an object")
    required_raw = audit.get("required", [])
    if not isinstance(required_raw, list):
        raise ConfigError("audit.required must be a list")
    snapshot_raw = raw.get("snapshot_dirs", [])
    if not isinstance(snapshot_raw, list) or not all(isinstance(x, str) for x in snapshot_raw):
        raise ConfigError("snapshot_dirs must be a list of strings")

    return Config(
        base_dir=base,
        project=str(raw.get("project", base.name)),
        workdir=p(raw.get("workdir", "work")),
        log_dir=p(raw.get("log_dir", "logs")),
        evidence_dir=p(raw.get("evidence_dir", "evidence")),
        snapshot_dirs=[p(x) for x in snapshot_raw],
        stages=stages,
        clean_cmd=_expand(_as_cmd(raw.get("clean_cmd"), "clean_cmd"), python),
        required_evidence=[str(x) for x in required_raw],
        evidence_max_age_sec=_positive_int(audit.get("max_age_sec", 300), "audit.max_age_sec"),
        expected_json={str(k): dict(v) for k, v in expected.items() if isinstance(v, dict)},
        max_stage_retries=_positive_int(budgets.get("max_stage_retries", 2), "budgets.max_stage_retries", 0),
        max_total_retries=_positive_int(budgets.get("max_total_retries", 5), "budgets.max_total_retries", 0),
        max_log_mb=_positive_float(budgets.get("max_log_mb", 8), "budgets.max_log_mb"),
        max_rss_mb=_positive_int(budgets.get("max_rss_mb", 1024), "budgets.max_rss_mb", 0),
        llm_enabled=bool(llm.get("enabled", False)),
        llm_model=str(llm.get("model", "deepseek-chat")),
        llm_base=str(llm.get("base", "https://api.deepseek.com/v1")),
        llm_api_key_env=str(llm.get("api_key_env", "DEEPSEEK_API_KEY")),
    )



