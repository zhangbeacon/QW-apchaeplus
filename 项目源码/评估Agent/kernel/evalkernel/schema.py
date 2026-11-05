"""Schema, config loading, and canonical hashing for the offline evaluation kernel.

Only stdlib. No LLM, no network, no wall-clock dependence (timestamps optional).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SchemaError(ValueError):
    pass


REQUIRED_TRIAL_KEYS = ("cve", "probe", "variant", "repeat")
VALID_GROUPS = {"A+", "A-"}


def canon(obj: Any) -> str:
    """Canonical JSON text used for hashing and byte-stable output."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RawTrial:
    """One attempt: a probe sent to one variant, one repeat."""

    cve: str
    probe: str
    variant: str
    repeat: int
    group: str = "A+"
    resp: dict = field(default_factory=dict)
    logs: dict = field(default_factory=dict)
    process: dict = field(default_factory=dict)
    rc: dict = field(default_factory=dict)
    backend: dict | None = None
    uds: dict | None = None
    asan: dict | None = None
    latency_ms: int = 0
    ts: str = ""
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "RawTrial":
        for k in REQUIRED_TRIAL_KEYS:
            if k not in d:
                raise SchemaError(f"missing required key: {k}")
        if not isinstance(d["repeat"], int) or d["repeat"] < 1:
            raise SchemaError("repeat must be a positive integer")
        if d.get("group", "A+") not in VALID_GROUPS:
            raise SchemaError(f"group must be one of {sorted(VALID_GROUPS)}")
        known = {
            "cve", "probe", "variant", "repeat", "group", "resp", "logs",
            "process", "rc", "backend", "uds", "asan", "latency_ms", "ts",
        }
        extra = {k: v for k, v in d.items() if k not in known}
        return cls(
            cve=str(d["cve"]),
            probe=str(d["probe"]),
            variant=str(d["variant"]),
            repeat=int(d["repeat"]),
            group=d.get("group", "A+"),
            resp=d.get("resp") or {},
            logs=d.get("logs") or {},
            process=d.get("process") or {},
            rc=d.get("rc") or {},
            backend=d.get("backend"),
            uds=d.get("uds"),
            asan=d.get("asan"),
            latency_ms=int(d.get("latency_ms") or 0),
            ts=str(d.get("ts") or ""),
            extra=extra,
        )

    def evidence_payload(self) -> dict:
        """Everything except the timestamp; this is what the evidence hash covers."""
        return {
            "cve": self.cve,
            "probe": self.probe,
            "variant": self.variant,
            "repeat": self.repeat,
            "group": self.group,
            "resp": self.resp,
            "logs": self.logs,
            "process": self.process,
            "rc": self.rc,
            "backend": self.backend,
            "uds": self.uds,
            "asan": self.asan,
            "latency_ms": self.latency_ms,
            **self.extra,
        }

    def evidence_sha(self) -> str:
        return sha256_text(canon(self.evidence_payload()))


def load_trials(path: str | Path) -> list[RawTrial]:
    trials: list[RawTrial] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SchemaError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            try:
                trials.append(RawTrial.from_dict(obj))
            except SchemaError as exc:
                raise SchemaError(f"{path}:{lineno}: {exc}") from exc
    return trials


def load_config(config_dir: str | Path) -> dict:
    """Load probes.json + variants.json."""
    d = Path(config_dir)
    probes = json.loads((d / "probes.json").read_text(encoding="utf-8"))
    variants = json.loads((d / "variants.json").read_text(encoding="utf-8"))
    _validate_config(probes, variants)
    return {"probes": probes, "variants": variants}


def _validate_config(probes: dict, variants: dict) -> None:
    if "cves" not in probes or "cves" not in variants:
        # cves live in probes.json; variants.json holds variant sets
        pass
    for short, cfg in probes.get("cves", {}).items():
        for key in ("canonical", "family"):
            if key not in cfg:
                raise SchemaError(f"probes[{short}] missing {key}")
        fam = cfg["family"]
        if cfg["canonical"] not in fam:
            raise SchemaError(f"probes[{short}].canonical not in family")
        for key in ("selection", "test"):
            for pid in cfg.get(key, []):
                if pid not in fam:
                    raise SchemaError(f"probes[{short}].{key} has unknown probe {pid}")
    v = variants
    for key in ("variants", "final", "b0", "h_group", "t_group", "kh_group"):
        if key not in v:
            raise SchemaError(f"variants.json missing {key}")
    for vid in v["final"] + v["b0"] + v["h_group"] + v["t_group"] + v["kh_group"]:
        if vid not in v["variants"]:
            raise SchemaError(f"variants.json references unknown variant {vid}")


def dump_json(path: str | Path, obj: Any) -> None:
    """Byte-stable JSON: sorted keys, UTF-8, trailing newline, 6-decimal floats."""
    text = json.dumps(_round(obj), sort_keys=True, ensure_ascii=False, indent=2)
    Path(path).write_text(text + "\n", encoding="utf-8")


def dump_jsonl(path: str | Path, rows: list[dict]) -> None:
    lines = [canon(_round(r)) for r in rows]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _round(obj: Any) -> Any:
    if isinstance(obj, float):
        return round(obj, 6)
    if isinstance(obj, dict):
        return {k: _round(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_round(v) for v in obj]
    return obj
