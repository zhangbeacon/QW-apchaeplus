"""A1 · 计划与运行状态：读 plan.yaml（校验参数缺失/重复 → 直接报错，不猜），
管理 artifacts/<run_id>/state.json 台账。

注意：state.json 是 A1 自己的台账；监管 Agent 的 status.json / 评估的 hde.json
A1 一律不碰（设计文档 §7 铁律）。
"""

import json
import os
import re
import time

from ..domain import SpecError, canonical_hash, load_yaml

STATE_SCHEMA = "qw9/genstate/v1"
ID_RE = re.compile(r"^[a-z][a-z0-9]{0,7}$")
AXES = {"compile", "harden", "thread", "isolation"}
REQUIRED_PARAMS = ("cc", "opt", "allocator", "mpm", "harden")
DEFAULT_V2_AXES = ["compile", "harden", "thread"]


class PlanError(SpecError):
    pass


class Plan:
    """plan.yaml 的内存表示，构造即全量校验。"""

    def __init__(self, data, path):
        if not isinstance(data, dict):
            raise PlanError("plan 根节点必须是映射")
        base = os.path.dirname(os.path.abspath(path))

        self.id = str((data.get("metadata") or {}).get("id", ""))
        if not ID_RE.match(self.id or ""):
            raise PlanError(f"metadata.id 非法: {self.id!r}")

        self.candidates = list(data.get("candidates") or [])
        self.isolation_candidates = list(data.get("isolation_candidates") or [])
        if not self.candidates:
            raise PlanError("candidates 不能为空")
        if not self.isolation_candidates:
            raise PlanError("isolation_candidates 不能为空（V3 预注册必须有载体）")

        all_entries = self.candidates + self.isolation_candidates
        ids = [str(c.get("id", "")) for c in all_entries]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise PlanError(f"候选 id 重复: {dupes}")

        for c in all_entries:
            cid = str(c.get("id", ""))
            if not ID_RE.match(cid):
                raise PlanError(f"候选 id 非法: {cid!r}")
            axis = c.get("axis")
            if axis not in AXES:
                raise PlanError(f"{cid}: axis 必须是 {sorted(AXES)} 之一，得到 {axis!r}")
            if axis == "isolation":
                pol = c.get("policy")
                if not pol:
                    raise PlanError(f"{cid}: 隔离候选必须声明 policy 路径")
                pol_abs = os.path.normpath(os.path.join(base, pol))
                if not os.path.isfile(pol_abs):
                    raise PlanError(f"{cid}: 隔离策略文件不存在: {pol_abs}")
                c["_policy_path"] = pol_abs
            else:
                missing = [k for k in REQUIRED_PARAMS if k not in c]
                if missing:
                    raise PlanError(f"{cid}: 缺构建参数 {missing}")
                if str(c["harden"]).lower() not in ("true", "false"):
                    raise PlanError(f"{cid}: harden 必须是 true/false")

        delivery = data.get("delivery") or {}
        self.v3_preregistered = str(delivery.get("v3_preregistered", ""))
        iso_ids = [str(c.get("id")) for c in self.isolation_candidates]
        if self.v3_preregistered not in iso_ids:
            raise PlanError(
                f"delivery.v3_preregistered={self.v3_preregistered!r} 必须指向 isolation_candidates 之一")
        self.v2_axes = list(delivery.get("v2_axes") or DEFAULT_V2_AXES)
        bad = [a for a in self.v2_axes if a not in AXES]
        if bad:
            raise PlanError(f"v2_axes 含未知轴: {bad}")
        if "isolation" in self.v2_axes:
            raise PlanError("v2_axes 不得包含 isolation（V3 是隔离轴，V2 不得与之撞轴）")
        self.baseline_id = str(delivery.get("baseline_id", "c1"))
        if self.baseline_id not in set(ids):
            raise PlanError(f"delivery.baseline_id={self.baseline_id!r} 不在候选里")

        basecfg = data.get("base") or {}
        src = basecfg.get("source") or {}
        pkg = str(src.get("package", ""))
        if not pkg:
            raise PlanError("base.source.package 不能为空")
        self.tarball = os.path.normpath(os.path.join(base, pkg))
        if not os.path.isfile(self.tarball):
            raise PlanError(f"源码包不存在: {self.tarball}")
        self.tarball_sha256 = str(src.get("sha256", "")).lower()
        if len(self.tarball_sha256) != 64:
            raise PlanError("base.source.sha256 必须是 64 位十六进制")

        self.configure_args = [str(a) for a in (basecfg.get("configure_args") or [])]
        needs_mpm = any(str(c.get("mpm") or "") for c in self.candidates)
        if needs_mpm and "--enable-mpms-shared=all" not in self.configure_args:
            raise PlanError(
                "候选含 MPM 轴时，base.configure_args 必须包含 --enable-mpms-shared=all")
        self.bin_name = str(basecfg.get("bin_name", "httpd"))
        self.timeout_s = int(basecfg.get("timeout_s", 1800))

        ports = data.get("ports") or {}
        self.port_start = int(ports.get("start", 8200))
        self.allocator = {str(k): str(v) for k, v in (data.get("allocator") or {}).items()}

        self.raw = data
        self.path = os.path.abspath(path)
        self.hash = canonical_hash(data)

    @classmethod
    def load(cls, path):
        return cls(load_yaml(path), path)


# ---------------------------------------------------------------- 运行状态

def create_run(plan, root, run_id, recipes_out=None):
    """建 run 台账：artifacts/<run_id>/state.json + recipes/gen/<run_id>/。"""
    run_dir = os.path.join(root, "artifacts", run_id)
    recipes_dir = recipes_out or os.path.join(root, "recipes", "gen", run_id)
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(recipes_dir, exist_ok=True)

    entries = []
    port = plan.port_start
    for c in plan.candidates + plan.isolation_candidates:
        cid = str(c["id"])
        if c.get("axis") == "isolation":
            bp = c.get("base_params") or {}
            params = {k: bp.get(k) for k in REQUIRED_PARAMS}
            if bp.get("extra_cflags"):
                params["extra_cflags"] = str(bp["extra_cflags"])
            missing = [k for k in REQUIRED_PARAMS if params.get(k) is None]
            if missing:
                raise PlanError(f"{cid}: 隔离候选 base_params 缺 {missing}")
        else:
            params = {k: c.get(k) for k in REQUIRED_PARAMS}
            if c.get("extra_cflags"):
                params["extra_cflags"] = str(c["extra_cflags"])
        entries.append({
            "id": cid,
            "axis": c["axis"],
            "role": str(c.get("role", "CANDIDATE")),
            "desc": str(c.get("desc", "")),
            "params": params,
            "policy_path": c.get("_policy_path"),
            "recipe_path": os.path.join(recipes_dir, f"{cid}.yaml"),
            "runtime_path": os.path.join(run_dir, cid, "runtime.json"),
            "artifact_dir": os.path.join(run_dir, cid),
            "prefix": f"/opt/qw9/{cid}",
            "port": port,
            "status": "PENDING",
            "attempts": [],
            "notes": "",
        })
        port += 1

    state = {
        "schema": STATE_SCHEMA,
        "run_id": run_id,
        "plan_id": plan.id,
        "plan_sha": plan.hash,
        "created_at": time.strftime("%F %T"),
        "configure_args": plan.configure_args,
        "timeout_s": plan.timeout_s,
        "bin_name": plan.bin_name,
        "allocator": plan.allocator,
        "tarball": plan.tarball,
        "tarball_sha256": plan.tarball_sha256,
        "delivery": {
            "v2_axes": plan.v2_axes,
            "v3_preregistered": plan.v3_preregistered,
            "baseline_id": plan.baseline_id,
        },
        "candidates": entries,
    }
    save_run(run_dir, state)
    return run_dir, state


def run_dir_of(root, run_id):
    d = os.path.join(root, "artifacts", run_id)
    if not os.path.isdir(d):
        raise PlanError(f"run 目录不存在: {d}（先 qw9 gen expand）")
    return d


def load_run(root, run_id):
    p = os.path.join(run_dir_of(root, run_id), "state.json")
    with open(p, encoding="utf-8") as f:
        state = json.load(f)
    if state.get("schema") != STATE_SCHEMA:
        raise PlanError(f"state.json schema 不符: {state.get('schema')!r}")
    return state


def save_run(run_dir, state):
    state["updated_at"] = time.strftime("%F %T")
    p = os.path.join(run_dir, "state.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
