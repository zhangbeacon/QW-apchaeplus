"""领域对象：Recipe（变体配方）、IsolationPolicy（隔离策略）、BusinessContract（业务契约）、
Verdict（判定结果）与轴表达式求值。

只依赖 stdlib + PyYAML；不做任何进程操作（那是 builder/isolator/runner 的事）。
"""

import hashlib
import json
import os
import re

class SpecError(ValueError):
    """规格文件不合法。"""


# ---------------------------------------------------------------- 基础工具

def load_yaml(path):
    import yaml  # 延迟导入，便于给出清晰安装提示
    if not os.path.isfile(path):
        raise SpecError(f"YAML 不存在: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:  # pragma: no cover
        raise SpecError(f"YAML 解析失败 {path}: {e}") from e


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def canonical_hash(obj):
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _abspath(p, base):
    p = str(p)
    if not os.path.isabs(p):
        p = os.path.normpath(os.path.join(base, p))
    return os.path.normpath(p)


# ---------------------------------------------------------------- Recipe

_ROLES = {"BASELINE", "CANDIDATE", "CONTROL"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class Recipe:
    """一份变体构建配方。字段经过校验；policy_path 可指向隔离策略（V3）。"""

    KEYS_REQUIRED = ("metadata", "source", "toolchain", "configure", "install")

    def __init__(self, data, path):
        if not isinstance(data, dict):
            raise SpecError("recipe 根节点必须是映射")
        missing = [k for k in self.KEYS_REQUIRED if k not in data]
        if missing:
            raise SpecError(f"recipe 缺少字段: {missing}")
        base = os.path.dirname(os.path.abspath(path))

        meta = data["metadata"]
        self.id = meta.get("id", "")
        if not _ID_RE.match(self.id or ""):
            raise SpecError(f"metadata.id 非法: {self.id!r}（需匹配 {_ID_RE.pattern}）")
        self.role = meta.get("role", "")
        if self.role not in _ROLES:
            raise SpecError(f"metadata.role 必须是 {_ROLES} 之一，得到 {self.role!r}")
        self.description = meta.get("description", "")

        src = data["source"]
        self.tarball = _abspath(src.get("package", ""), base)
        self.tarball_sha256 = str(src.get("sha256", "")).lower()
        if not _SHA_RE.match(self.tarball_sha256):
            raise SpecError("source.sha256 必须是 64 位十六进制")
        if not os.path.isfile(self.tarball):
            raise SpecError(f"source.package 不存在: {self.tarball}")

        tc = data["toolchain"]
        self.cc = tc.get("cc", "gcc")
        self.cc_min_version = str(tc.get("cc_min_version", "0"))

        flags = data.get("flags") or {}
        self.cflags = flags.get("cflags", "-O2 -g")
        self.ldflags = flags.get("ldflags", "")

        conf = data["configure"]
        self.configure_args = [str(a) for a in (conf.get("args") or [])]
        env = conf.get("env") or {}
        self.configure_env = {str(k): str(v) for k, v in env.items()}

        inst = data["install"]
        self.prefix = os.path.normpath(str(inst.get("prefix", "")))
        if not (self.prefix.startswith("/opt/") or self.prefix.startswith("/usr/local/")):
            raise SpecError(
                f"install.prefix 必须位于 /opt/ 或 /usr/local/ 之下（安全护栏），得到 {self.prefix}")
        self.workroot = str(inst.get("workroot", "/root/work/qw9"))
        self.bin_name = str(inst.get("bin", "httpd"))  # 非 Apache 目标可自定义可执行名

        self.jobs = int((data.get("build") or {}).get("jobs", 4))

        verify = data.get("verify") or {}
        self.require_fortify = bool(verify.get("require_fortify", False))

        iso = data.get("isolation")
        self.isolation_ref = str(iso) if iso else None

        self.raw = data
        self.path = os.path.abspath(path)
        self.hash = canonical_hash(data)

    @classmethod
    def load(cls, path):
        return cls(load_yaml(path), path)

    def policy_path(self):
        if not self.isolation_ref:
            return None
        return _abspath(self.isolation_ref, os.path.dirname(self.path))


# ---------------------------------------------------------------- IsolationPolicy

class IsolationPolicy:
    """V3 的声明式资源边界：UID、业务可读目录、可写目录、UDS 白名单、root-only 标记。"""

    def __init__(self, data, path):
        if not isinstance(data, dict):
            raise SpecError("policy 根节点必须是映射")
        rt = data.get("runtime") or {}
        self.user = rt.get("user", "")
        self.group = rt.get("group", "")
        if not re.match(r"^[a-z_][a-z0-9_-]*$", self.user or ""):
            raise SpecError(f"runtime.user 非法: {self.user!r}")
        if not re.match(r"^[a-z_][a-z0-9_-]*$", self.group or ""):
            raise SpecError(f"runtime.group 非法: {self.group!r}")
        self.server_root = os.path.normpath(str(rt.get("server_root", "")))
        if not self.server_root.startswith("/opt/"):
            raise SpecError("runtime.server_root 必须位于 /opt/ 之下")

        # 业务可读/可写：允许相对 server_root
        self.readable = [_abspath(p, self.server_root)
                         for p in (data.get("business_readable") or [])]
        self.writable = [_abspath(p, self.server_root)
                         for p in (data.get("writable") or [])]

        uds = data.get("uds") or {}
        self.uds_allowed_dir = _abspath(uds.get("allowed_dir", ""), self.server_root) \
            if uds.get("allowed_dir") else None
        self.uds_blocked_dir = _abspath(uds.get("blocked_dir", ""), "/") \
            if uds.get("blocked_dir") else None

        markers = []
        for m in (data.get("markers") or []):
            mp = os.path.normpath(str(m.get("path", "")))
            if not mp.startswith("/opt/"):
                raise SpecError(f"markers.path 必须位于 /opt/ 之下: {mp}")
            markers.append({
                "path": mp,
                "content": str(m.get("content", "QW9_MARKER\n")),
                "mode": str(m.get("mode", "0600")),
            })
        self.markers = markers
        self.raw = data
        self.hash = canonical_hash(data)

    @classmethod
    def load(cls, path):
        return cls(load_yaml(path), path)

    def httpd_user_block(self):
        """插入 httpd.conf 的 User/Group 指令（需在 unixd_module 之后）。"""
        return f"User {self.user}\nGroup {self.group}\n"


# ---------------------------------------------------------------- BusinessContract

class BusinessContract:
    """V1/V2/V3 必须同时满足的正常业务能力清单（G2 功能一致性门的数据源）。"""

    def __init__(self, data, path):
        caps = (data or {}).get("capabilities") or []
        if not caps:
            raise SpecError("capabilities 不能为空")
        self.capabilities = []
        for c in caps:
            req = c.get("request") or {}
            exp = c.get("expect") or {}
            self.capabilities.append({
                "id": c.get("id", ""),
                "desc": c.get("desc", ""),
                "method": str(req.get("method", "GET")),
                "path": str(req.get("path", "/")),
                "data": req.get("data"),
                "content_type": req.get("content_type"),
                "via_proxy": bool(req.get("via_proxy", False)),
                "keepalive_paths": list(req.get("keepalive_paths") or []),
                "status": int(exp.get("status", 200)),
                "body_contains": str(exp.get("body_contains", "")),
            })
        self.hash = canonical_hash(data)

    @classmethod
    def load(cls, path):
        return BusinessContract(load_yaml(path), path)


# ---------------------------------------------------------------- Verdict

VALIDITY = {"VALID", "INVALID", "NOT_RUN"}
GOALS = {"GOAL_REACHED", "GOAL_NOT_OBSERVED", "INCONCLUSIVE"}


def make_verdict(run_id, cve, variant, validity, goal_outcome, phenotypes,
                 axes, evidence, oracle_version, notes=""):
    if validity not in VALIDITY:
        raise SpecError(f"validity 非法: {validity}")
    if goal_outcome not in GOALS:
        raise SpecError(f"goal_outcome 非法: {goal_outcome}")
    return {
        "schema": "qw9/verdict/v1",
        "run_id": run_id,
        "cve": cve,
        "variant": variant,
        "validity": validity,
        "goal_outcome": goal_outcome,
        "phenotypes": sorted(set(phenotypes)),
        "axes": dict(axes),
        "evidence": list(evidence),
        "oracle_version": oracle_version,
        "notes": notes,
    }


def write_verdict(out_dir, verdict):
    os.makedirs(out_dir, exist_ok=True)
    p = os.path.join(out_dir, "verdict.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(verdict, f, ensure_ascii=False, indent=2)
    return p


# ---------------------------------------------------------------- 轴表达式

_EXPR_RE = re.compile(r'^[\w\s()=!<>|&"\']+$')
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {"and", "or", "not", "in", "is", "True", "False", "None"}


def eval_axis_expr(expr, axes):
    """受限表达式求值：仅允许轴变量与 ==/!=/and/or/not/括号。

    未出现的轴按 0 处理（适配器没输出的轴视为假），避免拼写差异导致崩溃。
    """
    if not isinstance(expr, str) or not _EXPR_RE.match(expr):
        raise SpecError(f"非法轴表达式: {expr!r}")
    scope = {k: (1 if v in (True, "1", 1) else 0 if v in (False, "0", "", 0, None) else v)
             for k, v in axes.items()}
    for name in set(_IDENT_RE.findall(expr)) - _KEYWORDS:
        scope.setdefault(name, 0)
    try:
        return bool(eval(expr, {"__builtins__": {}}, scope))  # noqa: S307 — 受限词表
    except Exception as e:  # pragma: no cover
        raise SpecError(f"轴表达式求值失败 {expr!r}: {e}") from e


def parse_adapter_axes(stdout_text):
    """从适配器 stdout 解析 `key=value` 行（值中允许非空白字符）。"""
    axes = {}
    for line in (stdout_text or "").splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            axes[m.group(1)] = m.group(2).strip()
    return axes
