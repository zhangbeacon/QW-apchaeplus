"""A1 · 配方展开：模板(@@TOKEN@@) + 参数 → 每候选一份 recipe.yaml + runtime.json。

模板占位用 @@TOKEN@@（避免与 YAML 花括号、builder 的 {SRC} 运行时记号冲突）。
隔离候选额外生成"落地版 policy"（server_root 改写为该候选自己的前缀）。
展开时即用 Recipe 构造器做 schema 校验——非法策略在展开阶段就挡下（schema 安全带）。
"""

import copy
import json
import os

import yaml

from ..domain import Recipe, SpecError, load_yaml
from . import plan as plan_mod

TEMPLATE_PATH = "recipes/template.yaml"


class ExpandError(SpecError):
    pass


def _cflags_ldflags(params):
    cflags = "-" + str(params["opt"]) + " -g -ffile-prefix-map=" + "{SRC}" + "=."
    if str(params["harden"]).lower() == "true":
        cflags += " -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2"
        ldflags = "-pie -Wl,-z,relro,-z,now"
        require_fortify = "true"
    else:
        ldflags = ""
        require_fortify = "false"
    return cflags, ldflags, require_fortify


def _render(tpl_text, tokens):
    out = tpl_text
    for k, v in tokens.items():
        out = out.replace("@@" + k + "@@", str(v))
    if "@@" in out:
        left = sorted(set(out.split("@@")[1::2]))
        raise ExpandError(f"模板存在未替换占位符: {left}")
    return out


def expand_one(tpl_text, entry, state):
    """生成单候选 recipe 文本，并用 Recipe 构造器做 schema 校验（不落盘）。"""
    params = entry["params"]
    missing = [k for k in plan_mod.REQUIRED_PARAMS if params.get(k) is None]
    if missing:
        raise ExpandError(f"{entry['id']}: 参数不全，缺 {missing}")
    cflags, ldflags, require_fortify = _cflags_ldflags(params)
    extra = str(params.get("extra_cflags", "") or "").strip()
    if extra:
        cflags += " " + extra
    tokens = {
        "ID": entry["id"],
        "ROLE": entry["role"],
        "AXIS": entry["axis"],
        "DESC": entry.get("desc", ""),
        "TARBALL": state["tarball"],
        "SHA": state["tarball_sha256"],
        "CC": params["cc"],
        "CFLAGS": cflags,
        "LDFLAGS": ldflags,
        "CONFIGURE_ARGS": json.dumps(state["configure_args"]),
        "PREFIX": entry["prefix"],
        "REQUIRE_FORTIFY": require_fortify,
        "BIN": state.get("bin_name", "httpd"),
    }
    recipe_text = _render(tpl_text, tokens)
    Recipe(yaml.safe_load(recipe_text), entry["recipe_path"] + ".preview")
    return recipe_text


def runtime_dict(entry, state):
    """启动说明：前缀、端口、MPM、分配器预加载环境（打靶时由 runner 消费）。"""
    allocator = str(entry["params"].get("allocator", "ptmalloc"))
    env_overrides = {}
    if allocator != "ptmalloc":
        lib = (state.get("allocator") or {}).get(allocator, "")
        if not lib:
            raise ExpandError(
                f"{entry['id']}: 非默认分配器 {allocator} 需在 plan.allocator.{allocator} 声明预加载库")
        env_overrides["LD_PRELOAD"] = lib
    return {
        "schema": "qw9/runtime/v1",
        "candidate": entry["id"],
        "prefix": entry["prefix"],
        "port": entry["port"],
        "mpm": entry["params"].get("mpm"),
        "allocator": allocator,
        "env_overrides": env_overrides,
    }


def _emit_policy(entry, runtime):
    """隔离候选：读策略模板 → server_root 改写为该候选前缀 → artifact_dir/policy.yaml。"""
    raw = copy.deepcopy(load_yaml(entry["policy_path"]))
    raw.setdefault("runtime", {})["server_root"] = runtime["prefix"]
    out = os.path.join(entry["artifact_dir"], "policy.yaml")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(raw, f, allow_unicode=True, sort_keys=False)
    entry["policy_effective_path"] = out


def run_expand(root, run_id):
    st_dir = plan_mod.run_dir_of(root, run_id)
    state = plan_mod.load_run(root, run_id)
    tpl_path = os.path.join(root, TEMPLATE_PATH)
    if not os.path.isfile(tpl_path):
        raise ExpandError(f"配方模板不存在: {tpl_path}")
    with open(tpl_path, encoding="utf-8") as f:
        tpl_text = f.read()

    for entry in state["candidates"]:
        recipe_text = expand_one(tpl_text, entry, state)
        os.makedirs(os.path.dirname(entry["recipe_path"]), exist_ok=True)
        with open(entry["recipe_path"], "w", encoding="utf-8", newline="\n") as f:
            f.write(recipe_text)
        os.makedirs(entry["artifact_dir"], exist_ok=True)
        rt = runtime_dict(entry, state)
        with open(entry["runtime_path"], "w", encoding="utf-8") as f:
            json.dump(rt, f, ensure_ascii=False, indent=2)
        if entry["axis"] == "isolation":
            _emit_policy(entry, rt)
        entry["status"] = "EXPANDED"
    plan_mod.save_run(st_dir, state)
    return state
