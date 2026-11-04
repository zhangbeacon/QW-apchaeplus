"""A1 · 交付：V2/V3 产物 + 选择理由 + 溯源清单；缺任一关键文件 → 不交付。

V3 取预注册的隔离候选（不经挑选，设计文档 §4.3）；溯源清单把
计划哈希、源码哈希、每候选配方哈希、产物哈希、分数文件哈希全部固化。
"""

import json
import os
import shutil
import subprocess

from ..domain import sha256_file
from . import plan as plan_mod, select as sel

COPY_FILES = ["manifest.json", "build.log", "runtime.json"]
ISO_EXTRA = ["policy.yaml", "isolate-verify.json", "isolate.log"]


class DeliverError(ValueError):
    pass


def _load_json(path):
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _cand_trace(entry):
    manifest = _load_json(os.path.join(entry["artifact_dir"], "manifest.json"))
    runtime = _load_json(os.path.join(entry["artifact_dir"], "runtime.json"))
    files = {f.get("path"): f.get("sha256") for f in manifest.get("files", [])}
    return {
        "id": entry["id"], "axis": entry["axis"], "params": entry["params"],
        "prefix": entry["prefix"], "port": entry["port"],
        "recipe_sha256": sha256_file(entry["recipe_path"]),
        "httpd_sha256": files.get("bin/httpd"),
        "toolchain": manifest.get("toolchain"),
        "cflags": manifest.get("cflags"),
        "allocator_env": runtime.get("env_overrides", {}),
    }


def deliver(root, run_id, scores_path, score_key="score", include_tree=False,
            out_root="delivery"):
    run_dir = plan_mod.run_dir_of(root, run_id)
    state = plan_mod.load_run(root, run_id)
    if not os.path.isabs(scores_path):
        scores_path = os.path.abspath(scores_path)
    if not os.path.isfile(scores_path):
        raise DeliverError(f"分数文件不存在: {scores_path}（评估 Agent 产出）")

    _scores_doc, scores_map = sel.load_scores(scores_path, score_key)
    pick = sel.pick_v2(state, scores_map, score_key)
    by_id = {e["id"]: e for e in state["candidates"]}

    v2_entry = by_id[pick["chosen"]["id"]]
    v3_id = state.get("delivery", {}).get("v3_preregistered")
    v3_entry = by_id.get(v3_id)
    if not v3_entry:
        raise DeliverError(f"预注册 V3 {v3_id!r} 不在候选中")
    if v3_entry["status"] != "VERIFIED":
        raise DeliverError(f"V3({v3_id}) 未通过完整性自检: {v3_entry['status']} → 不交付")

    out_dir = os.path.join(root, out_root, run_id)
    v2_dir, v3_dir = os.path.join(out_dir, "V2"), os.path.join(out_dir, "V3")
    os.makedirs(v2_dir, exist_ok=True)
    os.makedirs(v3_dir, exist_ok=True)

    missing = []
    for entry, dst, extra in ((v2_entry, v2_dir, []), (v3_entry, v3_dir, ISO_EXTRA)):
        for name in COPY_FILES + extra:
            src = os.path.join(entry["artifact_dir"], name)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(dst, name))
            elif name in ("manifest.json", "runtime.json"):
                missing.append(f"{entry['id']}/{name}")
        shutil.copy2(entry["recipe_path"],
                     os.path.join(dst, os.path.basename(entry["recipe_path"])))

    with open(os.path.join(v2_dir, "selection.md"), "w", encoding="utf-8") as f:
        f.write(sel.render_selection_md(pick, state, scores_path, score_key))

    if include_tree:
        for entry, dst in ((v2_entry, v2_dir), (v3_entry, v3_dir)):
            tar_path = os.path.join(dst, "install-tree.tar.gz")
            r = subprocess.run(
                ["tar", "czf", tar_path, "-C", os.path.dirname(entry["prefix"]),
                 os.path.basename(entry["prefix"])], capture_output=True, text=True)
            if r.returncode != 0:
                raise DeliverError(f"打包安装树失败: {r.stderr[:200]}")

    trace = {
        "schema": "qw9/traceability/v1",
        "run_id": state["run_id"],
        "plan_sha": state["plan_sha"],
        "source": {"package": state["tarball"], "sha256": state["tarball_sha256"]},
        "scores": {"path": scores_path, "sha256": sha256_file(scores_path),
                   "score_key": score_key, "note": "评估 Agent 产出，A1 只读"},
        "V2": {**_cand_trace(v2_entry), "selection": {
            "score": pick["chosen"]["score"],
            "runner_up": (pick["runner_up"] or {}).get("id"),
            "margin": pick["margin"],
            "risks": pick["risks"],
            "diff_axes_vs_baseline": pick["chosen"]["diff_axes"],
            "baseline_id": state.get("delivery", {}).get("baseline_id", "c1"),
        }},
        "V3": {**_cand_trace(v3_entry), "preregistered": True},
        "excluded": pick["rejected"],
    }
    with open(os.path.join(out_dir, "traceability.json"), "w", encoding="utf-8") as f:
        json.dump(trace, f, ensure_ascii=False, indent=2)

    if missing:
        raise DeliverError("缺关键文件，不交付: " + ", ".join(missing))
    index = {
        "schema": "qw9/delivery/v1",
        "run_id": run_id,
        "V2": {"candidate": v2_entry["id"], "prefix": v2_entry["prefix"], "dir": v2_dir},
        "V3": {"candidate": v3_entry["id"], "prefix": v3_entry["prefix"], "dir": v3_dir,
               "preregistered": True},
        "traceability": os.path.join(out_dir, "traceability.json"),
    }
    with open(os.path.join(out_dir, "delivery.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    return index
