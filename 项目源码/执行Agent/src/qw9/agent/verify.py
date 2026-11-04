"""A1 · 完整性自检（不是判分）。

只回答"造没造对"：二进制在不在、manifest 全不全、哈希对不对、
MPM DSO 在不在、非默认分配器的预加载机制是否真实可用、隔离自检是否通过。
缺项 → 判"建造无效"（INVALID），重跑该候选；性能好坏是评估 Agent 的事。
"""

import json
import os
import subprocess

from ..domain import sha256_file
from . import plan as plan_mod


def check_candidate(entry, state):
    prefix = entry["prefix"]
    art = entry["artifact_dir"]
    checks = []

    def add(what, ok, detail=""):
        checks.append({"what": what, "ok": bool(ok), "detail": str(detail)[:200]})

    bin_dir = os.path.join(prefix, "bin")
    has_bin = os.path.isdir(bin_dir) and any(
        os.path.isfile(os.path.join(bin_dir, x)) for x in os.listdir(bin_dir))
    add("binary_exists", has_bin, bin_dir)

    mp = os.path.join(art, "manifest.json")
    manifest = {}
    if os.path.isfile(mp):
        with open(mp, encoding="utf-8") as f:
            manifest = json.load(f)
    add("manifest_exists", bool(manifest), mp)

    mpm = entry["params"].get("mpm")
    if manifest:
        files = manifest.get("files", [])
        min_files = 2 if mpm else 1  # 非 Apache 目标（无 DSO）只要求主程序 1 个文件
        add("manifest_covers_modules", len(files) >= min_files,
            f"files={len(files)}/min={min_files}")
        by_path = {f.get("path"): f.get("sha256") for f in files}
        bin_files = [p for p in by_path if str(p).startswith("bin/")]
        if bin_files:
            try:
                ok = all(
                    os.path.isfile(os.path.join(prefix, rel))
                    and sha256_file(os.path.join(prefix, rel)) == by_path[rel]
                    for rel in bin_files)
                add("bin_sha_matches_manifest", ok, ",".join(bin_files))
            except OSError as e:
                add("bin_sha_matches_manifest", False, str(e))
        else:
            add("bin_sha_matches_manifest", False, "manifest 无 bin/ 条目")
        summary = manifest.get("summary", {})
        if str(entry["params"].get("harden")).lower() == "true":
            add("fortify_symbols_present", summary.get("fortify_files", 0) > 0,
                f"coverage={summary.get('fortify_coverage')}")
        if mpm:
            dso = os.path.join(prefix, "modules", f"mod_mpm_{mpm}.so")
            add("mpm_dso_present", os.path.isfile(dso), dso)
    else:
        add("manifest_covers_modules", False)
        add("bin_sha_matches_manifest", False)
        add("mpm_dso_present", False)

    alloc = str(entry["params"].get("allocator", "ptmalloc"))
    if alloc != "ptmalloc":
        lib = (state.get("allocator") or {}).get(alloc, "")
        add("allocator_lib_declared", bool(lib), lib)
        if lib:
            found = _find_lib(lib)
            add("allocator_lib_found", bool(found), found or "ldconfig/常见目录未找到")
            add("allocator_preload_works", _preload_smoke(lib),
                f"LD_PRELOAD={lib} 下 /proc/self/maps 未见该库")
    else:
        add("allocator_default", True, "ptmalloc 无需预加载")

    if entry["axis"] == "isolation":
        iv = os.path.join(art, "isolate-verify.json")
        ok = False
        if os.path.isfile(iv):
            with open(iv, encoding="utf-8") as f:
                ok = bool(json.load(f).get("ok"))
        add("isolation_selfcheck_ok", ok, iv)
    return checks


def _find_lib(name):
    try:
        r = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, timeout=20)
        if name in (r.stdout or ""):
            return name
    except (OSError, subprocess.TimeoutExpired):
        pass
    for d in ("/usr/lib/x86_64-linux-gnu", "/usr/lib", "/usr/local/lib"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return ""


def _preload_smoke(lib):
    """进程级实证：LD_PRELOAD 起一个进程，看它自己的内存映射里有没有这个库。"""
    env = {"LD_PRELOAD": lib, "PATH": "/usr/bin:/bin"}
    try:
        r = subprocess.run(["/bin/cat", "/proc/self/maps"], env=env,
                           capture_output=True, text=True, timeout=20)
        return os.path.basename(lib) in (r.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_verify(root, run_id):
    run_dir = plan_mod.run_dir_of(root, run_id)
    state = plan_mod.load_run(root, run_id)
    report = {}
    for entry in state["candidates"]:
        if entry["status"] not in ("BUILT", "VERIFIED", "INVALID"):
            continue
        checks = check_candidate(entry, state)
        ok = all(c["ok"] for c in checks)
        entry["status"] = "VERIFIED" if ok else "INVALID"
        if not ok:
            entry["reason"] = "完整性自检未过: " + "; ".join(
                c["what"] for c in checks if not c["ok"])
        report[entry["id"]] = {"ok": ok, "checks": checks}
        plan_mod.save_run(run_dir, state)
    with open(os.path.join(run_dir, "verify.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "qw9/genverify/v1", "run_id": run_id,
                   "candidates": report}, f, ensure_ascii=False, indent=2)
    return report
