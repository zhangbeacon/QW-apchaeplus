"""A1 · 构建编排：逐候选 build →（隔离类）isolate → 落 artifacts。

失败处理（设计文档 §5）：
- 只允许因"环境/构建问题"重试，上限 3 次；每次重试记录原因与改动；
- 隔离装不上 → BLOCKED，不降级、不跳过、必须报告；
- 不允许因"结果不好看"重跑（本模块没有打分能力，天然杜绝）。
"""

import json
import os
import re
import time

from .. import builder, isolator
from ..domain import Recipe
from . import plan as plan_mod

MAX_ATTEMPTS = 3

# 构建日志尾部的错误签名 → (故障类, 是否可重试, 处置动作)
RULES = [
    (r"No space left on device", "disk_full", True, "cleanup"),
    (r"Cannot allocate memory|virtual memory exhausted|out of memory|Killed signal",
     "oom", True, "lower_jobs"),
    (r"error: unrecognized|invalid option|unknown option", "bad_config", False, None),
    (r"timed out|Timeout expired|TIMEOUT", "timeout", True, "lower_jobs"),
    (r"Could not get lock|dpkg lock|E: Unable to locate package", "deps", True, "hint_deps"),
]


def classify_tail(tail_text):
    for pattern, fault, retryable, action in RULES:
        if re.search(pattern, tail_text):
            return fault, retryable, action
    return "unknown", True, None


def _tail(path, n=200):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return ""


def _cleanup_run_logs(run_dir):
    """disk_full 处置：裁掉本 run 里超过 64MB 的旧日志（留空壳注明轮转）。"""
    if not os.path.isdir(run_dir):
        return
    for dirpath, _dirs, files in os.walk(run_dir):
        for name in files:
            if not name.endswith(".log"):
                continue
            p = os.path.join(dirpath, name)
            try:
                if os.path.getsize(p) > 64 << 20:
                    os.rename(p, p + f".trimmed-{int(time.time())}")
                    with open(p, "w", encoding="utf-8") as f:
                        f.write("(rotated by A1 disk_full cleanup)\n")
            except OSError:
                pass


def build_candidate(entry, state, jobs):
    artifact_dir = entry["artifact_dir"]
    timeout_s = int(state.get("timeout_s", 1800))
    jobs_cur = max(1, int(jobs))
    attempts = []
    disk_cleaned = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            recipe = Recipe.load(entry["recipe_path"])
            manifest = builder.build(recipe, artifact_dir, jobs=jobs_cur,
                                     timeout_s=timeout_s, log_name="build.log")
            attempts.append({"attempt": attempt, "result": "ok", "jobs": jobs_cur})
            return {"status": "BUILT", "attempts": attempts, "jobs_final": jobs_cur}
        except builder.BuildError as e:
            tail = _tail(os.path.join(artifact_dir, "build.log"))
            fault, retryable, action = classify_tail(tail)
            if fault == "unknown" and attempt >= 2:
                retryable = False  # unknown 只盲重试一次，不做无意义的三连撞
            attempts.append({"attempt": attempt, "result": "fail", "fault": fault,
                             "action": action or "none", "err": str(e)[:200]})
            if not retryable or attempt == MAX_ATTEMPTS:
                break
            if action == "lower_jobs":
                jobs_cur = max(1, jobs_cur // 2)
            elif action == "cleanup" and not disk_cleaned:
                _cleanup_run_logs(os.path.dirname(artifact_dir))
                disk_cleaned = True
            elif action == "hint_deps":
                time.sleep(30)
    fault = attempts[-1].get("fault", "unknown") if attempts else "unknown"
    return {"status": "BLOCKED", "attempts": attempts, "fault": fault,
            "reason": f"构建失败（{fault}），达重试上限或不可重试"}


def run_build(root, run_id, jobs=4, only=None):
    run_dir = plan_mod.run_dir_of(root, run_id)
    state = plan_mod.load_run(root, run_id)
    summary = []
    for entry in state["candidates"]:
        if only and entry["id"] not in only:
            continue
        if entry["status"] in ("BLOCKED", "BUILT", "VERIFIED"):
            summary.append({"id": entry["id"], "status": entry["status"],
                            "attempts": len(entry["attempts"]), "skipped": True})
            continue
        t0 = time.time()
        res = build_candidate(entry, state, jobs)
        entry["status"] = res["status"]
        entry["attempts"] = res["attempts"]
        entry["build_seconds"] = round(time.time() - t0, 1)
        if res["status"] == "BUILT" and entry["axis"] == "isolation":
            try:
                pol_path = entry.get("policy_effective_path") or entry.get("policy_path")
                policy = isolator.IsolationPolicy.load(pol_path)
                checks = isolator.apply(policy, entry["artifact_dir"])
                entry["isolation_ok"] = bool(checks.get("ok"))
                entry["notes"] = "隔离已装并自检" if checks.get("ok") else "隔离自检未全过"
                if not checks.get("ok"):
                    entry["status"] = "BLOCKED"
                    entry["reason"] = "隔离自检未全过（见 isolate-verify.json）——BLOCKED 不降级"
            except isolator.IsolateError as e:
                entry["status"] = "BLOCKED"
                entry["reason"] = f"隔离装不上: {e}——BLOCKED 不降级"
        elif res["status"] == "BLOCKED":
            entry["reason"] = res.get("reason", "")
        summary.append({"id": entry["id"], "status": entry["status"],
                        "attempts": len(entry["attempts"]), "seconds": entry["build_seconds"]})
        plan_mod.save_run(run_dir, state)  # 每候选落盘，崩溃可续跑
    with open(os.path.join(run_dir, "builds.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "qw9/builds/v1", "run_id": run_id, "results": summary},
                  f, ensure_ascii=False, indent=2)
    return summary
