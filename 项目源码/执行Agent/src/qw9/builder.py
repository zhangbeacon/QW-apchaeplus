"""构建执行器：干净源码树 → configure/make/make install → 产物清单（manifest）。

工程纪律（对应实现方案 §5）：
1. 每次构建从 tarball 重新解压，绝不复用 Makefile / .o；
2. 记录并校验 bin/httpd 与全部 modules/*.so（漏洞代码在 DSO 里）；
3. FORTIFY 必须实证（readelf 查 __*_chk 符号），不接受"加了宏就算加固"；
4. 前缀删除有安全护栏：只允许 /opt/qw9*、/opt/httpd*；
5. 同配方重复构建可比对产物哈希（可重复性验收）。
"""

import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import time

from . import domain
from .domain import Recipe, SpecError

# 允许 /opt/qw9、/opt/qw9/v1、/opt/qw9/d1 等多段前缀；仍锁死 /opt/qw9*、/opt/httpd* 开头
ALLOWED_PREFIX_RE = re.compile(r"^/opt/(qw9|httpd)(/[A-Za-z0-9_-]+)*/?$")


class BuildError(RuntimeError):
    pass


def _log_run(cmd, cwd, env, logh, check=True, timeout=None):
    pretty = " ".join(shlex.quote(c) for c in cmd)
    logh.write(f"\n+ {pretty}\n")
    logh.flush()
    try:
        r = subprocess.run(cmd, cwd=cwd, env=env,
                           stdout=logh, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        logh.write(f"\n!! TIMEOUT after {timeout}s: {pretty}\n")
        raise BuildError(f"命令超时（{timeout}s）: {pretty}")
    if check and r.returncode != 0:
        raise BuildError(f"命令失败 (exit {r.returncode}): {pretty}（详见 build.log）")


def check_toolchain(recipe):
    """返回 (cc_path, version_str)；版本低于配方要求时报错。"""
    r = subprocess.run([recipe.cc, "--version"], capture_output=True, text=True)
    if r.returncode != 0:
        raise BuildError(f"编译器不可用: {recipe.cc}")
    first = (r.stdout or r.stderr).splitlines()[0].strip()
    m = re.search(r"(\d+)\.(\d+)", first)
    major = int(m.group(1)) if m else 0
    need = int(str(recipe.cc_min_version).split(".")[0]) or 0
    if major < need:
        raise BuildError(
            f"{recipe.cc} 版本 {major} 低于配方要求 {need}（{first}）")
    return shutil.which(recipe.cc) or recipe.cc, first


def _safe_wipe_prefix(prefix):
    if not ALLOWED_PREFIX_RE.match(prefix):
        raise BuildError(
            f"拒绝删除非白名单前缀 {prefix}（只允许 /opt/qw9*、/opt/httpd*）")
    if os.path.isdir(prefix):
        shutil.rmtree(prefix)


def _extract_tarball(recipe, tree):
    if os.path.isdir(tree):
        shutil.rmtree(tree)
    os.makedirs(tree)
    tar = shutil.which("tar") or "/bin/tar"
    with open(os.devnull, "w") as devnull:
        r = subprocess.run(
            [tar, "xzf", recipe.tarball, "-C", tree, "--strip-components=1"],
            stdout=devnull, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise BuildError(f"tar 解压失败: {r.stderr.strip()[:400]}")


def _readelf_out(path, args):
    r = subprocess.run(["readelf", "-W", *args, path],
                       capture_output=True, text=True)
    return r.stdout or ""


def inspect_artifact(path, rel):
    """单文件指纹：sha256、大小、编译器注释、FORTIFY 符号、栈保护。"""
    out = {
        "path": rel,
        "sha256": domain.sha256_file(path),
        "size": os.path.getsize(path),
        "fortify": [],
        "stack_guard": False,
        "comment": "",
    }
    syms = _readelf_out(path, ["-s"])
    out["fortify"] = sorted(set(re.findall(r"__[A-Za-z0-9_]+_chk\b", syms)))
    out["stack_guard"] = "__stack_chk_fail" in syms
    comment = _readelf_out(path, ["-p", ".comment"])
    out["comment"] = " / ".join(
        l.strip() for l in comment.splitlines()
        if "clang version" in l or "GCC:" in l or "gcc version" in l)[:200]
    return out


def collect_manifest(recipe, cc_path, cc_version, configure_cmd, env):
    files = [os.path.join(recipe.prefix, "bin", recipe.bin_name)]
    files += sorted(glob.glob(os.path.join(recipe.prefix, "modules", "*.so")))
    if not os.path.isfile(files[0]):
        raise BuildError(f"主程序缺失: {files[0]}")
    entries = []
    for f in files:
        if os.path.isfile(f):
            entries.append(inspect_artifact(f, os.path.relpath(f, recipe.prefix)))
    fortify_files = sum(1 for e in entries if e["fortify"])
    return {
        "schema": "qw9/manifest/v1",
        "recipe_id": recipe.id,
        "recipe_hash": recipe.hash,
        "source": {"package": recipe.tarball, "sha256": recipe.tarball_sha256},
        "toolchain": {"cc": cc_path, "version": cc_version},
        "cflags": recipe.cflags,
        "ldflags": recipe.ldflags,
        "configure": {"cmd": configure_cmd, "env": env},
        "prefix": recipe.prefix,
        "built_at_epoch": int(time.time()),
        "files": entries,
        "summary": {
            "files_total": len(entries),
            "fortify_files": fortify_files,
            "fortify_coverage": round(fortify_files / max(1, len(entries)), 3),
        },
    }


def build(recipe, artifacts_dir, cc_override=None, jobs=None, log_name="build.log",
          timeout_s=None):
    """执行一次完整构建，写 manifest.json，返回 manifest。timeout_s 为每步命令超时。"""
    os.makedirs(artifacts_dir, exist_ok=True)
    cc = cc_override or recipe.cc
    cc_path, cc_version = check_toolchain(
        Recipe({**recipe.raw, "toolchain": {**recipe.raw["toolchain"], "cc": cc}},
               recipe.path))

    actual_sha = domain.sha256_file(recipe.tarball)
    if actual_sha != recipe.tarball_sha256:
        raise BuildError(
            f"tarball sha256 不匹配：期望 {recipe.tarball_sha256}，实际 {actual_sha}")

    tree = os.path.join(recipe.workroot, f"{recipe.id}-src")
    os.makedirs(recipe.workroot, exist_ok=True)
    _extract_tarball(recipe, tree)

    cflags = recipe.cflags.replace("{SRC}", tree)
    ldflags = recipe.ldflags
    env = dict(os.environ)
    env.update({
        "CC": cc,
        "CFLAGS": cflags,
        "LDFLAGS": ldflags,
    })
    env.update(recipe.configure_env)

    configure_cmd = ["./configure", f"--prefix={recipe.prefix}", *recipe.configure_args]
    njobs = str(jobs or recipe.jobs)

    log_path = os.path.join(artifacts_dir, log_name)
    with open(log_path, "a", encoding="utf-8") as logh:
        logh.write(f"\n===== qw9 build recipe={recipe.id} prefix={recipe.prefix} "
                   f"time={time.strftime('%F %T')} =====\n")
        _safe_wipe_prefix(recipe.prefix)  # 白名单校验后删除旧前缀（防误删）
        _log_run(configure_cmd, tree, env, logh, timeout=timeout_s)
        _log_run(["make", f"-j{njobs}"], tree, env, logh, timeout=timeout_s)
        _log_run(["make", "install"], tree, env, logh, timeout=timeout_s)

    manifest = collect_manifest(recipe, cc_path, cc_version,
                                " ".join(shlex.quote(c) for c in configure_cmd),
                                {k: env[k] for k in recipe.configure_env})
    if recipe.require_fortify and manifest["summary"]["fortify_files"] == 0:
        raise BuildError(
            "require_fortify=true 但没有任何产物含 __*_chk 符号——"
            "FORTIFY 未生效，禁止宣称整栈加固")

    with open(os.path.join(artifacts_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest


def repro_check(recipe, artifacts_dir, times=2):
    """同配方构建 times 次，比对逐文件哈希；返回 {equal, diffs, reports}。"""
    if times < 2:
        raise SpecError("repro 至少 2 次")
    reports = []
    hashes = []
    for i in range(times):
        prefix = recipe.prefix if i == 0 else f"{recipe.prefix}-repro{i}"
        r2 = Recipe({**recipe.raw,
                     "install": {**recipe.raw["install"], "prefix": prefix}},
                    recipe.path)
        m = build(r2, artifacts_dir,
                  log_name=f"build-repro{i}.log")
        hashes.append({e["path"]: e["sha256"] for e in m["files"]})
        reports.append(m["summary"])
    equal = all(h == hashes[0] for h in hashes[1:])
    diffs = []
    if not equal:
        keys = sorted(set().union(*[set(h) for h in hashes]))
        for k in keys:
            vals = [h.get(k) for h in hashes]
            if len(set(vals)) > 1:
                diffs.append({"path": k, "hashes": vals})
    result = {"recipe": recipe.id, "times": times, "equal": equal,
              "diffs": diffs, "reports": reports}
    with open(os.path.join(artifacts_dir, "repro.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    # 清理重复构建占用的第二前缀
    for i in range(1, times):
        p = f"{recipe.prefix}-repro{i}"
        if ALLOWED_PREFIX_RE.match(p) and os.path.isdir(p):
            shutil.rmtree(p)
    return result
