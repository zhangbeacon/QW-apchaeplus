"""V3 隔离执行器：把声明式 IsolationPolicy 落成 UID/权限/markers/UDS 目录。

边界（对应实现方案 §4.2）：
- 这是"后果抑制"，不是修复——报告措辞必须是"利用受抑制/后果受限"；
- 必须保留业务可读目录（功能一致性），只收紧 root-only 标记与 UDS 目录；
- 只在 Linux 文件系统（/opt）上操作：drvfs（/mnt/*）不支持 chmod/chown。
"""

import json
import os
import subprocess
import time

from .domain import IsolationPolicy, SpecError


class IsolateError(RuntimeError):
    pass


def _render_setup(policy: IsolationPolicy):
    """生成幂等的落地脚本（bash，root 执行）。"""
    dirs_business = " ".join(f'"{p}"' for p in policy.readable)
    dirs_writable = " ".join(f'"{p}"' for p in policy.writable)
    marker_cmds = []
    for m in policy.markers:
        marker_cmds.append(
            f'mkdir -p "$(dirname "{m["path"]}")"\n'
            f'printf %s "{m["content"]}" > "{m["path"]}"\n'
            f'chown root:root "{m["path"]}"\n'
            f'chmod {m["mode"]} "{m["path"]}"\n')
    markers = "\n".join(marker_cmds)

    uds_allowed = policy.uds_allowed_dir or ""
    uds_blocked = policy.uds_blocked_dir or ""

    return f"""#!/usr/bin/env bash
# 由 qw9 isolator 生成——请勿手改；重跑幂等。
set -euo pipefail

USER_N="{policy.user}"
GROUP_N="{policy.group}"
SRV="{policy.server_root}"

# 1) 账号（幂等）
getent group "{policy.group}" >/dev/null || groupadd -r "{policy.group}"
id -u "$USER_N" >/dev/null 2>&1 || \\
  useradd -r -g "$GROUP_N" -d "$SRV" -s /usr/sbin/nologin "$USER_N"

# 2) 目录骨架
mkdir -p "$SRV" {dirs_business} {dirs_writable}
[ -n "{uds_allowed}" ] && mkdir -p "{uds_allowed}" || true
[ -n "{uds_blocked}" ] && mkdir -p "{uds_blocked}" || true

# 3) 业务可读目录：root 属主 + 全员可读执行（功能一致性所需）
for d in {dirs_business}; do chown root:root "$d"; chmod a+rx "$d"; done
# 可写目录：变体用户属主（logs/run/cgid socket/UDS）
for d in {dirs_writable}; do chown "$USER_N:$GROUP_N" "$d"; chmod 750 "$d"; done

# 4) UDS：白名单目录组可达；封锁目录仅 root
[ -n "{uds_allowed}" ] && {{ chown root:"$GROUP_N" "{uds_allowed}"; chmod 750 "{uds_allowed}"; }}
[ -n "{uds_blocked}" ] && {{ chown root:root "{uds_blocked}"; chmod 700 "{uds_blocked}"; }}

# 5) root-only 标记（差异观测点：V1 root 可读 / V3 非 root 不可读）
{markers}

echo ISOLATE_OK user=$USER_N root=$SRV
"""


def apply(policy: IsolationPolicy, artifacts_dir: str):
    """root 校验 → 生成并执行 setup → 可达性自检 → isolate-verify.json。"""
    if os.geteuid() != 0:
        raise IsolateError("isolate 需要 root（httpd 主进程也要 root 才能 setuid）")

    os.makedirs(artifacts_dir, exist_ok=True)
    script = _render_setup(policy)
    script_path = os.path.join(artifacts_dir, "isolate-setup.sh")
    with open(script_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(script)
    os.chmod(script_path, 0o755)

    log_path = os.path.join(artifacts_dir, "isolate.log")
    with open(log_path, "a", encoding="utf-8") as logh:
        logh.write(f"\n===== qw9 isolate time={time.strftime('%F %T')} =====\n")
        r = subprocess.run(["bash", script_path], stdout=logh,
                           stderr=subprocess.STDOUT)
    if r.returncode != 0:
        raise IsolateError(f"isolate-setup.sh 失败 (exit {r.returncode})，见 {log_path}")

    checks = verify_access(policy)
    with open(os.path.join(artifacts_dir, "isolate-verify.json"), "w",
              encoding="utf-8") as f:
        json.dump(checks, f, ensure_ascii=False, indent=2)
    return checks


def _run_as(user, cmd):
    return subprocess.run(["su", "-s", "/bin/sh", "-c", cmd, user],
                          capture_output=True, text=True).returncode


def verify_access(policy: IsolationPolicy):
    """以变体用户身份验证：业务目录可读、root-only 标记不可读、UDS 目录权限正确。"""
    checks = []
    for d in policy.readable:
        checks.append({"what": "business_readable", "target": d,
                       "expect": "readable", "ok": _run_as(policy.user, f"test -r '{d}'") == 0})
    for m in policy.markers:
        checks.append({"what": "marker_unreadable", "target": m["path"],
                       "expect": "denied", "ok": _run_as(policy.user, f"test -r '{m['path']}'") != 0})
    if policy.uds_blocked_dir:
        checks.append({"what": "uds_blocked_dir", "target": policy.uds_blocked_dir,
                       "expect": "denied", "ok": _run_as(
                           policy.user, f"test -x '{policy.uds_blocked_dir}'") != 0})
    if policy.uds_allowed_dir:
        checks.append({"what": "uds_allowed_dir", "target": policy.uds_allowed_dir,
                       "expect": "accessible", "ok": _run_as(
                           policy.user, f"test -x '{policy.uds_allowed_dir}'") == 0})
    ok = all(c["ok"] for c in checks)
    return {"ok": ok, "user": policy.user, "server_root": policy.server_root,
            "checks": checks, "checked_at": time.strftime("%F %T")}
