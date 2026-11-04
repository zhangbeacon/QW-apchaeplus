"""矩阵 runner：场景部署 → 起停 → 适配器 → verdict.json → matrix.md。

关键契约：
- 所有 httpd 实例只按"本场景 conf 路径 + 记录的 PID"清理，禁止全局 pkill；
- 适配器退出码：0=正常观测（axes 有效），3=环境问题（validity=INVALID）；
- 超时/起不来 = INVALID/NOT_RUN，一律不得计防御成功；
- 证据写入 artifacts/runs/<run_id>/<variant>/<scenario>/，防陈旧：每次 run_id 唯一。
"""

import glob
import json
import os
import re
import shutil
import subprocess
import time

from . import domain
from .domain import (BusinessContract, IsolationPolicy, Recipe, SpecError,
                     eval_axis_expr, make_verdict, parse_adapter_axes,
                     write_verdict)

VARIANT_RECIPES = {
    "v1": "recipes/v1-normal.yaml",
    "v2": "recipes/v2-hardened.yaml",
    "v3": "recipes/v3-isolated.yaml",
}
VARIANT_PORTS = {"v1": 8100, "v2": 8110, "v3": 8120}
MARKER_REL = "opt/qw9/markers/root-only.txt"          # 相对根的穿越目标
EVIL_SOCK = "/opt/qw9/markers/evil/evil.sock"


class RunnerError(RuntimeError):
    pass


class Variant:
    def __init__(self, vid, recipe: Recipe):
        self.id = vid
        self.recipe = recipe
        self.prefix = recipe.prefix
        policy_path = recipe.policy_path()
        self.policy = IsolationPolicy.load(policy_path) if policy_path else None

    @property
    def port(self):
        return VARIANT_PORTS[self.id]

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"

    def user_block(self):
        return self.policy.httpd_user_block() if self.policy else ""

    def uds_dir(self):
        if self.policy and self.policy.uds_allowed_dir:
            return self.policy.uds_allowed_dir
        return os.path.join(self.prefix, "run", "uds")


def load_variant(root, vid):
    if vid not in VARIANT_RECIPES:
        raise RunnerError(f"未知变体 {vid}，可选: {list(VARIANT_RECIPES)}")
    return Variant(vid, Recipe.load(os.path.join(root, VARIANT_RECIPES[vid])))


def render_conf(template_path, var: Variant, out_path, extra=None):
    with open(template_path, encoding="utf-8") as f:
        text = f.read()
    for k, v in {
        "PREFIX": var.prefix,
        "PORT": str(var.port),
        "USER_BLOCK": var.user_block(),
        "UDS_DIR": var.uds_dir(),
        "MARKER_DIR": "/opt/qw9/markers",
    }.items():
        text = text.replace("{{" + k + "}}", str(v))
    if extra:
        for k, v in extra.items():
            text = text.replace("{{" + k + "}}", str(v))
    if "{{" in text:
        left = sorted(set(re.findall(r"\{\{(\w+)\}\}", text)))
        raise SpecError(f"conf 模板存在未替换占位符: {left}")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return out_path


def deploy_scenario(scen_dir, var: Variant):
    """overlay 拷贝进变体前缀 + 渲染 scenario.conf。"""
    overlay = os.path.join(scen_dir, "overlay")
    if os.path.isdir(overlay):
        subprocess.run(["cp", "-r", overlay + "/.", var.prefix + "/"], check=True)
        if var.id == "v3":
            # 业务文件 root 属主、全员可读（policy.business_readable 的运行时补齐）
            for sub in ("htdocs", "icons", "cgi-bin", "lua", "conf"):
                d = os.path.join(var.prefix, sub)
                if os.path.isdir(d):
                    subprocess.run(["chmod", "-R", "a+rX", d], check=True)
    return render_conf(os.path.join(scen_dir, "conf.template"), var,
                       os.path.join(var.prefix, "conf", "scenario.conf"))


def _support_env(root, var, out_dir):
    env = dict(os.environ)
    env.update({
        "QW9_BASE_URL": var.base_url,
        "QW9_PORT": str(var.port),
        "QW9_PREFIX": var.prefix,
        "QW9_OUT_DIR": out_dir,
        "QW9_UDS_DIR": var.uds_dir(),
        "QW9_EVIL_SOCK": EVIL_SOCK,
        "QW9_MARKER_REL": MARKER_REL,
        "QW9_POC_ROOT": env.get("QW9_POC_ROOT",
                                os.path.join(root, "..", "cve", "apache")),
        "QW9_SUPPORT": os.path.join(root, "scenarios", "support"),
    })
    return env


def run_hook(scen_dir, name, env):
    hook = os.path.join(scen_dir, name)
    if not os.path.isfile(hook):
        return
    r = subprocess.run(["bash", hook], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RunnerError(f"{name} 失败: {r.stdout}\n{r.stderr}")


def launch(var: Variant, conf_path, console_log):
    """启动 httpd（-DFOREGROUND），等待 curl 就绪；返回 master Popen。"""
    subprocess.run(["pkill", "-f", conf_path], capture_output=True)
    time.sleep(0.3)
    httpd = os.path.join(var.prefix, "bin", "httpd")
    if not os.path.isfile(httpd):
        raise RunnerError(f"变体 {var.id} 二进制缺失: {httpd}（先 qw9 build）")
    logf = open(console_log, "ab")
    proc = subprocess.Popen([httpd, "-f", conf_path, "-DFOREGROUND"],
                            stdout=logf, stderr=subprocess.STDOUT,
                            cwd=var.prefix)
    deadline = time.time() + 30
    while time.time() < deadline:
        if subprocess.run(["curl", "-s", "-o", os.devnull, var.base_url + "/"],
                          capture_output=True).returncode == 0:
            return proc
        if proc.poll() is not None:
            logf.close()
            raise RunnerError(f"httpd 启动即退出 (exit {proc.returncode})，见 {console_log}")
        time.sleep(0.3)
    logf.close()
    raise RunnerError(f"httpd 30s 未就绪，见 {console_log}")


def stop(proc, conf_path):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    subprocess.run(["pkill", "-f", conf_path], capture_output=True)
    time.sleep(0.5)


def run_adapter(root, scen, var: Variant, out_dir):
    """执行适配器并解析轴；返回 (axes, validity, exit_code)。"""
    os.makedirs(out_dir, exist_ok=True)
    env = _support_env(root, var, out_dir)
    adapter = os.path.join(root, "adapters", scen["adapter"])
    r = subprocess.run(["bash", adapter], env=env, capture_output=True, text=True)
    with open(os.path.join(out_dir, "adapter.log"), "w", encoding="utf-8") as f:
        f.write(f"$ {adapter}\nexit={r.returncode}\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}")
    axes = parse_adapter_axes(r.stdout)
    if r.returncode == 3:
        return axes, "INVALID", r.returncode
    if r.returncode != 0:
        return axes, "INVALID", r.returncode
    return axes, "VALID", r.returncode


def to_verdict(scen, axes, validity, run_id, var_id, evidence):
    if validity != "VALID":
        return make_verdict(run_id, scen["id"], var_id, validity, "INCONCLUSIVE",
                            [], axes, evidence, scen.get("oracle_version", ""),
                            notes="适配器异常，不产生结论")
    mapping = scen.get("mapping") or {}
    try:
        reached = eval_axis_expr(mapping.get("goal_expr", "0"), axes)
    except SpecError as e:
        return make_verdict(run_id, scen["id"], var_id, "INVALID", "INCONCLUSIVE",
                            [], axes, evidence, scen.get("oracle_version", ""),
                            notes=f"goal_expr 非法: {e}")
    phenotypes = []
    for rule in mapping.get("phenotypes") or []:
        try:
            if eval_axis_expr(rule.get("expr", "0"), axes):
                phenotypes.append(rule.get("tag", "untagged"))
        except SpecError:
            phenotypes.append(f"bad_rule:{rule.get('tag')}")
    goal = "GOAL_REACHED" if reached else "GOAL_NOT_OBSERVED"
    return make_verdict(run_id, scen["id"], var_id, validity, goal,
                        phenotypes, axes, evidence,
                        scen.get("oracle_version", ""))


def run_matrix(root, cves, vids, run_id):
    """主循环：CVE × 变体 → verdicts + matrix.json + matrix.md。"""
    results = []
    for cve in cves:
        scen_dir = os.path.join(root, "scenarios", cve)
        if not os.path.isdir(scen_dir):
            raise RunnerError(f"场景不存在: {scen_dir}")
        scen = domain.load_yaml(os.path.join(scen_dir, "scenario.yaml"))
        scen["id"] = scen.get("id", cve)
        for vid in vids:
            var = load_variant(root, vid)
            out_dir = os.path.join(root, "artifacts", "runs", run_id, vid, cve)
            os.makedirs(out_dir, exist_ok=True)
            conf = deploy_scenario(scen_dir, var)
            env = _support_env(root, var, out_dir)
            proc = None
            try:
                run_hook(scen_dir, "pre_start.sh", env)
                proc = launch(var, conf, os.path.join(out_dir, "httpd-console.log"))
                axes, validity, _ = run_adapter(root, scen, var, out_dir)
            except RunnerError as e:
                axes, validity = {"runner_error": str(e)}, "INVALID"
            finally:
                stop(proc, conf)
                run_hook(scen_dir, "post_stop.sh", env)
            evidence = sorted(
                os.path.relpath(p, out_dir)
                for p in glob.glob(os.path.join(out_dir, "*"))
                if os.path.isfile(p) and not p.endswith("httpd-console.log"))
            verdict = to_verdict(scen, axes, validity, run_id, vid, evidence)
            write_verdict(out_dir, verdict)
            results.append(verdict)
    report = render_matrix_report(results, run_id)
    with open(os.path.join(root, "artifacts", "runs", run_id, "matrix.json"), "w",
              encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    md_path = os.path.join(root, "artifacts", "runs", run_id, "matrix.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    return md_path, results


def render_matrix_report(results, run_id):
    cves, vids = [], []
    for v in results:
        if v["cve"] not in cves:
            cves.append(v["cve"])
        if v["variant"] not in vids:
            vids.append(v["variant"])
    by = {(v["cve"], v["variant"]): v for v in results}

    def cell(cve, vid):
        v = by.get((cve, vid))
        if not v:
            return "—"
        goal = {"GOAL_REACHED": "触发", "GOAL_NOT_OBSERVED": "未观测",
                "INCONCLUSIVE": "不确定"}[v["goal_outcome"]]
        if v["validity"] != "VALID":
            goal += f"（{v['validity']}）"
        ph = ",".join(v["phenotypes"]) or "-"
        return f"{goal}<br>{ph}"

    lines = [f"# 三版本矩阵 run_id={run_id}", "",
             f"- 生成时间：{time.strftime('%F %T')}",
             f"- 口径：触发=GOAL_REACHED；未观测=GOAL_NOT_OBSERVED；"
             f"INVALID/NOT_RUN 不计防御成功。", ""]
    header = "| CVE | " + " | ".join(vids) + " | 差异候选 |"
    sep = "|---" * (len(vids) + 2) + "|"
    lines += [header, sep]
    for cve in cves:
        cells = [cell(cve, vid) for vid in vids]
        verdicts = [by.get((cve, vid), {}).get("goal_outcome") for vid in vids]
        ph_sets = {tuple(by.get((cve, vid), {}).get("phenotypes", [])) for vid in vids}
        diff = "是" if (len(set(verdicts)) > 1 or len(ph_sets) > 1) else "否"
        lines.append(f"| {cve} | " + " | ".join(cells) + f" | {diff} |")
    lines += ["", "> 差异候选=是 仅为初筛（goal 或表型集合不同）；G4 验收需人工复核证据文件。"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- 业务契约（G2）

def run_contract(root, vid, contract: BusinessContract, run_id):
    """部署 business 场景并逐能力探测；全部通过才算 G2 PASS。"""
    var = load_variant(root, vid)
    scen_dir = os.path.join(root, "scenarios", "business")
    out_dir = os.path.join(root, "artifacts", "runs", run_id, vid, "business")
    os.makedirs(out_dir, exist_ok=True)
    conf = deploy_scenario(scen_dir, var)
    env = _support_env(root, var, out_dir)
    proc = None
    rows = []
    try:
        run_hook(scen_dir, "pre_start.sh", env)
        proc = launch(var, conf, os.path.join(out_dir, "httpd-console.log"))
        for cap in contract.capabilities:
            rows.append(_probe(var, cap, out_dir))
    except RunnerError as e:
        rows.append({"id": "launch", "ok": False, "detail": str(e)})
    finally:
        stop(proc, conf)
        run_hook(scen_dir, "post_stop.sh", env)
    ok = all(r["ok"] for r in rows)
    result = {"variant": vid, "ok": ok, "capabilities": rows,
              "run_id": run_id, "at": time.strftime("%F %T")}
    with open(os.path.join(out_dir, "contract.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return result


def _curl(args, timeout=15):
    return subprocess.run(["curl", "-sS", "--max-time", str(timeout), *args],
                          capture_output=True, text=True)


def _probe(var: Variant, cap, out_dir):
    ok, detail = False, ""
    tag = re.sub(r"[^A-Za-z0-9_.-]", "_", cap["id"])
    body_file = os.path.join(out_dir, f"probe-{tag}.body")
    try:
        if cap["keepalive_paths"]:
            urls = [var.base_url + p for p in cap["keepalive_paths"]]
            r = _curl(["-o", body_file, "-w", "%{http_code}\\n", *urls])
            codes = [l for l in r.stdout.splitlines() if l.strip().isdigit()]
            ok = codes == [str(cap["status"])] * len(urls) and len(codes) == len(urls)
            detail = f"codes={codes}"
        else:
            args = ["-o", body_file, "-w", "%{http_code}"]
            if cap["via_proxy"]:
                args += ["-x", var.base_url]
            url = var.base_url + cap["path"] if not cap["via_proxy"] else cap["path"]
            if not str(url).startswith("http"):
                url = "http://" + str(url)
            if cap["method"] != "GET":
                args += ["-X", cap["method"]]
            if cap["data"] is not None:
                args += ["--data-binary", str(cap["data"])]
            if cap["content_type"]:
                args += ["-H", f"Content-Type: {cap['content_type']}"]
            args.append(url)
            r = _curl(args)
            code = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "0"
            body = open(body_file, encoding="utf-8", errors="replace").read() \
                if os.path.isfile(body_file) else ""
            ok = code == str(cap["status"]) and (
                not cap["body_contains"] or cap["body_contains"] in body)
            detail = f"code={code} body_has={cap['body_contains']!r}"
    except Exception as e:  # pragma: no cover
        detail = f"probe error: {e}"
    return {"id": cap["id"], "ok": ok, "detail": detail}
