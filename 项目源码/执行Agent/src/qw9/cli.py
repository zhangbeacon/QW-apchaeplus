"""qw9 命令行入口。

    PYTHONPATH=src python3 -m qw9 <cmd> ...

子命令：
  build     按 recipe 构建变体（干净树 + 全 DSO + manifest + FORTIFY 实证）
  repro     同配方构建两次并比对产物哈希（可重复性验收）
  isolate   落地 V3 隔离策略（UID/权限/markers/UDS）+ 可达性自检
  contract  对变体跑业务契约探测（G2 功能一致性门）
  matrix    CVE × 变体 矩阵执行，产出 verdict.json + matrix.md
  gen       A1 执行 Agent：plan / expand / build / verify / deliver
  p0        P0 可行性三问（clang/FORTIFY、V2 构建、WSL 隔离）
"""

import argparse
import os
import subprocess
import sys
import time

from . import builder, isolator, runner
from .agent import deliver as gen_deliver
from .agent import expand as gen_expand
from .agent import generate as gen_generate
from .agent import plan as gen_plan
from .agent import verify as gen_verify
from .domain import BusinessContract, Recipe


def _root(args):
    root = os.path.abspath(args.root)
    if not os.path.isdir(os.path.join(root, "recipes")):
        sys.exit(f"错误：{root} 下没有 recipes/，请用 --root 指向 platform/ 目录")
    return root


def _artifacts(root, name):
    d = os.path.join(root, "artifacts", name)
    os.makedirs(d, exist_ok=True)
    return d


def cmd_build(args):
    root = _root(args)
    recipe = Recipe.load(os.path.join(root, args.recipe)
                         if not os.path.isabs(args.recipe) else args.recipe)
    m = builder.build(recipe, _artifacts(root, recipe.id),
                      cc_override=args.cc, jobs=args.jobs)
    s = m["summary"]
    print(f"OK recipe={recipe.id} prefix={recipe.prefix}")
    print(f"   files={s['files_total']} fortify_files={s['fortify_files']} "
          f"coverage={s['fortify_coverage']}")
    return 0


def cmd_repro(args):
    root = _root(args)
    recipe = Recipe.load(os.path.join(root, args.recipe)
                         if not os.path.isabs(args.recipe) else args.recipe)
    r = builder.repro_check(recipe, _artifacts(root, recipe.id), times=args.times)
    print(f"{'OK' if r['equal'] else 'DIFF'} recipe={recipe.id} "
          f"times={r['times']} diffs={len(r['diffs'])}")
    return 0 if r["equal"] else 1


def cmd_isolate(args):
    root = _root(args)
    recipe = Recipe.load(os.path.join(root, args.recipe)
                         if not os.path.isabs(args.recipe) else args.recipe)
    policy_path = recipe.policy_path()
    if not policy_path:
        sys.exit("错误：该配方没有 isolation 字段（v3-isolated 才有）")
    from .domain import IsolationPolicy
    checks = isolator.apply(IsolationPolicy.load(policy_path),
                            _artifacts(root, recipe.id))
    for c in checks["checks"]:
        mark = "PASS" if c["ok"] else "FAIL"
        print(f"[{mark}] {c['what']}: {c['target']} (expect {c['expect']})")
    print("ISOLATE OVERALL:", "PASS" if checks["ok"] else "FAIL")
    return 0 if checks["ok"] else 1


def cmd_contract(args):
    root = _root(args)
    contract = BusinessContract.load(os.path.join(root, args.contract))
    ok_all = True
    for vid in args.variants:
        r = runner.run_contract(root, vid, contract, args.run_id)
        for cap in r["capabilities"]:
            mark = "PASS" if cap["ok"] else "FAIL"
            print(f"[{mark}] {vid}/{cap['id']} {cap.get('detail', '')}")
        print(f"CONTRACT {vid}: {'PASS' if r['ok'] else 'FAIL'}")
        ok_all = ok_all and r["ok"]
    return 0 if ok_all else 1


def cmd_matrix(args):
    root = _root(args)
    run_id = args.run_id or time.strftime("r-%Y%m%d-%H%M%S")
    md, results = runner.run_matrix(root, args.cves, args.variants, run_id)
    n_valid = sum(1 for v in results if v["validity"] == "VALID")
    print(f"run_id={run_id} verdicts={len(results)} valid={n_valid}")
    print(f"report: {md}")
    return 0


def cmd_p0(args):
    root = _root(args)
    script = os.path.join(root, "scripts", "p0_feasibility.sh")
    r = subprocess.run(["bash", script], cwd=root,
                       env={**os.environ, "QW9_ROOT": root})
    return r.returncode


# ------------------------------------------------- A1 执行 Agent（gen 命令族）

def _load_plan(root, path):
    if not os.path.isabs(path):
        path = os.path.join(root, path)
    return gen_plan.Plan.load(path)


def cmd_gen_plan(args):
    plan_obj = _load_plan(_root(args), args.plan)
    n, ni = len(plan_obj.candidates), len(plan_obj.isolation_candidates)
    print(f"OK plan={plan_obj.id} candidates={n} isolation={ni} "
          f"v3={plan_obj.v3_preregistered}(预注册) baseline={plan_obj.baseline_id}")
    print(f"   ports={plan_obj.port_start}..{plan_obj.port_start + n + ni - 1} "
          f"timeout={plan_obj.timeout_s}s plan_sha={plan_obj.hash[:16]}…")
    return 0


def cmd_gen_expand(args):
    root = _root(args)
    plan_obj = _load_plan(root, args.plan)
    run_id = args.run_id or time.strftime("gen-%Y%m%d-%H%M%S")
    gen_plan.create_run(plan_obj, root, run_id, recipes_out=args.out)
    gen_expand.run_expand(root, run_id)
    state = gen_plan.load_run(root, run_id)
    print(f"OK run_id={run_id} 已展开 {len(state['candidates'])} 份配方+runtime")
    print(f"   recipes: {state['candidates'][0]['recipe_path']}")
    print(f"   state:   {os.path.join(root, 'artifacts', run_id, 'state.json')}")
    return 0


def cmd_gen_build(args):
    root = _root(args)
    summary = gen_generate.run_build(root, args.run_id, jobs=args.jobs,
                                     only=set(args.only) if args.only else None)
    blocked = []
    for row in summary:
        mark = "OK " if row["status"] in ("BUILT", "VERIFIED") else "BAD"
        print(f"[{mark}] {row['id']:<4} {row['status']:<9} attempts={row['attempts']}")
        if row["status"] == "BLOCKED":
            blocked.append(row["id"])
    if blocked:
        print(f"BLOCKED: {blocked}（详见 artifacts/{args.run_id}/builds.json）")
        return 1
    print("BUILD: 全部候选已建成")
    return 0


def cmd_gen_verify(args):
    root = _root(args)
    report = gen_verify.run_verify(root, args.run_id)
    for cid, r in report.items():
        print(f"[{'PASS' if r['ok'] else 'FAIL'}] {cid}")
        for c in r["checks"]:
            if not c["ok"]:
                print(f"        - {c['what']}: {c.get('detail', '')}")
    bad = [cid for cid, r in report.items() if not r["ok"]]
    print("VERIFY:", "ALL OK" if not bad else f"INVALID: {bad}")
    return 0 if not bad else 1


def cmd_gen_deliver(args):
    root = _root(args)
    index = gen_deliver.deliver(root, args.run_id, args.scores,
                                score_key=args.score_key,
                                include_tree=args.include_tree, out_root=args.out)
    print(f"OK delivery: V2={index['V2']['candidate']}（{index['V2']['prefix']}）")
    print(f"             V3={index['V3']['candidate']}（预注册，{index['V3']['prefix']}）")
    print(f"   dir: {os.path.dirname(index['traceability'])}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="qw9")
    p.add_argument("--root", default=os.getcwd(),
                   help="platform 目录（默认当前目录）")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="按 recipe 构建变体")
    b.add_argument("--recipe", required=True)
    b.add_argument("--jobs", type=int, default=None)
    b.add_argument("--cc", default=None, help="临时覆盖编译器（如 gcc-12）")
    b.set_defaults(fn=cmd_build)

    rp = sub.add_parser("repro", help="构建两次比对哈希")
    rp.add_argument("--recipe", required=True)
    rp.add_argument("--times", type=int, default=2)
    rp.set_defaults(fn=cmd_repro)

    i = sub.add_parser("isolate", help="落地 V3 隔离并自检")
    i.add_argument("--recipe", required=True)
    i.set_defaults(fn=cmd_isolate)

    c = sub.add_parser("contract", help="业务契约探测（G2）")
    c.add_argument("--variants", nargs="+", default=["v1", "v2", "v3"])
    c.add_argument("--contract", default="contracts/apache-business.yaml")
    c.add_argument("--run-id", default=time.strftime("r-%Y%m%d-%H%M%S"))
    c.set_defaults(fn=cmd_contract)

    m = sub.add_parser("matrix", help="CVE × 变体矩阵")
    m.add_argument("--cves", nargs="+", required=True,
                   help="场景目录名，如 CVE-2021-41773")
    m.add_argument("--variants", nargs="+", default=["v1", "v2", "v3"])
    m.add_argument("--run-id", default=None)
    m.set_defaults(fn=cmd_matrix)

    p0 = sub.add_parser("p0", help="P0 可行性三问")
    p0.set_defaults(fn=cmd_p0)

    g = sub.add_parser("gen", help="A1 执行 Agent：计划/展开/构建/自检/交付")
    gsub = g.add_subparsers(dest="gcmd", required=True)

    gp = gsub.add_parser("plan", help="校验生成计划（参数缺失/重复直接报错，不猜）")
    gp.add_argument("--plan", required=True, help="计划文件，如 plans/hde12.yaml")
    gp.set_defaults(fn=cmd_gen_plan)

    ge = gsub.add_parser("expand", help="模板+参数 → 每候选 recipe.yaml + runtime.json")
    ge.add_argument("--plan", required=True)
    ge.add_argument("--run-id", default=None, help="缺省自动生成 gen-时间戳")
    ge.add_argument("--out", default=None, help="配方输出目录（默认 recipes/gen/<run_id>）")
    ge.set_defaults(fn=cmd_gen_expand)

    gb = gsub.add_parser("build", help="逐候选构建（隔离类候选追加 isolate+自检）")
    gb.add_argument("--run-id", required=True)
    gb.add_argument("--jobs", type=int, default=4)
    gb.add_argument("--only", nargs="*", default=None, help="只构建这些候选 id")
    gb.set_defaults(fn=cmd_gen_build)

    gv = gsub.add_parser("verify", help="完整性自检（二进制/哈希/MPM DSO/分配器/隔离）")
    gv.add_argument("--run-id", required=True)
    gv.set_defaults(fn=cmd_gen_verify)

    gd = gsub.add_parser("deliver", help="按分数挑 V2 + 预注册 V3，组装交付目录")
    gd.add_argument("--run-id", required=True)
    gd.add_argument("--scores", required=True, help="评估分数 JSON（A3 产出，A1 只读）")
    gd.add_argument("--score-key", default="score")
    gd.add_argument("--include-tree", action="store_true", help="打包安装树进交付目录")
    gd.add_argument("--out", default="delivery")
    gd.set_defaults(fn=cmd_gen_deliver)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
