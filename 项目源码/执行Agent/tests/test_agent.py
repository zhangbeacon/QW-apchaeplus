"""A1 执行 Agent 单元测试（纯逻辑：计划校验/展开/初筛/完整性检查，不启动构建）。"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qw9.agent import expand as gexpand, plan as gplan, select as gsel, verify as gverify  # noqa: E402
from qw9.domain import Recipe, SpecError  # noqa: E402

TEMPLATE = """apiVersion: qw9/v1
kind: VariantRecipe
metadata:
  id: @@ID@@
  role: @@ROLE@@
  description: "@@AXIS@@轴候选 @@ID@@：@@DESC@@"
source:
  package: @@TARBALL@@
  sha256: @@SHA@@
toolchain:
  cc: @@CC@@
  cc_min_version: "9"
flags:
  cflags: "@@CFLAGS@@"
  ldflags: "@@LDFLAGS@@"
configure:
  args: @@CONFIGURE_ARGS@@
  env:
    SOURCE_DATE_EPOCH: "1631836800"
install:
  prefix: @@PREFIX@@
  workroot: /root/work/qw9
build:
  jobs: 4
verify:
  require_fortify: @@REQUIRE_FORTIFY@@
"""

POLICY = """
runtime: {user: httpd-v3, group: httpd-v3, server_root: /opt/qw9/v3}
business_readable: [htdocs]
writable: [logs, run]
uds: {allowed_dir: run/uds, blocked_dir: /opt/qw9/markers/evil}
markers:
  - {path: /opt/qw9/markers/root-only.txt, content: "M\\n", mode: "0600"}
"""


def _make_env(tmp, plan_data):
    root = tempfile.mkdtemp(dir=tmp)
    os.makedirs(os.path.join(root, "plans"))
    os.makedirs(os.path.join(root, "recipes"))
    tarball = os.path.join(root, "src.tar.gz")
    with open(tarball, "w") as f:
        f.write("x")
    sha = hashlib.sha256(b"x").hexdigest()
    pol_dir = os.path.join(root, "contracts")
    os.makedirs(pol_dir)
    with open(os.path.join(pol_dir, "apache-resources.yaml"), "w") as f:
        f.write(POLICY)
    plan_data["base"]["source"]["package"] = "../src.tar.gz"
    plan_data["base"]["source"]["sha256"] = sha
    ppath = os.path.join(root, "plans", "p.yaml")
    with open(ppath, "w", encoding="utf-8") as f:
        yaml.safe_dump(plan_data, f, allow_unicode=True)
    with open(os.path.join(root, "recipes", "template.yaml"), "w", encoding="utf-8") as f:
        f.write(TEMPLATE)
    return root, ppath, sha


def base_plan(**over):
    p = {
        "metadata": {"id": "t12"},
        "base": {
            "source": {"package": "", "sha256": ""},
            "configure_args": ["--with-apr=/usr", "--enable-mpms-shared=all"],
            "timeout_s": 600,
        },
        "allocator": {"jemalloc": "libjemalloc.so.2"},
        "ports": {"start": 8300},
        "candidates": [
            {"id": "c1", "axis": "compile", "role": "BASELINE", "cc": "gcc", "opt": "O2",
             "allocator": "ptmalloc", "mpm": "event", "harden": False, "desc": "基线"},
            {"id": "c2", "axis": "compile", "cc": "clang", "opt": "O2",
             "allocator": "jemalloc", "mpm": "event", "harden": False},
            {"id": "h1", "axis": "harden", "cc": "gcc", "opt": "O2",
             "allocator": "ptmalloc", "mpm": "event", "harden": True},
        ],
        "isolation_candidates": [
            {"id": "i1", "axis": "isolation",
             "base_params": {"cc": "gcc", "opt": "O2", "allocator": "ptmalloc",
                             "mpm": "event", "harden": False},
             "policy": "../contracts/apache-resources.yaml"},
        ],
        "delivery": {"baseline_id": "c1", "v2_axes": ["compile", "harden", "thread"],
                     "v3_preregistered": "i1"},
    }
    p.update(over)
    return p


class PlanTests(unittest.TestCase):
    def test_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, base_plan())
            plan_obj = gplan.Plan.load(ppath)
            self.assertEqual(len(plan_obj.candidates), 3)
            self.assertEqual(plan_obj.v3_preregistered, "i1")
            self.assertEqual(plan_obj.port_start, 8300)

    def test_dup_id(self):
        bad = base_plan()
        bad["candidates"].append(dict(bad["candidates"][1]))
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, bad)
            with self.assertRaises(SpecError):
                gplan.Plan.load(ppath)

    def test_missing_param(self):
        bad = base_plan()
        del bad["candidates"][1]["allocator"]
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, bad)
            with self.assertRaises(SpecError):
                gplan.Plan.load(ppath)

    def test_v3_must_be_isolation(self):
        bad = base_plan()
        bad["delivery"]["v3_preregistered"] = "c2"
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, bad)
            with self.assertRaises(SpecError):
                gplan.Plan.load(ppath)

    def test_mpms_shared_required(self):
        bad = base_plan()
        bad["base"]["configure_args"] = ["--with-apr=/usr"]
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, bad)
            with self.assertRaises(SpecError):
                gplan.Plan.load(ppath)

    def test_isolation_not_in_v2_axes(self):
        bad = base_plan()
        bad["delivery"]["v2_axes"] = ["compile", "isolation"]
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, bad)
            with self.assertRaises(SpecError):
                gplan.Plan.load(ppath)


class ExpandTests(unittest.TestCase):
    def test_expand_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, ppath, _ = _make_env(tmp, base_plan())
            plan_obj = gplan.Plan.load(ppath)
            gplan.create_run(plan_obj, root, "r1")
            state = gexpand.run_expand(root, "r1")
            by = {e["id"]: e for e in state["candidates"]}
            self.assertEqual(len(state["candidates"]), 4)
            # 端口顺序分配
            self.assertEqual([e["port"] for e in state["candidates"]],
                             [8300, 8301, 8302, 8303])
            # 每份配方都能过 Recipe schema 校验
            for e in state["candidates"]:
                r = Recipe.load(e["recipe_path"])
                self.assertEqual(r.prefix, f"/opt/qw9/{e['id']}")
            # c2: clang + jemalloc 预加载
            r2 = Recipe.load(by["c2"]["recipe_path"])
            self.assertEqual(r2.cc, "clang")
            rt2 = json.load(open(by["c2"]["runtime_path"], encoding="utf-8"))
            self.assertEqual(rt2["env_overrides"]["LD_PRELOAD"], "libjemalloc.so.2")
            # h1: 加固 → FORTIFY 必查
            r1h = Recipe.load(by["h1"]["recipe_path"])
            self.assertIn("_FORTIFY_SOURCE=2", r1h.cflags)
            self.assertTrue(r1h.require_fortify)
            # i1: 落地版 policy 的 server_root 已改写
            pol = yaml.safe_load(open(by["i1"]["policy_effective_path"], encoding="utf-8"))
            self.assertEqual(pol["runtime"]["server_root"], "/opt/qw9/i1")


def _state_for_select():
    def entry(cid, params, status="VERIFIED", axis="compile"):
        return {"id": cid, "axis": axis, "status": status, "params": params}
    p_base = {"cc": "gcc", "opt": "O2", "allocator": "ptmalloc", "mpm": "event",
              "harden": False}
    return {
        "run_id": "r-test",
        "delivery": {"baseline_id": "c1", "v2_axes": ["compile", "harden", "thread"],
                     "v3_preregistered": "i1"},
        "candidates": [
            entry("c1", dict(p_base)),
            entry("c2", {**p_base, "cc": "clang"}),
            entry("h1", {**p_base, "harden": True}, axis="harden"),
            entry("i1", dict(p_base), axis="isolation"),
        ],
    }


class SelectTests(unittest.TestCase):
    def test_pick_and_rejects(self):
        state = _state_for_select()
        scores = {
            "c1": {"score": 0.9},           # 与基线同参数 → 淘汰
            "c2": {"score": "N/A"},         # 无有效分数 → 淘汰
            "h1": {"score": 0.7, "detail": {"hde": "L2 分布", "per_cve": {"x": 1}}},
            "i1": {"score": 0.99},          # 隔离轴不进池
        }
        pick = gsel.pick_v2(state, scores)
        self.assertEqual(pick["chosen"]["id"], "h1")
        self.assertEqual(pick["chosen"]["diff_axes"], ["harden"])
        self.assertIn("c1", pick["rejected"])
        self.assertIn("c2", pick["rejected"])
        self.assertIn("i1", pick["rejected"])
        md = gsel.render_selection_md(pick, state, "hde.json", "score")
        self.assertIn("h1", md)
        self.assertIn("落选原因", md)

    def test_blocked_when_no_valid(self):
        state = _state_for_select()
        scores = {"c2": {"score": "N/A"}, "h1": {"score": "N/A"}}
        with self.assertRaises(gsel.SelectError):
            gsel.pick_v2(state, scores)

    def test_detail_required_for_rationale(self):
        state = _state_for_select()
        scores = {"h1": {"score": 0.7}}  # 无 detail → 理由无法溯源 → 退回
        with self.assertRaises(gsel.SelectError):
            gsel.pick_v2(state, scores)


class VerifyTests(unittest.TestCase):
    def _fake_candidate(self, tmp, sha_ok=True):
        prefix = tempfile.mkdtemp(dir=tmp)
        os.makedirs(os.path.join(prefix, "bin"))
        os.makedirs(os.path.join(prefix, "modules"))
        binp = os.path.join(prefix, "bin", "httpd")
        with open(binp, "w") as f:
            f.write("ELF")
        mod = os.path.join(prefix, "modules", "mod_mpm_event.so")
        with open(mod, "w") as f:
            f.write("ELF2")
        art = tempfile.mkdtemp(dir=tmp)
        sha = hashlib.sha256(b"ELF").hexdigest()
        manifest = {"schema": "qw9/manifest/v1",
                    "summary": {"files_total": 2, "fortify_files": 1,
                                "fortify_coverage": 0.5},
                    "files": [
                        {"path": "bin/httpd",
                         "sha256": sha if sha_ok else "dead" * 16},
                        {"path": "modules/mod_mpm_event.so", "sha256": "beef" * 16},
                    ]}
        with open(os.path.join(art, "manifest.json"), "w") as f:
            json.dump(manifest, f)
        entry = {"id": "c1", "axis": "compile", "prefix": prefix, "artifact_dir": art,
                 "params": {"cc": "gcc", "opt": "O2", "allocator": "ptmalloc",
                            "mpm": "event", "harden": True}}
        return entry

    def test_check_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry = self._fake_candidate(tmp)
            state = {"allocator": {}}
            checks = gverify.check_candidate(entry, state)
            self.assertTrue(all(c["ok"] for c in checks), checks)

    def test_check_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry = self._fake_candidate(tmp, sha_ok=False)
            state = {"allocator": {}}
            checks = gverify.check_candidate(entry, state)
            bad = [c for c in checks if not c["ok"]]
            self.assertTrue(any(c["what"] == "bin_sha_matches_manifest" for c in bad))


if __name__ == "__main__":
    unittest.main()
