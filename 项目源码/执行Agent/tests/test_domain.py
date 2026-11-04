"""纯逻辑单元测试（不启动进程、不碰 /opt）：python3 -m unittest discover -s tests"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qw9 import domain  # noqa: E402
from qw9.domain import (IsolationPolicy, Recipe, SpecError, eval_axis_expr,  # noqa: E402
                        make_verdict, parse_adapter_axes)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _make_recipe_dir(tmp, tarball_rel="fake.tar.gz"):
    d = tempfile.mkdtemp(dir=tmp)
    tb = _write(os.path.join(d, "fake.tar.gz"), "x")
    import hashlib
    sha = hashlib.sha256(b"x").hexdigest()
    yml = f"""
metadata: {{id: test-a, role: CANDIDATE}}
source:
  package: {tarball_rel}
  sha256: {sha}
toolchain: {{cc: gcc, cc_min_version: "9"}}
flags: {{cflags: "-O2", ldflags: ""}}
configure: {{args: ["--with-apr=/usr"], env: {{}}}}
install: {{prefix: /opt/qw9/t1, workroot: /root/work/qw9}}
"""
    return os.path.join(d, "r.yaml"), yml, tb


class RecipeTests(unittest.TestCase):
    def test_load_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, yml, tb = _make_recipe_dir(tmp)
            _write(p, yml)
            r = Recipe.load(p)
            self.assertEqual(r.id, "test-a")
            self.assertEqual(r.prefix, "/opt/qw9/t1")
            self.assertEqual(r.tarball, os.path.abspath(tb))

    def test_prefix_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, yml, _ = _make_recipe_dir(tmp)
            _write(p, yml.replace("/opt/qw9/t1", "/home/oops/x"))
            with self.assertRaises(SpecError):
                Recipe.load(p)

    def test_missing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, yml, _ = _make_recipe_dir(tmp)
            _write(p, yml.replace("toolchain: {cc: gcc, cc_min_version: \"9\"}\n", ""))
            with self.assertRaises(SpecError):
                Recipe.load(p)

    def test_bad_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            p, yml, _ = _make_recipe_dir(tmp)
            _write(p, yml.replace("sha256: ", "sha256: deadbeef\n#"))
            with self.assertRaises(SpecError):
                Recipe.load(p)


class PolicyTests(unittest.TestCase):
    POLICY = """
runtime: {user: httpd-v3, group: httpd-v3, server_root: /opt/qw9/v3}
business_readable: [htdocs, cgi-bin]
writable: [logs, run]
uds: {allowed_dir: run/uds, blocked_dir: /opt/qw9/markers/evil}
markers:
  - {path: /opt/qw9/markers/root-only.txt, content: "M\n", mode: "0600"}
"""

    def test_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(os.path.join(tmp, "p.yaml"), self.POLICY)
            pol = IsolationPolicy.load(p)
            self.assertEqual(pol.readable, ["/opt/qw9/v3/htdocs", "/opt/qw9/v3/cgi-bin"])
            self.assertEqual(pol.uds_allowed_dir, "/opt/qw9/v3/run/uds")
            self.assertEqual(pol.httpd_user_block(), "User httpd-v3\nGroup httpd-v3\n")

    def test_marker_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(os.path.join(tmp, "p.yaml"),
                       self.POLICY.replace("/opt/qw9/markers/", "/home/x/"))
            with self.assertRaises(SpecError):
                IsolationPolicy.load(p)


class ExprTests(unittest.TestCase):
    def test_basic(self):
        axes = {"a": 1, "b": 0}
        self.assertTrue(eval_axis_expr("a == 1 or b == 1", axes))
        self.assertFalse(eval_axis_expr("a == 1 and b == 1", axes))
        self.assertTrue(eval_axis_expr("a == 1 and not (b == 1)", axes))

    def test_missing_axis_defaults_zero(self):
        self.assertFalse(eval_axis_expr("ghost == 1", {}))

    def test_reject_injection(self):
        with self.assertRaises(SpecError):
            eval_axis_expr("__import__('os').system('id')", {})


class AdapterAxesTests(unittest.TestCase):
    def test_parse(self):
        out = "hello\na=1\nexec_user=uid=0(root)\nb = 2\n"
        axes = parse_adapter_axes(out)
        self.assertEqual(axes, {"a": "1", "exec_user": "uid=0(root)"})


class VerdictTests(unittest.TestCase):
    def test_ok_and_reject(self):
        v = make_verdict("r1", "CVE-X", "v3", "VALID", "GOAL_NOT_OBSERVED",
                         ["permission_denied"], {"a": 1}, ["e.txt"], "ov1")
        self.assertEqual(v["schema"], "qw9/verdict/v1")
        with self.assertRaises(SpecError):
            make_verdict("r1", "CVE-X", "v3", "MAYBE", "GOAL_REACHED",
                         [], {}, [], "ov1")
        with self.assertRaises(SpecError):
            make_verdict("r1", "CVE-X", "v3", "VALID", "MAYBE",
                         [], {}, [], "ov1")


if __name__ == "__main__":
    unittest.main()
