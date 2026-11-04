#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""findings 自检：交付前把「不可复现/不可分级/重复」的条目拦下来。

输入：符合 schema/findings.schema.json 的数组
输出：assessment.json（verdict / counts / top_risks），失败时退出码 1

用法：
  python evidence_lint.py --findings evidence/findings.json --out evidence/assessment.json
  python evidence_lint.py --findings 接入示例/findings.example.json --out /tmp/a.json
"""
import argparse
import json
import re
import sys

SEV = ["critical", "high", "medium", "low", "info"]
SEV_ORDER = {s: i for i, s in enumerate(SEV)}

# 每条复现步骤至少包含一个「可执行动作」特征
ACTION_HINT = re.compile(
    r"(POST|GET|PUT|DELETE|HEAD|OPTIONS)\s+/|curl|python|powershell|node\s|nmap|openssl|"
    r"报文|请求|命令|执行|访问|点击|解密|加密|构造|获取|携带|重放|替换|修改|设置|"
    r"查看|读取|调用|遍历|枚举|发送|返回|输入|提交|导出|比对|对照",
    re.IGNORECASE,
)

# 禁止出现在步骤里的破坏性动作
FORBIDDEN = re.compile(r"(DELETE\s+/|\brm\s+-rf|drop\s+table|truncate\s+table|"
                       r"发送短信|send\s*sms|批量导出|dump\s+all)", re.IGNORECASE)


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError("findings 必须是数组")
    return data


def lint(items):
    issues, seen = [], set()

    for idx, f in enumerate(items):
        fid = f.get("id") or f"#{idx+1}"
        for key in ("title", "severity", "description"):
            if not f.get(key):
                issues.append({"finding": fid, "kind": "missing_field", "detail": key})

        sev = f.get("severity")
        if sev not in SEV:
            issues.append({"finding": fid, "kind": "bad_severity", "detail": str(sev)})

        steps = f.get("reproducibleSteps") or []
        if not isinstance(steps, list) or not steps:
            issues.append({"finding": fid, "kind": "missing_steps", "detail": "reproducibleSteps 为空"})
        else:
            for si, s in enumerate(steps):
                if not isinstance(s, str) or len(s.strip()) < 8:
                    issues.append({"finding": fid, "kind": "weak_step", "detail": f"第 {si+1} 步过短"})
                elif not ACTION_HINT.search(s):
                    issues.append({"finding": fid, "kind": "no_action", "detail": f"第 {si+1} 步缺少可执行动作"})
                if isinstance(s, str) and FORBIDDEN.search(s):
                    issues.append({"finding": fid, "kind": "forbidden_action", "detail": s[:60]})

        if sev in ("critical", "high"):
            conf = f.get("confidence", 1.0)
            if isinstance(conf, (int, float)) and conf < 0.6:
                issues.append({"finding": fid, "kind": "low_confidence_high_sev",
                               "detail": f"confidence={conf}"})

        key = (f.get("asset", ""), f.get("title", ""))
        if key in seen:
            issues.append({"finding": fid, "kind": "duplicate", "detail": str(key)})
        seen.add(key)

    counts = {}
    for f in items:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    tops = sorted(
        [f for f in items if f.get("severity") in ("critical", "high", "medium")],
        key=lambda x: SEV_ORDER.get(x.get("severity"), 9),
    )[:3]

    return issues, counts, [{"id": t.get("id"), "severity": t.get("severity"), "title": t.get("title")} for t in tops]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    try:
        items = load(args.findings)
    except Exception as e:
        result = {"verdict": "fail", "issues": [{"kind": "load_error", "detail": str(e)}]}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(json.dumps(result, ensure_ascii=False))
        sys.exit(1)

    issues, counts, tops = lint(items)
    result = {
        "verdict": "pass" if not issues else "fail",
        "findings": len(items),
        "counts": counts,
        "top_risks": tops,
        "issues": issues,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if not issues else 1)


if __name__ == "__main__":
    main()
