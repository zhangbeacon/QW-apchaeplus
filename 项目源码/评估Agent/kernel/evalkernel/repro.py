"""异构分化熵的稳定性门（行为指纹熵）—— 千相设计文档 §2.9 / §5.4。

对候选 i 以同一配方重复 K 轮（构建 + 同一攻击用例），每轮得到一个行为指纹：
判定文件四层字段（validity、goal、phenotypes、三轴/state/Y/crash）的规范化
哈希——不含时间戳、路径、进程号等噪声字段（文档 §2.9 明文要求）。

    H(i) = − Σ p_k · log p_k / log K        归一化到 [0,1]

  H = 0：K 轮完全一致 → 分化是"真的"；
  H 越大：结果越分散 → 该候选与 V1 的分化可能只是抖动。

门禁阈值（设计取 0.15）：超过的候选，其分化不计入证据。
**计算者与使用者分离**：A3（repro 模块）只输出 H 值与门禁结论，执行权在 A2。
产物落在 hde.json 的 reproducibility 段，并随 scores.json 的 detail.stability
透出（qw9/scores/v1 契约）。
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict

FIELDS = ("cve", "probe", "validity", "goal_outcome", "phenotypes",
          "state", "Y", "crash")
DEFAULT_THRESHOLD = 0.15


def round_fingerprints(classified: list[dict],
                       variants: list[str] | None = None) -> dict[str, list[str]]:
    """{variant: [fp_轮1, fp_轮2, ...]} —— 每轮一个指纹，按轮号排序。"""
    by: dict[tuple, list] = defaultdict(list)
    for r in classified:
        if not r.get("valid", True):
            continue
        if r.get("group", "A+") != "A+":
            continue  # 行为指纹只取攻击探针；阴性对照不属于攻击行为
        if variants is not None and r.get("variant") not in variants:
            continue
        key = (r.get("variant"), r.get("repeat", 1))
        by[key].append({k: r.get(k) for k in FIELDS})
    fps: dict[str, list[str]] = defaultdict(list)
    for (v, rep), rows in by.items():
        canon = json.dumps(sorted(rows, key=lambda x: (x["cve"], x["probe"])),
                           sort_keys=True, ensure_ascii=False,
                           separators=(",", ":"))
        fps[v].append((rep, hashlib.sha256(canon.encode("utf-8")).hexdigest()))
    for v in fps:
        fps[v] = [h for _, h in sorted(fps[v])]
    return fps


def entropy_h(fps: list[str]) -> dict:
    K = len(fps)
    if K < 2:
        return {"H": None, "reason": "K_LESS_THAN_2", "K": K,
                "distinct": K, "gate_pass": None}
    cnt = Counter(fps)
    m = len(cnt)
    if m == 1:
        return {"H": 0.0, "K": K, "distinct": 1, "gate_pass": True,
                "distribution": {k[:12]: n for k, n in cnt.items()}}
    H = min(1.0, -sum((n / K) * math.log(n / K)
                      for n in cnt.values()) / math.log(K))
    return {"H": H, "K": K, "distinct": m, "gate_pass": H <= DEFAULT_THRESHOLD,
            "distribution": {k[:12]: n for k, n in cnt.items()}}


def reproducibility(classified: list[dict], threshold: float = DEFAULT_THRESHOLD,
                    variants: list[str] | None = None) -> dict:
    fps = round_fingerprints(classified, variants)
    out = {}
    for v, fl in fps.items():
        r = entropy_h(fl)
        r["threshold"] = threshold
        if r["H"] is not None:
            r["gate_pass"] = r["H"] <= threshold
        out[v] = r
    return out
