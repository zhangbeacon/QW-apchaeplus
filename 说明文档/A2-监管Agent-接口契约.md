# A2 监管 Agent · 接口契约

三个 Agent 只通过 JSON 交互；A2 的读写边界：只写 `state/`（规则冻结、放行记录、时间线、归档），不改 A1 产物与 A3 评分。

## 1. 规则 `rules.json`（A2 持有）

```json
{
  "version": "1.0",
  "thresholds": {"max_retries": 3, "min_differences": 3, "entropy_max": 0.15},
  "allowed_variants": ["V1", "V2", "V3"],
  "functional": {
    "capabilities": [
      {"id": "static", "probe": "GET /index.html", "expect": "200 + marker"},
      {"id": "cgi", "probe": "GET /cgi-bin/env.sh", "expect": "200 + env"},
      {"id": "lua", "probe": "POST /parse.lua", "expect": "200 + fields"},
      {"id": "forward_proxy", "probe": "GET via proxy", "expect": "200 + body"},
      {"id": "reverse_proxy", "probe": "GET /uds/", "expect": "200 + body"},
      {"id": "rewrite", "probe": "GET /rewrite/", "expect": "mapped path"},
      {"id": "headers", "probe": "GET /index.html", "expect": "security headers"}
    ]
  }
}
```

冻结后任何字段变化都会让 `freeze.json` 的哈希失配，A2 拒绝继续。

## 2. 申请单（A1 → A2）

```json
{
  "action": "build | isolate | target | expand",
  "target": "V2",
  "params": {"cflags": "-O2 -g"},
  "eta": "300s",
  "requester": "A1"
}
```

禁止字段：`rules`、`rules_patch`、`thresholds`（出现即拒绝）。

## 3. 放行记录（A2 → A1/A3）

```json
{
  "id": "dec-20261104-193201-0304",
  "ts": "2026-11-04T19:32:01+08:00",
  "request": {"action": "build", "target": "V2", "params": {}, "eta": "300", "requester": "A1"},
  "decision": "approve | reject | need_evidence",
  "reason": "ok"
}
```

写入 `state/decisions.jsonl`，同时追加到 `state/timeline.jsonl`。

## 4. 功能一致性结果（A1 产出，A2 校验）

```json
{
  "run_id": "run-001",
  "variant": "V2",
  "capabilities": [
    {"id": "static", "pass": true},
    {"id": "cgi", "pass": true},
    {"id": "lua", "pass": true},
    {"id": "forward_proxy", "pass": true},
    {"id": "reverse_proxy", "pass": true},
    {"id": "rewrite", "pass": true},
    {"id": "headers", "pass": true}
  ]
}
```

`id` 必须覆盖规则里的七项；任一 `pass=false` 或缺项，G2 失败。

## 5. 差异结果（A1 产出，A2 用于 G3/G4）

```json
{
  "v1_positive": true,
  "fixed_negative": true,
  "vulns": [
    {"cve": "CVE-2021-41773", "v1": "exec", "v2": "exec", "v3": "blocked", "difference": true},
    {"cve": "CVE-2021-44224", "v1": "ssrf", "v2": "ssrf", "v3": "blocked", "difference": true},
    {"cve": "CVE-2021-44790", "v1": "crash", "v2": "crash", "v3": "blocked", "difference": true}
  ]
}
```

`difference=true` 的独立根因数量 ≥ `min_differences` 才过 G4。

## 6. 门禁状态 `state/gates.json`

```json
{
  "G0": {"pass": true, "reason": "spec frozen"},
  "G1": {"pass": true, "reason": "clean build/env manifest present"},
  "G2": {"pass": true, "reason": "7/7 capabilities pass", "run_id": "run-001"},
  "G3": {"pass": true, "reason": "V1 positive + fixed negative present"},
  "G4": {"pass": true, "reason": "3 independent differences"}
}
```

## 7. 运行元数据 `state/runs/<run_id>.json`

```json
{
  "run_id": "run-001",
  "started_at": 1793791921.89,
  "started_iso": "2026-11-04T19:32:01+08:00",
  "evidence_dir": ".../evidence",
  "binary_sha256": "..."
}
```

`binary_sha256` 由 `check` 在验证二进制时补写。

## 8. 时间线 `state/timeline.jsonl`

```json
{"ts":"2026-11-04T19:32:01+08:00","seq":1,"actor":"A2","action":"approval","target":"V2","result":"approve","detail":{"id":"dec-...","reason":"ok"}}
```

`action` 取值：`approval`、`gate`、`archive`、`evidence_check`。

## 9. CLI

```text
a2 freeze   --rules rules.json --state state
a2 status   --rules rules.json --state state
a2 request  --rules rules.json --state state --action build --target V2 [--param k=v] [--eta 300]
a2 functional --state state --results functional.json
a2 gate     --rules rules.json --state state [--functional functional.json] [--results results.json]
a2 begin    --state state --evidence evidence --run-id run-001
a2 check    --state state --run-id run-001 --evidence evidence [--binary path]
a2 timeline --state state
```

退出码：`0` 通过；`2` 拒绝/校验失败；`1` 参数错误。
