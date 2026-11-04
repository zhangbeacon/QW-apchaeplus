# 评估 Agent · 接口契约

## 1. 配置（assessment.config.json）

```json
{
  "engagement": {
    "name": "demo-assessment",
    "target": "https://app.example.com",
    "authorization": "书面授权编号 DEMO-2026-001",
    "scope": ["app.example.com", "192.0.2.0/24"],
    "out_of_scope": ["admin.example.net"],
    "mode": "read-only",
    "test_account": null
  },
  "tooling": {
    "des_request": {"key_env": "REQ_KEY", "iv_env": "REQ_IV"},
    "browser": {"cdp_port": 9222, "node_min": 21}
  },
  "limits": {
    "max_requests_per_intent": 150,
    "max_login_attempts": 3,
    "max_samples_per_finding": 2,
    "forbid": ["write", "delete", "sms", "email", "bruteforce"]
  },
  "output": {
    "findings": "evidence/findings.json",
    "assessment": "evidence/assessment.json",
    "journal": "evidence/journal.jsonl"
  }
}
```

约束：

- `mode` 目前仅支持 `read-only`；其它取值直接拒绝加载；
- `forbid` 中的动作类型由执行 Agent 与自检脚本共同强制，`evidence_lint.py` 发现相关步骤直接判 fail；
- `scope` 之外的目标，执行 Agent 必须在第一步就拒绝并记录 `scope_reject` 事件。

## 2. 阶段事件（assessment_event）

评估作为独立阶段挂载时，事件沿用 `接入示例/stage_event.schema.json` 的 `type / stage` 基础字段，并扩展：

```json
{"type":"assessment_done","stage":"assessment","verdict":"pass","findings":12,"counts":{"high":3,"medium":5,"low":4},"duration_sec":8.4}
{"type":"assessment_fail","stage":"assessment","issues":[{"kind":"missing_steps","detail":"F-003 has empty reproducibleSteps"}],"source":"lint"}
```

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `type` | string | 是 | `assessment_done` / `assessment_fail` |
| `stage` | string | 是 | 固定 `assessment` |
| `verdict` | string | 否 | `pass` / `fail` |
| `findings` | int | 否 | 入库 finding 数 |
| `counts` | object | 否 | 按 severity 计数 |
| `issues` | array | 否 | 失败原因列表 |
| `source` | string | 否 | `lint` / `agent` |

## 3. findings.json

数组，每条：

```json
{
  "id": "F-001",
  "title": "未授权访问：接口按连续 ID 读取他人业务记录",
  "severity": "high",
  "asset": "https://app.example.com/api/gateway",
  "description": "影响、根因、可枚举性说明",
  "reproducibleSteps": [
    "报文①：POST /api/gateway ... （获取匿名令牌）",
    "报文②：POST /api/gateway ... （按他人记录 ID 取值）",
    "解密响应得 {\"code\":0,\"data\":[...]}"
  ],
  "evidence": {"requestRef": "evidence/raw/F-001.http", "responseSnippet": "code:0 ..."},
  "confidence": 0.95,
  "foundBy": {"intent": "intent-3", "facts": ["fact-7", "fact-9"]}
}
```

规则：

- `reproducibleSteps` 至少 1 条，且每条必须包含**可执行动作**（URL、命令或操作序列）；
- `severity` ∈ `critical / high / medium / low / info`；
- 同一 `asset + title` 不得重复；
- `confidence` 为 0..1，低于 0.6 的条目不得标记 `critical/high`。

字段级校验见 `schema/findings.schema.json`。

## 4. 证据目录

```text
evidence/
  findings.json          # 漏洞清单（见第 3 节）
  assessment.json        # 自检汇总：{"verdict":"pass","findings":12,"counts":{...},"top_risks":[...]}
  journal.jsonl          # append-only 决策与取证日志
  raw/                   # 原始报文、响应片段（脱敏后）
```

`assessment.json` 至少包含 `verdict`；`top_risks` 用于裁决侧快速定位高危项。

## 5. journal

append-only JSONL，与监管 Agent 同风格：

```json
{"ts":"2026-11-03T17:20:00+08:00","run_id":"20261103-1720-ab12","type":"intent_created","intent":"intent-1","title":"资产与服务确认","source":"agent"}
{"ts":"2026-11-03T17:21:10+08:00","run_id":"20261103-1720-ab12","type":"fact_recorded","intent":"intent-1","fact":"fact-2","kind":"http","detail":"200 OK, Server: nginx"}
{"ts":"2026-11-03T17:24:00+08:00","run_id":"20261103-1720-ab12","type":"finding_confirmed","finding":"F-001","intent":"intent-3","severity":"high"}
{"ts":"2026-11-03T17:25:30+08:00","run_id":"20261103-1720-ab12","type":"lint","verdict":"pass","findings":12}
```

事件类型：`goal_created`、`intent_created`、`fact_recorded`、`finding_confirmed`、`scope_reject`、`lint`、`run_end`。

## 6. 与监管 Agent 的交接

评估作为一个 stage：

```json
{"name": "assessment",
 "cmd": ["python", "scripts/evidence_lint.py", "--findings", "evidence/findings.json", "--out", "evidence/assessment.json"],
 "timeout": 120, "retries": 0, "snapshot": false}
```

- 审计条目：`audit.required` 增加 `assessment.json`，`expected_json` 增加 `{"assessment.json": {"verdict": "pass"}}`；
- 评估阶段的失败不触发构建回滚，只标记本轮评估无效。

## 7. 与裁决 Agent 的交接

裁决侧只读：

- `findings.json`：逐条复核可复现步骤；
- `assessment.json`：确认自检通过、计数与实际一致；
- `journal.jsonl`：确认 finding 可回溯到 intent 与 fact。

裁决不读取 README、叙事文档或口头结论。
