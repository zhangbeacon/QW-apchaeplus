# 监管 Agent · 接口契约

## 1. 配置（supervisor.pipeline.json）

```json
{
  "project": "apache-2.4.49",
  "base_dir": ".",
  "workdir": "work",
  "log_dir": "logs",
  "evidence_dir": "evidence",
  "snapshot_dirs": ["work/src"],
  "clean_cmd": ["bash", "scripts/clean.sh"],
  "stages": [
    {"name": "build", "cmd": ["bash", "scripts/build.sh"], "timeout": 600, "retries": 1},
    {"name": "functional", "cmd": ["bash", "scripts/functional.sh"], "timeout": 120, "retries": 1, "snapshot": false},
    {"name": "security", "cmd": ["bash", "scripts/security.sh"], "timeout": 300, "retries": 1, "snapshot": false}
  ],
  "audit": {
    "required": ["functional.ok", "security.json", "negative.ok"],
    "max_age_sec": 900,
    "expected_json": {"security.json": {"verdict": "pass"}}
  },
  "budgets": {"max_stage_retries": 2, "max_total_retries": 5, "max_log_mb": 32, "max_rss_mb": 1024},
  "llm": {"enabled": false, "model": "deepseek-chat", "base": "https://api.deepseek.com/v1", "api_key_env": "DEEPSEEK_API_KEY"}
}
```

- `cmd` 直接 `exec`，不经 shell；需要 shell 时显式写 `["bash","-lc","..."]`；
- `{python}` 会替换为当前解释器；
- 只读阶段设 `"snapshot": false`，避免重复拷贝大源码树。

## 2. 外部事件（watch 模式）

流水线自己跑时，按行写 JSONL：

```json
{"type":"stage_fail","stage":"build","exit_code":1,"timed_out":false,"log_too_big":false,"rss_exceeded":false,"duration_sec":0.5,"peak_rss_mb":10,"log":"logs/build.log"}
{"type":"audit_fail","issues":[{"kind":"stale","detail":"security.json is 999s old"}],"source":"pipeline"}
```

字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `type` | string | 是 | `stage_fail` / `audit_fail` |
| `stage` | string | 是 | 阶段名，需与配置一致 |
| `exit_code` | int/null | 是 | `null` 表示无法启动 |
| `timed_out` | bool | 否 | 默认 false |
| `log_too_big` | bool | 否 | 默认 false |
| `rss_exceeded` | bool | 否 | 默认 false |
| `duration_sec` | number | 否 | 秒 |
| `peak_rss_mb` | number | 否 | MB |
| `log` | string | 是 | 相对 `base_dir` 或绝对路径 |

## 3. 证据目录

```text
evidence/
  functional.ok          # 空文件即可，表示功能测试本轮通过
  security.json          # 结构化安全结果，至少含 {"verdict":"pass"}
  negative.ok            # 负向对照本轮已生成
  manifest.json          # 可选：文件清单与 sha256
```

`security.json` 建议字段：

```json
{"verdict": "pass", "cve": "CVE-2021-44224", "variant": "V2", "hits": 5, "rounds": 5, "crashed": true}
```

审计只校验 `audit.expected_json` 中列出的键；关键结论字段必须显式列出。

## 4. journal

append-only JSONL，每行：

```json
{"ts":"2026-11-03T17:20:00+08:00","run_id":"20261103-172000-ab12","type":"diagnosis","stage":"build","attempt":1,"cause":"PORT_CONFLICT","action":"clean","confidence":0.95,"rationale":"matched /address already in use/","source":"rule"}
```

事件类型与字段见 `监管Agent-设计说明.md` 第 8 节。

## 5. 与生成 Agent 的交接

生成侧提供 `variant_spec`，监管侧只消费其中的构建入口：

```json
{
  "id": "V2",
  "profile": "asan",
  "build_cmd": ["bash", "pipeline/build_variant.sh", "v2", "/opt/qw/httpd-v2", "-O1 -g -fsanitize=address"],
  "evidence_dir": "evidence/V2",
  "runtime": {"chroot": false}
}
```

监管 Agent 不解释 `profile` 的语义，只按 `build_cmd` 执行、按 `evidence_dir` 审计。

## 6. 与裁决 Agent 的交接

裁决侧只读：

- `journal.jsonl`：确认阶段完整、重试与失败可追溯；
- `evidence/`：按四规则复核；
- `results.json`（若流水线产出）：漏洞 × 变体 × 轮次的机器结果。

裁决不得读取 `README`、LLM 叙事或口头结论。
