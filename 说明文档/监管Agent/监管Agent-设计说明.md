# 监管 Agent · 设计说明

## 1. 定位与职责边界

监管 Agent 位于“执行层”和“裁决层”之间，负责把一条构建/测试流水线跑稳、跑可追溯，但不参与安全结论。

| 能做 | 不能做 |
|---|---|
| 执行阶段、设置超时/RSS/日志上限 | 判定漏洞是否命中 |
| 归因失败、选择处置动作 | 修改判据、阈值、证据要求 |
| 重试、清理、回滚、升级人工 | 生成 V2/V3 变体 |
| 采集并审计证据 | 用 LLM 的叙述替代机器判据 |
| 写 append-only journal | 复用上一轮 PASS |

一句话：**只有处置权，没有判定权。**

## 2. 运行级状态

```text
RUNNING ──全部阶段 ok──► 证据审计 ──通过──► PASS
   │                        │
   │                        ├─失败且还有预算─► 重跑 security 一次 ──► 审计
   │                        └─失败且无预算──► NEEDS_HUMAN
   ├─动作 abort────────────────────────────► ABORTED
   ├─动作 escalate─────────────────────────► NEEDS_HUMAN
   └─预算耗尽──────────────────────────────► NEEDS_HUMAN
```

| 状态 | 含义 |
|---|---|
| `RUNNING` | 正在执行阶段 |
| `PASS` | 全部阶段成功且证据审计通过 |
| `FAIL` | 不可重试的阶段失败或未预期异常 |
| `NEEDS_HUMAN` | 预算耗尽、审计不通过、需要人工介入 |
| `ABORTED` | 中止动作或键盘中断 |

## 3. 阶段级状态

`pending / ok / escalated / clean_failed / retries_exhausted / budget_exhausted / aborted`

每个阶段的 `attempts`、`exit_code`、`duration_sec`、`peak_rss_mb` 都写入 journal。

## 4. 失败归因与处置

| 现象 | cause | action |
|---|---|---|
| `Address already in use` | `PORT_CONFLICT` | `clean` 后重试 |
| 阶段超时 | `TIMEOUT` | `retry` |
| 日志超上限 | `LOG_OVERFLOW` | `clean` |
| RSS 超限 / exit 137 | `OOM` | `escalate` |
| 命令无法启动 | `SPAWN_ERROR` | `escalate` |
| `No such file` | `MISSING_DEP` | `escalate` |
| `Permission denied` | `PERMISSION` | `escalate` |
| 缺头文件 | `MISSING_HEADER` | `escalate` |
| `undefined reference` | `LINK_ERROR` | `retry` |
| 校验和不匹配 / 补丁失败 | `PATCH_FAILED` | `rollback` |
| 断言失败 | `TEST_FAIL` | `retry` |
| 普通编译错误 | `BUILD_ERROR` | `retry` |
| 无已知特征 | `UNKNOWN` | `retry`（低置信度） |

规则按顺序匹配；超时、日志超限、RSS 超限、exit 137、无法启动优先于文本规则。预算用尽时 `retry/clean/rollback` 统一降级为 `escalate`。

## 5. 预算

| 预算 | 默认 | 作用 |
|---|---|---|
| `max_stage_retries` | 2 | 单阶段重试上限 |
| `max_total_retries` | 5 | 整轮重试上限 |
| `max_log_mb` | 8 | 单阶段日志上限 |
| `max_rss_mb` | 1024 | 单阶段峰值内存上限 |

每次 `retry/clean/rollback` 消耗一次全局预算；审计失败后的 security 重跑也消耗一次。

## 6. 证据审计

审计回答四个问题：在不在、是不是本轮的、新不新、值对不对。

1. 必填文件存在且非空；
2. `mtime` 晚于本轮开始（容差 2 秒）；
3. 未超过 `max_age_sec`；
4. `expected_json` 关键字段符合预期（如 `verdict=pass`）。

审计失败且还有预算时，自动重跑 `security` 一次并重新审计；仍失败则 `NEEDS_HUMAN`。负向对照（`negative.ok`）必须本轮生成，不能复用。

## 7. LLM 诊断的边界

- 默认关闭，纯规则离线可跑；
- 只接受 `{cause, action, confidence, rationale}`；
- 仅当 `confidence ≥ 0.65` 且 `action` 在白名单 `{retry, clean, rollback, abort, escalate}` 内才采纳；
- LLM 原始返回写入 journal，但不进证据目录；
- LLM 不得改判据、阈值、证据要求，也不得直接给 PASS/FAIL。

## 8. journal

append-only JSONL，每行含 `ts`、`run_id`、`type`。事件类型：

`run_start / snapshot / stage_start / stage_result / stage_ok / diagnosis / llm_diagnosis / llm_unavailable / budget_exhausted / action / clean_result / audit / run_end / run_crash / watch_*`

`stage_result` 记录 `exit_code`、`timed_out`、`log_too_big`、`rss_exceeded`、`duration_sec`、`peak_rss_mb`、`log`。

## 9. 与生成/裁决的交接

- **生成 → 监管**：`variant_spec` 给出每个变体的构建命令、模块集合、运行约束；
- **监管 → 裁决**：`evidence/` + `journal.jsonl` + 审计结论；裁决只读这些，不看 README；
- **监管 → 文档**：本文件的状态机、处置表、审计规则，以及失败样本（journal 里的 `diagnosis/action` 对）。

## 10. 已知限制

1. 不是沙箱：`clean_cmd` 只应做安全本地清理；
2. 不自动装依赖，缺依赖升级人工；
3. 回滚只覆盖 `snapshot_dirs`；
4. 当前实现为单机 CLI，未做多候选并行与跨机事件总线；
5. 单测 19 项，覆盖配置、端口冲突、超时、缺依赖、LLM 门控、证据缺失/过期/字段错误、快照回滚、watch 诊断。
