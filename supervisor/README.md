# 变体流水线监管 Agent（MVP）

一个**可运行的**监管 Agent：执行构建/功能/安全三个阶段，失败时诊断并做有边界的处置（重试、清理、回滚、升级人工），最后审计证据新鲜度与完整性，全程写 `journal.jsonl`。

设计原则：**Agent 只有处置权，没有判定权。** 漏洞是否命中、功能是否等价，由脚本退出码和审计规则决定。

## 快速开始

```bash
# 1. 重置 demo 状态（制造一次端口冲突）
python demo/reset.py

# 2. 运行受监管流水线
python -m variant_supervisor run --config supervisor.pipeline.json

# 3. 查看决策日志
python -m variant_supervisor report --journal demo/logs/journal.jsonl --limit 8
```

预期输出：

```text
[supervisor] build attempt 1/3
[supervisor] build FAIL cause=PORT_CONFLICT action=clean (rule)
[supervisor] build attempt 2/3
[supervisor] build OK (0.09s, 1.9 MB)
[supervisor] functional OK
[supervisor] security OK
[supervisor] audit OK
[supervisor] verdict=PASS retries=1
```

demo 的第一次构建会打印 `Address already in use`；监管 Agent 识别为 `PORT_CONFLICT`，执行 `clean_cmd`，重试后成功。

### 演示“证据审计失败 → 自动重跑”

```bash
python demo/reset.py
DEMO_SECURITY_SKIP_NEGATIVE_ONCE=1 python -m variant_supervisor run --config supervisor.pipeline.json
```

第一次 security 故意不写 `negative.ok`，审计失败后 Agent 自动重跑 security，第二次补齐证据，最终 `PASS`。

## 事件流模式（接入已有流水线）

如果构建/测试脚本已经在别处运行，可以让它们写 JSONL 事件，监管 Agent 只消费事件：

```bash
python -m variant_supervisor watch \
  --config supervisor.pipeline.json \
  --events demo/events.sample.jsonl \
  --execute-clean
```

事件格式：

```json
{"type":"stage_fail","stage":"build","exit_code":1,
 "timed_out":false,"log_too_big":false,"rss_exceeded":false,
 "duration_sec":0.5,"peak_rss_mb":10,"log":"logs/build.log"}
```

`watch` 会诊断每条 `stage_fail`，写 `watch_diagnosis`；加 `--execute-clean` 时，
若诊断动作为 `clean`，会执行配置里的 `clean_cmd`。加 `--follow` 可持续跟踪文件。

## 架构

```text
            ┌──────────────────────────────┐
            │        SupervisorAgent        │
            │  run_id · journal · budget   │
            └──────────────┬───────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   StageRunner        Policy/LLM          Audit
   watchdog           diagnosis           evidence
   timeout/RSS/log    retry/clean/        fresh? complete?
   process tree       rollback/escalate   expected values?
        │                  │                  │
        └──────────────────┴──────────────────┘
                           ▼
                    journal.jsonl
```

## 目录

```text
variant_supervisor/
  config.py      # JSON 配置加载与路径解析
  watchdog.py    # 子进程执行、超时、RSS、日志上限、进程树清理
  policy.py      # 规则诊断 + 预算降级 + LLM 结果校验
  llm.py         # 可选 OpenAI 兼容接口（默认关闭）
  audit.py       # 证据存在性、新鲜度、JSON 字段校验
  snapshot.py    # 源码目录快照与回滚
  watch.py       # 外部事件流诊断（watch 模式）
  agent.py       # 状态机：阶段、重试、审计、最终裁决
  journal.py     # append-only JSONL 决策日志
  cli.py         # run / report / audit / watch
supervisor.pipeline.json   # demo 配置
demo/                      # 可运行的假流水线
tests/test_policy.py       # 规则与 LLM 校验单测
```

## 配置说明

```json
{
  "project": "demo-apache-44224",
  "base_dir": ".",
  "workdir": "demo/work",
  "log_dir": "demo/logs",
  "evidence_dir": "demo/evidence",
  "snapshot_dirs": ["demo/work/src"],
  "clean_cmd": ["{python}", "demo/clean.py"],
  "stages": [
    {"name": "build", "cmd": ["{python}", "demo/fake_build.py"],
     "timeout": 10, "retries": 2},
    {"name": "functional", "cmd": ["{python}", "demo/fake_functional.py"],
     "timeout": 10, "retries": 1, "snapshot": false}
  ],
  "audit": {
    "required": ["functional.ok", "security.json", "negative.ok"],
    "max_age_sec": 300,
    "expected_json": {"security.json": {"verdict": "pass"}}
  },
  "budgets": {"max_stage_retries": 2, "max_total_retries": 5,
              "max_log_mb": 2, "max_rss_mb": 256}
}
```

- `{python}` 会替换为当前解释器路径，避免 Windows/Linux 的 `python`/`python3` 差异。
- `cmd` 直接 `exec`，不经过 shell；需要 shell 时显式写 `["bash", "-lc", "..."]`。
- `clean_cmd` 只在诊断出 `PORT_CONFLICT`/日志超限等可清理场景时执行。
- `snapshot` 默认 `true`；对只读阶段（functional/security）设为 `false`，避免重复拷贝大源码树。
- 配置读取兼容 UTF-8 BOM（Windows 记事本保存的 JSON 也能直接跑）。

## 诊断与动作

| 现象 | cause | 动作 |
|---|---|---|
| `Address already in use` | `PORT_CONFLICT` | `clean` 后重试 |
| 超时 | `TIMEOUT` | 重试，预算用完升级人工 |
| RSS 超限 / exit 137 | `OOM` | 升级人工 |
| `No such file` / `Permission denied` | `MISSING_DEP` / `PERMISSION` | 升级人工 |
| `undefined reference` | `LINK_ERROR` | 重试 |
| 普通编译错误 | `BUILD_ERROR` | 重试 |
| 测试断言失败 | `TEST_FAIL` | 重试 |

所有动作写 journal；重试次数受 `max_stage_retries` 与 `max_total_retries` 双重限制，用尽后 `NEEDS_HUMAN`。

## 证据审计

审计不是“看文件在不在”，而是：

1. 必填文件存在且非空；
2. mtime 晚于本轮开始（防止旧 PASS 复用）；
3. 未超过 `max_age_sec`；
4. `expected_json` 中的关键字段符合预期（例如 `"verdict": "pass"`）。

审计失败时，若还有预算，自动重跑 `security` 阶段一次；仍失败则 `NEEDS_HUMAN`。

## 启用 LLM 诊断（可选）

默认纯规则，离线可跑。启用：

```bash
export DEEPSEEK_API_KEY=sk-...
# 修改 supervisor.pipeline.json：
# "llm": {"enabled": true, "model": "deepseek-chat",
#         "base": "https://api.deepseek.com/v1",
#         "api_key_env": "DEEPSEEK_API_KEY"}
```

LLM 只返回 `{cause, action, confidence, rationale}`；只有 `confidence >= 0.65` 且动作在白名单内才会被采纳，否则回退规则。LLM 的原始返回也会写入 journal，便于审计。

## 接入真实流水线

把 `stages` 换成你的命令即可：

```json
{"name": "build", "cmd": ["bash", "cve/apache/build/build.sh", "2.4.49"], "retries": 1},
{"name": "functional", "cmd": ["bash", "tests/functional.sh"], "retries": 1},
{"name": "security", "cmd": ["bash", "cve/apache/poc/CVE-2021-44224/verify.sh"], "retries": 1}
```

要求：

- 每个阶段用**退出码**表达成败；
- 证据写入 `evidence_dir`，文件名与 `audit.required` 对齐；
- 负向对照单独产出一个标记文件（如 `negative.ok`），审计会检查它是否本轮生成；
- 不要在脚本里 `exit 0` 掩盖失败——监管 Agent 只看退出码和证据，不读你的“结论”。

## 边界与后续

- 这不是沙箱：`clean_cmd` 只应做安全的本地清理（删 pid、解端口），不要 `pkill -9` 全系统。
- 不自动安装依赖：缺依赖会升级人工，避免污染评测环境。
- 回滚只覆盖 `snapshot_dirs`，大源码树请谨慎配置。
- 下一步可加：多候选变体并行、Web 看板、与生成 Agent 的 `variant_spec` 对接、跨机器事件总线。

## 测试

```bash
python -m unittest discover -s tests -v
```

共 19 个单测，覆盖：配置校验、端口冲突清理、超时重试/升级、缺依赖升级、LLM 低/高置信度、LLM HTTP 解析、证据缺失/过期/字段错误、旧证据复用、启动失败、快照回滚、watch 事件诊断。


