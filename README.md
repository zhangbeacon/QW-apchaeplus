# 监管 Agent（提交件）

> 这是「强网设计」作品里的**监管层**组件，不是整条变体生成流水线，也不负责漏洞判定。

## 1. 它解决什么

构建/功能/安全三段流水线跑起来之后，失败往往不是“代码错了”，而是端口被占、日志打满、内存超限、依赖缺失、旧证据复用。人工处理慢且不可追溯。

监管 Agent 做四件事：

1. **执行**：按配置跑阶段，带超时、RSS 上限、日志上限、进程树清理；
2. **诊断**：把失败归因到 `PORT_CONFLICT / TIMEOUT / OOM / MISSING_DEP / LINK_ERROR / TEST_FAIL` 等；
3. **处置**：在预算内做有边界的动作（重试、清理、回滚、升级人工），所有动作写 journal；
4. **审计**：检查证据是否本轮生成、是否新鲜、关键字段是否符合预期，不通过则重跑安全阶段一次。

**它只有处置权，没有判定权。** 漏洞是否命中、功能是否等价，由脚本退出码、探针和证据审计裁决。

## 2. 目录

```text
监管Agent提交/
  README.md                    # 本文件
  监管Agent-设计说明.md         # 职责、状态机、处置策略、审计规则、LLM 边界
  监管Agent-接口契约.md         # stage_event / evidence / journal / config 四套契约
  supervisor/                  # 可运行源码（12 个模块 + demo + 19 个单测）
  接入示例/                    # 真实流水线的配置与事件示例
  运行证据/
    demo-output.txt            # 本次实跑输出
    demo-journal.jsonl         # 20 条决策日志
```

## 3. 快速开始

```bash
cd supervisor
python demo/reset.py
python -m variant_supervisor run --config supervisor.pipeline.json
```

本次实跑结果：

```text
[supervisor] build FAIL cause=PORT_CONFLICT action=clean (rule)
[supervisor] build OK (0.11s, 1.9 MB)
[supervisor] functional OK
[supervisor] security OK
[supervisor] audit OK
[supervisor] verdict=PASS retries=1
```

`运行证据/demo-journal.jsonl` 是同一轮的 20 条事件，包含 `diagnosis`、`action`、`clean_result`、`audit`、`run_end`。

## 4. 接入真实流水线

两种方式：

- **直接托管阶段**：把 `supervisor.pipeline.json` 的 `stages` 换成真实命令（构建、功能、安全），每段用退出码表达成败；
- **只消费事件**：流水线自己跑，按 `接入示例/stage_event.schema.json` 写 JSONL，监管 Agent 用 `watch` 模式诊断：

```bash
python -m variant_supervisor watch \
  --config supervisor.pipeline.json \
  --events events.jsonl \
  --execute-clean
```

## 5. 边界

- 不生成变体，不决定 V2/V3 怎么构造；
- 不判定漏洞是否命中，不修改判据或阈值；
- 不自动安装依赖，不 `pkill -9` 全系统；
- 不做沙箱，只做本地安全清理；
- LLM 默认关闭，开启后仅接受高置信度、白名单内的建议。

## 6. 与团队其他部分的接口

| 上游/下游 | 交接物 |
|---|---|
| 生成 Agent → 监管 | `variant_spec.json`、每个变体的 `build_cmd` |
| 监管 → 裁决 | `journal.jsonl`、`evidence/`、审计结论 |
| 监管 → 文档 | 状态机图、处置表、审计规则、失败样本 |

接口字段见 `监管Agent-接口契约.md`。
