# A2 监管 Agent（提交件）

> 按团队《千相-作品设计文档-v3》实现的 A2：**只负责“守”**。持有规则与阈值，组织功能一致性验证，审批 A1 的申请单，拦截越界动作，封存证据；不产生变体，不参与打分。

## 1. 五项值守与实现

| 值守 | 文档要求 | 实现 |
|---|---|---|
| 规则与阈值唯一持有者 | 判定规则、差异阈值、重试上限写在 A2 侧，A1/A3 只读 | `rules.py`：规则哈希冻结（G0），改规则即失效 |
| 功能一致性组织者 | 七项业务能力全过才签 G2 | `gate.py`：7 项能力校验，缺一即淘汰 |
| 申请单审批者 | A1 构建/装隔离/打靶前交申请单，A2 放行/拒绝/要求补证据 | `approvals.py`：`build/isolate/target/expand` 四类审批 |
| 越界拦截者 | 改分数/改源码/改规则、G4 未过扩平台 → 拒绝并留痕 | `approvals.py`：规则字段直接拒绝；G4 前 `target/expand` 拒绝 |
| 证据封存者 | 每轮前归档旧证据，判定前校验 run_id，二进制缺失即失败 | `evidence.py`：归档 + run_id 绑定 + 新鲜度/二进制校验 |

## 2. 目录

```text
A2-监管Agent提交/
  说明文档/
    A2-监管Agent-README.md
    A2-监管Agent-设计说明.md
    A2-监管Agent-接口契约.md
    接入示例/                  # 申请单、放行记录、时间线 schema
    运行证据/                  # 本次 demo 的输出、timeline、gates、decisions
  项目源码/
    a2_gatekeeper/             # 6 个模块 + 6 个单测
    demo/                      # 可跑的端到端 demo
  历史版本/
    20261104-supervisor-v1.zip # 旧“执行编排”实现，留档
```

## 3. 快速开始

```bash
cd 项目源码
python demo/run_demo.py
python -m unittest discover -s a2_gatekeeper/tests -v
```

demo 的预期结果：

```text
freeze            -> G0 冻结
request build V2  -> approve
request target V2 -> reject（G4 未过）
gate              -> G0-G4 全过
request target V2 -> approve
begin run         -> 旧证据归档
check             -> pass（run_id、二进制、新鲜度）
```

本次实跑 6 条 timeline，见 `说明文档/运行证据/demo-output.txt` 与 `timeline.jsonl`；6 个单测全部通过。

## 4. 与 A1 / A3 的边界

| 角色 | 能写 | 不能写 |
|---|---|---|
| A1 执行 | 产物目录、交付目录、申请单 | 分数、规则、阈值 |
| **A2 监管** | 规则与冻结哈希、放行记录、时间线、证据封存 | 分数、变体、证据原件 |
| A3 评估 | 评分、判定文件、报告 | 规则、证据原件 |

A2 不读 A3 的分数来决定放行；G4 是否通过只看机器可读的差异结果，不看“结论写得好不好”。

## 5. 边界与已知限制

- 本实现是 A2 的**门禁层 MVP**：覆盖 G0-G4、审批、归档、run_id 校验；七项能力的**探针执行**仍由 A1 的测试脚本产出结果文件，A2 负责校验与放行；
- 未实现：与 A1 的在线 RPC（当前用 JSON 文件/CLI 交互）、跨机时间线、规则的可视化编辑；
- 不宣称“过了 A2 就一定安全”：A2 只保证流程约束与证据新鲜，不保证漏洞一定被阻断。
