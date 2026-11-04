# A2 监管 Agent · 设计说明

> 对应《千相-作品设计文档-v3》第 3.2 节与表 8/表 9。A2 的产物是**约束**，不是变体，也不是分数。

## 1. 为什么需要 A2

如果“定义标准”和“交结果”在同一个人手里，标准会随结果移动。A2 把三样东西拿走并锁住：

- 判定规则与阈值；
- 重试上限；
- 证据的封存与 run_id 绑定。

A1 只能申请，A3 只能读，A2 只放行或拒绝。这样“我们的 V3 不是挑出来的”“没有因结果不好看重跑”就不再是口头承诺，而是可检查的记录。

## 2. 五项值守的机制

### 2.1 规则与阈值唯一持有者

`rules.json` 是唯一规则源，包含：

- `thresholds.max_retries`：同一 `action+target` 的放行上限；
- `thresholds.min_differences`：G4 需要的最少独立差异数；
- `functional.capabilities`：七项业务能力清单；
- `allowed_variants`：允许的变体标识。

冻结（G0）时对规则做规范化 JSON 的 SHA256，写入 `state/freeze.json`。之后任何修改都会让哈希不匹配，A2 拒绝继续，直到显式重新冻结（重新冻结会写时间线，谁改的、什么时候改的都留痕）。

### 2.2 功能一致性组织者（G2）

七项能力：静态文件、CGI、Lua、正向代理、反向代理、Rewrite、Headers。A2 校验 A1 提交的 `functional.json`：

- `run_id` 必须存在；
- 七项能力必须全部 `pass`；
- 缺项、失败项都直接淘汰，不进入打靶。

A2 不修改能力定义；能力清单在规则里，规则已冻结。

### 2.3 申请单审批者

A1 在四类动作前提交申请单：

| action | 说明 | 审批条件 |
|---|---|---|
| `build` | 构建候选 | 已冻结；未超重试上限 |
| `isolate` | 装隔离 | 已冻结；未超重试上限 |
| `target` | 开始打靶 | **G4 已通过** |
| `expand` | 扩平台/扩候选 | **G4 已通过** |

返回三种决策：`approve / reject / need_evidence`。当前 MVP 的 `need_evidence` 预留给“申请单缺参数”的场景，默认走 `reject` 并写明原因。

### 2.4 越界拦截者

以下请求直接拒绝并写时间线：

- 申请单里出现 `rules`、`rules_patch`、`thresholds` 字段（A1 试图改规则）；
- `target/expand` 在 G4 未通过时提交；
- 同一 `action+target` 放行次数达到 `max_retries`。

拒绝记录包含 `reason` 与原始申请单，A3 和复核者可查。

### 2.5 证据封存者

`begin` 做三件事：

1. 把上一轮 `evidence/` 整体移到 `state/archive/<时间戳>/`；
2. 新建空 `evidence/`；
3. 写 `state/runs/<run_id>.json`，记录 `started_at`。

`check` 在判定前做三项校验：

- `run_id` 有 `begin` 记录；
- 二进制存在（并计算 SHA256）；
- 证据文件非空，且 `mtime` 不早于本轮开始（容差 2 秒）。

任一不满足即失败，不允许用上一轮证据兜底。

## 3. 门禁 G0–G4

| 门 | 检查 | 失败处理 |
|---|---|---|
| G0 规格冻结 | 规则哈希与冻结记录一致 | 拒绝所有申请 |
| G1 环境 | `state/env.json` 存在（干净构建树、端口、挂载） | 拒绝启动 |
| G2 功能一致性 | 七项能力全过 + run_id | 候选淘汰 |
| G3 本轮对照 | `v1_positive` 与 `fixed_negative` 同时为真 | 暂停比较 |
| G4 差异成立 | 至少 3 个独立差异 | 禁止 `target/expand` |

G3/G4 的数据来自 A1 的测试结果文件，A2 只做机器校验，不读叙述性结论。

## 4. 时间线

`state/timeline.jsonl`，append-only，每行：

```json
{"ts":"...","seq":1,"actor":"A2","action":"approval","target":"V2","result":"approve","detail":{...}}
```

覆盖：`approval`、`gate`、`archive`、`evidence_check`。它不记录 A3 的评分，评分由 A3 自己的判定文件承载。

## 5. 与文档的对应

| 文档要求 | 本实现 |
|---|---|
| 表 8 七项业务能力 | `rules.functional.capabilities` + `gate.py` |
| 表 9 申请单/放行记录 | `approvals.py` + `decisions.jsonl` |
| 表 6 六道门禁 | `gate.py` 的 G0–G4（G5 证据完整由 `evidence.check` 承担） |
| “规则冻结哈希握在 A2 手里” | `freeze.json` 的 SHA256 |
| “每轮前归档旧证据” | `evidence.begin` |
| “判定前校验 run_id” | `evidence.check` |

## 6. 失败处理

- 规则被改：G0 失败，所有申请拒绝，提示重新冻结；
- 七项能力缺项：G2 失败，候选淘汰；
- G4 未过：`target/expand` 拒绝，A1 只能补差异或停在当前阶段；
- 二进制缺失/证据过期：`check` 失败，A3 不得出分；
- 重试超限：拒绝，并要求人工介入。

## 7. 已知限制

1. 七项能力的探针执行由 A1 的测试脚本完成，A2 只校验结果文件；若要 A2 亲自执行，需要在规则里配置命令并增加沙箱；
2. 审批交互目前是 JSON 文件 + CLI，不是常驻服务；
3. 未实现跨机时间线、规则可视化、A1/A3 的在线 RPC；
4. A2 不判断“变体是否真的更安全”，只保证流程与证据满足预注册约束。
