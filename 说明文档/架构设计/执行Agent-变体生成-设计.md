# 执行 Agent（变体生成）设计

> 三 Agent 里的 **A1**。只写它自己这一块：**干什么、按什么步骤干、代码落在哪**。
> 判定、打分、写报告不在这里——分别在**监管 Agent**和**评估 Agent**。

---

## 0. 一句话

给它一份 12 组的参数清单，它把 12 个变体造出来、编好号、存好档；等评估给出分数后，它结合分数和自己的判断挑出 V2，再配上预注册的 V3，写下"为什么是这两个"。

## 1. 边界：它做什么、不做什么

| 做 | 不做（谁做） |
|---|---|
| 读计划、展开 12 份配方 | 判分（评估 Agent） |
| 调 `qw9 build` / `qw9 isolate` 造变体 | 跑功能一致性测试（监管 Agent 组织） |
| 收 manifest、构建日志、哈希 | 改判定规则/阈值（谁都不许） |
| 记录"建成/失败/重试几次" | 修改 C 源码（谁都不许） |
| 等分、挑 V2、写选择理由 | 写报告正文（评估 Agent） |

**一句话记法**：它只负责"把东西造出来、摆整齐"，不负责"说这东西好不好"。

## 2. 输入 / 输出

| | 内容 | 存在哪 |
|---|---|---|
| 输入 | `plan.yaml`：12 组参数（编译器/优化/分配器/线程模式/加固） | `platform/plans/` |
| 输入 | 配方模板 `recipes/template.yaml` | `platform/recipes/` |
| 输入 | 源码包 `httpd-2.4.49.tar.bz2` | `cve/_downloads/` |
| 输出 | 12 个变体二进制 | `/opt/qw9/<id>/` |
| 输出 | 每个变体的 `manifest.json`（哈希、编译器、FORTIFY 符号） | `artifacts/<run_id>/<id>/` |
| 输出 | 每个变体的 `build.log`（失败时是证据） | 同上 |
| 输出 | 交付目录（V2/V3 + 选择理由） | `delivery/<run_id>/` |

## 3. 主流程（12 步，可直接照着实现）

| # | 动作 | 怎么调 | 产物 | 失败怎么办 |
|---|---|---|---|---|
| 1 | 领任务：读 `plan.yaml`，数出 12 组 | `qw9 gen plan` | 校验通过的计划 | 参数缺失/重复 → 直接报错，不猜 |
| 2 | 展开配方：模板 + 参数 → 12 份 `recipe.yaml` | `qw9 gen expand` | `recipes/gen/c1.yaml…m2.yaml` | 模板变量对不上 → 报错并列出缺的字段 |
| 3 | 逐份构建 | `qw9 build --recipe recipes/gen/<id>.yaml` | 二进制 + `manifest.json` + `build.log` | 进第 4 步 |
| 4 | 构建失败：读 `build.log` 末 200 行，判断是"缺依赖 / 参数错 / 环境问题" | 规则匹配 + 必要时模型给建议 | 重试记录 | 改参数重试 **≤3 次**；仍失败 → 标记 `BLOCKED`，跳过该候选，**不静默丢弃** |
| 5 | 装隔离（只对隔离类候选） | `qw9 isolate --recipe recipes/gen/i1.yaml` | 隔离脚本 + 自检结果 | 装不上 → `BLOCKED`，V3 不可用，必须报告 |
| 6 | 完整性自检：二进制在不在、manifest 全不全、哈希对不对 | `qw9 gen verify` | `verify.json` | 缺项 → 判"建造无效"，重跑该候选（不判性能好坏） |
| 7 | 报备：把"我要开始打靶"递交给监管 | 申请单 JSON | `journal.jsonl` 一条 | 被拒 → 停下等人，不绕过 |
| 8 | 等分：读评估产出的 `hde.json` / `safety.json` | 只读，不改 | 12 个候选的分数表 | 分不全 → 只对"有分"的候选做下一步 |
| 9 | 初筛：按分数排序，去掉没分的、被淘汰的 | — | 候选短名单 | 短名单为空 → 报 `BLOCKED`，不硬选 |
| 10 | 定 V2：结合分数 + 自己的判断，选 1 个，**写下理由** | — | `delivery/V2/selection.md` | 理由必须能指到具体分数和差异维度 |
| 11 | 定 V3：取预注册的隔离配方 `i1`，不经挑选 | — | `delivery/V3/` | 见 §4.3 |
| 12 | 交付：V2/V3 二进制 + manifest + 选择理由 + 溯源清单 | `qw9 gen deliver` | `delivery/<run_id>/` | 缺任一文件 → 不交付 |

> **第 4 步是唯一允许"改东西"的地方**，且只能改**构建参数**，不能改源码、不能改判定规则。改了什么、为什么改、改了几次，全部写进 `journal.jsonl`。

## 4. 生成策略

### 4.1 12 个候选从哪来

四根轴按"每条轴至少覆盖两个取值"展开，正好 12 个：

| 组 | 编号 | 编译器 | 优化 | 分配器 | 线程模式 | 加固 |
|---|---|---|---|---|---|---|
| 编译 | c1 | gcc | O2 | ptmalloc | event | 无 |
| 编译 | c2 | gcc | O0 | ptmalloc | event | 无 |
| 编译 | c3 | clang | O2 | ptmalloc | event | 无 |
| 编译 | c4 | clang | O0 | ptmalloc | event | 无 |
| 编译 | c5 | gcc | O2 | jemalloc | event | 无 |
| 编译 | c6 | gcc | O0 | jemalloc | event | 无 |
| 编译 | c7 | clang | O2 | jemalloc | event | 无 |
| 编译 | c8 | clang | O0 | jemalloc | event | 无 |
| 加固 | h1 | gcc | O2 + FORTIFY/SSP | ptmalloc | event | 有 |
| 加固 | h2 | clang | O2 + FORTIFY/SSP | ptmalloc | event | 有 |
| 线程 | m1 | gcc | O2 | ptmalloc | **prefork** | 无 |
| 线程 | m2 | gcc | O2 | ptmalloc | **worker** | 无 |

**为什么是这 12 个**：能一对一归因——`c1 vs c3` 只差编译器，`c1 vs c2` 只差优化，`c1 vs c5` 只差分配器，`c1 vs m1` 只差线程模式。这样"哪个变体为什么不一样"才说得清。

### 4.2 V2 怎么挑（分数 + 判断）

三条硬约束先过：

1. **必须有分**：评估给了分、且不是 `N/A`；
2. **不能和 V1 同轴**：V2 必须至少在一根轴上和 V1 不同（否则等于没变）；
3. **不能和 V3 撞**：V3 是隔离轴，V2 必须来自编译轴——两条轴不重叠。

过完约束，按分数排序，**由它自己给出前 2 名的取舍理由**：

- 为什么是 A 不是 B：分差多少、差在哪个 CVE 上；
- 这个选择的风险：如果 A 的优势只来自一条探针，要写明。

> 分数是机器算的，判断是它给的，**理由必须能溯源到 `hde.json` 里的具体字段**；写不出来就退回重写。

### 4.3 V3 为什么是预注册

V3 走**隔离轴**（独立低权用户、敏感文件 root-only、UDS 目录收口、CGI 执行身份降级）。

它**不参与上面 12 个的打分**，原因有二：

1. 隔离的收益不在"编译类"那几根轴上，分数选不出来；
2. 一旦让它参与打分，就等于"用分数去挑一个专门用来出差异的变体"，评委一眼看穿。

所以 V3 **写死在计划里**，生成 Agent 只负责造出来、过完整性自检、交付。

## 5. 失败处理

| 现象 | 处理 | 上限 | 记录 |
|---|---|---|---|
| 构建报错 | 读日志分类 → 改参数重试 | 3 次 | 原因、改了什么 |
| 构建超时 | 降并发重试一次 | 2 次 | 耗时 |
| 磁盘满 | 清理本 run 的旧日志后重试 | 1 次 | 清了多少 |
| 端口占用 | 换预分配端口段 | 自动 | 原端口/新端口 |
| 隔离装不上 | 不降级、不跳过，直接 `BLOCKED` | — | 报错原文 |
| manifest 缺项 | 判"建造无效"，整体重跑该候选 | 3 次 | 缺哪项 |
| 12 个全失败 | 停下，交人 | — | 全量日志 |

**总原则**：任何一次重试都必须留下"为什么重试"，且只允许因**环境/构建问题**重试，**不允许因"结果不好看"重跑**。

## 6. 代码结构

复用本地工作区的 `platform/src/qw9`（**代码未入库，本节目录树、函数与 CLI 均为拟建契约，不代表已实现**），只新增一个子模块：

```
platform/src/qw9/
├── domain.py      # 已有：Recipe / IsolationPolicy / sha256 / canonical_hash
├── builder.py     # 已有：build() / collect_manifest() / repro_check()
├── isolator.py    # 已有：apply() / verify_access()
├── runner.py      # 已有：Variant / launch() / run_matrix()
├── cli.py         # 已有：cmd_build / cmd_isolate / cmd_contract / cmd_matrix
└── agent/
    ├── plan.py        # 读 plan.yaml，校验 12 组不重复、字段齐全
    ├── expand.py      # 模板 + 参数 → 12 份 recipe.yaml
    ├── generate.py    # 编排：build → isolate → verify，逐个落 artifacts
    ├── verify.py      # 完整性自检（不是判分）：二进制/哈希/manifest 字段
    ├── select.py      # 读 hde.json，过三条约束，产出候选短名单 + 理由
    └── deliver.py     # 组装 delivery/，生成溯源清单
```

**关键复用点**：

| 要做的事 | 直接调 |
|---|---|
| 造一个变体 | `builder.build(recipe, artifacts_dir)` |
| 收 manifest | `builder.collect_manifest(...)` |
| 装隔离 | `isolator.apply(policy, artifacts_dir)` |
| 校验隔离 | `isolator.verify_access(policy)` |
| 读配方 | `domain.Recipe.load(path)` |

**CLI**（新增 5 个子命令）：

```bash
qw9 gen plan    --plan plans/hde12.yaml
qw9 gen expand  --plan plans/hde12.yaml --out recipes/gen
qw9 gen build   --plan plans/hde12.yaml --jobs 4
qw9 gen verify  --run-id <run_id>
qw9 gen deliver --run-id <run_id> --scores artifacts/<run_id>/hde.json
```

**配置**：`plans/hde12.yaml`（12 组参数）+ `recipes/template.yaml`（变量占位）。

## 7. 与另外两个 Agent 的接口

| 方向 | 交什么 | 格式 |
|---|---|---|
| → 监管 Agent | 每次构建/隔离的"申请单"：动作、目标、参数、预计耗时 | JSON，一行一条 |
| ← 监管 Agent | 放行 / 拒绝 / 要求补证据 | 同上，带 `decision` 字段 |
| → 评估 Agent | 12 个变体的 manifest + 构建日志（"我造了什么"） | `artifacts/<run_id>/` |
| ← 评估 Agent | `hde.json` / `safety.json`（只读，不改） | JSON |

**铁律**：A1 只读分数，**不能改分数**；A1 只写自己的产物目录，**不能碰 `status.json` / `hde.json`**。

## 8. 演示（答辩现场一条命令）

```bash
# 12 个候选全自动：展开 → 构建 → 隔离 → 自检 → 出清单
qw9 gen build --plan plans/hde12.yaml --jobs 4

# 出分后挑 V2/V3，并打印选择理由
qw9 gen deliver --run-id <run_id> --scores artifacts/<run_id>/hde.json
```

预期屏幕输出：12 行"建成/失败/重试次数" + 2 行"V2 = c3（理由…）/ V3 = i1（预注册）"。

## 9. 待定（写进文档前要和队友对一下）

1. **12 个全是编译类，V3 走预注册隔离** —— 若希望 V3 也从 12 个里挑，就得把 `i1/i2` 加进候选池（变 14 个），但会和"隔离不参与打分"打架；
2. `plan.yaml` 的 12 组是否就照 §4.1 这张表定死；
3. 构建失败时"改参数"的具体范围（允许改并发/超时，是否允许改 `--enable-*`）；
4. 第 4 步要不要接模型做日志分类——不接也能跑（规则匹配），接了只是少人工。
