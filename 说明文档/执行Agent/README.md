# 执行 Agent（A1）

> 这是「强网设计」作品里的**生成层**组件：把一份 12 组参数的计划，变成 12 份可归因的配方、构建产物和一份交付目录。它不判分、不写结论。

## 1. 它解决什么

变体造得越多，越难说清"差异到底来自哪里"；造得越少，又越像碰运气。A1 的办法是：**不挑一个能出差异的，而是设计一组可归因的**。

它做四件事：

1. **展开**：读 `plan.yaml`，把四根轴（编译器 / 优化级别 / 分配器 / 线程模式）展开成 12 个候选，任意两个相邻候选只差一个因素；
2. **构建**：逐份 `build`（隔离类候选追加 `isolate`），收 `manifest.json`、`build.log`、逐文件哈希；
3. **自检**：查二进制在不在、哈希对不对、manifest 覆盖全不全、FORTIFY 符号是否真的链进来、隔离是否装得上——**判定"建造是否有效"，不判"好不好"**；
4. **挑选与交付**：等评估 Agent 给分后，在三条硬约束下挑出 V2，配上预注册的 V3，写下能溯源到具体分数字段的选择理由。

**它只有提案权，没有判定权。** 判分归评估 Agent，测试组织归监管 Agent，判定规则谁都不许改。

## 2. 目录

```text
说明文档/执行Agent/
  README.md                  # 本文件
  执行Agent-设计说明.md       # 12 步主流程、候选池、失败处理、代码结构、FAQ 级待定项
  执行Agent-接口契约.md       # CLI / plan / recipe / scores / delivery / 溯源 六套契约
  接入示例/
    scores.example.json      # A3 → A1 的分数 JSON（A1 只读）
    接入说明.md               # 怎么把 A1 接进自己的流水线
  运行证据/
    demo-matrix.md           # demo01 三版本差异矩阵（实跑输出）
    verify.json              # 逐候选完整性自检结果
    builds.json              # 逐候选构建结果
    selection-V2.md          # V2 选择理由（demo01）
    traceability.json        # 全链溯源清单（计划→配方→产物→分数）
    delivery.json            # 交付清单

项目源码/执行Agent/          # qw9 流水线：src/qw9 + src/qw9/agent（十二步）+ recipes/plans/tests
```

## 3. 快速开始

```bash
cd 项目源码/执行Agent

# ① 校验计划（参数缺失/重复直接报错，不猜）
PYTHONPATH=src python3 -m qw9 gen plan --plan plans/hde12.yaml

# ② 模板+参数 → 每候选配方 + runtime.json（端口/MPM/分配器）
PYTHONPATH=src python3 -m qw9 gen expand --plan plans/hde12.yaml --run-id gen01

# ③ 逐候选构建（失败读日志分类重试 ≤3；隔离装不上 → BLOCKED，不降级）
PYTHONPATH=src python3 -m qw9 gen build --run-id gen01 --jobs 4

# ④ 完整性自检（二进制/哈希/MPM DSO/分配器 LD_PRELOAD/隔离自检）
PYTHONPATH=src python3 -m qw9 gen verify --run-id gen01

# ⑤ 等评估分后挑 V2 + 预注册 V3，出选择理由 + 溯源清单
PYTHONPATH=src python3 -m qw9 gen deliver --run-id gen01 --scores artifacts/gen01/hde.json
```

运行环境：WSL `Ubuntu-CTF`（Ubuntu 22.04，root），依赖 `python3-yaml`、`clang`、`readelf`(binutils)。

## 4. 接入真实流水线

A1 是 **命令族**，不是常驻服务。接入通常是三步：

1. 把 `plans/hde12.yaml` 的 `base.source` 指向你的源码包（`package` + `sha256`），候选表按需增删；
2. 跑 ①→④，产物落在 `artifacts/<run_id>/`；
3. 把 A3 的分数文件交给 ⑤，交付落在 `delivery/<run_id>/`。

分数文件契约（A3 产出，A1 只读，示例见 [接入示例/scores.example.json](接入示例/scores.example.json)）：

```json
{"schema": "qw9/scores/v1", "run_id": "gen01",
 "candidates": {"c1": {"score": "N/A"},
                "c3": {"score": 0.71, "detail": {"hde": "…", "per_cve": {}}}}}
```

V2 遴选三条硬约束：**有有效分数**；**与基线至少一轴不同**；**轴 ∈ `v2_axes`**（隔离轴永远排除）。
理由必须能溯源到 `detail` 字段，写不出来直接报错退回。

## 5. 边界

- 只读分数，**不改** `hde.json` / `status.json`，也不写别人的产物目录；
- **不改 C 源码**、不改判定规则或阈值；
- 重试只允许因**环境/构建问题**，且每次必须记录"为什么重试"，**不允许因结果不好看而重跑**；
- 构建前缀删除有 `/opt/qw9*`、`/opt/httpd*` 白名单护栏，不做全局 `pkill`；
- 适配器退出码 0=观测有效、3=环境问题；`INVALID` / `NOT_RUN` 一律不计防御成功。

## 6. 与团队其他部分的接口

| 上游/下游 | 交接物 | 契约 |
|---|---|---|
| 计划/源码 → A1 | `plan.yaml`、源码包（含 sha256） | [执行Agent-接口契约.md](执行Agent-接口契约.md) §2 |
| A1 → 监管 Agent（A2） | 每次构建/隔离的"申请单"（动作、目标、参数、预计耗时） | 同上 §6 |
| A1 → 评估 Agent（A3） | `artifacts/<run_id>/` 的 manifest + 构建日志 | 同上 §5 |
| A3 → A1 | `hde.json`（只读） | 同上 §4 |
| A1 → 裁决/文档 | `delivery/<run_id>/`：V2/V3 + 选择理由 + 溯源清单 | 同上 §5.2 |

## 7. 运行证据（demo01）

本仓库附带一次**合成靶标**的完整跑通记录（`run_id=demo01`，2026-11-03 18:24）：

| 候选 | 功能面 `--hello` | 漏洞面 200B 栈溢出 | 泄露面 root-only 标记 |
|---|---|---|---|
| d1 | PASS | 触发 SIGSEGV(11) | 泄露成功 |
| d2（V2） | PASS | 触发 SIGABRT(6)，栈破坏被检测 | 泄露成功 |
| i1（V3） | PASS | 触发 SIGABRT(6) | **泄露被拒（权限）** |

结论口径（与 [运行证据/demo-matrix.md](运行证据/demo-matrix.md) 一致）：

- 溢出漏洞在三个变体上**都仍然存在**，没有任何变体把它修掉；
- V1→V2：同一攻击、同一根因，表型从 SIGSEGV 变为 SIGABRT（对应赛题 P029"均触发但表现不一致"）；
- V1/V2→V3：泄露轴被权限边界拦下（对应 P030"漏洞仍存在但该轴利用受抑制"）；
- **本 demo 用的是合成靶标（`demo-target/`），只验证流水线，不是真实软件，不计入赛题漏洞分**；真实 Apache 2.4.49 的 V2/V3 构建与三版本矩阵**尚未运行**。

> 证据文件里的绝对路径是当时工作区的 `03_platform/...`，归档到本仓库后目录位置变了，文件内容未改。
