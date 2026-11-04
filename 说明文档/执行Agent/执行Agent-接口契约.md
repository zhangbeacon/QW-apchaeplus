# 执行 Agent（A1）接口契约

> 口径：以下字段与产物均取自 `项目源码/执行Agent/` 的实现与 `demo01` 实跑产物；**未实现的部分会显式标注"未实现"**，不写成已支持。

## 1. 命令行契约

`python3 -m qw9 gen <子命令>`，需要 `PYTHONPATH=src`。

| 子命令 | 必填参数 | 可选参数 | 作用 |
|---|---|---|---|
| `gen plan` | `--plan` | — | 校验计划：候选重复、字段缺失、轴取值非法直接报错 |
| `gen expand` | `--plan` | `--run-id`（缺省 `gen-<时间戳>`）、`--out`（缺省 `recipes/gen/<run_id>`） | 模板 + 参数 → 每候选一份 recipe.yaml + `runtime.json` |
| `gen build` | `--run-id` | `--jobs`（默认 4）、`--only <id…>` | 逐候选构建；隔离类候选追加 isolate + 自检 |
| `gen verify` | `--run-id` | — | 完整性自检，产出 `verify.json` |
| `gen deliver` | `--run-id`、`--scores` | `--score-key`（默认 `score`）、`--include-tree`、`--out`（默认 `delivery`） | 挑 V2 + 预注册 V3，组装交付目录 |

退出码约定（与适配器一致）：`0` = 动作完成；`3` = 环境问题（缺依赖、无权限等，**不计入"建造失败"**）；其它非 0 = 失败。

## 2. 输入契约：`plan.yaml`（`kind: GenerationPlan`，`apiVersion: qw9/v1`）

```yaml
apiVersion: qw9/v1
kind: GenerationPlan
metadata: { id: hde12 }
base:
  source:   { package: ../../cve/_downloads/httpd-2.4.49.tar.gz, sha256: <64 hex> }
  configure_args: [ "--with-apr=/usr", "--enable-mpms-shared=all", ... ]
  timeout_s: 1800
allocator:  { jemalloc: libjemalloc.so.2 }
ports:      { start: 8200 }
candidates:
  - { id: c1, axis: compile, role: BASELINE, cc: gcc, opt: O2, allocator: ptmalloc, mpm: event, harden: false }
  - { id: i1, axis: isolation, cc: gcc, opt: O2, allocator: ptmalloc, mpm: event, harden: false }
```

| 字段 | 约束 |
|---|---|
| `metadata.id` | 计划标识，进入溯源清单 |
| `base.source.sha256` | 必填，构建前校验源码包 |
| `candidates[].id` | **全局唯一**，重复即报错 |
| `candidates[].axis` | `compile` / `harden` / `thread` / `isolation`；只有非 `isolation` 的轴可进 V2 候选 |
| `candidates[].role` | `BASELINE` 标记基线（通常是 `c1`），V2 必须与它至少一轴不同 |
| `ports.start` | 端口段起点，`expand` 时逐候选分配，避免撞端口 |

## 3. 输入契约：`recipe.yaml`（`kind: VariantRecipe`，`apiVersion: qw9/v1`）

```yaml
apiVersion: qw9/v1
kind: VariantRecipe
metadata: { id: v2-hardened, role: CANDIDATE, description: "…" }
source:   { package: <tar.gz>, sha256: <64 hex> }
toolchain:{ cc: clang, cc_min_version: "14" }
flags:    { cflags: "-O2 -g -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2", ldflags: "-pie -Wl,-z,relro,-z,now" }
configure:{ args: [...], env: { SOURCE_DATE_EPOCH: "1631836800" } }
install:  { prefix: /opt/qw9/v2, workroot: /root/work/qw9 }
build:    { jobs: 4 }
verify:   { require_fortify: true }
```

`verify.require_fortify: true` 时，产物里没有 `__*_chk` 符号即**构建失败**——禁止"加了宏就算加固"。

## 4. 输入契约：分数 JSON（A3 产出，A1 只读）

```json
{
  "schema": "qw9/scores/v1",
  "run_id": "gen01",
  "candidates": {
    "c1": { "score": "N/A" },
    "c3": { "score": 0.71, "detail": { "hde": "...", "per_cve": {} } }
  }
}
```

- `score` 取 `--score-key` 指定的字段（默认 `score`）；`"N/A"` 或缺省 = 无有效分，不参与挑选；
- `detail` 是选择理由的**唯一合法溯源目标**：理由里的每个论断都要能指到具体字段，写不出来即退回；
- A1 **不得写回**该文件，也不得修改 `status.json`。

## 5. 产物契约

### 5.1 `artifacts/<run_id>/`

| 路径 | 内容 |
|---|---|
| `state.json` | 本次 run 的候选清单、参数、端口分配 |
| `builds.json` | 逐候选构建结果（成功/失败/耗时） |
| `verify.json` | 完整性自检，`schema: qw9/genverify/v1` |
| `<id>/manifest.json` | 二进制与 DSO 的逐文件 sha256、编译器注释、FORTIFY 符号 |
| `<id>/build.log` | 构建日志（失败时是证据） |
| `<id>/runtime.json` | 运行时参数（端口、MPM、分配器环境） |
| `<id>/isolate-verify.json` | 隔离自检结果（仅隔离类候选） |

`verify.json` 的检查项（demo01 实际出现的）：`binary_exists`、`manifest_exists`、`manifest_covers_modules`、`bin_sha_matches_manifest`、`fortify_symbols_present`、`allocator_default`、`isolation_selfcheck_ok`。

### 5.2 `delivery/<run_id>/`

| 文件 | 内容 |
|---|---|
| `delivery.json` | `schema: qw9/delivery/v1`，记录 V2/V3 的候选 id、安装前缀、目录 |
| `traceability.json` | `schema: qw9/traceability/v1`，全链溯源 |
| `V2/` | 配方 + manifest + 构建日志 |
| `V3/` | 配方 + manifest + 隔离脚本/自检 |

`delivery.json` 形态：

```json
{"schema": "qw9/delivery/v1", "run_id": "demo01",
 "V2": {"candidate": "d2", "prefix": "/opt/qw9/d2", "dir": "..."},
 "V3": {"candidate": "i1", "prefix": "/opt/qw9/i1", "dir": "...", "preregistered": true},
 "traceability": "..."}
```

`traceability.json` 形态（节选）：

```json
{"schema": "qw9/traceability/v1", "run_id": "demo01",
 "plan_sha": "<sha256>",
 "source": {"package": "...", "sha256": "..."},
 "scores": {"path": "...", "sha256": "...", "score_key": "score", "note": "评估 Agent 产出，A1 只读"},
 "V2": {"id": "d2", "axis": "harden", "params": {}, "prefix": "/opt/qw9/d2", "port": 8401,
        "recipe_sha256": "...", "toolchain": {"cc": "...", "version": "..."}, "cflags": "...",
        "selection": {"score": 0.5, "runner_up": null, "margin": null, "risks": [],
                     "diff_axes_vs_baseline": ["harden"], "baseline_id": "d1"}},
 "V3": {"id": "i1", "axis": "isolation", "preregistered": true},
 "excluded": {"d1": "分数 N/A", "i1": "轴不在 v2_axes（isolation，V3 预注册轴不参与挑选）"}}
```

`excluded` 是硬要求：每个落选候选都要写明落选原因，不允许"没提就是没选"。

## 6. 与监管 Agent（A2）的接口

| 方向 | 内容 | 格式 |
|---|---|---|
| A1 → A2 | 构建/隔离"申请单"：动作、目标、参数、预计耗时 | 一行一条 JSON（`journal.jsonl`） |
| A2 → A1 | 放行 / 拒绝 / 要求补证据 | 同上，带 `decision` 字段 |

> 当前状态：A1 侧的**申请单写盘**与 A2 侧的 `journal.jsonl` 消费已有实现（A2 见 [../监管Agent/](../监管Agent/README.md)），但两边**尚未联调**成一条自动流水线；demo01 是 A1 单独跑通的。

## 7. 不变量（改代码时必须守）

1. **`run_id` 唯一**：每个 run 独立目录，旧证据天然隔离，不覆盖；
2. **前缀白名单**：构建前缀删除只允许 `/opt/qw9*`、`/opt/httpd*`，禁止全局 `pkill`；
3. **重试有上限且必须留因**：构建 ≤3 次、超时 ≤2 次、磁盘 ≤1 次；只允许环境/构建原因；
4. **V3 预注册**：`i1` 不参与打分、不被挑选，`preregistered: true` 写死；
5. **A1 不产判定结论**：`selection.md` 只能引用分数与差异轴，不能写"更安全""抑制率"之类结论；
6. **证据路径可追溯**：`traceability.json` 必须覆盖 计划→配方→产物→分数 四段哈希。
