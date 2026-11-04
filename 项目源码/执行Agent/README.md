# qw9 — V2/V3 自动化生成流水线（实现）

> **事实边界**：本代码库按[实现方案](../../说明文档/架构设计/V2V3自动化生成实现方案.md)落地。`demo01`（合成靶标）已跑通；**真实 Apache 2.4.49 的三变体构建与三版本矩阵尚未运行**。
> 在 P0/构建/矩阵命令实际产出证据之前，不得宣称任何变体效果或安全增益；`demo01` 的结论只对合成靶标成立。
> 运行环境：WSL `Ubuntu-CTF`（Ubuntu 22.04，root），依赖 `python3-yaml`、`clang`、`readelf`(binutils)。

## 一分钟上手

```bash
# 在 WSL 内（首次）
sudo apt install -y python3-yaml clang
cd /mnt/e/强网拟态/03_platform

# P0 可行性三问（A 编译器/FORTIFY、B V2 构建、C 隔离）——先跑这个
PYTHONPATH=src python3 -m qw9 p0

# 三变体构建（V3 额外落地隔离）
PYTHONPATH=src python3 -m qw9 build --recipe recipes/v1-normal.yaml
PYTHONPATH=src python3 -m qw9 build --recipe recipes/v2-hardened.yaml
PYTHONPATH=src python3 -m qw9 build --recipe recipes/v3-isolated.yaml
PYTHONPATH=src python3 -m qw9 isolate --recipe recipes/v3-isolated.yaml

# G2 业务契约（七项能力，三个变体都要全过）
PYTHONPATH=src python3 -m qw9 contract --variants v1 v2 v3

# 三版本矩阵（三轴 oracle，产出 verdict.json + matrix.md）
PYTHONPATH=src python3 -m qw9 matrix \
  --cves CVE-2021-41773 CVE-2021-44790 CVE-2021-44224 \
  --variants v1 v2 v3

# 可重复性验收（同配方两次构建哈希比对）
PYTHONPATH=src python3 -m qw9 repro --recipe recipes/v2-hardened.yaml

# 单元测试（纯逻辑，不起进程）
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## A1 执行 Agent（gen 命令族）

> 设计：[执行Agent-设计说明.md](../../说明文档/执行Agent/执行Agent-设计说明.md)。
> A1 只负责"把 12 个候选造出来、摆整齐、按分数挑 V2、交付预注册 V3"；
> 判分归评估 Agent，测试组织归监管 Agent，判定规则谁都不许改。

```bash
# ① 校验计划（参数缺失/重复直接报错，不猜）
PYTHONPATH=src python3 -m qw9 gen plan --plan plans/hde12.yaml

# ② 模板+参数 → 13 份配方（12 编译类 + i1 隔离）+ runtime.json（端口/MPM/分配器）
PYTHONPATH=src python3 -m qw9 gen expand --plan plans/hde12.yaml --run-id gen01

# ③ 逐候选构建（失败读日志分类重试≤3；隔离装不上 → BLOCKED 不降级）
PYTHONPATH=src python3 -m qw9 gen build --run-id gen01 --jobs 4

# ④ 完整性自检（二进制/哈希/MPM DSO/分配器 LD_PRELOAD 实证/隔离自检）
PYTHONPATH=src python3 -m qw9 gen verify --run-id gen01

# ⑤ 等评估分后挑 V2 + 预注册 V3，出选择理由 + 溯源清单
PYTHONPATH=src python3 -m qw9 gen deliver --run-id gen01 \
  --scores artifacts/gen01/hde.json
```

产物对照：

| 命令 | 产物 |
|---|---|
| `gen expand` | `recipes/gen/<run_id>/*.yaml` + `artifacts/<run_id>/state.json`、每候选 `runtime.json`（端口/MPM/分配器环境） |
| `gen build` | `/opt/qw9/<id>/` 安装树 + `artifacts/<run_id>/<id>/{manifest.json,build.log}` + `builds.json` |
| `gen verify` | `artifacts/<run_id>/verify.json`（逐项 PASS/FAIL） |
| `gen deliver` | `delivery/<run_id>/{V2,V3}/…` + `selection.md` + `traceability.json` + `delivery.json` |

评估分数 JSON 契约（A3 产出，A1 只读）：

```json
{"schema": "qw9/scores/v1", "run_id": "gen01",
 "candidates": {"c1": {"score": "N/A"},
                "c3": {"score": 0.71, "detail": {"hde": "…", "per_cve": {}}}}}
```

V2 遴选三条硬约束：有有效分数；参数与基线（c1）至少一轴不同；轴 ∈ `delivery.v2_axes`（隔离轴永远排除）。理由必须能溯源到 `detail` 字段，写不出来直接报错退回。

## 命令与产物对照

| 命令 | 产物 | 对应门禁 |
|---|---|---|
| `p0` | 终端 PASS/FAIL + `artifacts/*/…` | 方案 §8 P0 三问 |
| `build` | `/opt/qw9/{v1,v2,v3}` + `artifacts/<id>/manifest.json`、`build.log` | G1 环境 |
| `repro` | `artifacts/<id>/repro.json` | 系统完整性 12 分（可重复） |
| `isolate` | `isolate-setup.sh`（生成）、`isolate.log`、`isolate-verify.json` | V3 落地 + 自检 |
| `contract` | `artifacts/runs/<id>/<v>/business/contract.json` | G2 功能一致性 |
| `matrix` | `artifacts/runs/<run_id>/{matrix.json,matrix.md,<v>/<CVE>/verdict.json}` | G4 差异初筛 |

## 差异设计（哪来的三态）

| 变体 | 身份 | 预期差异轴（以实测为准） |
|---|---|---|
| V1 | gcc -O2 原始构建，无 User 指令（子进程 root，与既有证据一致） | 基线：全部触发 |
| V2 | clang/-O2/FORTIFY2/SSP/PIE/RELRO，全 DSO 重编 | 44790：崩溃/检测信号/存活形态（**go/no-go 门**） |
| V3 | 同 V1 构建 + 独立 UID + root-only 标记不可达 + UDS 目录收口 | 41773：marker 被拒/执行身份降级；44224：任意 UDS 受阻、声明 UDS 仍通 |

> V3 是"利用受抑制/后果受限"，**不是"漏洞消除"**；`passwd_read` 轴（world-readable）预期三变体都可读，不作为差异证据。

## 工程纪律（代码里强制）

1. 每次构建从 tarball 重解干净树；前缀删除有 `/opt/qw9*|/opt/httpd*` 白名单护栏；
2. manifest 覆盖 `bin/httpd` + 全部 `modules/*.so`（漏洞代码在 DSO），逐文件 sha256/编译器注释/FORTIFY 符号/栈保护；
3. `require_fortify: true` 时无任何 `__*_chk` 符号即构建失败——禁止"加了宏就算加固"；
4. httpd 实例只按本场景 conf 路径清理，禁止全局 pkill；后端只杀记录 PID；
5. 适配器退出码 0=观测有效、3=环境问题；INVALID/NOT_RUN 一律不计防御成功；
6. 每 run_id 唯一，旧证据天然隔离；44790 统一普通构建 V1，ASAN 基线不混入。

## 目录

```
03_platform/
├── recipes/            v1-normal / v2-hardened / v3-isolated（V3 引用隔离策略）
├── contracts/          apache-business.yaml（G2 七能力） apache-resources.yaml（V3 边界）
├── scenarios/          business + 3 CVE：conf.template + overlay + pre/post 钩子
│   └── support/        uds_backend.py / tcp_backend.py（假后端）
├── adapters/           三轴 oracle 攻击侧（bash，环境变量注入）
├── scripts/            p0_feasibility.sh
├── src/qw9/            domain/builder/isolator/runner/cli
└── tests/              纯逻辑单测
```

## 已知边界与下一步

- `CVE-2021-44224` 场景 conf 按 `cve/apache/conf/httpd-44224.conf` 同构重写，**首轮实跑如行为不符以实测为准回改模板**（scenario.yaml notes 已标注）；
- APR/APR-util 来自 `/usr`（apt），不在 V2 加固覆盖内——报告必须如实单列，不得写"整栈加固"；
- allocator 未进 V2 身份；熵实验（轨道 E）、网关、监管 Agent 均未实现（按方案 §10 推迟）；
- 第 5 天门：`matrix` 跑完看 `CVE-2021-44790` 行——三变体 goal/表型全同则 NO-GO（方案 §7）。
