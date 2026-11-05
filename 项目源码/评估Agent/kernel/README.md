# 评估 Agent · 评分内核（evalkernel）

设计文档 §2.9 / §3.3 的 A3 参考实现：变体矩阵的**判定与评分内核**。
与本目录 `scripts/`（漏洞评估取证工具）分工不同：

| 组件 | 评什么 | 输入 | 输出 |
|---|---|---|---|
| `kernel/`（本目录） | **变体集**：安全增益验证的判定与评分 | 监测侧原始试验记录 / 矩阵裁决的 qw9/verdict-v1 判定文件 / 预注册根因状态表 | hde.json、safety.json、scores.json、fitness.json 等 |
| `scripts/` | 授权目标的资产与漏洞评估 | findings（探测取证） | assessment.json |

## 与设计文档的对应（异构分化熵口径）

- **异构分化熵 HDE**：对候选 v 在二变体集 {V1, v} 上逐探针计算 `I(S;V) = H(S) − H(S|V)`，
  除以 log₂q 归一化，各探针等权、各 CVE 等权聚合；伴生 DIV（总分化）与 ATTR = HDE/DIV（归因率）。
  实现：`evalkernel/metrics.py`，主产物 `hde.json`。
- **稳定性门**（K 轮行为指纹熵，归一化，阈值 0.15）：每轮取判定文件四层字段的规范化哈希为指纹，
  指纹分布熵超阈值的候选，其分化不计入证据。**A3 计算、A2 执行**——`repro` 模块只输出
  H 值与门禁结论，不做剔除。实现：`evalkernel/repro.py`。
- **三值判定 / 四层拆解**：validity → goal → phenotypes → 三轴；INVALID（超时/OOM/服务不可用）
  既不计攻击成功也不计防御成功。实现：`evalkernel/predicates.py`、`verdicts.py`。
- **三道资格门**：状态全 P、类别 pure、有分——scores.json 的 `gates` 字段，全部通过才 `eligible`。

## 产物（一套固定命名）

`hde.json`（双轨之异构轨 + 稳定性门 + 灵敏度）、`safety.json`（安全轨）、`scores.json`（逐候选分数卡）、
`fitness.json`（仅校准分集）、`classified_trials.jsonl`（逐条判定，附证据哈希）、`audit.json`、
`matrix.json`、`status.json`、`report.md`、`manifest.json`；与监管交接时另出 `results.json`。

同输入同种子重复运行，产物**逐字节一致**（journal/evidence 携带时间戳，除外）。

## 与执行 Agent（qw9）的对接

`scores.json` 按 **qw9/scores/v1** 契约输出（schema/run_id 注入，`detail` 为 A1 选择理由唯一
合法溯源目标）。执行侧直接：

```bash
PYTHONPATH=src python3 -m qw9 gen deliver --run-id gen01 --scores <评估产物目录>/scores.json
```

- 合格候选：`score` 为浮点数，`detail` 携带 per_cve / gates / 轴差 / 稳定性门事实；
- 不合格候选：`score = "N/A"`，`detail.reason` 给出第一道未过的门（STATUS_NOT_ALL_P /
  CLASS_NOT_PURE / NO_VALID_SCORE）；
- 隔离轴候选（V3）：`score = 0.0` + `detail.note`（仓库示例约定，占位非测量值）。

## 运行

```bash
# 回归测试（应全部通过）
python -m unittest discover -s tests

# 端到端：合成数据冒烟
python tools/make_synthetic.py --out data/synthetic/raw_trials.jsonl --repeats 3
python -m evalkernel --raw data/synthetic/raw_trials.jsonl --config config --out out/run

# 用矩阵裁决的判定文件作为输入
python -m evalkernel --verdicts <verdict 目录> --config config --out out/run \
    --journal journal.jsonl --evidence-dir evidence
```

## 边界

- 评分只进文件，不进对话；A1 只能读分数，A3 只能写分数，互不越界；
- V3 预注册隔离轴不参与评分（class 门排除），仅进入异构轨的 Track B；
- `fitness.json` 只含校准分集，测量不可用时分数为空——生成侧不得继续优化；
- 本内核不含任何"安全增益 X%"结论；所有数值等真实实验回填。
