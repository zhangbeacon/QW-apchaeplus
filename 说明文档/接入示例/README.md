# 接入示例

A2 与 A1/A3 的交互全部走 JSON 文件，不依赖常驻服务。

## 典型时序

```text
A1 -> A2   request(build, V2)        -> decisions.jsonl: approve
A1 -> A2   request(target, V2)       -> reject（G4 未过）
A1 -> A2   functional.json + results.json
A2         gate                     -> gates.json: G0-G4
A1 -> A2   request(target, V2)       -> approve
A2         begin(run_id)            -> archive/ + runs/<run_id>.json
A1         产出 evidence/
A2         check(run_id, binary)    -> pass/fail
A3         只读 gates.json、decisions.jsonl、timeline.jsonl、evidence/
```

## 字段

- 申请单 / 放行记录 / 时间线：见 `schemas.json`；
- 规则：见 `../A2-监管Agent-接口契约.md` 第 1 节；
- 功能结果与差异结果：见第 4、5 节。

## 约定

- A1 不得在申请单里携带 `rules`、`rules_patch`、`thresholds`；
- A3 不得修改 `decisions.jsonl`、`timeline.jsonl`、`evidence/`；
- 所有时间戳用本地时区 ISO8601（`+08:00`）。
