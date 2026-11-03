# 评估 Agent（提交件）

> 这是「强网设计」作品里的**评估层**组件：对已授权目标做资产与漏洞评估，产出**可复现证据**和**分级建议**，不参与变体生成，也不做最终裁决。

## 1. 它解决什么

漏洞判定环节常见的三个问题：

1. **证据不可复现**——只有截图或口头结论，复现者需要从头猜；
2. **结论不可追溯**——不知道一条 finding 从哪次探测推出来，改了判据无法回溯；
3. **边界失控**——探测动作越权、写操作、批量拉取真实数据。

评估 Agent 做四件事：

1. **探索**：按 `goal → intent → fact → finding` 四层链路推进，每个节点落库、可追溯；
2. **取证**：每条 finding 必须是**可复现步骤**（命令/HTTP 报文/操作序列）+ 观测结果，无步骤不入库；
3. **分级**：按真实影响给出 `critical/high/medium/low/info`，只保留能被真实攻击者利用的结论；
4. **自检**：交付前跑 `evidence_lint.py`，缺步骤、缺影响、缺资产归属的一律打回。

**它只有发现权和取证权，没有判定权。** 漏洞是否成立、定级是否合理，仍由人复核。

## 2. 目录

```text
评估Agent/
  README.md                    # 本文件
  评估Agent-设计说明.md         # 链路、角色、证据纪律、边界
  评估Agent-接口契约.md         # config / event / findings / evidence / journal 五套契约
  scripts/
    des_request.py             # 通用加密请求构造器（把明文参数转成可直接粘贴的报文）
    browser_harness.js         # CDP 浏览器取证钩子（Node，零依赖）
    cdp_probe.py               # browser_harness 的 Python 包装
    evidence_lint.py           # findings 自检与 assessment.json 生成
  schema/
    findings.schema.json
    assessment_event.schema.json
  接入示例/
    assessment.pipeline.example.json
    findings.example.json
    journal.example.jsonl
```

## 3. 快速开始

```bash
# 1) 自检示例 findings
python scripts/evidence_lint.py --findings 接入示例/findings.example.json --out /tmp/assessment.json
cat /tmp/assessment.json

# 2) 生成一条可直接粘贴到 Burp Repeater 的报文
python scripts/des_request.py --key 01234567 --func GetToken --class Public --payload '{}'

# 3) 浏览器取证（需 Node >= 21，Chrome 以 --remote-debugging-port=9222 启动）
python scripts/cdp_probe.py --port 9222 --list
python scripts/cdp_probe.py --port 9222 --hook --seconds 20
```

## 4. 接入真实流水线

评估作为一个独立阶段挂在监管 Agent 下面，与 `security` 并列：

```json
{"name": "assessment", "cmd": ["python", "scripts/evidence_lint.py",
  "--findings", "evidence/findings.json", "--out", "evidence/assessment.json"],
 "timeout": 120, "retries": 0, "snapshot": false}
```

审计只认 `evidence/assessment.json` 的 `verdict`，与 `security.json` 同一套口径。完整示例见 `接入示例/assessment.pipeline.example.json`。

## 5. 边界

- 只在**书面授权范围**内探测；范围外目标一律拒绝执行；
- 默认只读：不调用写接口、不提交表单、不触发短信/邮件、不做口令爆破；
- 敏感数据最小化：命中样例只取 2 条并脱敏，不翻页、不批量导出；
- 只产出证据与建议，不改判据、不写死结论、不替代人工复核；
- 不内置任何真实目标数据：示例一律使用 `example.com` / `192.0.2.0/24` 占位。

## 6. 与团队其他部分的接口

| 上游/下游 | 交接物 |
|---|---|
| 授权方 → 评估 | 目标、范围、授权说明、可用的测试账号 |
| 评估 → 监管 | `evidence/assessment.json`（verdict + 计数）、`evidence/findings.json` |
| 评估 → 裁决 | `journal.jsonl`、`findings.json`、可复现报文 |
| 评估 → 文档 | 资产清单、漏洞复现册、修复优先级 |

字段与事件类型见 `评估Agent-接口契约.md`。
