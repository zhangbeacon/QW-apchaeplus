# 接入脚本约定

`supervisor.pipeline.example.json` 里的 `scripts/*.sh` 是占位，需要按你的真实流水线实现：

| 脚本 | 职责 | 约定 |
|---|---|---|
| `build.sh` | 构建 V1/V2/V3 | 全部成功 `exit 0`，任一失败返回非 0；构建日志写 `logs/build.log` |
| `functional.sh` | 功能契约测试 | 通过时写 `evidence/functional.ok`，失败返回非 0 |
| `security.sh` | 三个漏洞 × 三个变体 | 通过时写 `evidence/security.json`（`verdict=pass`）和 `evidence/negative.ok` |
| `clean.sh` | 端口/pid 清理 | 只做本地安全清理，不 `pkill -9` |

要点：

- 用退出码表达成败，不要用 `exit 0` 掩盖失败；
- 证据文件名必须与 `audit.required` 完全一致；
- 负向对照必须本轮生成，不能复用旧文件；
- 不要在脚本里打印“结论”，监管 Agent 不读你的结论。

如果流水线已经在别处运行，可以不改这些脚本，改用 `watch` 模式消费 `stage_fail` 事件，见 `stage_event.schema.json`。
