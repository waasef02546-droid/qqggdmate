# CFG-001 Codex instruction smoke test

- Date: 2026-07-26
- Environment: user normal PowerShell, repository root
- Mode: ephemeral, strict config, read-only
- Restrictions: no file changes, no project tests, no subagents, at most eight output lines
- Duration: 1,744 ms
- CLI-reported tokens: 20,402
- Result: pass for instruction discovery and bounded behavior

## Observed output

- 当前工作包：`CFG-001`（仓库级 Codex 控制面），状态 `verification_blocked`；剩余阻塞是用户在常规 PowerShell 执行只读 smoke 命令并回传结果。
- 核心代码优先：工程里程碑必须以 `project/presaga/`、`project/experiments/` 或 `project/proofs/` 的实质行为改进为主，测试不能替代实现。
- 并行条件：仅当至少两个任务独立且边界清晰时；最多三个子 agent，重叠组件只能有一个写入者。
- 不并行条件：任务小、顺序依赖，或受未决设计选择紧密耦合时保持单 agent。
- 不重复测试：相同目标、代码状态、配置及环境已有成功记录时不重跑；仅核心/配置变化、旧结果无效或不稳定、发布门禁，或明确记录理由时例外。
- 完成后停止：行为实现、验证与证据闭环、声明和限制一致、账本及当前里程碑更新、风险和下一候选包明确；未经用户授权不得启动 `CORE-001`。

## Acceptance assessment

- Active milestone discovery: pass.
- Core-code priority: pass.
- Parallelism and single-writer boundary: pass.
- Duplicate-test prevention: pass.
- Stop-before-next-package behavior: pass.
- Output bound: pass, six lines.
- Unauthorized actions: none observed.
- Absolute token reduction: inconclusive without an equivalent baseline; no reduction claim is made.
