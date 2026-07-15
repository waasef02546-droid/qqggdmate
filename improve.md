# 当前会话效率改进建议

## 1. 先明确交付物清单

本轮推进阶段 1 时，任务可以直接拆成以下固定交付物：

- `paper/protocol_spec.md`
- `paper/threat_model.md`
- `configs/policies/data_sharing_policy_examples.yaml`
- `paper/diagrams/presaga_protocol_flow.mmd`
- `paper/diagrams/presaga_state_machine.mmd`
- 覆写 `improve.md`

后续继续推进阶段 2、阶段 3 时，也建议先列出目标文件，再进入实现，能减少反复确认。

## 2. 区分“论文设计”和“代码实现”

当前项目同时包含论文、SAGA 复现、原型代码和实验结果。为了提高效率，后续指令最好明确属于哪一类：

- 论文设计：补充协议、威胁模型、安全目标、实验设计；
- 代码实现：创建 `presaga/` 模块、测试、runner；
- 复现实验：运行 SAGA 或 PRE-SAGA 实验；
- GitHub 上传：提交、推送、同步远程仓库。

这样可以避免在一次任务中同时修改文档、跑实验和处理 Git，降低出错概率。

## 3. 对验收标准使用可检查表达

本轮“按照阶段 1 的验收标准”是有效指令。后续可以继续使用类似格式：

```text
按照 plan.md 阶段 2 的完成标准推进；
必须生成对应文件；
最后用 checklist 说明每条标准是否满足。
```

这种表达比“继续完善”更高效，因为可以直接对照验收标准完成。

## 4. 对 GitHub 上传先说明是否需要提交

当前本地已经连接远程仓库。后续如果完成某阶段后需要同步，可以直接说明：

```text
完成后提交并推送到 GitHub。
```

如果只是生成文件、不想上传，则说明：

```text
只修改本地文件，不提交。
```

这能避免每次都停下来确认是否要推送。

## 5. 注意敏感材料边界

项目中存在 SAGA 复现实验产生的本地密钥、证书、token 日志和 runtime 输出。后续所有上传都应继续遵守当前 `.gitignore` 策略：

- 不上传 `saga_reproduction/runtime/`
- 不上传 `saga_reproduction/saga_clean/`
- 不上传 `saga_reproduction/saga_work/`
- 不上传 `*.key`、`*.crt`、真实 token 日志

只上传脱敏后的说明文档、截图、论文草稿、原型代码和结果摘要。

## 6. 下一步建议

阶段 1 已形成协议规范后，下一轮最有效的任务是推进阶段 2：

```text
按照 plan.md 阶段 2 的验收标准，创建 presaga/ 代码框架，实现 policy evaluator、token service、encrypted store 和 toy PRE 接口，附带最小单元测试。
```

阶段 2 不应一开始追求完整密码学实现，优先目标是让协议字段、策略判断、token 绑定、审计日志和 toy PRE transform 全部可运行、可测试。
