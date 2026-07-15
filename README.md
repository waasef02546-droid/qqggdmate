# PRE-SAGA

本项目是一个面向一个月科研产出的最小研究包，主题为：

**在 SAGA 的 Agent Contact Policy 基础上，引入 Data Sharing Policy 与代理重加密（Proxy Re-Encryption, PRE），实现多智能体系统中的加密数据共享。**

研究基调：

SAGA 已经解决“哪个 agent 可以联系哪个 agent”的问题，但它没有把本地数据、记忆、文档、邮件、日历等数据对象的解密权限作为独立层次处理。PRE-SAGA 的目标是在 SAGA 的通信管控之后，增加一层“可联系不等于可解密”的数据共享管控。

交付内容包括：

- `paper/pre_saga_draft.md`：PRE-SAGA 中文论文初稿。
- `paper/publication_plan.md`：对标 SAGA 的长期论文产出计划、代码框架和实验路线。
- `EXPERIMENT_TRACKING.md`：实验跟踪日志，后续实验进展追加到该文件末尾。
- `paper/system_architecture.mmd`：PRE-SAGA 系统架构 Mermaid 图。
- `prototype/pre_saga.py`：PRE-SAGA 协议行为模拟原型。
- `prototype/run_experiments.py`：四类数据共享安全场景实验脚本。
- `results/experiment_summary.csv`：实验结果。
- `paper/submission_checklist.md`：投稿前检查清单。

快速运行：

```powershell
python .\prototype\run_experiments.py
```

预期结果：

- 正常数据共享应通过。
- Contact Policy 允许但 Data Sharing Policy 不允许的数据请求应被拒绝。
- Provider 能完成密文密钥转换，但不能恢复数据明文。
- token 超额复用应被拦截。

说明：

原型中的 PRE 是行为模拟，用于验证论文机制，不是生产级密码实现。真实系统应替换为经过审计的 PRE/KEM/混合加密库。
