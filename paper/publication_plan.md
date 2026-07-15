# PRE-SAGA 优秀论文产出计划

## 1. 论文基调

本文不再定位为“一个月内快速产出”的短文，而是对标 SAGA 这类完整会议论文，目标是形成一个具备完整逻辑设计、协议实现、形式化分析、攻击测试和系统评估的研究型文章。

核心主题：

> SAGA 解决 agent 间“可否建立联系”的治理问题；PRE-SAGA 进一步解决 agent 建立联系后“可否解密特定数据”的数据共享治理问题。

论文主张：

> 在 SAGA 的 Agent Contact Policy 之外，引入 Data Sharing Policy，并通过信封加密与代理重加密 PRE，使 Provider 能在不接触明文和数据密钥明文的情况下完成跨 agent 数据授权。

需要避免的主张：

- 不声称提出新的 PRE 密码学算法。
- 不声称替代 SAGA。
- 不声称完全解决 agent 解密后的二次泄露。
- 不声称 Provider 完全不知道任何信息。Provider 仍可观察访问元数据。

## 2. 与 SAGA 的基线关系

SAGA 原文和仓库提供了较完整的基线：

- 论文：`SAGA: A Security Architecture for Governing AI Agentic Systems`
- 公开仓库：`https://github.com/gsiros/saga`
- 关键目录：`saga/`、`experiments/`、`proofs/`、`agent_backend/`
- 原文贡献：用户注册、agent 注册、Contact Policy、OTK、Access Control Token、ProVerif 形式化验证、三类 agent 任务实验、Provider 扩展性评估。

PRE-SAGA 的扩展点：

```text
SAGA:
  User / Agent Registration
  Agent Contact Policy
  OTK + DH + Access Control Token
  Agent-to-Agent communication control

PRE-SAGA:
  Data Sharing Policy
  Encrypted local agent data
  Envelope encryption
  PRE-based encrypted data key conversion
  Data-level authorization audit
```

一句话区别：

> SAGA 控制谁能联系谁；PRE-SAGA 控制联系之后谁能解密什么。

## 3. 推荐代码目录结构

长期版本不应停留在当前 `prototype/` 的几十行 toy 模拟，而应扩展成可测试、可替换密码后端、可复现实验的框架。

```text
pre-saga/
├── README.md
├── pyproject.toml
├── configs/
│   ├── local.yaml
│   ├── experiment.yaml
│   └── policies/
│       ├── contact_policy_examples.yaml
│       └── data_sharing_policy_examples.yaml
├── presaga/
│   ├── __init__.py
│   ├── crypto/
│   │   ├── envelope.py
│   │   ├── pre_interface.py
│   │   ├── toy_pre.py
│   │   ├── hpke_kem_stub.py
│   │   └── key_rotation.py
│   ├── provider/
│   │   ├── app.py
│   │   ├── registry.py
│   │   ├── contact_policy.py
│   │   ├── data_policy.py
│   │   ├── token_service.py
│   │   ├── pre_proxy.py
│   │   └── audit.py
│   ├── agent/
│   │   ├── agent.py
│   │   ├── local_store.py
│   │   ├── data_index.py
│   │   ├── requester.py
│   │   └── receiver.py
│   ├── storage/
│   │   ├── encrypted_store.py
│   │   ├── memory_store.py
│   │   ├── calendar_store.py
│   │   ├── mail_store.py
│   │   └── document_store.py
│   ├── protocol/
│   │   ├── messages.py
│   │   ├── schemas.py
│   │   ├── validation.py
│   │   └── errors.py
│   └── observability/
│       ├── metrics.py
│       ├── traces.py
│       └── experiment_logger.py
├── experiments/
│   ├── data/
│   │   ├── calendar_seed.json
│   │   ├── mail_seed.json
│   │   ├── memory_seed.json
│   │   └── documents_seed.json
│   ├── tasks/
│   │   ├── schedule_meeting.py
│   │   ├── expense_report.py
│   │   ├── collaborative_writing.py
│   │   └── cross_agent_memory_query.py
│   ├── attacks/
│   │   ├── unauthorized_data_class.py
│   │   ├── purpose_mismatch.py
│   │   ├── token_reuse.py
│   │   ├── requester_mismatch.py
│   │   ├── provider_plaintext_probe.py
│   │   ├── metadata_linkage_probe.py
│   │   ├── stale_rekey_use.py
│   │   └── compromised_agent_exfiltration.py
│   ├── baselines/
│   │   ├── saga_contact_only.py
│   │   ├── token_plaintext_server.py
│   │   └── presaga.py
│   └── run_all.py
├── proofs/
│   ├── presaga_token_secrecy.pv
│   ├── presaga_dek_secrecy.pv
│   ├── presaga_rekey_authentication.pv
│   └── README.md
├── tests/
│   ├── unit/
│   │   ├── test_envelope.py
│   │   ├── test_data_policy.py
│   │   ├── test_token_service.py
│   │   └── test_pre_proxy.py
│   ├── integration/
│   │   ├── test_normal_sharing.py
│   │   ├── test_policy_denial.py
│   │   ├── test_token_limits.py
│   │   └── test_audit_log.py
│   └── security/
│       ├── test_provider_cannot_decrypt.py
│       ├── test_wrong_requester_cannot_decrypt.py
│       ├── test_rekey_scope_binding.py
│       └── test_revocation_window.py
├── results/
│   ├── raw/
│   ├── tables/
│   └── figures/
└── paper/
    ├── pre_saga_draft.md
    ├── threat_model.md
    ├── protocol_spec.md
    ├── evaluation_plan.md
    └── related_work.md
```

当前项目可先逐步向该结构迁移，不需要一次性重写。

## 4. 时间线

### 阶段 0：基线复现与差距确认

目标：明确 SAGA 做了什么、代码能否跑通、PRE-SAGA 精确补哪一块。

任务清单：

- [ ] 阅读 SAGA 原文的协议、威胁模型、ProVerif、实验和扩展性章节。
- [ ] 拉取并运行 SAGA 官方仓库的最小本地示例。
- [ ] 确认 SAGA 的 contact token 数据结构、agent registry、contact policy 存储方式。
- [ ] 记录 SAGA 不能直接表达的 data sharing policy 场景。
- [ ] 写出 baseline comparison：SAGA-only、token plaintext server、PRE-SAGA。

交付物：

- `paper/baseline_gap_analysis.md`
- 可运行的 SAGA baseline 笔记或复现实验日志。

### 阶段 1：协议规范化

目标：把 PRE-SAGA 从想法变成可被审稿人检查的协议。

任务清单：

- [ ] 定义实体：User、Owner Agent、Requester Agent、Provider/PRE Proxy、Encrypted Store。
- [ ] 定义数据对象：record id、data class、ciphertext、encrypted DEK、metadata。
- [ ] 定义 Data Sharing Policy schema。
- [ ] 定义 token 与 PRE 转换绑定字段。
- [ ] 定义审计日志格式。
- [ ] 明确撤销边界：短期 token、max uses、DEK rotation、data versioning。
- [ ] 明确安全目标：DEK secrecy、data confidentiality、requester binding、policy compliance、auditability。

交付物：

- `paper/protocol_spec.md`
- `configs/policies/data_sharing_policy_examples.yaml`
- 协议流程图和状态机图。

### 阶段 2：系统实现

目标：实现可复现实验框架，而不是 toy demo。

任务清单：

- [ ] 将当前 `prototype/pre_saga.py` 拆分为 crypto/provider/agent/storage/protocol 模块。
- [ ] 实现信封加密接口。
- [ ] 实现 PRE 后端接口，保留 toy PRE 作为测试后端。
- [ ] 增加可替换真实密码后端的接口，例如 HPKE/KEM 包装层或现成 PRE 库适配层。
- [ ] 实现 Provider API：register agent、issue contact token、request re-encryption、audit query。
- [ ] 实现 Agent 本地密文存储。
- [ ] 实现 Data Sharing Policy parser 和 evaluator。
- [ ] 实现实验日志和指标采集。

交付物：

- `presaga/` 主代码包。
- `tests/` 单元测试与集成测试。
- `experiments/run_all.py`。

### 阶段 3：攻击与安全测试

目标：像 SAGA 一样不只展示正常功能，还要展示攻击被拦截。

攻击测试矩阵：

| 攻击 | 攻击目标 | 预期检测点 |
|---|---|---|
| 未授权 data_class | 联系被允许但请求邮件正文 | Data Sharing Policy |
| purpose mismatch | 用会议目的 token 请求报销数据 | policy evaluator |
| token reuse | 超过 max_uses 复用 token | token service |
| requester mismatch | B 的 token 被 C 使用 | requester binding |
| stale rekey | 使用过期 re-encryption context | token expiry / rekey context |
| provider plaintext probe | Provider 尝试恢复 DEK 或 D | crypto boundary test |
| metadata linkage | Provider 通过访问模式推断敏感关系 | privacy analysis |
| compromised requester | B 解密后外发数据 | 局限性实验，不声称完全防御 |

任务清单：

- [ ] 为每类攻击写独立脚本。
- [ ] 统一输出：success/blocked/reason/latency/audit id。
- [ ] 统计攻击拦截率、误拒率、平均延迟。
- [ ] 对 compromised requester 单独写成局限性和缓解讨论。

交付物：

- `experiments/attacks/`
- `results/tables/security_matrix.csv`
- `paper/security_analysis.md`

### 阶段 4：形式化分析

目标：补齐会议论文需要的安全论证强度。

任务清单：

- [ ] 参考 SAGA `proofs/` 中的 ProVerif 结构。
- [ ] 建模 token 签发、Data Sharing Policy 决策和 PRE 转换。
- [ ] 证明攻击者无法获得 DEK。
- [ ] 证明不满足策略时无法获得可解密的 `EDEK_B`。
- [ ] 证明 token requester mismatch 会被拒绝。
- [ ] 明确 ProVerif 模型不覆盖真实实现漏洞和请求方解密后二次泄露。

交付物：

- `proofs/presaga_dek_secrecy.pv`
- `proofs/presaga_rekey_authentication.pv`
- 论文中的 Formal Analysis 章节。

### 阶段 5：系统评估

目标：证明系统不是只在逻辑上可行，也有可接受开销。

实验维度：

- 数据对象数量：100、1K、10K、100K。
- agent 数量：10、100、1K。
- Data Sharing Policy 规则数量：10、100、1K。
- token lifetime：1 min、10 min、1 h。
- max uses：1、5、20、100。
- 数据类别：calendar、mail、memory、document。
- baseline：SAGA-only、plaintext token server、PRE-SAGA。

指标：

- 正常任务成功率。
- 攻击拦截率。
- token 签发延迟。
- policy evaluation 延迟。
- PRE transform 延迟。
- 数据解密端到端延迟。
- Provider CPU/内存占用。
- 审计日志大小。
- 明文暴露面：Provider 是否可见 DEK/D。

交付物：

- `results/tables/performance.csv`
- `results/figures/latency_breakdown.png`
- `results/figures/scalability_policy_rules.png`
- `paper/evaluation.md`

### 阶段 6：论文写作

推荐论文结构：

```text
1. Introduction
2. Background and Motivation
3. SAGA Baseline and Data-Sharing Gap
4. Threat Model and Security Goals
5. PRE-SAGA Design
6. Implementation
7. Formal Analysis
8. Evaluation
9. Security Discussion and Limitations
10. Related Work
11. Conclusion
```

写作重点：

- 引言要用具体场景说明“能联系不等于能解密”。
- 方法部分要清楚区分 Contact Policy 和 Data Sharing Policy。
- 安全分析要承认 Provider 仍能观察元数据。
- 实验部分要有 baseline comparison，不能只报告 PRE-SAGA 自己跑通。

## 5. 待完成任务总清单

### 论文与设计

- [ ] 完成 SAGA baseline gap analysis。
- [ ] 完成 PRE-SAGA protocol spec。
- [ ] 完成 threat model。
- [ ] 完成 Data Sharing Policy schema。
- [ ] 完成 security goals。
- [ ] 完成 limitation taxonomy。

### 代码

- [ ] 将 toy prototype 模块化。
- [ ] 增加真实密码后端接口。
- [ ] 实现 Provider API。
- [ ] 实现 agent encrypted local store。
- [ ] 实现 policy evaluator。
- [ ] 实现 audit logger。
- [ ] 实现实验 runner。

### 测试

- [ ] 单元测试覆盖 crypto、policy、token、store。
- [ ] 集成测试覆盖正常数据共享流程。
- [ ] 安全测试覆盖 8 类攻击。
- [ ] 压力测试覆盖 policy 数量和 agent 数量。
- [ ] 对比测试覆盖 SAGA-only 和 plaintext token server。

### 形式化

- [ ] 复用 SAGA ProVerif 风格。
- [ ] 建模 DEK secrecy。
- [ ] 建模 requester binding。
- [ ] 建模 policy denial。
- [ ] 在论文中解释模型边界。

### 实验与图表

- [ ] 生成攻击拦截矩阵。
- [ ] 生成延迟分解图。
- [ ] 生成扩展性图。
- [ ] 生成系统架构图。
- [ ] 生成协议时序图。

## 6. 第一次审阅：对照 SAGA 的不足

SAGA 成为完整会议论文的原因，不只是提出了 OTK/token 设计，还包含：

- 清晰的问题定义。
- 明确的系统假设。
- 严格的威胁模型。
- 可复现代码。
- ProVerif 形式化验证。
- 攻击模型评估。
- 多任务 agent 实验。
- Provider 吞吐和扩展性测试。

PRE-SAGA 当前草稿的不足：

- 仍停留在 toy PRE 和四个小场景。
- 缺少真实 SAGA baseline 接入或至少协议级复现。
- 缺少形式化安全模型。
- 缺少性能与扩展性评估。
- 缺少真实任务，例如会议安排、报销、文档协作。

第一次优化结论：

> 必须把 PRE-SAGA 从“概念 demo”升级为“可复现系统扩展”，并至少复刻 SAGA 的一部分评估结构：攻击模型、任务成功率、性能开销、Provider 扩展性。

## 7. 第二次审阅：自身分析后的收敛方案

不建议一开始完整复刻 SAGA 的所有系统复杂度。更现实的优秀论文路线是分三层推进：

```text
Layer 1: Protocol correctness
  token + policy + encrypted DEK conversion

Layer 2: Security evidence
  attacks + ProVerif + provider blindness tests

Layer 3: System evidence
  realistic agent tasks + performance + baseline comparison
```

优先级排序：

1. 先做 Data Sharing Policy 和 encrypted data model。
2. 再做 PRE proxy 的可替换密码接口。
3. 然后做攻击矩阵。
4. 再接入 SAGA-style agent task。
5. 最后做 ProVerif 和扩展性实验。

第二次优化结论：

> 论文的最佳创新点不是“PRE 本身”，而是把 PRE 放进 SAGA 的治理框架后，提出 Contact Policy 与 Data Sharing Policy 的双层治理模型，并用实验说明它能减少 Provider 和中间层的明文暴露。

