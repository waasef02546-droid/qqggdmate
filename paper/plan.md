# PRE-SAGA 论文产出计划与阶段设计

## 1. 目标定位

本项目目标是形成一篇围绕 PRE-SAGA 的研究型论文。论文不以提出全新的代理重加密密码学原语为目标，而是以 SAGA 为基线，在其 Agent Contact Policy 之外引入 Data Sharing Policy，形成面向智能体系统的数据共享治理扩展。

核心问题是：

> SAGA 解决“谁可以联系谁”，PRE-SAGA 进一步解决“联系建立之后，谁可以解密什么数据”。

论文应围绕以下主张展开：

> 在智能体系统中，仅有联系层访问控制不足以约束跨智能体数据共享。PRE-SAGA 在 SAGA 的身份、注册、Contact Policy 和 token 流程基础上，引入数据对象、数据分类、用途约束、短期授权、审计日志与代理重加密代理，使 Provider 可以在不接触数据明文和数据密钥明文的前提下辅助完成受策略约束的数据共享。

## 2. 预期产出

### 2.1 论文产出

计划形成一篇结构完整的研究论文，建议章节如下：

1. Introduction
2. Background and Motivation
3. SAGA Baseline and Data-Sharing Gap
4. Threat Model and Security Goals
5. PRE-SAGA Design
6. Implementation
7. Security Analysis
8. Evaluation
9. Discussion and Limitations
10. Related Work
11. Conclusion

论文重点不应停留在概念描述，而应具备：

- 明确的问题定义；
- 与 SAGA 的基线差距分析；
- 清晰的实体、协议和策略定义；
- 可运行的系统原型；
- 正常场景与攻击场景实验；
- 安全目标与边界说明；
- 性能与可扩展性评估；
- 对局限性的诚实讨论。

### 2.2 代码产出

计划形成一个可复现实验原型，建议目录结构如下：

```text
pre-saga/
├── README.md
├── configs/
│   ├── local.yaml
│   ├── experiment.yaml
│   └── policies/
│       ├── contact_policy_examples.yaml
│       └── data_sharing_policy_examples.yaml
├── presaga/
│   ├── crypto/
│   │   ├── envelope.py
│   │   ├── pre_interface.py
│   │   ├── toy_pre.py
│   │   └── key_rotation.py
│   ├── provider/
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
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
├── results/
│   ├── raw/
│   ├── tables/
│   └── figures/
└── paper/
    ├── threat_model.md
    ├── protocol_spec.md
    ├── security_analysis.md
    ├── evaluation.md
    └── related_work.md
```

### 2.3 实验产出

实验部分至少应包含：

- SAGA baseline 复现；
- SAGA 多智能体场景复现；
- PRE-SAGA 正常数据共享流程；
- 未授权数据类别访问拦截；
- 用途不匹配拦截；
- token 复用拦截；
- requester mismatch 拦截；
- Provider 无法恢复 DEK 或数据明文的边界测试；
- 性能评估；
- 可扩展性评估。

## 3. 阶段设计

## 阶段 0：SAGA 基线复现与差距确认

### 目标

明确 SAGA 已经解决的问题、源码中的关键机制，以及 PRE-SAGA 需要补足的数据共享治理缺口。

### 任务

- 阅读 SAGA 论文中的协议设计、威胁模型、形式化分析、实验和扩展性评估部分。
- 运行 SAGA 官方仓库的最小本地示例。
- 完成 SAGA 多智能体复现实验。
- 确认 agent registry、contact policy、one-time key、access-control token 的数据结构。
- 分析 SAGA 无法直接表达的数据共享策略场景。
- 写出 SAGA-only、plaintext token server、PRE-SAGA 三组 baseline comparison。

### 交付物

- `paper/baseline_gap_analysis.md`
- SAGA 本地复现实验记录
- SAGA 多智能体复现实验记录
- baseline comparison 初稿

### 完成标准

- 能明确说明 SAGA 控制的是联系层授权，而不是数据对象级解密授权。
- 能用复现实验说明 SAGA 的身份、注册、Provider access、OTK、token 和 quota 流程已经跑通。
- 能列出 PRE-SAGA 的必要扩展点。

## 阶段 1：协议规范化

### 目标

将 PRE-SAGA 从概念扩展为可检查、可实现、可评估的协议规范。

### 任务

- 定义系统实体：
  - User
  - Owner Agent
  - Requester Agent
  - Provider / PRE Proxy
  - Encrypted Store
- 定义数据对象：
  - record id
  - data class
  - ciphertext
  - encrypted DEK
  - metadata
  - version
- 定义 Data Sharing Policy schema。
- 定义 token 与 PRE transform 的绑定字段。
- 定义审计日志格式。
- 明确撤销边界：
  - short-lived token
  - max uses
  - DEK rotation
  - data versioning
- 明确安全目标：
  - DEK secrecy
  - data confidentiality
  - requester binding
  - policy compliance
  - provider blindness
  - auditability

### 交付物

- `paper/protocol_spec.md`
- `paper/threat_model.md`
- `configs/policies/data_sharing_policy_examples.yaml`
- 协议流程图
- 状态机图

### 完成标准

- 协议字段足够具体，可以直接指导实现。
- Data Sharing Policy 能表达数据类别、用途、请求者、有效期、次数和数据版本。
- 安全目标和非目标边界清晰。

## 阶段 2：系统原型实现

### 目标

实现可复现实验框架，而不是仅用于说明概念的最小脚本。

### 任务

- 将现有原型拆分为 crypto、provider、agent、storage、protocol、observability 模块。
- 实现 envelope encryption 接口。
- 实现 PRE 后端接口，保留 toy PRE 作为测试后端。
- 设计可替换密码后端接口。
- 实现 Provider 侧接口：
  - register agent
  - issue contact token
  - evaluate data sharing policy
  - request re-encryption
  - audit query
- 实现 Agent 本地密文存储。
- 实现 Data Sharing Policy parser 和 evaluator。
- 实现实验日志和指标采集。

### 交付物

- `presaga/` 主代码包
- `tests/` 单元测试与集成测试
- `experiments/run_all.py`
- 基础实验结果表

### 完成标准

- 正常数据共享流程可运行。
- Provider 不直接接触数据明文和 DEK 明文。
- 策略判断、token 绑定、PRE transform、审计日志均可观察。

## 阶段 3：攻击测试与安全实验

### 目标

证明系统不仅能完成正常流程，也能拒绝典型越权请求。

### 攻击矩阵

| 攻击 | 攻击目标 | 预期检测点 |
|---|---|---|
| unauthorized data class | 联系被允许但请求未授权数据类别 | Data Sharing Policy |
| purpose mismatch | 使用会议用途 token 请求报销数据 | policy evaluator |
| token reuse | 超过 max uses 后继续复用 token | token service |
| requester mismatch | B 的 token 被 C 使用 | requester binding |
| stale rekey | 使用过期 re-encryption context | token expiry / data version |
| provider plaintext probe | Provider 尝试恢复 DEK 或数据明文 | crypto boundary test |
| metadata linkage | Provider 通过访问模式推断敏感关系 | privacy analysis |
| compromised requester | 请求方解密后外发数据 | limitation discussion |

### 任务

- 为每类攻击编写独立脚本。
- 统一输出 success、blocked、reason、latency、audit id。
- 统计攻击拦截率、误拒率、平均延迟。
- 对 compromised requester 单独写成局限性和缓解讨论。

### 交付物

- `experiments/attacks/`
- `results/tables/security_matrix.csv`
- `paper/security_analysis.md`

### 完成标准

- 主要越权场景能被策略、token 或 requester binding 拦截。
- 无法完全防止的场景被明确列为系统边界。
- 攻击实验结果可复现。

## 阶段 4：形式化与安全分析

### 目标

补足研究论文所需的安全论证强度。

### 任务

- 参考 SAGA 的形式化建模结构。
- 建模 token 签发、Data Sharing Policy 判断和 PRE transform。
- 分析攻击者无法获得 DEK 的条件。
- 分析不满足策略时无法获得可解密 EDEK 的条件。
- 分析 requester mismatch 的拒绝条件。
- 明确模型不覆盖真实实现漏洞、元数据泄露和请求方解密后的二次泄露。

### 交付物

- `proofs/presaga_dek_secrecy.pv`
- `proofs/presaga_rekey_authentication.pv`
- 论文中的 Security Analysis 或 Formal Analysis 章节

### 完成标准

- 安全目标、假设和攻击者能力一致。
- 形式化模型与协议设计字段对应。
- 模型边界说明充分。

## 阶段 5：系统评估

### 目标

证明 PRE-SAGA 不仅在逻辑上可行，也具有可接受的系统开销。

### 实验维度

- 数据对象数量：100、1K、10K、100K
- agent 数量：10、100、1K
- Data Sharing Policy 规则数量：10、100、1K
- token lifetime：1 min、10 min、1 h
- max uses：1、5、10、100
- 数据类别：calendar、mail、memory、document
- baseline：SAGA-only、plaintext token server、PRE-SAGA

### 指标

- 正常任务成功率
- 攻击拦截率
- token 签发延迟
- policy evaluation 延迟
- PRE transform 延迟
- 数据解密端到端延迟
- Provider CPU / 内存占用
- 审计日志大小
- Provider 明文暴露面

### 交付物

- `results/tables/performance.csv`
- `results/tables/security_matrix.csv`
- `results/figures/latency_breakdown.png`
- `results/figures/scalability_policy_rules.png`
- `paper/evaluation.md`

### 完成标准

- 至少完成正常流程、攻击拦截和基本性能三类实验。
- 实验结果能支持 PRE-SAGA 相比 plaintext token server 的安全优势。
- 实验结果能说明 PRE-SAGA 相比 SAGA-only 多控制了数据解密层。

## 阶段 6：论文写作与整合

### 目标

将设计、实现、实验和安全分析整合为完整论文。

### 任务

- 完成 Introduction，突出“能联系不等于能解密”的问题。
- 完成 Background and Motivation，说明 SAGA 与 PRE 的关系。
- 完成 SAGA Baseline and Data-Sharing Gap。
- 完成 Threat Model and Security Goals。
- 完成 PRE-SAGA Design。
- 完成 Implementation。
- 完成 Security Analysis。
- 完成 Evaluation。
- 完成 Discussion and Limitations。
- 完成 Related Work。
- 统一图表、术语、符号和实验编号。

### 交付物

- 完整论文初稿
- 图表目录
- 实验复现说明
- 投稿前检查清单

### 完成标准

- 论文主张清晰，不夸大密码学贡献。
- SAGA 与 PRE-SAGA 的边界明确。
- 实验能支撑论文核心主张。
- 局限性说明充分。

## 4. 总体里程碑

| 阶段 | 核心目标 | 主要交付物 |
|---|---|---|
| 阶段 0 | SAGA baseline 与差距确认 | `baseline_gap_analysis.md`、SAGA 复现记录 |
| 阶段 1 | 协议规范化 | `protocol_spec.md`、policy schema |
| 阶段 2 | 系统原型实现 | `presaga/`、测试与实验 runner |
| 阶段 3 | 攻击测试 | attack scripts、security matrix |
| 阶段 4 | 安全分析 | ProVerif 模型或等价安全分析 |
| 阶段 5 | 系统评估 | 性能表、扩展性图、评估章节 |
| 阶段 6 | 论文整合 | 完整论文初稿 |

