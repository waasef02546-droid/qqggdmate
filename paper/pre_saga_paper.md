# PRE-SAGA：在智能体接触授权之后实施可验证的数据级授权

> 状态：证据对齐工作稿（2026-07-29）。本文只引用
> `project/results/release-manifest.json` 所列的 REL-001 结果。它不是最终投稿版。

## 摘要

SAGA 将智能体注册、接触策略和通信令牌纳入 Provider 治理，但“允许两个智能体建立
联系”并不自动回答“请求方可以解密哪些本地数据”。本文提出 PRE-SAGA：在
SAGA-compatible Contact 授权之后增加 Data Sharing Policy、绑定到具体 Contact
会话和注册密钥版本的 DataToken，以及受策略约束的加密数据密钥转换。当前原型把
contact、policy、token、trusted object lookup、re-encryption consumption 和 audit
纳入同一服务端路径，并实现 JSON/Mongo 持久化、密钥轮换恢复与过期写入者隔离。

我们建立了一个带来源、配置、环境和逐文件哈希的分阶段发布流程。一次完整本地运行
通过了 7 个预期阻断攻击、4 个工具任务、12 行性能比较、9 行扩展性测试、3 个
ProVerif 模型中的 4 个查询、2 个 SAGA 证据桥接案例以及 MongoDB E2E；随后完整
回归 89/89 通过。结果支持“可联系不等于可获得数据令牌或转换结果”这一原型行为。

同时，主动攻击探针发现 ToyPRE 可由公开材料恢复 DEK。因而本文不声称当前具体后端
实现 Provider 侧密码学机密性。当前证据只说明服务控制流不显式接收明文 DEK/记录，
且抽象 ProVerif 模型中的查询成立。真实 PRE/HPKE 后端及其具体安全验证是下一阶段
的必要条件。

关键词：多智能体系统；SAGA；数据授权；代理重加密；可复现实验；证据追踪

## 1 引言

多智能体协作常把“通信可达”和“数据可读”混在同一个授权决定中。例如，Alice 的
日历智能体允许 Bob 的调度智能体发起联系，不代表 Bob 应读取 Alice 的邮件、文档
全文或长期记忆。若 Provider 在 contact allow 后直接返回对象或明文，Contact
Policy 就被错误地当成了 Data Sharing Policy。

PRE-SAGA 研究的问题是：

> 在一个已经通过 SAGA-compatible contact authorization 的会话中，Provider
> 如何继续对 owner、requester、record、data class、purpose、version、注册密钥
> 和使用次数实施服务端绑定，并只在全部条件成立时允许加密数据密钥转换？

本文贡献被限定为以下四项：

1. 将 contact authorization 与 data authorization 建模为顺序且独立的服务端
   决策，并把 DataToken 绑定到精确 Contact 会话和 AID 注册版本。
2. 实现可信管理面、数据面、加密对象存储、令牌消费、轮换恢复与 Mongo 持久化的一条
   可运行原型路径。
3. 将攻击、任务、性能、形式化、SAGA 桥接和 Mongo 证据统一到一个可验证发布清单，
   阻止跨运行表格混用和测试覆盖正式结果。
4. 通过主动探针公开 ToyPRE 的具体密码学失败，从论文主张中分离“控制流不显式传递
   明文”和“Provider 无法恢复 DEK”。

本文不提出新的 PRE 算法，也不声称达到 SAGA 原文在真实 LLM、地域、RAFT 或分片
实验上的覆盖度。

## 2 系统与威胁边界

### 2.1 参与方

- Owner Agent：拥有记录和当前注册密钥。
- Requester Agent：先获得 Contact 会话，再请求指定目的和范围的数据。
- Provider：维护注册、接触规则、数据策略、令牌、审计和持久化状态。
- Encrypted Store：保存记录密文、owner-wrapped DEK 和注册来源信息。
- PRE Backend：把 owner-wrapped DEK 转换为 requester-bound 结果的接口。

### 2.2 授权对象

Data Sharing Policy 至少约束：

- owner AID 和 requester selector；
- data class、subclass、record ID 或前缀；
- purpose；
- 生效/失效时间；
-最小/最大数据版本；
- 最大使用次数、最大记录数和 projection obligation。

DataToken 进一步绑定 Contact token ID、Contact session reference、requester 注册
版本与公钥指纹，以及 owner 注册 ID、版本、算法和公钥指纹。Provider 在转换消费时
重新解析可信注册和可信存储对象，而不接受调用方传入 owner-wrapped DEK。

### 2.3 对手与非目标

当前实验覆盖 contact 已允许后的越权 data class、purpose 变更、token replay、
requester 替换、旧版本/rekey、记录范围探测和已受损 requester 的权限扩张。系统不
阻止合法 requester 在本地解密后复制数据，也不隐藏访问元数据、时间和关系图。

可信管理面目前由进程内 capability 或静态 Bearer token 保护，仅适用于原型。
数据面把请求绑定到已注册公钥，但当前没有生产级请求签名或私钥持有证明；公钥匹配
本身不能证明调用方实时持有对应私钥。
Mongo 证据假设单一活动 Provider；CAS 失败会隔离旧写入者，但这不是 leader
election、线性一致性或分布式事务。

最重要的密码边界是：AES-256-GCM envelope 路径使用标准库，但 ToyPRE 与
HPKEKEMStub 是协议桩。ToyPRE 的公开材料足以恢复 DEK，不能用于真实数据。

## 3 设计

### 3.1 顺序授权

一次正常访问经过：

1. 管理面注册 owner/requester，并设置 Contact rulebook 和 Data Sharing Policy。
2. Provider 依据 Contact rulebook 签发 Contact token。
3. Requester 提交包含 Contact token ID 的 DataAccessRequest。
4. Provider 重新验证 Contact 会话、可信 requester 注册和 Data Sharing Policy。
5. Contact token 可解析后，policy allow 或 policy deny 均产生一个
   `data_token_issuance` audit；缺失或未知 Contact token ID 由 HTTP 边界提前拒绝，
   不在该 domain-audit 主张内。
6. requester 提交 DataToken 和 rekey 请求。
7. Provider 从可信存储解析对象和 owner-wrap provenance，原子验证并消费 token。
8. PRE Proxy 只在上述条件成立后返回 transformed encrypted DEK，并记录转换审计。

HTTP 层只负责序列化、持久化和状态码映射；审计决定由 domain path 产生，避免实验
或适配器伪造拒绝证据。

### 3.2 注册与轮换

AID 注册是版本化记录。请求方不能在数据面自行选择另一个公钥；令牌签发使用当前
可信注册，消费时重新核对版本。替换或撤销注册会使旧 token 失败关闭。

Owner 轮换采用 prepare、stage/rewrap、commit 或 abort、cleanup 状态机。journal
和对象 revision 支持 JSON 重启恢复与 Mongo 单文档条件更新。Mongo Provider
aggregate 另有 `state_revision`；旧 Provider CAS 失败后进入
`repository_recovery_required`，避免继续写入。

### 3.3 证据发布

统一发布器先写入唯一 staging 目录，运行所有阶段，生成 source fingerprint、
release config hash、Git HEAD/dirty 摘要、Python/依赖/ProVerif/Mongo 版本以及
每个 artifact 的 SHA-256、字节数和 CSV 行数。独立 verifier 检查：

- 哈希、大小、行数和路径安全；
- 所有 gate 的通过状态；
- 当前 source fingerprint；
- 攻击的 expected-blocked/limitation 语义；
- task results 与 latency table 来自同一运行；
- ProviderService 性能行和 ToyPRE 机密性边界；
- ProVerif 查询数；
- Bob allow/Mallory deny 的 SAGA bridge；
- Mongo normal/attack/persistence 结果。

只有 verifier 接受 staging 后才发布。各文件以临时文件替换，manifest 最后写入；
这保证中断后不可能静默接受混合结果，但不是整个目录的单一原子事务。

## 4 实现

原型使用 Python 3.12。Provider domain、HTTP service、JSON/Mongo repository、
encrypted stores、rotation journal 和实验 harness 位于 `project/presaga/` 与
`project/experiments/`。MongoDB 版本为 8.3.4，ProVerif 版本为 2.05。

`AuthoritativeProviderHarness` 是实验对生产服务 facade 的小型适配器。攻击和任务
可以在内存中准备 owner 数据，但不能自行合成 policy decision、DataToken 或 audit。
policy-only 和 contact-only 测量保留为显式 microbenchmark/modeled baseline，不
混同于完整 Provider flow。

## 5 评估

### 5.1 配置

权威运行 ID、来源指纹和环境由当前
`project/results/release-manifest.json` 指定。性能配置为 10、100、1000 条策略，
每种 50 次；任务扩展性每个点 20 次。发布时源树为 dirty 状态，但记录了 Git HEAD、
状态摘要哈希和 128 个输入文件的组合 fingerprint。该事实降低了外部复现的便利性，
但没有被隐藏。

### 5.2 攻击

| 类别 | 预期 | 结果/原因 |
|---|---|---|
| unauthorized data class | 阻断 | `data_class_denied` |
| purpose mismatch | 阻断 | `purpose_mismatch` |
| token reuse | 阻断 | `token_exhausted` |
| requester substitution | 阻断 | `contact_requester_mismatch` |
| stale rekey/version | 阻断 | `version_out_of_bounds` |
| record metadata linkage probe | 阻断 | `record_scope_denied` |
| compromised requester scope expansion | 阻断 | `data_class_denied` |
| ToyPRE public-material recovery | 应成功暴露限制 | `toy_backend_public_material_recovers_dek` |

前七项均在 Contact 已允许后被 ProviderService 阻断。第八项不是防御成功，而是安全
声明的反例：服务控制流虽然没有显式传递 plaintext DEK，Provider 仍能利用 ToyPRE
公开输入恢复同一 DEK。

### 5.3 工具任务

schedule meeting、expense report、collaborative writing 和 cross-agent memory
query 均成功，只返回 projection 允许字段。四项总延迟在本机为 2.257–2.484 ms；
这些值包含 fixture 建立路径，且只作为本机描述数据。

### 5.4 性能与扩展性

| 策略数 | SAGA contact-only 平均 ms | plaintext baseline 平均 ms | PRE-SAGA service 平均 ms |
|---:|---:|---:|---:|
| 10 | 0.0074 | 0.0451 | 0.7428 |
| 100 | 0.0030 | 0.0674 | 0.7248 |
| 1000 | 0.0028 | 0.3030 | 0.8428 |

contact-only 和 plaintext server 是本地 modeled baselines，不是 SAGA 官方系统或
生产服务器的性能。PRE-SAGA 行跨越真实 ProviderService facade，但仍使用内存
fixture 和 ToyPRE。

9 个 agent/policy/record 扩展性点全部取得 1.0 success rate。当前规模最大为 32
agents、500 policies 或 500 records；每点只有 20 次，不能据此推导大规模尾延迟。

### 5.5 Mongo 与 SAGA bridge

Mongo E2E 通过同一 ProviderService 持久化 3 个 agent、1 条 policy、2 个 contact
tokens、1 个 data token、3 条 audit 和 1 个 encrypted object。Bob 正常路径成功，
Mallory 因 requester mismatch 被拒绝。报告中的 plaintext visibility `False` 只
表示插桩未观察到显式 plaintext 变量，不抵消 ToyPRE 主动恢复反例。

SAGA bridge 使用仓库中的两份已记录终端证据。Bob 的 contact allow 后数据 allow
并释放 projection；Mallory 的 contact 也 allow，但 data policy deny，未释放
plaintext。该实验不是 live SAGA interoperability。

### 5.6 形式化与回归

三个 ProVerif 模型均由 2.05 实际执行，分别验证 1、2、1 个 true queries。模型支持
token acceptance、抽象 DEK secrecy/policy implication 和 rekey authentication。
它不建模 AID 注册轮换、journal、Mongo CAS、Provider fencing 或 Python 代码等价。
特别是，抽象 DEK secrecy 不能覆盖 ToyPRE 的具体实现缺陷。

发布后完整测试在 live Mongo 环境中 89/89 通过。测试支持实现行为，但不替代独立
密码分析或跨主机复现。

## 6 结论有效性与局限

当前证据支持：

- Contact allow 不是 DataToken allow；
- DataToken issuance 和 consumption 对会话、注册、范围、目的、版本和次数进行
  服务端绑定；
- 所有当前发布实验来自同一可校验源状态；
- JSON/Mongo 中的已测恢复和 CAS 冲突路径失败关闭。

当前证据不支持：

- ToyPRE/HPKE 的生产安全或 Provider 无法恢复 DEK；
- 恶意或内存受损 Provider、侧信道、元数据隐私；
- 合法 requester 解密后的防外泄；
- 多 Provider 线性一致性、RAFT、sharding 或跨文档事务；
- 与 SAGA live runtime 的完整互操作；
- 与 SAGA 原文真实 LLM、地域及大规模系统实验的效果对等。

因此，最优先的下一研究包应替换 ToyPRE，建立明确的真实密码后端接口和攻击验收，
再重新运行 active recovery probe。随后才适合扩大 comparative baseline、独立
环境复现和论文投稿实验。

## 7 复现

从 `project/` 执行：

```powershell
python -m pip install -e .
$env:PRESAGA_MONGODB_URI = "mongodb://127.0.0.1:27017"
python -m experiments.run_all
python scripts/verify_release.py
python -m unittest discover -s tests -v
```

完整配置位于 `project/configs/release.yaml`。当前权威 artifact 清单、环境和哈希在
`project/results/release-manifest.json`。任何不在 manifest 中的旧 result 文件都
不属于本次运行。

## 参考文献

[1] G. Syros, A. Suri, J. Ginesin, C. Nita-Rotaru, and A. Oprea,
“SAGA: A Security Architecture for Governing AI Agentic Systems,”
arXiv:2504.21034v2, 2025.

> 投稿前仍需按目标 venue 补齐 PRE、HPKE、capability security、agent authorization
> 和 reproducible systems evaluation 的系统性相关工作；本文不以占位引用冒充完成。
