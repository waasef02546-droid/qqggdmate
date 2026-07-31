# PRE-SAGA：在智能体接触授权之后实施可验证的数据级授权

> 状态：KEYCUSTODY-001 证据对齐工作稿（2026-07-31）。本文只引用
> `project/results/release-manifest.json` 所列的当前权威结果。它不是最终投稿版。

## 摘要

SAGA 将智能体注册、接触策略和通信令牌纳入 Provider 治理，但“允许两个智能体建立
联系”并不自动回答“请求方可以解密哪些本地数据”。本文提出 PRE-SAGA：在
SAGA-compatible Contact 授权之后增加 Data Sharing Policy、绑定到具体 Contact
会话和注册密钥版本的 DataToken，以及受策略约束的加密数据密钥转换。当前原型把
contact、policy、token、trusted object lookup、re-encryption consumption 和 audit
纳入同一服务端路径，并实现 JSON/Mongo 持久化、密钥轮换恢复与过期写入者隔离。
轮换期间，Provider 导出不含秘密的确定性请求，并只接受 owner/KMS 在 Provider 外部
生成且绑定精确对象状态的签名重包 artifact；旧的私钥输入被拒绝。

我们建立了一个带来源、配置、环境和逐文件哈希的分阶段发布流程。一次完整本地运行
通过了 8 个预期阻断攻击、4 个工具任务、12 行性能比较、9 行扩展性测试、3 个
ProVerif 模型中的 4 个查询、2 个 SAGA 证据桥接案例以及 MongoDB E2E；随后完整
回归 115/115 通过。结果支持“可联系不等于可获得数据令牌或转换结果”这一原型行为。

CRYPTO-001 以 `nucypher-core==0.15.0` 的 Umbral 原语[2]替换权威实验中的 ToyPRE：
owner 生成经签名的 1-of-1 KFrag，Provider 验证 owner、requester 与 owner-wrap
context 后生成 CFrag，而 requester 在验证 CFrag 后解密。主动探针向恶意数据面
Provider 暴露 owner wrap、全部公钥、context、KFrag、CFrag 和审计元数据；探针无法
恢复 DEK，同时预期 requester 成功解密。该结果是原型边界内的经验性证据，不是
密码学归约、独立审计、侧信道结论或整个共址管理进程的安全保证。

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
4. 集成版本化 Umbral 1-of-1 PRE 后端，并以同时要求“Provider 公开材料恢复失败”
   和“预期 requester 解密成功”的主动探针约束具体实现；ToyPRE 仅保留为历史缺陷
   回归。
5. 把 owner 私钥和明文 DEK 从 Provider 轮换接口与持久化/导出状态中移出，以规范化
   请求、owner 侧签名 artifact、对象 CAS、幂等重试和语义发布门禁约束该边界。

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

最重要的密码边界是：AES-256-GCM envelope 路径使用标准库；权威 PRE 路径使用
`nucypher-core==0.15.0` 暴露的 MessageKit、签名并验证的 KFrag、CFrag 和
`decrypt_reencrypted`。外层适配格式绑定 suite、版本、对象类型、owner/requester
公钥和 context 摘要，并对未知、旧版、截断和篡改输入失败关闭。该依赖标记为 Alpha
且采用 GPLv3，本项目未独立审计其 Rust 实现。KFrag 是 owner/requester 密钥对级，
不是 record/purpose/token 级；Provider 与合法 requester 串谋并保留 KFrag 的情形
不在当前机密性主张内。轮换解密已迁移到 owner/KMS 侧，但该进程仍会短暂持有源私钥
和 DEK，且当前用同一 Umbral 源密钥生成域分离签名；这不是 HSM 或安全内存保证。

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
7. Provider 从可信存储解析对象和 owner-wrap provenance，验证 KFrag 的 owner、
   requester 和 context 绑定并预计算公开的 CFrag；畸形密码材料形成统一拒绝审计且
   不消费 token。
8. Provider 原子消费 token；并发失败者丢弃预计算 CFrag。PRE Proxy 只在消费成功
   后返回 transformed encrypted DEK，并记录允许审计。

HTTP 层只负责序列化、持久化和状态码映射；审计决定由 domain path 产生，避免实验
或适配器伪造拒绝证据。

### 3.2 注册与轮换

AID 注册是版本化记录。请求方不能在数据面自行选择另一个公钥；令牌签发使用当前
可信注册，消费时重新核对版本。替换或撤销注册会使旧 token 失败关闭。

Owner 轮换采用 prepare、stage/rewrap、commit 或 abort、cleanup 状态机。journal
和对象 revision 支持 JSON 重启恢复与 Mongo 单文档条件更新。Mongo Provider
aggregate 另有 `state_revision`；旧 Provider CAS 失败后进入
`repository_recovery_required`，避免继续写入。

KEYCUSTODY-001 将 stage 前的重包分成两个边界。Provider 从活动源注册、候选注册、
rotation journal、对象 provenance、源 wrapper、源/目标 context 和对象 revision
重建规范化请求；owner/KMS 验证源密钥后在本地解包和重新加密，并对请求摘要与目标
wrapper 摘要签名。Provider 只用活动源注册公钥验签并验证目标 Umbral wrapper，再做
对象 CAS。完全相同的 artifact 可安全重试，不同 artifact、跨对象/轮换替换、篡改和
过期 revision 均在写入前失败。该机制不解决复制 KFrag 的密钥对级授权范围。

### 3.3 证据发布

统一发布器先写入唯一 staging 目录，运行所有阶段，生成 source fingerprint、
release config hash、Git HEAD/dirty 摘要、Python/依赖/ProVerif/Mongo 版本以及
每个 artifact 的 SHA-256、字节数和 CSV 行数。独立 verifier 检查：

- 哈希、大小、行数和路径安全；
- 所有 gate 的通过状态；
- 当前 source fingerprint；
- 攻击的 expected-blocked/limitation 语义；
- task results 与 latency table 来自同一运行；
- ProviderService 性能行和具体 Umbral 恢复探针边界；
- ProVerif 查询数；
- Bob allow/Mallory deny 的 SAGA bridge；
- owner/KMS custody artifact 的签名、幂等/冲突重试、旧私钥输入拒绝、目标解密和
  Provider 可见状态秘密扫描；
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
每种 50 次；任务扩展性每个点 20 次。权威 manifest 要求声明的 release inputs
相对当前 Git HEAD 保持 clean，并记录这些输入文件的组合 fingerprint；工作区中
不属于 release source set 的历史资料可以继续存在，但其状态摘要会被单独记录。
具体 Git HEAD、输入文件数与 fingerprint 以同一 manifest 为准。

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
| Umbral Provider public-material recovery | 阻断且 requester 成功 | `provider_public_material_recovery_blocked` |

八项均通过权威 ProviderService 路径。第八项额外使用 owner 私钥在探针外部取得
oracle DEK，并确认：Provider 可见材料不包含或恢复该 DEK，而注册 requester 能从
同一 CFrag 恢复它。这只能排除已实现的公开材料攻击面，不能替代密码分析。

### 5.3 工具任务

schedule meeting、expense report、collaborative writing 和 cross-agent memory
query 均成功，只返回 projection 允许字段。四项总延迟在本机为 2.257–2.484 ms；
这些值包含 fixture 建立路径，且只作为本机描述数据。

### 5.4 性能与扩展性

contact-only 和 plaintext server 是本地 modeled baselines，不是 SAGA 官方系统或
生产服务器的性能。PRE-SAGA 行跨越真实 ProviderService facade，并使用具体 Umbral
后端。权威的逐策略规模平均值与 P95 仅保存在同一发布的 `tables/performance.csv`
中，避免把不同机器或不同运行的时间值写入论文。本地延迟不能外推到生产网络、HSM
或多 Provider 部署。

9 个 agent/policy/record 扩展性点全部取得 1.0 success rate。当前规模最大为 32
agents、500 policies 或 500 records；每点只有 20 次，不能据此推导大规模尾延迟。

### 5.5 Mongo 与 SAGA bridge

Mongo E2E 通过同一 ProviderService 持久化 3 个 agent、1 条 policy、2 个 contact
tokens、1 个 data token、3 条 audit 和 1 个 encrypted object。Bob 正常路径成功，
Mallory 因 requester mismatch 被拒绝。报告中的 plaintext visibility `False` 是
控制流插桩；具体机密性边界由独立的 Umbral 公开材料恢复探针补充，但仍不是证明。

SAGA bridge 使用仓库中的两份已记录终端证据。Bob 的 contact allow 后数据 allow
并释放 projection；Mallory 的 contact 也 allow，但 data policy deny，未释放
plaintext。该实验不是 live SAGA interoperability。

### 5.6 Owner/KMS 轮换边界

独立的一行 custody 证据必须同时满足：签名 artifact 经权威源注册验证；完全相同的
stage 重试幂等；另一份有效但不同的目标 wrapper 被判为冲突；旧
`source_private_key_b64` 字段以稳定原因失败；commit 后目标私钥可恢复 DEK 和记录；
在 request、artifact、对象、journal、audit、结果及错误等限定 Provider 可见面中，
源私钥和明文 DEK 的 raw/base64/hex 形式均未出现。独立 verifier 直接检查这些字段，
而不是仅信任 gate 名称或测试数量。该扫描不包含调用方刻意发送的秘密 payload，且
不是进程内存取证。

### 5.7 形式化与回归

三个 ProVerif 模型均由 2.05 实际执行，分别验证 1、2、1 个 true queries。模型支持
token acceptance、抽象 DEK secrecy/policy implication 和 rekey authentication。
它不建模 AID 注册轮换、journal、Mongo CAS、Provider fencing 或 Python 代码等价。
特别是，抽象 DEK secrecy 不证明 `nucypher-core`、适配器、KFrag 生命周期或
Provider/requester 串谋安全。

发布前完整测试在 live Mongo 环境中 115/115 通过。测试支持实现行为，但不替代独立
密码分析或跨主机复现。

## 6 结论有效性与局限

当前证据支持：

- Contact allow 不是 DataToken allow；
- DataToken issuance 和 consumption 对会话、注册、范围、目的、版本和次数进行
  服务端绑定；
- 所有当前发布实验来自同一可校验源状态；
- JSON/Mongo 中的已测恢复和 CAS 冲突路径失败关闭。
- owner 私钥和明文 DEK 不再是 Provider 轮换 API 或持久化/导出状态的一部分，签名
  artifact 的精确绑定、幂等重试和冲突拒绝由实现与语义 gate 共同约束。

当前证据不支持：

- `nucypher-core` 或适配器的生产安全、独立审计或供应链可复现构建；
- owner/KMS 进程受损、Provider/requester 串谋、侧信道、元数据隐私；
- 合法 requester 解密后的防外泄；
- 多 Provider 线性一致性、RAFT、sharding 或跨文档事务；
- 与 SAGA live runtime 的完整互操作；
- 与 SAGA 原文真实 LLM、地域及大规模系统实验的效果对等。

因此，下一研究包不应再重复实现 ToyPRE 替换或再次迁移轮换解密，而应在当前具体
后端上通过 per-record-version delegating key（或具备等价语义的 label-bound PRE）
缩小 KFrag 的密钥对级授权范围，并用直接保留 KFrag 的跨记录攻击验证。随后才适合
扩大 comparative baseline、独立环境复现和论文投稿实验。

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

[2] D. Nuñez, “Umbral: A Threshold Proxy Re-Encryption Scheme,”
NuCypher Inc. and NICS Lab, University of Malaga, technical report, 2018.

> 投稿前仍需按目标 venue 补齐 PRE、HPKE、capability security、agent authorization
> 和 reproducible systems evaluation 的系统性相关工作；本文不以占位引用冒充完成。
