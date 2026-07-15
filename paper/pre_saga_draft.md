# PRE-SAGA：面向多智能体系统的策略驱动代理重加密数据共享机制

## 摘要

SAGA 为多智能体系统提出了面向 agent 生命周期治理的安全架构，通过用户注册、agent 注册、Agent Contact Policy、一次性密钥和访问控制 token，控制“哪个 agent 可以联系哪个 agent”。然而，在实际多智能体应用中，通信许可并不等价于数据访问许可。一个 agent 被允许联系另一个 agent，并不意味着它应当解密对方的本地记忆、邮件、日历、文档或工具数据。若系统仍依赖明文服务端返回数据或粗粒度 token 授权，则 Provider、工具服务或中间组件可能获得超出必要范围的数据可见性。

本文提出 PRE-SAGA，一种在 SAGA 基础上扩展的策略驱动加密数据共享机制。PRE-SAGA 在 Agent Contact Policy 之外引入 Data Sharing Policy，将“能否建立联系”和“能否解密特定数据”分离。系统采用信封加密保存 agent 本地数据：数据以随机数据密钥加密，数据密钥再在数据拥有者 agent 的公钥下加密。Provider 在满足 SAGA token 与 Data Sharing Policy 条件时，作为代理重加密（Proxy Re-Encryption, PRE）代理，将加密数据密钥从数据拥有者 agent 的公钥域转换到请求 agent 的公钥域。Provider 不接触数据明文，也不获得数据密钥明文。

本文实现了一个最小原型，用于模拟 PRE-SAGA 的协议行为，并在正常数据共享、Data Sharing Policy 拒绝、Provider 明文不可见和 token 滥用拦截四类场景中进行验证。实验结果表明，PRE-SAGA 可以在 SAGA 的通信管控基础上补充数据级访问控制，为多智能体系统中的本地数据、记忆、邮件、日历和文档共享提供一条更清晰的隐私保护路径。

关键词：多智能体系统；SAGA；代理重加密；数据共享策略；加密访问控制；Agent Contact Policy

## 1 引言

多智能体系统正在从单一工具调用走向跨 agent 协作。例如，一个会议安排 agent 可能需要联系另一个用户的日历 agent；一个报销 agent 可能需要从多个邮箱 agent 中提取票据信息；一个写作 agent 可能需要访问本地文档、长期记忆和外部知识库。这类系统不仅要回答“谁可以和谁通信”，还要回答“通信建立后，哪些数据可以被解密、以什么粒度解密、在什么目的和时间窗口内解密”。

SAGA 提出了一个可扩展的 agent 治理架构。用户向 Provider 注册自己和自己的 agent，并为每个 agent 设置 Agent Contact Policy。接收方 agent 预先生成一次性密钥 OTK 并上传公钥。发起方 agent 请求联系接收方时，Provider 检查 Contact Policy，返回 OTK 和元数据；随后两端通过 Diffie-Hellman 派生共享密钥，由接收方生成加密的访问控制 token。该机制使 Provider 不必参与每一次 agent 通信，同时能够控制 agent 间接触权限。

但 SAGA 的核心控制对象是“接触”，不是“数据”。一旦两个 agent 被允许通信，接收方是否共享日历全文、空闲时间、邮件正文、附件、长期记忆或工具输出，仍需要额外机制约束。直接使用 OAuth/JWT/DPoP 式 token 可以表达范围和时效，但常见实现仍依赖服务端解密后返回明文，难以保证 Provider 或中间层最小可见。

本文的基调是：不替代 SAGA，而是在 SAGA 之后补充一层加密数据共享机制。本文提出 PRE-SAGA，将 SAGA 的 Agent Contact Policy 扩展为两层访问控制：

1. Agent Contact Policy：控制请求 agent 是否可以联系数据拥有者 agent。
2. Data Sharing Policy：控制请求 agent 是否可以解密特定数据类别。

在 PRE-SAGA 中，本地数据、工具数据、记忆、文档、邮件、日历等均以密文形式保存。Provider 在策略满足时只执行密文密钥转换：把 `Enc(PK_A, DEK)` 转换为 `Enc(PK_B, DEK)`，使请求 agent B 可以解出数据密钥 DEK，进而解密被授权的数据密文。Provider 不获得 DEK 明文，也不读取数据明文。

本文贡献如下：

1. 提出 SAGA 的数据共享扩展问题，指出“agent 可联系”与“agent 可解密数据”应当分层处理。
2. 设计 PRE-SAGA，将 Data Sharing Policy、SAGA token、数据类别、请求目的和代理重加密转换绑定起来。
3. 实现一个最小原型，验证正常共享、数据策略拒绝、Provider 明文不可见和 token 滥用拦截四类场景。

## 2 背景与相关工作

### 2.1 SAGA 与 Agent Contact Policy

SAGA 的目标是提供一个可治理的多智能体安全架构。其 Provider 维护用户注册表和 agent 注册表，保存 agent 元数据、加密凭证、端点信息和通信策略。用户可以为自己的 agent 设置 Contact Policy，定义哪些其他 agent 被允许发起联系。SAGA 使用 OTK 和访问控制 token 限制 agent 间通信窗口，并通过 token 过期时间和最大请求次数降低滥用风险。

SAGA 的优势在于工程可落地：Provider 只参与 contact resolution 和 token 获取，后续通信由 agent 间直接进行。但其重点不是数据对象级访问控制。PRE-SAGA 正是在这一点上扩展 SAGA。

### 2.2 代理重加密

代理重加密允许代理方将一个接收者公钥下的密文转换为另一个接收者公钥下的密文，而代理方不能解密得到明文。该思想适合云存储、跨域数据共享和多主体授权场景。本文不提出新的 PRE 密码学构造，而是将 PRE 作为系统组件，用于多智能体系统中的数据密钥转换。

### 2.3 信封加密

信封加密通常使用随机数据密钥 DEK 加密大数据对象，再用主体公钥或密钥管理系统加密 DEK。这样系统无需对大文件反复执行公钥加密，也便于进行密钥轮换和授权转换。PRE-SAGA 对 agent 本地数据采用信封加密：数据密文长期保存，授权共享时只转换加密数据密钥。

### 2.4 主流 token 方式的边界

OAuth、JWT、DPoP 等机制可以证明请求方身份、token 持有能力、权限范围和有效期。它们适合 API 调用授权，但并不天然保证数据一直处于密文状态，也不要求授权中间层无法读取数据明文。PRE-SAGA 的目标不是替代这些机制，而是在 agent 本地数据共享场景中补充“密文态授权转换”能力。

## 3 问题定义与威胁模型

### 3.1 系统实体

PRE-SAGA 包含以下实体：

- 用户：注册和管理自己的 agent，定义 Contact Policy 与 Data Sharing Policy。
- 数据拥有者 agent A：持有本地密文数据，例如日历、邮件、文档或长期记忆。
- 请求 agent B：被允许联系 A，并可能请求访问 A 的某类数据。
- Provider / PRE Proxy：执行 agent 注册、contact policy 检查、token 签发和密文密钥转换。
- 密文存储：保存数据密文和加密数据密钥。

### 3.2 数据对象模型

每个数据对象包含：

- `record_id`：数据对象编号。
- `owner_agent`：数据拥有者。
- `data_class`：数据类别，例如 `calendar.free_busy`、`email.body`、`memory.summary`。
- `ciphertext`：由 DEK 加密的数据密文。
- `encrypted_dek`：由拥有者公钥加密的数据密钥，即 `Enc(PK_A, DEK)`。
- `metadata`：加密算法、版本、时间戳和审计摘要。

### 3.3 Data Sharing Policy

Data Sharing Policy 用于定义联系建立之后的数据解密权限。一个策略规则可以包含：

```json
{
  "requester": "bob@company.com:meeting_agent",
  "data_class": "calendar.free_busy",
  "purpose": "meeting_scheduling",
  "ttl": "10min",
  "max_uses": 3
}
```

该规则表达：请求 agent 只能在会议安排目的下访问日历空闲信息，不能访问邮件正文、日历全文或长期记忆。

### 3.4 威胁模型

本文考虑以下风险：

- 请求 agent 被允许联系数据拥有者 agent，但试图访问未授权数据类别。
- Provider 参与授权流程，但应避免接触数据明文和 DEK 明文。
- token 被复用、超额使用或被其他 agent 滥用。
- 数据拥有者希望撤销或缩短共享窗口。

本文暂不解决请求 agent 解密后的二次泄露、恶意 LLM 记忆泄露、底层操作系统被攻破、真实 PRE 算法被破解等问题。

## 4 PRE-SAGA 机制设计

### 4.1 基本流程

PRE-SAGA 放在 SAGA contact token 获取之后的数据访问阶段：

1. 用户注册 agent A，并设置 Agent Contact Policy。
2. 用户为 agent A 设置 Data Sharing Policy。
3. agent A 将本地数据以信封加密形式保存：`C = Enc(DEK, D)`，`EDEK_A = Enc(PK_A, DEK)`。
4. agent B 请求联系 agent A，Provider 按 SAGA 风格检查 Contact Policy 并签发短期 token。
5. agent B 请求访问某一 `data_class`，并声明 `purpose`。
6. Provider 检查 token、请求方身份、Data Sharing Policy、数据类别和目的。
7. 若允许，Provider 使用受限重加密能力将 `EDEK_A` 转换为 `EDEK_B = Enc(PK_B, DEK)`。
8. agent B 获取数据密文 C 和 `EDEK_B`，用自己的私钥解出 DEK，再解密 C。

### 4.2 Provider 的角色

Provider 不再只是发 OTK 和 agent 元数据，而是扩展为 PRE Proxy。但其权限被限制为：

- 可以检查 Contact Policy。
- 可以检查 Data Sharing Policy。
- 可以验证 token 是否过期或超额。
- 可以转换加密数据密钥。
- 可以写入审计日志。

Provider 不应获得：

- 数据明文。
- DEK 明文。
- agent 私钥。
- 未被策略允许的数据解密能力。

### 4.3 策略绑定

为了避免重加密能力被泛化滥用，PRE-SAGA 要求重加密操作绑定上下文：

- 请求 agent。
- 数据拥有者 agent。
- `record_id`。
- `data_class`。
- `purpose`。
- SAGA token 摘要。
- 过期时间。
- 最大使用次数。

这样，Contact Policy 只决定“能否接触”，Data Sharing Policy 才决定“能否解密”。

### 4.4 撤销与窗口控制

PRE 的撤销不是天然简单问题。PRE-SAGA 采用短窗口设计降低风险：

- token 设置短过期时间。
- token 设置最大使用次数。
- Data Sharing Policy 可以动态更新。
- 数据对象可以版本化，必要时轮换 DEK。
- 重加密上下文绑定 token 摘要，避免跨任务复用。

这不能撤回请求 agent 已经解密并保存的数据，但可以缩短未来滥用窗口。

## 5 原型实现

本文实现了一个无外部依赖的 Python 原型。原型包括：

- agent 注册与 Contact Policy 检查。
- Data Sharing Policy 检查。
- token 签发、请求方绑定和使用次数限制。
- 信封加密式数据对象。
- toy PRE 密文密钥转换。
- 审计日志。

原型中的 PRE 是行为模拟：`Enc(pk, dek) = dek XOR H(pk)`，`rk_A→B = H(pk_A) XOR H(pk_B)`。Provider 通过异或转换使 `Enc(PK_A, DEK)` 变为 `Enc(PK_B, DEK)`，但不恢复 DEK 明文。该实现只用于验证协议语义，真实系统必须替换为经过审计的 PRE 或 KEM 方案。

## 6 实验设计

### 6.1 正常数据共享

日历 agent A 允许会议 agent B 联系，并在 Data Sharing Policy 中允许 B 以 `meeting_scheduling` 目的访问 `calendar.free_busy`。预期结果为 B 成功解密空闲时间数据。

### 6.2 Data Sharing Policy 拒绝

B 已被允许联系 A，但尝试访问 `email.body`。由于策略只允许 `calendar.free_busy`，Provider 拒绝执行重加密转换。

### 6.3 Provider 明文不可见

Provider 执行密文密钥转换并写入审计日志，但日志和代理侧均不出现数据明文。该实验用于验证机制层面的最小披露目标。

### 6.4 token 滥用拦截

B 获得的 token 只允许一次重加密请求。第一次请求成功后，第二次复用同一 token 被拒绝。

## 7 实验结果与分析

实验脚本对四个场景各重复运行 20 次，结果如下：

| 场景 | 成功次数 | 总次数 | 成功率 | 平均耗时 |
|---|---:|---:|---:|---:|
| 正常数据共享 | 20 | 20 | 100% | 0.125 ms |
| 数据策略拒绝 | 20 | 20 | 100% | 0.044 ms |
| Provider 明文不可见 | 20 | 20 | 100% | 0.066 ms |
| token 滥用拦截 | 20 | 20 | 100% | 0.073 ms |

结果表明，在最小原型中，PRE-SAGA 能够实现“可联系不等于可解密”的核心目标。Contact Policy 允许 agent 建立联系后，Data Sharing Policy 仍能独立限制数据类别和使用目的。Provider 可以完成授权转换，但不需要获得数据明文或数据密钥明文。

## 8 局限性

本文仍有以下局限：

1. 原型采用 toy PRE 行为模拟，不是生产级密码实现。
2. 当前实验规模较小，仅验证协议逻辑，不代表真实 SAGA 或 MCP 生态性能。
3. PRE 无法阻止请求 agent 解密后的二次泄露。
4. Provider 仍可观察访问元数据，例如谁请求了哪类数据。
5. 撤销只能限制未来访问，不能撤回已经被解密的数据。

## 9 结论

本文提出 PRE-SAGA，一种在 SAGA Agent Contact Policy 基础上扩展的数据共享机制。其核心观点是：多智能体系统中，通信许可和数据解密许可应当分层处理。PRE-SAGA 通过 Data Sharing Policy、信封加密和代理重加密，使 Provider 能在不接触明文的情况下完成数据密钥转换。最小原型验证了正常共享、数据策略拒绝、Provider 明文不可见和 token 滥用拦截四类场景。该方向适合作为基于 SAGA 的独特改进视角，用于工作坊短文、中文普通会议或本科科研论文初稿。

## 参考文献

[1] Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, Alina Oprea. SAGA: A Security Architecture for Governing AI Agentic Systems. arXiv:2504.21034v2, 2025.

[2] Matt Blaze, Gerrit Bleumer, Martin Strauss. Divertible Protocols and Atomic Proxy Cryptography. EUROCRYPT, 1998.

[3] Giuseppe Ateniese, Kevin Fu, Matthew Green, Susan Hohenberger. Improved Proxy Re-Encryption Schemes with Applications to Secure Distributed Storage. NDSS, 2005.

[4] RFC 9449. OAuth 2.0 Demonstrating Proof of Possession (DPoP). IETF, 2023.

[5] OpenID Foundation. OpenID Connect Core 1.0.
