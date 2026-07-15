# SAGA Baseline Gap Analysis：阶段 0 交付稿

本文档对应 `publication_plan.md` 中“阶段 0：基线复现与差距确认”。目标是把 SAGA 已经解决的问题、当前源码可观察到的机制、以及 PRE-SAGA 需要补足的数据共享治理缺口明确下来。

## 1. 阶段 0 结论

SAGA 的核心治理对象是“agent 是否可以联系另一个 agent”。它通过用户注册、agent 注册、Provider 签发 stamp、contact rulebook、one-time key、Diffie-Hellman 派生密钥和 access-control token，完成 agent-to-agent 通信前的身份确认和联系许可。

PRE-SAGA 的可行扩展点不是替代 SAGA 的 contact policy，而是在 SAGA 已经允许联系之后，继续控制“请求方 agent 是否可以解密某类数据对象”。因此，本文的差距定位应写成：

> SAGA governs who may contact whom; PRE-SAGA further governs what encrypted data may be decrypted after contact is authorized.

换句话说，SAGA 解决的是联系层授权，PRE-SAGA 要补的是数据层授权。

## 2. 已完成的 SAGA baseline 复现状态

当前已经完成官方 SAGA 源码的本地复现：

- 官方源码副本：`D:\Users\New project 1\saga_reproduction\saga_clean\saga-main`
- 本地 MongoDB：`mongodb://127.0.0.1:27017/saga`
- 已跑通最小 `hello_world.py` 场景。
- 已跑通 Alice/Bob/Mallory 三 agent 场景。
- 已观察到 Provider access、OTK 消耗、SDHK 派生、token 签发、quota 递减、任务结束和 token 注销。

已有证据文件：

- `D:\Users\New project 1\saga_reproduction\SAGA_E2E_REPRODUCTION_RESULT.md`
- `D:\Users\New project 1\saga_reproduction\SAGA_MULTI_AGENT_REPRODUCTION_RESULT.md`
- `D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\bob_to_alice_multi.log`
- `D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\mallory_to_alice_multi.log`

## 3. SAGA baseline 机制拆解

### 3.1 Agent Identity / Registry

SAGA 中 agent 的身份标识为 AID：

```text
<user email>:<agent name>
```

例如：

```text
alice@mail.com:dummy_agent
bob@mail.com:dummy_agent
mallory@mail.com:dummy_agent
```

Provider 的 MongoDB `agents` 集合中保存 agent 的注册材料，包括：

- `aid`
- `device`
- `IP`
- `port`
- `agent_cert`
- `pac`
- `one_time_keys`
- `one_time_key_sigs`
- `contact_rulebook`
- `agent_sig`
- `counter`

这说明 SAGA 的 Provider 是 agent 身份目录、网络端点目录、OTK 分发点和 contact policy 执行点。

### 3.2 Contact Policy

SAGA 的 contact policy 是每个被联系 agent 的本地 rulebook。规则形态是：

```yaml
contact_rulebook:
  - pattern: "*"
    budget: 100
```

或者：

```yaml
contact_rulebook:
  - pattern: "*@mail.com:dummy_agent"
    budget: 10
```

源码中 `saga/common/contact_policy.py` 的 `match(contact_rulebook, t_aid)` 根据 AID pattern 匹配预算。Provider `/access` 端点读取目标 agent 的 `contact_rulebook`，判断发起方 agent 是否能联系目标 agent。

关键语义：

- `budget < 0`：blocklist / 拒绝。
- `budget == 0`：未授权或预算耗尽 / 拒绝。
- `budget > 0`：允许联系，并在 Provider 中递减 counter。

因此，contact policy 控制的是“能不能建立联系”，不是“能不能读取某个数据对象”。

### 3.3 One-Time Key 与 Access Token

Provider `/access` 在授权通过后返回目标 agent 的注册材料，并弹出一个 one-time key。

后续通信中：

1. 发起方 agent 获取目标 agent 的 OTK。
2. 发起方和接收方通过 DH 派生 SDHK。
3. 接收方 agent 生成 access-control token。
4. token 由 SDHK 加密返回给发起方。
5. 发起方后续消息携带 token。
6. 双方分别检查 token 是否存在、是否过期、quota 是否耗尽、recipient PAC 是否匹配。

源码中 token 字段包括：

- `nonce`
- `issue_timestamp`
- `expiration_timestamp`
- `communication_quota`
- `recipient_pac`

当前 token 绑定的是通信会话和 recipient PAC，不绑定具体数据对象、数据类别、数据用途、数据版本或数据密钥。

## 4. SAGA 不能直接表达的数据共享场景

SAGA 已经能表达：

- Bob 是否可以联系 Alice。
- Mallory 是否可以联系 Alice。
- 一个 agent 对另一个 agent 的联系预算是否耗尽。
- 通信 token 是否还有效。

但它不能直接表达：

1. Bob 可以联系 Alice，但只能读取 Alice 的日历空闲时间，不能读取邮件正文。
2. Bob 可以为了“安排会议”读取日历，但不能为了“报销统计”复用同一个授权。
3. Alice 的 memory、mail、document、calendar 需要不同数据分类和不同策略。
4. Provider 可以协助授权，但不应接触数据明文或 DEK 明文。
5. 同一 agent 对同一 owner agent 的不同数据对象，应有不同 max uses、有效期、purpose、data class、record scope。
6. token 注销后，已有 re-encryption context 是否仍可复用。
7. 数据版本轮换后，旧授权是否仍可解密新版本数据。

这些场景构成 PRE-SAGA 的论文动机。

## 5. PRE-SAGA 的精确补位

PRE-SAGA 应在 SAGA contact policy 之后新增 Data Sharing Policy。

建议把系统拆成两层：

```text
Layer 1: Contact Authorization
  SAGA decides whether requester agent may contact owner agent.

Layer 2: Data Decryption Authorization
  PRE-SAGA decides whether requester agent may obtain a decryptable encrypted DEK / ciphertext view.
```

PRE-SAGA 不需要声称提出新的 PRE 密码学原语。它的贡献应是：

- 把 PRE proxy 放入 SAGA-style Provider 治理框架。
- 增加 Data Sharing Policy schema。
- 把 token 与 requester、owner、data class、record scope、purpose、expiry、max uses、data version 绑定。
- 让 Provider/PRE Proxy 在不接触明文数据和 DEK 明文的情况下执行授权转换。
- 增加 audit log，记录每次数据授权和 re-encryption 事件。

## 6. Baseline Comparison 设计

后续论文实验建议至少比较三组 baseline：

| Baseline | 能力 | 暴露面 | 预期用途 |
|---|---|---|---|
| SAGA-only | 控制 agent 联系 | 不控制数据对象解密 | 证明 SAGA 的联系治理不足以表达数据共享治理 |
| Plaintext token server | Provider 直接管理明文 DEK 或明文数据授权 | Provider 可见 DEK/数据 | 作为性能和安全暴露面的弱 baseline |
| PRE-SAGA | Provider/PRE Proxy 只做策略判断和密文转换 | Provider 不见明文数据和 DEK 明文 | 论文主方案 |

核心评价指标：

- 正常任务成功率。
- 未授权 data class 拦截率。
- purpose mismatch 拦截率。
- requester mismatch 拦截率。
- token reuse 拦截率。
- Provider 是否可见 DEK 或数据明文。
- token 签发延迟。
- policy evaluation 延迟。
- PRE transform 延迟。
- 审计日志完整性。

## 7. 阶段 0 已完成 / 待完成核对

- [x] 拉取并运行 SAGA 官方仓库的最小本地示例。
- [x] 使用本地 MongoDB 跑通 Provider、用户注册、agent 注册。
- [x] 确认 contact token / access-control token 的主要字段。
- [x] 确认 agent registry 的关键字段。
- [x] 确认 contact policy 的存储与匹配方式。
- [x] 记录 SAGA 不能直接表达的数据共享策略场景。
- [x] 写出 baseline comparison：SAGA-only、plaintext token server、PRE-SAGA。
- [x] 增加不止两个 agent 的 SAGA 复现实验。

## 8. 进入阶段 1 前的建议

下一阶段不应直接写大段论文正文，而应先形成 `paper/protocol_spec.md`。最低应包含：

1. 实体定义：User、Owner Agent、Requester Agent、Provider/PRE Proxy、Encrypted Store。
2. 数据对象定义：record id、data class、ciphertext、encrypted DEK、metadata、version。
3. Data Sharing Policy schema。
4. token 与 PRE transform 的绑定字段。
5. audit log schema。
6. 安全目标：DEK secrecy、requester binding、policy compliance、provider blindness、auditability。

阶段 1 的关键判断标准是：审稿人能否仅凭协议规范理解 PRE-SAGA 比 SAGA 多控制了哪一层。
