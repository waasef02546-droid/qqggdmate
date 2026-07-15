# PRE-SAGA 选题基调与可行性说明

## 结论

本次论文主题已从“代理重签名用于 agent 身份认证”调整为：

> 在 SAGA 的 Agent Contact Policy 基础上，引入 Data Sharing Policy 与代理重加密 PRE，实现多智能体系统中的加密数据共享。

这一调整更稳。原因是当前 agent 身份认证与请求授权已经有大量工程化近道，例如 OAuth、OIDC、DPoP、JWT、DID/VC、能力令牌和 AIP/IBCT。继续把“代理重签名用于身份认证”作为主创新点，容易被认为是在重复已有授权链工作。

PRE-SAGA 避开了这个问题。它不和主流身份认证协议竞争，而是补 SAGA 的一个明确缺口：

> SAGA 控制“谁可以联系谁”；PRE-SAGA 进一步控制“联系之后，谁可以解密哪类数据”。

## 为什么这个方向更有创新辨识度

SAGA 的 Agent Contact Policy 面向通信接触权限。例如，会议 agent 是否可以联系日历 agent。它通过 Provider、OTK、DH 派生密钥和访问控制 token 限制 agent 间通信窗口。

但真实 agent 协作还涉及本地数据共享：

- 日历空闲时间。
- 邮件正文和附件。
- 本地文档。
- 长期记忆。
- 工具调用结果。
- 企业知识库片段。

被允许联系某个 agent，不应自动意味着可以访问这些数据。因此，PRE-SAGA 把访问控制拆成两层：

```text
Agent Contact Policy：能不能联系这个 agent
Data Sharing Policy：能不能解密这类数据
```

这个问题定义比“agent 身份认证”更具体，也更容易体现与 SAGA 的差异。

## 技术路线

PRE-SAGA 采用信封加密：

```text
D       = 数据明文
DEK     = 随机数据密钥
C       = Enc(DEK, D)
EDEK_A  = Enc(PK_A, DEK)
```

其中 A 是数据拥有者 agent。Provider 不保存 DEK 明文，也不保存 D 明文。

当请求 agent B 被允许访问某类数据时，Provider 作为 PRE Proxy 执行：

```text
EDEK_A = Enc(PK_A, DEK)
      ↓ PRE transform
EDEK_B = Enc(PK_B, DEK)
```

B 使用自己的私钥解出 DEK，再解密数据密文 C。Provider 只看到密文密钥和策略元数据，不能解密数据。

## 和 SAGA 的关系

PRE-SAGA 不是替代 SAGA，而是放在 SAGA 之后：

```text
SAGA OTK / ACT：控制 agent 是否可以建立通信
PRE-SAGA：控制 agent 是否可以解密特定数据
```

因此论文可以明确写成 SAGA baseline 的扩展，而不是另起炉灶。

## 和主流 token 方式的区别

普通 token 方案通常是：

```text
请求方出示 token
服务端验证 token
服务端解密或读取数据
服务端返回明文
```

PRE-SAGA 是：

```text
请求方出示 SAGA token
Provider 检查 Data Sharing Policy
Provider 只转换加密数据密钥
请求方自己解密被授权数据
```

区别在于，PRE-SAGA 把“谁能看到明文”变成密码学控制，而不是只依赖服务端执行访问控制时不泄露。

## 可以形成的论文贡献

建议论文贡献写成三点：

1. 提出 SAGA 的数据级扩展问题：Agent Contact Policy 只控制通信接触，不足以表达本地数据、记忆、文档、邮件和日历的解密权限。
2. 设计 Data Sharing Policy，将请求 agent、数据类别、访问目的、token 摘要、有效期和使用次数绑定到代理重加密流程。
3. 实现 PRE-SAGA 最小原型，验证正常共享、数据策略拒绝、Provider 明文不可见和 token 滥用拦截四类场景。

## 需要避免的表述

不要写：

- 提出新的代理重加密算法。
- PRE-SAGA 取代 SAGA。
- Provider 完全不知道任何信息。
- 机制可以撤回已经解密的数据。
- 机制可以防止请求 agent 解密后二次泄露。

建议写：

- 提出一种基于 PRE 的 SAGA 数据共享扩展。
- Provider 不接触数据明文和 DEK 明文。
- Contact Policy 与 Data Sharing Policy 分层。
- 通过短期 token、使用次数和数据版本化缩短滥用窗口。

## 投稿定位

一个月内更适合定位为：

- 工作坊短文。
- 中文普通会议。
- 本科科研训练论文。
- 应用安全方向短论文。

不建议定位为：

- 顶级密码学会议。
- 声称提出全新可证明安全 PRE 构造的论文。

## 参考依据

- SAGA: A Security Architecture for Governing AI Agentic Systems, arXiv:2504.21034v2.
- Matt Blaze, Gerrit Bleumer, Martin Strauss. Divertible Protocols and Atomic Proxy Cryptography. EUROCRYPT, 1998.
- Giuseppe Ateniese, Kevin Fu, Matthew Green, Susan Hohenberger. Improved Proxy Re-Encryption Schemes with Applications to Secure Distributed Storage. NDSS, 2005.
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP).

