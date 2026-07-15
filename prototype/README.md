# PRE-SAGA 原型

这是论文初稿配套的最小可运行原型。它用于模拟 PRE-SAGA 的核心行为：

- SAGA 风格的 Agent Contact Policy。
- 新增 Data Sharing Policy。
- 本地数据的信封加密。
- Provider 作为 PRE Proxy，在不接触明文和数据密钥的情况下转换加密数据密钥。
- token 有效期、请求方绑定和使用次数限制。

运行：

```powershell
python .\prototype\run_experiments.py
```

实验场景：

- `normal_data_sharing`：日历 agent 只共享 free/busy 数据，请求方成功解密。
- `denied_by_data_policy`：Contact Policy 允许联系，但 Data Sharing Policy 不允许访问邮件正文。
- `provider_plaintext_blindness`：Provider 能执行密钥转换，但审计日志和代理侧均不出现明文。
- `token_misuse_blocked`：token 超过使用次数后，重加密请求被拒绝。

实现说明：

- 凭证签发使用 Python 标准库 HMAC 模拟。
- 数据加密使用简化信封加密模型。
- PRE 使用 toy transform：`Enc(pk, dek) = dek XOR H(pk)`，`rk_a_b = H(pk_a) XOR H(pk_b)`。
- 该 toy transform 只用于演示“代理可转换密文密钥但不接触明文”的协议语义，不能用于真实安全系统。

