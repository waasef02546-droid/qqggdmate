# SAGA 本地端到端复现结果

复现状态：成功。

本次复现使用官方 SAGA 仓库源码的 Windows 可运行副本，配合 D 盘本地 MongoDB，完成了 `hello_world.py` 场景中的用户注册、代理注册、证书验证、token 申请、配额递减、代理通信、任务结束与 token 注销。

## 环境

- SAGA 源码副本：`D:\Users\New project 1\saga_reproduction\saga_clean\saga-main`
- MongoDB：`D:\MongoDB\SAGA_MongoDB`
- MongoDB 连接：`mongodb://127.0.0.1:27017/saga`
- Provider：`https://127.0.0.1:5000`
- Alice agent：`127.0.0.1:7000`
- Bob agent：`127.0.0.1:7001`

## 关键结果

- MongoDB 连接成功：`mongo_ping=1.0`
- 数据库集合：`agents`、`users`
- 用户数量：2
- 代理数量：2
- Alice 注册成功：`alice@mail.com`
- Bob 注册成功：`bob@mail.com`
- Alice agent 注册成功：`alice@mail.com:dummy_agent`
- Bob agent 注册成功：`bob@mail.com:dummy_agent`
- Provider `/access` 返回 200
- Bob 成功连接 Alice agent，并通过已验证证书建立通信
- Bob 从 Provider 请求并获得 token
- 通信过程中 token quota 从 49 递减到 46
- 任务以 `<TASK_FINISHED>` 结束
- token 在发起侧被注销

## 关键终端摘录

```text
Connected to 127.0.0.1:7000 with verified certificate.
Requesting new token from alice@mail.com:dummy_agent.
Derived SDHK: 6da011601e9771edb05180b5eb9f72dba360a0ead2282e2f3f2f8021761dc496
Received token: <redacted>
Sent: 'Hello world!'
Remaining token quota: 49
Received: 'Do you think we are alone in the universe?'
Sent: 'I don't know.'
Remaining token quota: 48
Received: 'Hello'
Sent: 'Do you think we are alone in the universe?'
Remaining token quota: 47
Received: 'I think we are not alone in the universe.'
Sent: '<TASK_FINISHED>'
Remaining token quota: 46
Task deemed complete from initiating side.
Token invalidated from the initiating side.
```

## 本地 Windows 兼容性修改

复现过程中发现官方源码在当前 Windows 环境下有三类阻塞点，因此只在 `saga_clean` 工作副本中做了兼容性修正：

1. 证书有效期时区问题：Provider 生成的证书在本地时区下会被验证为“尚未生效”，已改为 UTC 时间并向前留出 1 分钟余量。
2. Windows 路径非法字符问题：agent id 中的冒号 `:` 不能直接作为 Windows 文件夹名，已在本地目录名中替换为 `__`。
3. DummyAgent 统计项问题：`DummyAgent` 没有真实 LLM 初始化计时，原逻辑会读取不存在的 timing entry，已改为跳过该项。

这些修改不改变 SAGA 协议主流程，只是让官方实现能在当前 Windows 本地环境中跑通。

## 证据文件

- 终端输出摘录：`D:\Users\New project 1\saga_reproduction\saga_e2e_terminal_output.txt`
- 终端截图：`D:\Users\New project 1\saga_reproduction\saga_e2e_terminal_screenshot.png`
- Bob 查询日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_e2e\hello_bob_query_final.log`
- Alice 监听日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_e2e\hello_alice_listen_final.log`
- Provider 日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_e2e\provider.log`

## 结论

本次标准复现已经达到可作为 baseline 的最低要求：SAGA 的身份、证书、Provider 授权、一次性 token/密钥相关流程、agent 间通信和 token 消耗都能在本地被触发和观察。

后续如果要写论文中的 baseline 章节，建议不要只写“跑通 hello_world”，而是把本次复现扩展为三类实验：

1. 正常通信：当前已完成。
2. 拒绝通信：修改 contact policy，让未授权 agent 请求失败。
3. token 消耗与重放：验证 quota 递减、token 注销后不可复用。
