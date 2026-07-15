# SAGA 多 Agent 本地复现结果

复现状态：成功。

本次复现在已有 Alice/Bob 双 agent baseline 的基础上，新增 Mallory 作为第三个有效 agent，完成 Alice/Bob/Mallory 三 agent 场景：

```text
Bob     -> Alice
Mallory -> Alice
```

Alice 作为接收方 agent 保持监听；Bob 和 Mallory 分别作为发起方，请求访问 Alice，并各自完成 token 获取、通信、quota 递减和 token 注销。

## 环境

- SAGA 源码副本：`D:\Users\New project 1\saga_reproduction\saga_clean\saga-main`
- MongoDB：`mongodb://127.0.0.1:27017/saga`
- Provider：`https://127.0.0.1:5000`
- Alice agent：`alice@mail.com:dummy_agent`，端口 `7000`
- Bob agent：`bob@mail.com:dummy_agent`，端口 `7001`
- Mallory agent：`mallory@mail.com:dummy_agent`，端口 `7002`

## 注册结果

MongoDB 中当前包含 4 个 agent：

```text
alice@mail.com:dummy_agent
bob@mail.com:dummy_agent
candice@mail.com:dummy_agent
mallory@mail.com:dummy_agent
```

其中本次有效三 agent 复现使用：

```text
alice@mail.com:dummy_agent
bob@mail.com:dummy_agent
mallory@mail.com:dummy_agent
```

说明：Candice 曾在错误 Provider 工作目录下注册，保留在数据库中但不作为本次有效复现证据使用。

## Bob -> Alice 结果

关键日志：

```text
Connected to 127.0.0.1:7000 with verified certificate.
Requesting new token from alice@mail.com:dummy_agent.
Derived SDHK: e359609530ad5ddf959a33e4845c0cd851ff70dde2dab8f458f499b04a49a2db
Received token: <redacted>
Sent: 'Hello world!'
Remaining token quota: 49
...
Sent: '<TASK_FINISHED>'
Remaining token quota: 46
Task deemed complete from initiating side.
Token invalidated from the initiating side.
```

结论：Bob 成功通过 Provider access、证书验证、OTK/SDHK/token 流程联系 Alice。

## Mallory -> Alice 结果

关键日志：

```text
Connected to 127.0.0.1:7000 with verified certificate.
Requesting new token from alice@mail.com:dummy_agent.
Derived SDHK: 34c3803a67fc6626252b0f0abd35ee968bb784acc775c51870b269338a13760b
Received token: <redacted>
Sent: 'Hello world!'
Remaining token quota: 49
...
Sent: '<TASK_FINISHED>'
Remaining token quota: 44
Task deemed complete from initiating side.
Token invalidated from the initiating side.
```

结论：Mallory 作为第三个 agent，也成功通过同一 Alice 接收方完成独立授权和通信。

## 本次复现暴露的工程注意点

1. Provider 的启动目录必须保持一致。
   - 从 `saga/provider` 启动会使用 `saga/provider/provider.key/crt`。
   - 从仓库根目录启动会生成另一套 `provider.key/crt`。
   - 如果 Provider key 不一致，已有 agent material 的 Provider stamp 会验证失败。

2. Windows 环境中 `Path`/`PATH` 重复会导致 `Start-Process` 报错。
   - 复现实验中通过在单次 PowerShell 命令内移除重复 `PATH` 环境键规避。

3. SAGA 官方 CA 类默认强制从 CA endpoint 下载 CA 文件。
   - 本地复现中已加入一个兼容性补丁：如果本地 `ca.key` 和 `ca.crt` 已存在，则直接加载本地 CA。
   - 该补丁不改变协议语义，只减少临时 HTTP 文件服务依赖。

## 证据文件

- Bob 日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\bob_to_alice_multi.log`
- Mallory 日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\mallory_to_alice_multi.log`
- Mallory 注册日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\mallory_full_register.log`
- Provider 日志：`D:\Users\New project 1\saga_reproduction\runtime\saga_multi_agent\provider_correct_workdir.log`
- 终端摘录：`D:\Users\New project 1\saga_reproduction\saga_multi_agent_terminal_output.txt`
- 终端截图：`D:\Users\New project 1\saga_reproduction\saga_multi_agent_terminal_screenshot.png`

## 结论

本次实验说明，SAGA baseline 不只可以跑通两个 agent 的最小通信，也可以支持多个发起方 agent 分别联系同一个接收方 agent。该复现可作为后续 PRE-SAGA 设计中的多 requester 数据共享场景 baseline。
