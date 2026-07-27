# PRE-SAGA 实验跟踪日志

> 状态：历史实验日志，仅保留早期研究过程，不再作为当前验证结果的权威索引。
>
> 新测试与实验的命令、代码状态、环境、结果、证据路径和重跑理由统一记录在
> `docs/verification/test-ledger.yaml`；当前工作包记录在
> `docs/workflow/current-milestone.md`。本文件中的历史内容不覆盖、不删除。

本文件用于保留 PRE-SAGA 的早期实验、设计变更、失败原因和后续计划。

## 日志格式

```text
## YYYY-MM-DD HH:mm - 标题

- 目的：
- 修改：
- 命令：
- 结果：
- 问题：
- 下一步：
```

## 2026-07-14 设计基线确认

- 目的：将项目从快速 toy demo 调整为对标 SAGA 的长期论文产出计划。
- 修改：新增 `paper/publication_plan.md`，明确论文基调、代码目录、时间线、攻击矩阵、形式化分析与评估路线。
- 命令：未新增运行命令，本次以设计和文档为主。
- 结果：确定 PRE-SAGA 的主线为“Contact Policy 控制可联系，Data Sharing Policy 控制可解密”。
- 问题：当前原型仍是 toy PRE，无法支撑优秀会议文章的实验强度。
- 下一步：优先完成 `baseline_gap_analysis.md` 与模块化代码框架。

## 2026-07-14 SAGA 源码状态修正

- 目的：确认 SAGA 是否公开源码。
- 修改：在计划中记录 SAGA 官方仓库 `https://github.com/gsiros/saga`。
- 命令：通过论文 PDF 文本检索和网页核查确认。
- 结果：SAGA 源码和形式化验证模型是公开的，仓库包含 `saga/`、`experiments/`、`proofs/` 等目录。
- 问题：尚未在本地拉取和运行 SAGA 仓库。
- 下一步：后续实验应尝试复现 SAGA baseline，至少复刻其 contact policy 与 token 流程。

## 2026-07-14 18:20 - SAGA 官方仓库组件级复现

- 目的：新建独立目录，对 SAGA 官方仓库进行标准复现准备，并获取可验证终端输出和截图。
- 修改：新增 `saga_reproduction/`，下载官方仓库 zip，解压到 `saga_reproduction/saga_clean/saga-main`；生成 `saga_reproduction/terminal_output.txt` 和 `saga_reproduction/terminal_screenshot.png`。
- 命令：
  - `Invoke-WebRequest https://github.com/gsiros/saga/archive/refs/heads/main.zip`
  - `python -m pip install cryptography requests flask flask_sqlalchemy flask_pymongo flask_bcrypt flask_jwt_extended authlib smolagents simple-parsing`
  - `python generate_credentials.py ca .\saga_reproduction\runtime\ca\`
  - `python -c "... generate_ed25519_keypair ... verify_signature ..."`
  - `python -c "... UserConfig.load('alice.yaml') ..."`
- 结果：
  - 官方仓库下载成功。
  - 依赖安装成功，`simple_parsing` 使用 PyPI 包 `simple-parsing` 替代 README 中 GitHub 依赖。
  - Ed25519 签名验证成功：`signature_valid= True`。
  - X25519 公钥长度验证成功：`x25519_public_len= 32`。
  - Alice 配置加载成功：`email= alice@mail.com`，`agent= dummy_agent`，`port= 7000`。
  - 官方 CA 凭据生成成功：`ca.crt`、`ca.key`、`ca.pub`。
- 问题：
  - 完整 Provider/User/Agent 端到端复现尚未完成。
  - SAGA Provider 依赖 MongoDB；本机未检测到 `mongod`、Docker 或 127.0.0.1:27017 服务。
  - 解压目录对当前沙箱呈只读状态，无法在源码目录内 `pip install -e .` 或直接写入 `saga/ca`、`saga/provider`。
- 下一步：
  - 安装或启动隔离 MongoDB。
  - 准备可写源码副本或使用管理员/非沙箱权限运行官方 CA/Provider。
  - 按 README 完成 Alice/Bob 注册、agent 注册、`experiments/hello_world.py` listen/query 通信复现。

## 2026-07-14 19:13 - D 盘安装本地 SAGA MongoDB

- 目的：替代 Atlas SRV/DNS 连接问题，为 SAGA 官方 Provider 提供本地 MongoDB。
- 修改：
  - 新建 `D:\MongoDB\SAGA_MongoDB`。
  - 下载 MongoDB Community Server Windows x64 zip 包。
  - 解压到 `D:\MongoDB\SAGA_MongoDB\server`。
  - 新增 `mongod-saga.cfg`、`start-saga-mongodb.ps1`、`stop-saga-mongodb.ps1` 和 `README_SAGA_MongoDB.md`。
- 命令：
  - `Invoke-WebRequest https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-8.3.4.zip`
  - `Expand-Archive ...`
  - `& "D:\MongoDB\SAGA_MongoDB\start-saga-mongodb.ps1"`
  - `MongoClient("mongodb://127.0.0.1:27017/saga").admin.command("ping")`
- 结果：
  - `mongod.exe --version` 返回 `db version v8.3.4`。
  - MongoDB 进程已启动，进程 ID 为 `19120`。
  - `pymongo` 连接返回 `{'ok': 1.0}`。
  - SAGA 可用连接串：`mongodb://127.0.0.1:27017/saga`。
- 问题：
  - 当前以普通进程方式启动，尚未注册为 Windows 服务。
  - 重启电脑后需要重新运行启动脚本。
- 下一步：
  - 继续 SAGA 端到端复现：启动 CA server、Provider，注册 Alice/Bob，运行 `hello_world.py`。
## 2026-07-14 19:48 - SAGA 本地 MongoDB 端到端复现完成

- 目的：在本地 MongoDB 替代 Atlas 后，继续完成官方 SAGA baseline 的端到端复现。
- 修改：
  - 使用 `D:\MongoDB\SAGA_MongoDB` 提供本地 MongoDB。
  - 使用 `D:\Users\New project 1\saga_reproduction\saga_clean\saga-main` 作为官方源码的 Windows 可运行副本。
  - 在工作副本中修正证书 UTC 有效期、Windows agent 目录名冒号问题、DummyAgent timing 缺失问题。
  - 新增 `saga_reproduction\SAGA_E2E_REPRODUCTION_RESULT.md`。
  - 新增 `saga_reproduction\saga_e2e_terminal_output.txt`。
  - 新增 `saga_reproduction\saga_e2e_terminal_screenshot.png`。
- 命令：
  - 启动本地 MongoDB：`D:\MongoDB\SAGA_MongoDB\start-saga-mongodb.ps1`
  - 启动 CA 文件服务：`python -m http.server 8000`
  - 启动 Provider：`python provider.py`
  - 注册 Alice/Bob 用户和 agent：`python user.py --uconfig ... --register --register-agents`
  - 运行 SAGA hello_world：`python hello_world.py listen ...` 与 `python hello_world.py query ...`
- 结果：
  - MongoDB ping 成功：`mongo_ping=1.0`。
  - `saga` 数据库中包含 `users` 和 `agents` 集合。
  - 注册用户数量为 2，注册 agent 数量为 2。
  - Provider `/register`、`/register_agent`、`/certificate`、`/access` 均返回成功状态。
  - Bob 成功连接 Alice agent：`Connected to 127.0.0.1:7000 with verified certificate`。
  - Bob 成功申请 token，生成 SDHK，并完成多轮消息交互。
  - token quota 从 49 递减到 46。
  - 任务以 `<TASK_FINISHED>` 结束，token 在发起侧注销。
- 问题：
  - 当前只完成正常通信场景，尚未补充拒绝通信、token 重放、防越权等负面实验。
  - 当前本地修正是 Windows 兼容性修正，正式论文应明确区分“协议复现”与“工程适配”。
- 下一步：
  - 增加 contact policy 拒绝实验。
  - 增加 token 注销后重放失败实验。
  - 将复现结果写入 baseline 章节，作为后续 PRE-SAGA/Data Sharing Policy 改造的对照组。

## 2026-07-15 10:20 - 阶段 0 推进与 SAGA 三 Agent 复现

- 目的：
  - 根据 `paper/publication_plan.md` 推进阶段 0：基线复现与差距确认。
  - 在已完成 Alice/Bob 双 agent 复现的基础上，完成不止两个 agent 的 SAGA 复现。
- 修改：
  - 新增 `paper/baseline_gap_analysis.md`。
  - 新增 `saga_reproduction/SAGA_MULTI_AGENT_REPRODUCTION_RESULT.md`。
  - 新增 `saga_reproduction/saga_multi_agent_terminal_output.txt`。
  - 新增 `saga_reproduction/saga_multi_agent_terminal_screenshot.png`。
  - 修改 `saga_reproduction/saga_clean/saga-main/saga/ca/CA.py`：本地 CA 文件已存在时直接加载，避免本地复现实验依赖临时 HTTP CA 文件服务。
- 复现内容：
  - 保留 Alice/Bob baseline。
  - 新增 Mallory 作为第三个有效 agent。
  - Alice 作为接收方，Bob 和 Mallory 分别作为发起方连接 Alice。
- 结果：
  - Bob -> Alice 成功：证书验证、Provider access、SDHK、token、quota 递减、`<TASK_FINISHED>`、token 注销均完成。
  - Mallory -> Alice 成功：证书验证、Provider access、SDHK、token、quota 递减、`<TASK_FINISHED>`、token 注销均完成。
  - SAGA baseline 已验证可支持多个发起方 agent 联系同一接收方 agent。
- 注意：
  - Provider 启动目录必须与注册时一致，否则 Provider stamp 验证会失败。
  - Candice 曾在错误 Provider 工作目录下注册，因此不作为本次有效复现证据使用。
- 下一步：
  - 进入阶段 1，优先撰写 `paper/protocol_spec.md`。
  - 定义 Data Sharing Policy schema、数据对象模型、PRE transform 绑定字段和审计日志格式。
