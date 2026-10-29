# 更新记录

## 未发布

协议加固（2026-10-29 协议审查的 P1 / P2 项，Go 内核与参考网关、Node / Python / Java SDK、Java / Rust / Node / Python 模拟网关、mock SaaS 与 mock/web 同步修改）：

- `tool_calls[].index` 上限 127（Schema 与网关一致）；越界时网关发 task.cancel(protocol_error)，调用方得到 502 INTERNAL。
- 每个任务的输出上限 64 MiB（明文和 E2EE 密文增量都计入），超出即取消任务。
- 配对：网关不再列出待配对请求（`pending_pairings` 已移除），只能用设备上显示的配对码批准；`device_name` 拒绝控制字符和 bidi 等可伪装文本的字符，界面上按纯文本显示并标注「设备自报名称」。
- 设备授权：未注册租户返回 `invalid_client`；每个客户端地址每分钟 60 次，每个租户最多 1000 个未完成配对，超出返回 429 `slow_down`（`Retry-After: 60`）；设备收到 10 次 `slow_down` 后继续轮询，配对码作废（`expired_token`）。
- 批准配对码是单次、原子的；错误码按「租户 + 最终用户」每分钟计 10 次，`lookup` 也计入，不再让一个用户锁住整个租户。
- jti 防重放缓存改为按过期时间的最小堆淘汰，不再每次全表扫描。
- Node / Python / Java SDK 必须显式配置 `issuer`，不再从请求 Host 推导；Go 参考网关未配置 issuer 时只接受回环 Host（其他 Host 返回 421）。
- 任务进行中吊销设备：调用方得到 502 `OUTCOME_UNKNOWN`（此前是 401）。
- 连接器在会话内拒绝重放的 task.run（任务 nonce / E2EE rid）。
- 删除方案时保留其审计记录（§20）。
- `lmbp-conformance` 新增 L4、P9–P13、M9、V3、X-T5、Z9 检查，共 138 项。

## 2.1.3

- 模型适配层统一到 `internal/backend/`，新增 Grok Build 和 Antigravity CLI；后端注册表统一提供命令行和桌面端的服务配置，共用 CLI 进程树清理和协议测试。
- 订阅模型的思考强度按模型能力展示，增加「默认」，Antigravity 档位与模型变体联动；保留 Codex 的 `max` / `ultra` 和旧配置兼容，恢复分段选择样式并精简表单说明。
- 修复新建方案提前使用默认模型名的问题：名称初始为空，手动填写或首次选定模型后确定，之后切换模型不再自动改名。
- 修复 Antigravity 手动测试通过后被后台探测误判为不可用的问题：统一使用 15 秒探测超时，并在方案详情显示不可用原因。
- 「可用模型」和配对确认页顶部新增「允许全部模型」开关：打开后保存为 `*`，列表锁定并全部勾选，以后新增的方案和模型自动开放；关闭后恢复之前的逐个勾选。配对确认页按钮改为「拒绝 / 允许」。
- 修复：Windows 托盘右键菜单显示乱码（「é…ç½®」「é€€å‡º」）。Windows 原生代码现在按 UTF-8 编译（MSVC `/utf-8`），菜单显示「配置」「退出」。
- 移除改名过渡期的全部兼容代码：旧数据目录自动迁移、旧环境变量与旧调试变量回退、旧命令转发、旧 SaaS 发现路径、安装包清理旧安装目录和旧快捷方式。Avora 尚未正式发布，不需要这些过渡。

## 2.1.2

- 修复：网关的 task.ack 可能乱序发出。客户端取消后，设备迟到帧的确认（如 2）偶尔晚于终止帧的确认（3）写出，设备看到的确认倒退，像是对终止帧之后的帧做了确认（v2.1.1 macOS 打包时一致性检查 S3 因此失败）。现在每个任务的确认按序串行写出，低于已发确认的不再发送。
- 修复：设备发来非法帧（非法终止帧、非法增量、序号跳号）或网关落盘失败时，网关先发 task.cancel 再判定结果；设备对取消的回复（task.error CANCELLED）偶尔先到，任务就被记成设备取消而不是 INTERNAL。现在先判定结果再通知设备停止。

## 2.1.1

- 产品名只用 Avora：窗口标题、托盘提示、macOS 显示名、Windows 安装包名称与快捷方式、界面文字、文档、架构图和截图都改为 Avora。
- GitHub Release 标题为「Avora <版本>」。

## 2.1.0

- 应用定名 Avora。协议名不变：LMBP、`lmbp` 子协议、`/lmbp/v1`、`/.well-known/lmbp`、`lmbp-conformance`、SDK 包名 `lmbp-server`。
- 命令 `avora`；Go 模块 `github.com/tyro668/avora`；Java 包 / Maven groupId `dev.avora`；应用标识 `dev.avora.desktop`；数据目录 `<配置目录>/avora`；环境变量 `AVORA_*`；SaaS 发现文档 `/.well-known/avora`；Schema `$id` / 错误类型 `https://avora.dev/...`；安装包 `Avora-<版本>-...`。
- 参考网关环境变量 `LMBP_SIGNING_SEED`、`LMBP_DATA_KEY`、`LMBP_TENANT_KEY_*`（`avora server -tenants` 默认 `default:LMBP_TENANT_KEY_DEFAULT`）；内核 C 导出 `AVORA_Start` / `AVORA_Call` / `AVORA_Free`；调试变量 `AVORA_NATIVE_LIB`；测试变量 `AVORA_ACCEPT_MOCK_DIR`、`AVORA_ACCEPT_PORT`；mock 命令 `lmbpmock`。
- Windows 窗口标题显示「Avora」（此前为空，任务栏和 Alt-Tab 不显示名称）。
- 内核动态库（`libavora.dylib`、`avora.dll`）改为 `-trimpath` 构建，产物中不再带构建机的源码路径。
