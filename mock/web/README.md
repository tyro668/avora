# mock/web：模拟 SaaS 聊天页

各网关（Go 参考网关、`mock/node`、`mock/python`、`mock/java`、`mock/rust`）共用的一个静态页面，用来模拟“SaaS 用户通过已配对的本机模型聊天”。纯 HTML + JS，无构建步骤，中文界面。

| 路径 | 内容 |
|---|---|
| `/`、`/chat` | `chat.html` |
| `/chat/chat.js` | 页面逻辑 |
| `/chat/qrcode.js` | 二维码生成（[qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4，MIT，原样内置，不依赖 CDN） |

功能：

- **对话**：左栏是品牌（租户名 + Chat）、新对话、历史对话（保存在浏览器 localStorage，按租户和用户区分，按今天/昨天/更早分组，可删除）、设备状态和当前用户。回答像 agent 一样显示一条可折叠的执行步骤：已派发到设备（收到 `X-Task-Id` 响应头）、开始生成（首个 delta，含首字耗时）、模型请求调用工具（`finish_reason: tool_calls`）、生成完成、已停止或出错。步骤只来自页面真实观察到的事件。
- **工具调用**：模型在 `delta.tool_calls` 中请求的工具显示为卡片，标注「模型请求」，展示函数名、调用 ID 和参数；页面不执行工具，也不伪造结果。
- **回答排版**：内置一个小型 Markdown 渲染器（标题、列表、引用、粗体/斜体、行内代码、`http(s)` 链接、代码块），代码块带简单高亮和「复制」按钮。所有文本经 `textContent` 写入，HTML 原样当文本显示。生成中末尾显示光标。
- 回答下方一行显示首字耗时、总耗时、输入 → 输出 tokens、tok/s、非 `stop` 的 `finish_reason` 与 `task_id`。模型名显示短名，悬停显示完整 ID。
- **输入框**：模型选择、添加图片（以 `data:` URI 发送，超过 16 KiB 时网关走 blob 分块）、发送；生成中显示停止按钮，停止会中断请求，网关随即向设备发送 `task.cancel`。
- **配对新设备**：第一步复制 `lmbp://pair` 链接或 CLI 命令；第二步输入你自己桌面端显示的 8 位配对码后批准或拒绝（网关不再列出待配对请求，弹窗只在用户点击「配对新设备」或页面带 `?user_code=…&jkt=…` 打开时出现；设备名称是设备自报的，只按纯文本显示）。`jkt` 收在默认折叠的「高级」里。
- **我的设备**：点击左下角设备状态打开。只列在线设备及其模型与能力；离线和已吊销的设备收进「离线和已吊销 (N)」一行；吊销在每台设备的 ⋯ 菜单里，需确认。
- 错误按错误码显示中文说明（`DEVICE_OFFLINE`、`CONSENT_DENIED`、`MODEL_NOT_FOUND`、`DEVICE_BUSY`、`CAPABILITY_UNSUPPORTED`、`PAYLOAD_TOO_LARGE`、`UNAUTHENTICATED` 等）。

## 认证（开发登录）

页面本身**不含任何密钥**。打开后，用以下三项登录：

- 租户 ID（如 `acme`）
- 最终用户（作为 `X-End-User` 发送，如 `alice`）
- 租户 API Key（网关 `--tenant acme:ENV` 中环境变量 `ENV` 的值）

页面先调用 `GET /lmbp/v1/tenant/devices` 验证 Key，然后把它保存在**本标签页的 sessionStorage** 中（关闭标签页即清除），只发给本网关的 `/lmbp/v1/tenant/*` 与 `/v1/*`。

这相当于让浏览器扮演“租户后端”，**仅供开发与演示使用**。真实 SaaS 中，租户 Key 只能放在后端，`X-End-User` 应由后端根据登录会话注入。因此：

- Go 参考网关默认**不提供**此页面，需要显式加 `-chat-ui`（`lmbpmock gateway` 默认开启）；
- Node/Python 模拟网关默认开启，可用 `--no-chat-ui` 关闭。

所有页面文件都带严格的 CSP（`script-src 'self'`，`connect-src 'self'`，`frame-ancestors 'none'`），以及 `X-Content-Type-Options: nosniff` 和 `Referrer-Policy: no-referrer`。用户和模型的文本一律用 `textContent` 渲染。页面不依赖 CDN，字体使用系统字体。

## 运行

最快的方式是 `scripts/mock-start.sh [go|node|python|java|rust]`：它会自动完成下面这几步，并打印登录信息和 Connector 命令。手动步骤如下：

```bash
export LMBP_TENANT_KEY_ACME=$(openssl rand -hex 24)        # 租户 API Key，登录页面时粘贴它
export AVORA_DATA_KEY=$(openssl rand -hex 32)     # 连接器加密本机适配器配置用

# 1) 假模型（同时提供 Ollama 原生 /api/chat 和 OpenAI /v1）；有真实 Ollama 时可跳过
go run ./mock/cmd/lmbpmock fakemodel -listen 127.0.0.1:11500 -models qwen3-8b &

# 2) 任选一个网关（都在 http://127.0.0.1:8080/chat 提供页面）
go run ./cmd/avora server -listen 127.0.0.1:8080 -db /tmp/gw.db -tenants acme:LMBP_TENANT_KEY_ACME \
  -tenant-profiles mock/tenant-profiles.example.json -issuer http://127.0.0.1:8080 -chat-ui &
#   node mock/node/gateway.mjs --listen 127.0.0.1:8080 --issuer http://127.0.0.1:8080 --tenant-profiles mock/tenant-profiles.example.json &
#   mock/python/.venv/bin/python mock/python/gateway.py --listen 127.0.0.1:8080 --issuer http://127.0.0.1:8080 --tenant-profiles mock/tenant-profiles.example.json &

# 3) 浏览器打开 http://127.0.0.1:8080/chat ，以 acme / alice / $LMBP_TENANT_KEY_ACME 登录，复制页面上的 Connector 命令，例如：
go run ./cmd/avora connector -pair-link 'lmbp://pair?v=2&gateway=http%3A%2F%2F127.0.0.1%3A8080&tenant=acme' \
  -adapter-id local -ollama-url http://127.0.0.1:11500 -models qwen3-8b -capabilities vision \
  -identity /tmp/dev/id.json -adapter-file /tmp/dev/adapters.enc -audit-db /tmp/dev/audit.db
#    在终端确认授权后，把连接器打印的配对码填到页面上，点“批准”。设备上线后就可以对话（模型名为 local/qwen3-8b）。
```

接真实 Ollama：`-ollama-url http://127.0.0.1:11434 -models llama3.2`。

## 测试

`node --test mock/web/test` 测试 `chat.js` 中的纯函数（Markdown、高亮、tool_calls 合并、执行步骤、历史分组）；装了 Node 时 `go test ./mock/web` 也会运行它。

## 端到端测试

```bash
scripts/chat-ui-e2e.sh go node python java rust；SHOTS=目录 指定截图位置，CHROME=浏览器路径
```

对每个网关，用无头 Chrome（playwright-core）完成以下检查：

1. 页面与 CSP 正常，HTML 中没有 Key；
2. 错误 Key 被拒，正确 Key 登录成功；
3. 显示配对链接与二维码；
4. 启动真实 Go 连接器（Ollama 适配器 → 假模型的 `/api/chat`），在页面上用 `user_code` + `jkt` 批准；
5. 设备上线；
6. 流式回答（逐步增长）带耗时、tokens 与执行步骤；
7. 第二轮带上历史；刷新页面后历史对话仍在；
8. 上传 ~35 KB 图片（走 blob）并被模型原样收到；
9. 停止生效；
10. 拒绝后再批准显示 `CONSENT_DENIED`；
11. 关闭连接器后发消息显示 `DEVICE_OFFLINE`。

截图：`chat-<impl>-paired.png`、`chat-<impl>.png`、`chat-<impl>-errors.png`。
