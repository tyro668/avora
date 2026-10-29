# lmbpserver：LMBP 服务端 Go SDK

让你的 SaaS 后端使用**用户自己电脑上的模型**（经 Avora 桌面端）。业务代码只做两件事：

1. **配对**：给用户展示配对链接 / 二维码，再批准用户在桌面端看到的配对码；
2. **调用模型**：标准的 OpenAI（`/v1/chat/completions`、`/v1/models`）或 Anthropic（`/v1/messages`）请求，可以直接用官方 `openai-go` / `anthropic-sdk-go`，也可以用 SDK 自带的进程内客户端。

WebSocket 会话、JOSE 签名、令牌刷新、seq/ack/续传、信用流控、大图分块、E2EE 透传都封装在 SDK 内部（内嵌参考网关 `internal/lmbp/gateway`，与 `avora server` 同一份代码）。

> **成熟度**：本 SDK 内嵌 **Go 参考网关**（与 `avora server` 同一份代码），是各语言 SDK 的行为基准。Node、Python、Java SDK 是独立重新实现，与它存在真实的行为差异。
> 通过共享 Schema、测试向量和 `lmbp-conformance` 不等于符合规范，只说明在被检查的点上一致；见[各实现与成熟度](../../docs/implementations.md)。

## 安装

```bash
go get github.com/tyro668/avora/sdk/go
```

```go
import lmbpserver "github.com/tyro668/avora/sdk/go"
```

需要 Go ≥ 1.22（`go.mod` 下限）；为包含标准库安全修复，建议用 Go ≥ 1.24.6。SQLite 存储使用纯 Go 驱动，无需 cgo。

## 快速开始（net/http）

```go
srv, err := lmbpserver.New(ctx, lmbpserver.Options{
    Tenants: []lmbpserver.Tenant{{ID: "acme", APIKey: os.Getenv("TENANT_API_KEY"),
        Profile: lmbpserver.TenantProfile{DisplayName: "Acme CRM", RequestedScopes: []string{"lmbp.chat"}}}},
    Issuer: "https://saas.example.com",          // 网关对外 https origin；留空为开发模式
    Store:  must(lmbpserver.OpenSQLiteStore("lmbp.db", encKey32)), // 默认内存
})
defer srv.Close()

mux := http.NewServeMux()               // 你自己的路由
// 1. 配对
mux.HandleFunc("GET /app/pair", func(w http.ResponseWriter, r *http.Request) {
    info, _ := srv.Pairing.Create("acme", "")  // info.Link / info.QRSVG / info.QRPNG
    json.NewEncoder(w).Encode(info)
})
mux.HandleFunc("POST /app/pair/approve", func(w http.ResponseWriter, r *http.Request) {
    res, err := srv.Pairing.Approve(r.Context(), "acme", currentUser(r), r.FormValue("user_code"), "")
    ...
})
// 2. 调用模型（进程内，无网络开销）
c, _ := srv.Client("acme", currentUser(r))
models, _ := c.Models(ctx)
m, _ := c.Messages(ctx, lmbpserver.MessagesRequest{Model: models[0].ID, MaxTokens: 512,
    Messages: []lmbpserver.AnthropicMessage{{Role: "user", Content: "你好"}}})

http.ListenAndServe(":3000", srv.Middleware(mux)) // 协议路径由 SDK 处理，其余交给 mux
```

完整示例：[`examples/go-nethttp`](../../examples/go-nethttp/main.go)（独立 Go 模块，演示外部项目引用本 SDK）。

## API

| 分类 | API |
|---|---|
| 构造 | `New(ctx, Options{Tenants, Issuer, Store, SigningKey, MaxConcurrency, Logger, Retention})`；`ctx` 结束时停止过期任务清理 |
| 挂载 | `Handler()`（挂在根路径）、`Middleware(next)`（协议路径由 SDK 处理，其余交给 `next`）、`Close()` |
| 密钥 | `Keys.KID()`、`Keys.PublicJWK()`、`Keys.JWKS()`；`GenerateSigningKey()`、`GenerateTenantKey()`。未传 `SigningKey` 时，签名种子保存在 Store 中（实现了 `SecretStore` 的存储），首次启动生成 |
| 配对 | `Pairing.Link(tenant, issuer)`、`Pairing.Create(...) → PairingInfo{Link, QRSVG, QRPNG}`、`Pairing.Lookup(ctx, tenant, user, code) → PendingPairing{DeviceName, JKT, ...}`、`Pairing.Approve(ctx, tenant, user, code, jkt)`、`Pairing.Deny(...)`、`Pairing.ListDevices(ctx, tenant, user) → []DeviceInfo{Online, Models, ...}`、`Pairing.RevokeDevice(ctx, tenant, user, id)` |
| 错误 | `ErrCodeInvalid`、`ErrCodeDenied`、`ErrJKTMismatch`、`ErrDeviceUnknown`、`ErrUnknownTenant`、`ErrRateLimited`（每租户每分钟 10 次错误配对码后锁定，`Approve`/`Deny` 与 HTTP 批准接口共用同一计数）；模型调用返回 `*APIError{Status, Code, Message}` |
| 进程内客户端 | `Client(tenant, user)` → `Models`、`ChatCompletion`、`ChatCompletionStream`、`Messages`、`MessagesStream`；流为 `*Stream[T]`：`for s.Next() { s.Current() }; s.Err()`，`Close()` 会取消任务。只有读到终止符（`[DONE]`/`message_stop`）时 `s.Err()` 才为 nil；终止符前的 EOF 或断线返回 `ErrIncompleteStream`（`errors.As` 得到 `*IncompleteStreamError{TaskID, LastEventID, Cause}`），用其游标续传。调用选项 `WithIdempotencyKey(k)`、`WithLastEventID(id)`；`s.LastEventID()` 是续传游标，`s.TaskID()` 是任务 ID，`ResumeChatCompletionStream(ctx, taskID, lastEventID)` 从游标之后接着读 |
| E2EE | `SealE2EERequest(dev DeviceInfo, pinnedJKT, E2EERequest) → *E2EESealed{JWE, RID, ResponseKey}`，放进 `ChatRequest.E2EE`；响应帧 `ChatCompletionChunk.E2EE` / `ChatCompletion.E2EE` 依次交给 `rd := sealed.Reader()` 的 `rd.Next(frame)` 解密（要求 seq 连续递增、`task.done` 之后不再有帧），结束时检查 `rd.Finish()`（缺少密封 `task.done` 即视为截断），再用 `DecodeE2EEDelta` 解析 `task.delta`；续传用 `sealed.ReaderAfter(rd.Last())`。`sealed.Open` 只校验单帧，无法发现重排、重复、丢帧或截断。`pinnedJKT` 是配对时记录的设备指纹（`ApproveResult.JKT`），`DeviceInfo.PublicKey` / `E2EEKey` 来自 `ListDevices` |
| 传输层 | `Transport()`：进程内 `http.RoundTripper`，可交给任意 HTTP 客户端（包括官方 SDK 的 `option.WithHTTPClient`） |
| 存储 | `NewMemoryStore()`、`OpenSQLiteStore(path, key32)`（key 非空时 AES-256-GCM 加密提示词、输出与密钥）；自定义存储实现 `Store`（可选 `SecretStore`），只需公开类型 `StoreTenant`、`DeviceAuth`、`Device`、`Idempotency`、`Task`、`Event`、`ErrNotFound`、`ErrExists`（示例：[`examples/customstore`](examples/customstore)） |
| 协议类型 | `ChatMessage`、`Content`、`Text()`、`Tool`、`ToolCall`、`Usage`、`JWK`、`TenantProfile` 等（别名，外部模块无需引用 `internal/`） |

`Approve` 的 `jkt` 参数可选：传入 `Lookup` 返回的设备密钥指纹，可防止配对码被换成其他设备。

## 官方客户端原样可用

```go
oai := openai.NewClient(option.WithBaseURL("https://saas.example.com/v1/"), option.WithAPIKey(tenantKey),
    option.WithHeader("X-End-User", userID))
claude := anthropic.NewClient(option.WithBaseURL("https://saas.example.com/"), option.WithAPIKey(tenantKey))
// 同进程时：option.WithHTTPClient(&http.Client{Transport: srv.Transport()})
```

模型 ID 形如 `dev_xxx/qwen3-8b`（设备 ID / 模型名），从 `Models` 获取。

## 测试

```bash
go test ./sdk/go                         # 真实桌面连接器配对 + memory/sqlite + 中间件 + 进程内客户端
scripts/mock-interop.sh sdk-go sdk-go-sqlite   # lmbp-conformance + 连接器端到端 + 官方 openai/anthropic 客户端
```

## 限制

- 存储是单实例的：多副本部署需要共享会话路由（同一用户的设备 WebSocket 与请求须落到同一实例）。
- `/v1/messages` 不支持 E2EE（`lmbp_e2ee`），需要端到端加密时用 `/v1/chat/completions`。
- Anthropic 模型列表的 `display_name`、`created_at` 为占位值。
