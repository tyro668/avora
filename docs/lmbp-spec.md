# LMBP（Local Model Bridge Protocol）规范

| 项目 | 内容 |
|---|---|
| 状态 | 正式版（Final），协议版本 2.0（不兼容 1.x，变更见附录 A） |
| 发布日期 | 2026-10-17 |
| 线上标识 | WebSocket 子协议 `lmbp`（不带版本）；信封字段 `v: 2`（主版本）；元数据 `protocol_versions: ["2.0"]`、`profiles`（§13）；配对链接 `lmbp://pair?v=2`。HTTP 路径前缀 `/lmbp/v1` 是接口路径版本，与协议版本无关，2.0 不变 |
| 机器可读契约 | [`spec/schemas/`](../spec/schemas)（JSON Schema 2020-12）、[`spec/asyncapi.yaml`](../spec/asyncapi.yaml)（AsyncAPI 3.0）、[`spec/openapi.yaml`](../spec/openapi.yaml)（OpenAPI 3.1） |
| 测试向量 | [`spec/testvectors/`](../spec/testvectors)（`vectors.json`、`jose.json`、`params.json`）；`spec/validate.sh` 校验本文与契约中的示例和向量一致 |
| 一致性测试 | `go run ./cmd/lmbp-conformance`（黑盒测试任意语言实现的网关；`-list` 输出 §13.2 的需求表） |
| 参考实现 | Go：`internal/lmbp`（协议与 JOSE）、`internal/lmbp/gateway`（网关）、`internal/lmbp/client`（设备端） |
| 实现指南 | [`docs/implementers-guide.md`](implementers-guide.md)：Java、Node.js、Python、Go、Rust |

本文规定 lmbp 的线上行为。任何语言实现的网关或设备端，只要满足本文的 MUST 要求，就能与其他实现互通。本文刻意不引用任何语言或库的行为：所有编码、签名和时间格式都由下文列出的 IETF/W3C 标准定义。

**目录**
1. 约定与术语
2. 引用的标准与设计决策
3. 角色与总体流程
4. 编码规则
5. 密钥、令牌与证明（JOSE 配置）
6. HTTP 接口
7. WebSocket 通道
8. 状态机
9. 错误
10. 超时与限制
11. 版本与能力协商
12. 安全要求
13. 一致性配置与测试
14. 断线续传（能力 `resume`）
15. 流量控制（能力 `flow`）
16. tools 与多模态（能力 `tools`、`multimodal`）
17. 端到端加密（能力 `e2ee`）
18. 网关身份绑定
19. 配对同意（签名元数据、`lmbp://pair`、`CONSENT_DENIED`）
20. 本机审计日志与用量统计
21. 尚未定义的内容
附录 A. 相对 1.0 的变更

---

## 1. 约定与术语

本文中的 **MUST**、**MUST NOT**、**REQUIRED**、**SHALL**、**SHALL NOT**、**SHOULD**、**SHOULD NOT**、**RECOMMENDED**、**NOT RECOMMENDED**、**MAY**、**OPTIONAL**，仅在全部大写时按 [BCP 14](https://www.rfc-editor.org/info/bcp14)（RFC 2119、RFC 8174）解释。

| 术语 | 含义 |
|---|---|
| 设备（device / connector） | 运行在用户电脑上的程序。持有设备私钥，负责调用本机模型。 |
| 网关（gateway） | 公网服务。负责配对、签发令牌、维持设备的 WebSocket 会话、下发任务，并对外提供 OpenAI 兼容接口。 |
| 租户后端（tenant back end / SaaS） | 业务方服务器。持有租户 API Key，代表已登录的终端用户调用网关。 |
| 终端用户（end user） | 租户里的一个人，由租户后端通过 `X-End-User` 告知网关。一台设备只属于一个终端用户。 |
| 任务（task） | 一次模型调用。网关以 `task.run` 下发，设备以 `task.delta`/`task.done`/`task.error` 回报。 |
| 帧（frame） | 一条 WebSocket 文本消息，正好包含一个 JSON 对象。 |

---

## 2. 引用的标准与设计决策

| 需求 | 采用的标准 | 理由 |
|---|---|---|
| 数据格式 | JSON，RFC 8259（I-JSON，RFC 7493 子集） | 所有语言都有可靠实现 |
| 二进制转文本 | base64url，**不带填充**，RFC 4648 §5 | 与 JOSE 一致 |
| 签名算法 | Ed25519，RFC 8032；在 JOSE 中写作 `alg: "EdDSA"`，RFC 8037 | 确定性签名，密钥短，无参数选择问题 |
| 签名封装 | **JWS 紧凑序列化**，RFC 7515，载荷内嵌 | 见下面的决策 D1 |
| 令牌 | JWT，RFC 7519；访问令牌采用 RFC 9068 配置（`typ: at+jwt`） | 标准声明 iss/sub/aud/iat/exp/jti |
| 令牌与密钥绑定 | `cnf.jkt`，RFC 7800 / RFC 9449；指纹按 RFC 7638 计算 | 被盗的令牌离开设备私钥就无法使用 |
| 持钥证明 | DPoP 风格的证明 JWT（借鉴 RFC 9449 的 `ath` 和 `jti`） | 见决策 D2 |
| 显式类型 | 每种 JWS 都有不同的 `typ`，遵循 RFC 8725 §3.11 | 防止把一种令牌冒充成另一种 |
| 配对 | OAuth 2.0 设备授权流程，RFC 8628 | 设备上不需要浏览器，也不需要输入密码 |
| 令牌刷新 | JWT Bearer 授权，RFC 7523 §2.1 | 设备私钥是唯一的长期凭据，不需要 refresh token |
| 公钥发布 | JWK Set，RFC 7517，路径 `/.well-known/jwks.json` | 支持密钥轮换 |
| HTTP 错误 | OAuth 接口按 RFC 6749 §5.2；管理接口按 RFC 9457 Problem Details；OpenAI 接口使用 OpenAI 错误对象 | 每个接口沿用其生态的惯例 |
| 实时通道 | WebSocket，RFC 6455，子协议 `lmbp`，强制 TLS | 双向、可穿透 NAT |
| 流式输出 | Server-Sent Events（WHATWG HTML §9.2），OpenAI `chat.completion.chunk` 格式 | 现有 OpenAI SDK 可以直接使用 |
| 时间 | JWT 和帧内统一用 NumericDate（整数秒，RFC 7519 §2）；HTTP 管理接口的时间字段用 RFC 3339 UTC 字符串 | 整数没有时区和格式问题 |
| 标识符 | 不透明字符串，见 §4.4；RECOMMENDED 使用 UUIDv7（RFC 9562）或 ULID | 按时间排序，便于建立索引 |

**D1：签名封装采用 JWS 紧凑序列化，不使用 JSON 规范化（JCS）。**
`task.run` 的载荷直接放在 JWS 里：先把载荷序列化成 UTF-8 JSON 字节，再签名；接收方按收到的字节验证，然后才解析 JSON。这样，各语言的 JSON 序列化差异（键顺序、数字格式、Unicode 转义、`<` 是否转义成 `\u003c`）都不会影响验签。也就不需要 RFC 8785（JCS）：JCS 实现少，对数字的处理也容易出错。分离式载荷（RFC 7797，`b64: false`）同样**不使用**。

**D2：持钥证明采用证明 JWT。**
本协议中，访问令牌不止用于 HTTP 请求，还要在 WebSocket 握手和会话期间使用。RFC 9449 的 `htm`/`htu` 是为 HTTP 请求设计的，不适用于这些场景。因此本协议定义了自己的 `typ: lmbp-proof+jwt`，用 `aud` 区分用途，用 `ath` 绑定具体凭据。它的结构和校验方法与 DPoP 相同，主流 JOSE 库都能直接处理。

---

## 3. 角色与总体流程

```
 终端用户浏览器 ── 登录 ──▶ 租户后端（持租户 API Key）
                               │  HTTPS：/lmbp/v1/tenant/*、/v1/*（Bearer 租户 Key + X-End-User）
                               ▼
 设备 ── HTTPS：/lmbp/v1/device/authorize、/lmbp/v1/token ──▶ 网关
 设备 ══ WSS：/lmbp/v1/connect（子协议 lmbp）════════▶ 网关
```

1. **配对（RFC 8628）**：设备生成 Ed25519 密钥对，把公钥发到 `/lmbp/v1/device/authorize`，拿到 `user_code`。用户在已登录的租户页面输入 `user_code`，租户后端调用 `/lmbp/v1/tenant/devices/approvals` 确认。设备带上证明 JWT 轮询 `/lmbp/v1/token`，得到 `device_id` 和第一个访问令牌。
2. **连接**：设备用访问令牌建立 WebSocket 连接，第一帧发送 `hello`，其中包含证明 JWT。网关回复 `welcome`。
3. **执行**：租户后端调用 `/v1/chat/completions`，网关向设备下发 `task.run`（JWS 签名），设备流式回报结果，网关转换成 SSE 返回。
4. **续期**：令牌到期前，设备用 jwt-bearer 断言换取新令牌，并通过 `session.token` 交给网关，连接不中断。

---

## 4. 编码规则

### 4.1 JSON
- 所有 JSON 文本 MUST 是 UTF-8 编码的 RFC 8259 JSON，SHOULD 符合 I-JSON（RFC 7493）。
- 发送方 MUST NOT 产生重复的成员名。接收方 SHOULD 拒绝含重复成员名的消息。签名内容总是按收到的字节验证，所以重复成员名不会绕过签名；但不同解析器可能取不同的值。Go 参考实现目前不做这项检查。
- 接收方 MUST 忽略不认识的成员（前向兼容）。
- 整数 MUST 落在 [-(2^53-1), 2^53-1] 内。本协议中的整数（时间戳、seq、计数）都是非负整数，MUST NOT 带小数点或指数（`1.0`、`1e3` 不是合法整数）。
- 字符串 MUST 是合法 Unicode，MUST NOT 包含单独的代理项（lone surrogate）。
- **长度单位**：本文所有字符串长度限制（写作“字符”）按 **Unicode 码点**计数，与 JSON Schema `maxLength` 相同：`a`、`张`、`😀` 各算 1。实现 MUST NOT 改用 UTF-8 字节数或 UTF-16 码元数。按字节计的限制（帧、请求体、附件）一律写明“字节”。
- **ASCII 头**：`X-End-User`（1–128）与 `Idempotency-Key`（1–255）的值 MUST 只含可打印 ASCII（0x20–0x7E）；否则网关 MUST 返回 400，MUST NOT 截断或转码。HTTP 头没有统一的非 ASCII 解码方式，各语言会得到不同的字符串。

### 4.2 base64url
- 采用 RFC 4648 §5 字母表，**MUST NOT 带 `=` 填充**。
- 接收方 MUST 拒绝含填充、空白或字母表以外字符的输入。测试向量 `padded_base64url` 覆盖这一点。

### 4.3 时间
- 帧和 JWT 中的时间字段（`iat`、`exp`、`token_expires_at`）是 NumericDate：自 1970-01-01T00:00:00Z 起的整数秒。
- HTTP 管理接口中名为 `*_at` 的字符串字段使用 RFC 3339 格式，时区 MUST 为 `Z`，例如 `2026-01-01T00:00:00Z`。
- 时钟偏差：访问令牌和断言允许 30 秒偏差，证明 JWT 允许 60 秒（§5.4）。实现 SHOULD 使用 NTP 同步时钟。

### 4.4 标识符
- `device_id`、`task_id`、`session_id`、`jti`、`nonce`、帧的 `id` 都是不透明字符串：长度 1–128，字符集 `[A-Za-z0-9._~-]`。
- 网关 MAY 给标识符加类型前缀（参考实现用 `dev_`、`task_`、`sess_`）。`device_id` MUST NOT 包含 `/`，因为它会出现在模型 ID 里（§6.6）。
- 每个标识符 MUST 至少有 122 比特随机性，或者是 UUIDv7/ULID。

---

### 4.5 路由命名
- 本协议定义的每个 HTTP 路由，路径中的每一段 MUST 是一个小写单词（`[a-z0-9]+`），MUST NOT 用 `-` 或 `_` 连成复合词。需要表达多个概念时，拆成多段，例如 `/lmbp/v1/tenant/devices/approvals`，而不是用连字符连成一段；租户应用的示例路由同样如此，例如 `/app/ask/claude`，而不是把 `ask` 和 `claude` 连成一个复合段。
- 路径参数 MUST 是一个单词：`{task}`、`{device}`（不写作 `{task_id}`）。参数的取值不受此限制（如 `task_…`）。
- 文件名形式的段 MAY 带扩展名，但主名 MUST 是一个单词（`jwks.json`）。
- 以下由外部标准或兼容接口决定的路径不受本节约束，实现 MUST 保持原样：

| 路径 | 原因 |
|---|---|
| `/.well-known/…` 前缀 | RFC 8615 规定的 well-known URI 前缀（段名 `.well-known` 本身含连字符） |
| `/.well-known/jwks.json` | JWKS 的惯用位置（RFC 7517 / OIDC 生态）；本身已是单词加扩展名 |
| `/v1/chat/completions`、`/v1/models` | OpenAI 兼容接口，官方客户端写死这些路径 |
| `/v1/messages` | Anthropic Messages 兼容接口，官方客户端写死该路径 |
| `/api/chat`、`/api/tags`（上游 Ollama） | 连接器调用的上游 Ollama API，不是本协议的路由 |

- 仓库用 `scripts/route-lint.py` 检查 OpenAPI 路径、AsyncAPI 地址以及源码和文档中出现的路由，`scripts/verify-all.sh` 的第一步就是这项检查，出现复合段即失败。

## 5. 密钥、令牌与证明（JOSE 配置）

### 5.1 密钥
- 设备密钥和网关密钥都是 Ed25519 密钥（RFC 8032）。
- 在 JSON 中，公钥以 RFC 8037 OKP JWK 表示：`{"kty":"OKP","crv":"Ed25519","x":"<base64url 32 字节>"}`。在设备授权请求中，公钥以裸 32 字节的 base64url 传输。
- **指纹**：按 RFC 7638 计算，即 `base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"' + x + '"}'))`。成员按字典序排列，不含空白。指纹用作 `cnf.jkt` 和 `kid`。
- 设备私钥 MUST NOT 离开设备，SHOULD 保存在系统密钥库（Keychain、DPAPI、Secret Service）中，至少 MUST 加密存储。
- 网关 MUST 在 `/.well-known/jwks.json` 发布当前签名公钥。轮换期间 MUST 同时发布新旧两把公钥，时长不少于访问令牌 TTL。

### 5.2 JWS 通用规则
所有 JWS 都使用紧凑序列化。受保护头 MUST 恰好由 `alg: "EdDSA"`、`typ` 和可选的 `kid` 组成。验证方 MUST 依次：
1. 确认正好有三段，且每段都是合法 base64url（§4.2）；
2. 确认受保护头是 JSON 对象，且**只含 `alg`、`typ`、`kid`**：出现任何其他成员（包括 `crit`、`b64`、`jku`、`jwk`、`x5u`、`x5c` 及未知成员）MUST 拒绝；
3. 确认 `alg` 恰好为字符串 `EdDSA`，**拒绝 `none`、`HS*`、`RS*` 等其他值**；
4. 确认 `typ` 是字符串且等于预期值（下表）；
5. 若有 `kid`，它 MUST 是字符串，且等于验证所用公钥的 RFC 7638 指纹，否则拒绝；
6. 对 ASCII 字节串 `protected || "." || payload` 验证 Ed25519 签名，SHOULD 使用严格验证（拒绝小阶公钥和非规范 S 值）；
7. 签名通过后才解析载荷：载荷 MUST 是 JSON 对象；
8. 按各用途检查声明类型：要求的 NumericDate（`iat`、`exp`）MUST 是 0..2^53-1 的 JSON 整数（字符串、小数、布尔值、负数均拒绝）；要求的标识符（`iss`、`sub`、`aud`、`jti`、`ath` 等）MUST 是非空字符串（证明 JWT 的 `iss` 在配对前可为空字符串，但仍 MUST 是字符串）；同时有 `iat` 和 `exp` 时 MUST `exp ≥ iat`。

各用途的必需声明：证明 JWT `iss`(可空)、`aud`、`iat`、`jti`、`ath`；访问令牌与客户端断言 `iss`、`sub`、`aud`、`iat`、`exp`、`jti`；任务签名 `task_id`、`device_id`、`model`、`nonce`、`iat`、`exp`，且每个 `blobs[]` 项的 `id`、`media_type` 为非空字符串、`size` 为非负整数、`sha256` 为 32 字节 base64url；元数据 `issuer`、`tenant`、`audience`、`iat`、`exp`；E2EE 密钥声明 `iss`、`sub`、`iat`、`exp`。

`spec/testvectors/jose.json` 是这些规则的共享正/反向向量集（由 `go test ./internal/lmbp -run TestJOSEVectors -update` 生成）。LMBP 的证明 JWT 以 `aud`（用途）和 `ath`（凭据哈希）绑定上下文，不使用 DPoP 的 `htm`/`htu`。

| 用途 | `typ` | 签名方 | `kid` |
|---|---|---|---|
| 访问令牌 | `at+jwt` | 网关 | 网关公钥指纹（REQUIRED） |
| 客户端断言（刷新） | `JWT` | 设备 | 设备公钥指纹（OPTIONAL） |
| 证明 JWT | `lmbp-proof+jwt` | 设备 | 无 |
| 任务签名 | `lmbp-task+jws` | 网关 | 网关公钥指纹（REQUIRED） |
| E2EE 密钥声明（§17.1） | `lmbp-e2ee-key+jwt` | 设备 | 设备公钥指纹 |

### 5.3 访问令牌（RFC 9068 配置）
| 声明 | 要求 |
|---|---|
| `iss` | 网关的签发者标识 = 网关的 https 源（origin），如 `https://gw.example.com`（§18.1） |
| `sub` | `device_id` |
| `aud` | `<iss>/tenants/<tenant>`：同时绑定网关和 SaaS（租户），见 §18.3 |
| `tenant` | 租户 ID |
| `iat`、`exp` | NumericDate；`exp - iat` SHOULD ≤ 900 秒，MUST ≤ 3600 秒 |
| `jti` | 唯一 ID |
| `cnf.jkt` | 设备公钥的 RFC 7638 指纹 |

网关验证访问令牌时，除 §5.2 的步骤外，MUST 检查：`iss` 等于自身 issuer；`aud` 等于 `<iss>/tenants/<tenant>`；`exp + 30 ≥ now`；`iat - 30 ≤ now`；`sub` 对应的设备存在、状态为 `active`、属于 `tenant`；`cnf.jkt` 等于该设备公钥的指纹。

### 5.4 证明 JWT（`typ: lmbp-proof+jwt`）
载荷：

| 声明 | 要求 |
|---|---|
| `iss` | `device_id`。在配对阶段还没有 `device_id`，此时 MUST 为空字符串 `""` |
| `aud` | 用途：`lmbp:token`、`lmbp:hello` 或 `lmbp:session.token` |
| `iat` | 签名时刻 |
| `jti` | 唯一 ID |
| `ath` | `base64url(SHA-256(UTF-8(凭据)))`。被绑定的凭据：`lmbp:token` 绑定 `device_code`；`lmbp:hello` 绑定当前连接使用的访问令牌；`lmbp:session.token` 绑定新的访问令牌 |

验证方 MUST 检查：签名使用该设备登记的公钥；`aud`、`iss`、`ath` 都符合预期；`|now - iat| ≤ 60`；`jti` 在 120 秒内没有出现过。重复的 `jti` MUST 拒绝，这一点在网关多实例部署时同样 MUST 成立。

### 5.5 客户端断言（RFC 7523）
设备刷新令牌时提交 JWT：`typ: JWT`，`iss = sub = device_id`，`aud = <iss> + "/lmbp/v1/token"`（RFC 7523 §3：令牌端点地址），`exp - iat ≤ 300`，`jti` 唯一。网关 MUST 用该设备登记的公钥验证签名；在 `exp + 60` 秒之前，同一 `jti` 只能使用一次。

### 5.6 任务签名（`typ: lmbp-task+jws`）
载荷（[`task.run.payload.json`](../spec/schemas/task.run.payload.json)）：

| 字段 | 要求 |
|---|---|
| `task_id` | MUST 等于信封中的 `task_id`（防止把签名挪到别的任务上） |
| `iat`、`exp` | `exp - iat` SHOULD ≤ 60 秒。设备 MUST 拒绝 `now > exp` 的任务 |
| `nonce` | ≥ 16 字符。在 `exp + 60` 秒之前，设备 MUST 拒绝重复的 `nonce` |
| `device_id` | MUST 等于本设备的 ID |
| `model` | 本设备在 `hello`/`models.update` 中声明过的模型 ID（不带 `device_id/` 前缀） |
| `messages` | 1–200 条（使用 `e2ee` 时省略），`role ∈ {system, user, assistant, tool, developer}`；`content` 为字符串、内容片段数组（§16.2）或 `null`；可带 `tool_calls`、`tool_call_id` |
| `tools`、`tool_choice` | OPTIONAL，见 §16.1 |
| `blobs` | OPTIONAL，`[{id, size, sha256, media_type}]`，见 §16.3 |
| `e2ee` | OPTIONAL，`{blob}`，见 §17 |
| `max_tokens` | OPTIONAL，正整数 |
| `temperature` | OPTIONAL，0–2 |
| `top_p` | OPTIONAL，0–1 |
| `stop` | OPTIONAL，1–4 个非空字符串（每个 ≤ 256 字符） |

网关 MUST 在签名前按 `spec/schemas/task.run.payload.json` 校验将要签名的载荷；不满足时 MUST NOT 签名或下发，并以 400 `BAD_REQUEST` 拒绝请求（§6.5）。

设备 MUST 用配对时得到的网关公钥（或 JWKS 中 `kid` 对应的公钥）验证签名。验证失败时，MUST 回复 `task.error`（`BAD_SIGNATURE`），MUST NOT 调用模型。

---

## 6. HTTP 接口

完整定义见 [`spec/openapi.yaml`](../spec/openapi.yaml)。所有接口 MUST 通过 TLS 1.2 及以上版本提供；仅在开发环境的回环地址上可以例外。

**缓存**：网关返回的每个 JSON 响应（`application/json`、`application/problem+json`，包括成功结果、错误、列表、`/healthz`，以及 401/404 这类在路由或认证阶段就返回的错误）MUST 带 `Cache-Control: no-store`。唯一例外是 §6.1 的公开发现文档（`/.well-known/jwks.json`、`/.well-known/lmbp`、`/.well-known/avora`）：它们不含秘密，MAY 用 `Cache-Control: public, max-age=<秒>` 允许缓存（参考实现为 300 秒）。SSE 响应沿用 `Cache-Control: no-cache`。

### 6.1 发现
- 租户后端 SHOULD 在 `GET /.well-known/avora` 返回 `{gateway_url, tenant, link_url, protocol: "lmbp"}`（`protocol` 是协议族名，不含版本），供设备只凭租户网址就能完成配对。该文档 MUST NOT 包含任何秘密。
- 网关 MUST 提供 `GET /.well-known/jwks.json`（`application/jwk-set+json`）。
- 网关 MUST 提供 `GET /.well-known/lmbp[?tenant=<id>]` 元数据文档（§18.2）；带 `tenant` 时还包含签名的 SaaS 身份（§19.1）。`gateway_url` MUST 是网关的 origin（不带路径）。

### 6.2 设备授权：`POST /lmbp/v1/device/authorize`
- 请求 MUST 支持 `application/x-www-form-urlencoded`（RFC 8628 §3.1），MAY 同时接受 JSON。参数：`tenant`（必填）、`public_key`（必填，base64url 32 字节）、`device_name`（≤ 100 码点，超出返回 400）。
- `tenant` MUST 是网关已注册的租户，否则返回 400 `invalid_client`，MUST NOT 创建配对。
- `device_name` 由设备自报、不可信。它 MUST NOT 含以下字符，否则返回 400 `invalid_request`：C0/C1 控制字符（U+0000–U+001F、U+007F–U+009F）、U+00AD、U+061C、U+180E、U+200B–U+200F、U+2028–U+202E、U+2060–U+206F、U+FEFF、U+FFF9–U+FFFB（零宽、换行与双向控制字符可伪装文字）。任何界面 MUST 以纯文本显示它，并标明是设备自报的名称。
- **限流**：网关 MUST 限制每个客户端地址每分钟的授权请求数（参考实现 60 次），并 MUST 限制每个租户同时有效的待确认配对数（参考实现 1000 个）。超限返回 429，`{"error":"slow_down"}`，带 `Retry-After`。
- 响应字段：`device_code`、`user_code`、`expires_in`、`interval`（≥ 1）。响应头 MUST 带 `Cache-Control: no-store`。`verification_uri` 是 OPTIONAL：确认页由租户提供，地址通过发现文档的 `link_url` 告知设备，这是本协议对 RFC 8628 的唯一偏离。
- `user_code` MUST 为 `XXXX-XXXX` 格式，字母表 `BCDFGHJKLMNPQRSTVWXZ`（20 个辅音字母，约 34.6 比特）。比较时 MUST 忽略大小写和分隔符。
- `device_code` 是不透明的高熵字符串。网关 SHOULD 只保存其哈希。

### 6.3 令牌：`POST /lmbp/v1/token`
请求为表单编码（同样 MAY 接受 JSON）。

**device_code 授权**：`grant_type=urn:ietf:params:oauth:grant-type:device_code`、`device_code`、`proof`（证明 JWT，`aud=lmbp:token`，`iss=""`，`ath` 绑定 `device_code`，用配对时提交的公钥签名）。网关 MUST 按以下顺序处理：
1. `device_code` 未知 → `invalid_grant`；
2. 证明无效或 `jti` 重复 → `invalid_grant`（**先验证证明，再透露授权状态**）；
3. 已过期 → `expired_token`；已拒绝 → `access_denied`；已使用过 → `invalid_grant`。这三种情况下网关 MUST NOT 记录该证明的 `jti`（已失效的码不再占用去重存储）；
4. 尚未确认：轮询间隔小于 `interval` 时返回 `slow_down`，并把 `interval` 加 5 秒；否则返回 `authorization_pending`。同一 `device_code` 收到第 11 次 `slow_down` 条件的轮询时，网关 MUST 让该码过期并返回 `expired_token`；
5. 已确认：把 `device_code` 标记为已使用（一次性），返回令牌。

`jti` 去重存储 MUST 按到期时间淘汰条目，MUST NOT 在每次请求时扫描全部条目。

**jwt-bearer 授权**：`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`、`assertion`（§5.5）。设备不存在或已吊销时返回 `invalid_grant`。设备收到 `invalid_grant` 后 MUST 停止重试，提示用户重新配对。

**成功响应**：`{access_token, token_type: "Bearer", expires_in, device_id, gateway_key: <JWK>}`，响应头带 `Cache-Control: no-store`。错误响应为 RFC 6749 §5.2 格式的 `{"error": "..."}`，HTTP 状态码 400。

### 6.4 租户管理接口
认证：`Authorization: Bearer <租户 API Key>`，加上 `X-End-User: <终端用户 ID>`（1–128 个可打印 ASCII 字符，§4.1）。租户 API Key MUST 只在服务器之间使用，MUST NOT 出现在浏览器或设备上。网关 MUST 只存储 Key 的哈希，比较时 SHOULD 使用常数时间比较。

| 接口 | 作用 |
|---|---|
| `POST /lmbp/v1/tenant/devices/approvals` `{user_code, jkt?, deny?}` | 确认或拒绝配对码；设备归属于 `X-End-User`。带 `jkt` 时与设备公钥指纹不符 MUST 返回 409（§17.2） |
| `GET /lmbp/v1/tenant/devices` | 列出该终端用户的设备：`created_at`（RFC 3339）、`public_key`、`jkt`、`e2ee_key`、在线时还有 `model_capabilities`、`model_names`（可选）、`capabilities`、`max_concurrency`。MUST NOT 包含尚未确认的配对（§12.6） |
| `GET /lmbp/v1/tenant/tasks/{task}/events` | 按 `Last-Event-ID` 重新接入任务的 SSE 流（§14.4） |
| `POST /lmbp/v1/tenant/devices/{device}/revoke` | 吊销设备，网关 MUST 立即关闭该设备的在线会话；进行中的任务按 §7.5 结束（已下发的为 `OUTCOME_UNKNOWN`） |

- 错误响应 MUST 使用 RFC 9457（`application/problem+json`），含 `type`、`title`、`status`、`detail`，以及扩展成员 `code`（§9 的错误码）。`type` 为 `https://avora.dev/problems/<code 的小写连字符形式>`。
- 访问不属于该租户或该终端用户的设备，MUST 返回 404（不透露设备是否存在）。
- 同一终端用户（租户 + `X-End-User`）每分钟确认失败（码未知、已拒绝或 `jkt` 不符）达到 10 次后，网关 MUST 对该用户返回 429（`RATE_LIMITED`），并且不再查询配对码，用于防止暴力猜测；其他终端用户不受影响。限额检查与失败计数 MUST 是原子的，并发请求不能越过限额。按配对码查询待确认设备的接口（SDK 的 `lookup`）同样计数。
- 一个配对码 MUST 只能被确认或拒绝一次：并发的确认请求中只有一个成功，其余按“码未知”处理，同一设备不会产生多条记录。

### 6.5 OpenAI 兼容接口
认证方式同 §6.4。错误使用 OpenAI 错误对象：`{"error":{"message","type":"lmbp_error","code"}}`。
- `GET /v1/models`：只列出该终端用户**在线**设备上的模型，`id` 格式为 `<device_id>/<model>`；条目 MAY 含 `display_name`（来自设备 `hello`/`models.update` 的 `model_names`，见 §16.1）。
- `POST /v1/chat/completions`：不含 data: URI 时请求体 SHOULD ≤ 1 MiB，含图片/音频时 ≤ 48 MiB（§16.3）；不认识的 OpenAI 字段 MUST 忽略。支持 `tools`/`tool_choice`（§16）、内容片段数组（§16.2）、`lmbp_e2ee`（§17），以及请求头 `Idempotency-Key`、`Last-Event-ID`（§14.4）。
  - `stream: false`：返回一个 `chat.completion` 对象。
  - `stream: true`：返回 `text/event-stream`。第一个事件 SHOULD 是 `delta: {role: "assistant", content: ""}`；每个 `task.delta` 对应一个 `chat.completion.chunk` 事件；结束时发送带 `finish_reason`（以及 `usage`，如有）的块，然后发送 `data: [DONE]`。中途出错时 MUST 发送 `data: {"error":{...}}` 后关闭连接，MUST NOT 再发送 `[DONE]`。网关 SHOULD 每 15 秒发送一次注释行 `: keep-alive`。
  - 响应头 `X-Task-Id` 给出 `task_id`。
  - 调用方断开 HTTP 连接时，网关 MUST 向设备发送 `task.cancel`（`reason: "client_disconnected"`）。这条同样适用于 `stream: false`：非流式请求在任务结束前不会写出任何字节，网关 MUST 主动检测连接已关闭（而不是等到写结果失败才发现），并 SHOULD 在 2 秒内发出 `task.cancel`。带 `Idempotency-Key` 的请求按 §14.4 先等待宽限期。
- 请求参数校验：网关 MUST 在存储、排队或签名之前校验下列参数。非法值 MUST 以 400 拒绝，错误对象为 `{"error":{"message","type":"invalid_request_error","code":"BAD_REQUEST","param":"<顶层参数名>"}}`（`/v1/messages` 见 §6.7）。MUST NOT 静默丢弃或修正非法值。`null` 视同未提供。共享测试向量见 `spec/testvectors/params.json`，conformance 检查项为 Z8。

  | 参数 | 合法值 | 写入 `task.run` |
  |---|---|---|
  | `model` | 非空字符串 | `model`（路由后） |
  | `messages` | 数组，1–200 条；`role ∈ {system,user,assistant,tool,developer}`；`content` 为字符串、片段数组或 `null`；`tool` 消息必须有 `tool_call_id` 与 `content`；`tool_calls` 只能出现在 assistant 消息上 | `messages` |
  | `temperature` | 数字，0–2 | `temperature` |
  | `top_p` | 数字，0–1 | `top_p` |
  | `max_tokens`、`max_completion_tokens` | 正整数（后者为别名，两者都有时取 `max_tokens`） | `max_tokens` |
  | `stop` | 非空字符串，或 1–4 个非空字符串的数组（每个 ≤ 256 字符） | `stop`（统一为数组） |
  | `n` | 只支持 1 | — |
  | `stream` | 布尔值 | — |
  | `tools` | 数组，≤ 128 个；每个 `{type:"function", function:{name, description?, parameters?}}`，`name` 匹配 `^[A-Za-z0-9_-]{1,64}$`，`parameters` 为对象 | `tools` |
  | `tool_choice` | `"none"`、`"auto"`、`"required"`，或 `{type:"function",function:{name}}` 且 `name` 必须出现在 `tools` 中；除 `"none"` 外必须同时提供 `tools` | `tool_choice` |

  其余不认识的 OpenAI 字段（例如 `presence_penalty`、`seed`、`logprobs`）按上文忽略，不会转发给设备。哪些字段被忽略、哪些被拒绝，完整列表见 §16.5。

### 6.6 模型路由
`model` 为 `<device_id>/<model>` 时，路由到该设备（必须属于调用方）。`model` 不带设备前缀时，网关 MAY 选择调用方任意一台声明了该模型的在线设备。设备离线时返回 503（`DEVICE_OFFLINE`）；没有任何设备声明该模型时返回 404（`MODEL_NOT_FOUND`）；设备已达并发上限时返回 429（`DEVICE_BUSY`），并带 `Retry-After` 头。

判定顺序：
1. 指定了 `<device_id>`：设备不属于调用方，或调用方没有这台设备 → 404（`MODEL_NOT_FOUND`，不透露设备是否存在）；设备属于调用方但不在线（包括已连接、尚未完成握手）→ 503（`DEVICE_OFFLINE`）；设备在线但没有声明该模型 → **404（`MODEL_NOT_FOUND`）**；
2. 未指定设备前缀：调用方有在线设备声明了该模型 → 路由；调用方有设备、但没有一台在线 → 503（`DEVICE_OFFLINE`）；有在线设备但都没有声明该模型，或调用方没有任何设备 → 404（`MODEL_NOT_FOUND`）。

`DEVICE_OFFLINE` 只表示设备不可达（可重试），MUST NOT 用来表示“设备在线但模型不存在”（不可重试；Anthropic 接口为 404 `not_found_error`）。

### 6.7 Anthropic Messages 兼容接口
认证方式同 §6.4，另外接受 Anthropic 客户端使用的 `x-api-key: <tenant key>` 头（与 `Authorization: Bearer` 等价）；`anthropic-version` 头可有可无，网关不校验其取值。

- `POST /v1/messages`：请求体按下表翻译为 §6.5 的 chat 请求，然后走与 `/v1/chat/completions` 完全相同的路由（§6.6）、签名（§5.6）、blob（§16.3）、流控（§15）与续传（§14.4）逻辑，也支持 `Idempotency-Key`。`max_tokens`（正整数）与 `model` 为必填；`lmbp_e2ee` 不适用于本接口，MUST 以 400 拒绝。

| Anthropic 请求 | 翻译为 |
|---|---|
| `system`（字符串或 text 块数组） | 首条 `role: "system"` 消息（多个 text 块以 `\n\n` 连接） |
| `text` 块 | `{"type":"text"}` 片段 |
| `image` 块，`source.type: "base64"` | `image_url`，`url` 为 `data:<media_type>;base64,<data>`（大于 16 KiB 时照常走 blob） |
| `image` 块，`source.type: "url"` | `image_url`，`url` 原样 |
| assistant 的 `tool_use` 块 | `tool_calls[]`：`{id, type:"function", function:{name, arguments: JSON(input)}}` |
| user 的 `tool_result` 块 | 单独一条 `role:"tool"` 消息，`tool_call_id = tool_use_id`；`content` 为字符串或 text 块拼接，`is_error: true` 时加前缀 `Error: ` |
| `thinking` / `redacted_thinking` 块 | 丢弃 |
| 其他块类型、服务端工具（`tools[].type` 不是 `custom`） | 400 |
| `tools[]: {name, description, input_schema}` | `{type:"function", function:{name, description, parameters: input_schema}}` |
| `tool_choice` `auto` / `any` / `none` / `{type:"tool",name}` | `"auto"` / `"required"` / `"none"` / `{type:"function",function:{name}}` |
| `max_tokens`（必填，正整数）、`temperature`（0–1，Anthropic 的取值范围）、`top_p`（0–1）、`stream`（布尔） | 同名字段 |
| `stop_sequences`（1–4 个非空字符串的数组，每个 ≤ 256 字符） | `stop` |

- 参数校验：按上表的名称与取值范围在翻译之前校验；`tools[]` 必须有符合 `^[A-Za-z0-9_-]{1,64}$` 的 `name` 和对象类型的 `input_schema`；`tool_choice` 必须是对象，`type ∈ {auto, any, tool, none}`，`tool` 需要出现在 `tools` 中的 `name`，除 `none` 外必须同时提供 `tools`。非法值 MUST 以 400 拒绝，错误对象为 `{"type":"error","error":{"type":"invalid_request_error","message","lmbp_code":"BAD_REQUEST","lmbp_param":"<参数名>"}}`。`top_k` 等未列出的字段被忽略。

- **非流式**响应：`{"id":"msg_<task>","type":"message","role":"assistant","model","content":[...],"stop_reason","stop_sequence":null,"usage":{"input_tokens","output_tokens"}}`。`content` 依次为一个 `text` 块（如有文本）和每个工具调用一个 `tool_use` 块（`input` 为解析后的参数对象，解析失败时为 `{}`）。`stop_reason` 由 `finish_reason` 映射：`stop`→`end_turn`、`length`→`max_tokens`、`tool_calls`→`tool_use`，其余→`end_turn`。
- **流式**（`stream: true`）响应为带事件名的 SSE：`message_start` → 每个内容块 `content_block_start` / 若干 `content_block_delta`（`text_delta` 或 `input_json_delta`）/ `content_block_stop` → `message_delta`（`delta.stop_reason`、`usage`）→ `message_stop`。文本与工具调用交替出现时，网关 MUST 先关闭当前块再开始新块，`index` 从 0 递增。保活使用 `event: ping`。中途出错时发送 `event: error`，`data` 为下述错误对象，然后关闭连接。
- **续传**：由同一个 `task.delta`/`task.done` 产生的一组 SSE 事件中，只有最后一个带 `id: <seq>`，因此 `Last-Event-ID` 总是指向一组已完整送达的事件。用同一个 `Idempotency-Key` 加 `Last-Event-ID` 重新请求时，网关 MUST 只发送该 id 之后的事件组（不重发 `message_start`）。
- **错误**使用 Anthropic 错误对象：`{"type":"error","error":{"type","message","lmbp_code"}}`，`lmbp_code` 为 §9 的错误码。`error.type` 由 HTTP 状态决定：400/422→`invalid_request_error`，401→`authentication_error`，403→`permission_error`，404→`not_found_error`，413→`request_too_large`，429→`rate_limit_error`，503→`overloaded_error`，其他 5xx→`api_error`。
- `GET /v1/models` 在请求带 `anthropic-version` 头时返回 Anthropic 列表形状：`{"data":[{"type":"model","id","display_name","created_at"}],"has_more":false,"first_id","last_id"}`；否则返回 §6.5 的 OpenAI 形状。

---

## 7. WebSocket 通道

完整定义见 [`spec/asyncapi.yaml`](../spec/asyncapi.yaml) 和 [`spec/schemas/envelope.json`](../spec/schemas/envelope.json)。

### 7.1 建立连接
- `GET /lmbp/v1/connect`，请求头：`Authorization: Bearer <访问令牌>`、`Sec-WebSocket-Protocol: lmbp`。
- 网关在升级前 MUST 验证令牌（§5.3）。未提供 `lmbp` 时返回 400，`code` 为 `VERSION_UNSUPPORTED`（只提供其他名字，包括带版本号的变体，也一样）；令牌无效时返回 401；设备已吊销或令牌未绑定该设备时返回 403。错误响应使用 RFC 9457 格式。
- 网关 MUST 在响应中选择子协议 `lmbp`；设备看到其他值 MUST 断开。子协议名不带版本，版本只由信封 `v`、元数据 `protocol_versions` 和配对链接的 `v` 表示（§11）。
- 带 `Origin` 头的请求（来自浏览器）MUST 拒绝（403），以防跨站 WebSocket 劫持。
- 同一设备建立新会话时，网关 MUST 关闭该设备的旧会话。

### 7.2 帧
- 每条 WebSocket **文本**消息正好包含一个 JSON 对象。MUST NOT 发送二进制消息；收到二进制消息时 SHOULD 以关闭码 1003 断开。
- 单帧 MUST ≤ `welcome.max_frame_bytes`；该值 MUST 恰为 262144 字节（§10 的规范上限，不协商；welcome.json 拒绝其他值）。超限时接收方 MUST 以 1009 断开。
- 握手之后，网关收到 `v ≠ 2` 或无法解析为信封的帧时，MUST 回复 `error`（`BAD_REQUEST`）并丢弃该帧，MUST NOT 断开；设备收到 `v ≠ 2` 的帧 MUST 丢弃。

信封：

| 成员 | 类型 | 说明 |
|---|---|---|
| `v` | 整数 | MUST 为 `2` |
| `type` | 字符串 | 消息类型，格式 `^[a-z][a-z0-9._]{0,63}$` |
| `id` | 字符串 | 请求/响应关联 ID；`hello`、`session.token` 必填，响应 MUST 原样带回 |
| `task_id` | 字符串 | 任务相关消息必填 |
| `seq` | 整数 ≥ 1 | 数据帧（`task.run`、`blob.chunk`、`task.delta`、`task.done`、`task.error`）必填，与是否协商 `resume`/`flow` 无关；每个任务、每个方向从 1 开始，`task.run` 恒为 1（§14、§15） |
| `data` | 对象 | 消息体，结构由 `type` 决定 |
| `jws` | 字符串 | 只用于 `task.run`；此时 MUST NOT 出现 `data` |

### 7.3 消息
| `type` | 方向 | `data` 模式 | 说明 |
|---|---|---|---|
| `hello` | 设备→网关 | `hello.json` | 必须是第一帧，含证明 JWT（`aud=lmbp:hello`） |
| `welcome` | 网关→设备 | `welcome.json` | 握手成功，`id` 与 `hello` 相同 |
| `task.run` | 网关→设备 | 无；`jws` 载荷符合 `task.run.payload.json` | 下发任务 |
| `task.delta` | 设备→网关 | `task.delta.json` | 增量文本 |
| `task.done` | 设备→网关 | `task.done.json` | 任务成功结束（终止消息） |
| `task.error` | 设备→网关 | `task.error.json` | 任务失败结束（终止消息） |
| `task.cancel` | 网关→设备 | `task.cancel.json` | 要求停止任务 |
| `session.token` | 设备→网关；网关以同名消息回复 | 请求 `session.token.request.json`，回复 `session.token.response.json` | 连接内续期令牌 |
| `models.update` | 设备→网关 | `models.update.json` | 重新声明模型列表和并发数；不符合模式时网关回复 `error`（`BAD_REQUEST`），整帧不生效，会话保持；`max_concurrency` 提高时，网关 MUST 在同一临界区内把新增的并发槽按 FIFO 分给排队中的请求并立即唤醒它们 |
| `ping` / `pong` | 双向 | 无 | 应用层心跳；`pong` 带回 `ping` 的 `id` |
| `blob.chunk` | 网关→设备 | `blob.chunk.json` | 数据帧：二进制附件分块（§16.3） |
| `task.ack` | 双向 | `task.ack.json` | 控制帧：确认对方 `seq ≤ data.seq` 的数据帧（§14、§15） |
| `error` | 双向 | `error.json` | 连接级错误 |

### 7.4 握手
1. 连接建立后，设备 MUST 在 15 秒内发送 `hello`。超时，或第一帧不是 `hello`，网关 MUST 断开连接。
2. 网关按以下顺序检查 `hello`，任一失败即回复 `error`（带 `hello` 的 `id`）并断开，不发 `welcome`：
   1. `v == 2`，否则 `VERSION_UNSUPPORTED`（1.x 设备同样以子协议 `lmbp` 升级，在这一步被拒）；
   2. `data` 符合 `hello.json`，否则 `BAD_REQUEST`。其中 `max_concurrency` 是 1–16 的整数（必填），`model_names` 的显示名为 1–128 字符；越界值 MUST 拒绝，MUST NOT 截断；
   3. `data.device_id == token.sub`，证明 JWT 有效（`ath` 绑定**本次连接使用的访问令牌**）且 `jti` 未用过，否则 `UNAUTHENTICATED`；
   4. `flow`、`e2ee_key` 等扩展的语义检查（§15.1、§17.1），否则 `BAD_REQUEST`。
3. 网关回复 `welcome`：`session_id`、`heartbeat_seconds`、`max_frame_bytes`、`token_expires_at`、`capabilities`（§11）、`max_concurrency`（必填）。`welcome.max_concurrency = min(hello.max_concurrency, 网关上限)`：网关 MAY 降低，MUST NOT 提高；设备 MUST 以它为准。

### 7.5 任务与顺序
- 网关收到 OpenAI 请求后，创建 `task_id`，发送 `task.run`。
- 设备收到 `task.run` 后，依次检查签名（§5.6）、`device_id`、`exp`、`nonce`、模型是否在本机允许列表中、并发数是否已满，任一不满足即回复 `task.error`：签名错误为 `BAD_SIGNATURE`；不属于本设备、已过期或重放为 `FORBIDDEN` 或 `BAD_REQUEST`；并发已满为 `DEVICE_BUSY`。拒绝时 MUST NOT 调用模型。
- 同一 `task_id` 的设备回报帧中，`seq` MUST 从 1 开始、严格加 1；终止消息（`task.done` 或 `task.error`）的 `seq` 是最后一个。终止消息之后 MUST NOT 再发送该任务的帧。
- 网关发现 `seq` 不连续时，MUST 让该任务失败（`INTERNAL`，HTTP 502），并向设备发送 `task.cancel`（`reason: "protocol_error"`）。
- 未协商 `resume` 时，连接断开即让所有进行中的任务失败：`task.run` 尚未发出的任务为 `DEVICE_OFFLINE`（`retryable: true`），已发出的为 `OUTCOME_UNKNOWN`（不可自动重试，模型可能已执行）。协商了 `resume` 时按 §14 处理。设备被吊销或会话被网关关闭时同样按本条处理，MUST NOT 以 `UNAUTHENTICATED` 结束调用方的任务（调用方的租户凭据并无问题）。

### 7.6 取消
- 网关在以下情况发送 `task.cancel`：调用方断开连接（`client_disconnected`）、任务超时（`timeout`）、协议错误（`protocol_error`）。
- 取消、确认与窗口回收的完整规则见 §8.6 的状态转换表。

### 7.7 心跳与续期
- 网关每 `heartbeat_seconds` 发送一次 WebSocket 控制帧 ping，设备 MUST 回复 pong（RFC 6455 §5.5.2）。60 秒内没有收到任何数据，任一方都 MAY 断开。应用层 `ping` 帧 OPTIONAL。
- 设备 SHOULD 在 `max(token_expires_at - 60, 剩余有效期的一半)` 时刻用 jwt-bearer 授权取得新令牌，然后发送 `session.token`，`data` 为 `{access_token, proof}`，其中证明的 `aud=lmbp:session.token`，`ath` 绑定**新**令牌。
- 网关按握手的标准验证新令牌（`sub` 必须相同，设备必须仍为 `active`）。通过后回复 `session.token`，`data` 为 `{token_expires_at}`，`id` 与请求相同；失败时回复 `error`（`UNAUTHENTICATED`）并断开。
- 当前令牌过期超过 30 秒仍未续期时，网关 MUST 断开会话。

---

## 8. 状态机

### 8.1 配对（网关侧，每个 device_code）
```
pending ──确认──▶ approved ──令牌已签发──▶ consumed
   │  └──拒绝──▶ denied
   └──超过 expires_in──▶ expired
```

### 8.2 设备记录
`active ──吊销──▶ revoked`（终态）。被吊销的设备 MUST 立即被断开，并且 MUST NOT 再取得令牌。

### 8.3 会话（网关侧）
```
UPGRADED ──hello 有效──▶ OPEN ──关闭/吊销/令牌过期/错误──▶ CLOSED
    └──15 秒超时或 hello 无效──▶ CLOSED
OPEN 状态下：session.token 只延长令牌有效期，不改变状态
```

### 8.4 任务（网关侧）
```
RUNNING ──task.done──▶ SUCCEEDED
   ├──task.error(CANCELLED) 或调用方断开──▶ CANCELLED
   └──task.error / 超时 / 断线 / seq 不连续──▶ FAILED
```
设备侧：`RECEIVED → (验证失败 → REJECTED) | EXECUTING → DONE | ERROR | CANCELLED`。

### 8.5 设备连接（设备侧）
`IDLE → TOKEN → CONNECTING → HANDSHAKE → OPEN`。断开后按指数退避重连：1 秒起，翻倍，上限 30 秒，SHOULD 加随机抖动。收到 `invalid_grant` 时进入 `REVOKED`，停止重连。

### 8.6 取消、确认与窗口回收
网关对每个任务处于以下状态之一：**未知**（从未存在，或状态已被忘记）、**RUNNING**（已下发，尚未结束）、**DRAINING**（网关已在本地结束并发出 `task.cancel`，等待设备的终止帧）。“数据帧”“确认”见 §14.1。**确认属于 Core**：无论是否协商 `resume`、`flow`，双方都 MUST 按本表确认数据帧；`flow` 只在此之上增加窗口限制（§15），`resume` 只增加断线后的重传（§14.2）。确认释放对方保留的未确认帧，协商了 `flow` 时同时释放窗口。

| 行 | 网关侧状态 | 事件 | 动作 | 下一状态 |
|---|---|---|---|---|
| U1 | 未知 | 收到该任务的设备数据帧 | 回复 `task.cancel {reason: "unknown_task"}`，不确认，不交付 | 未知 |
| R1 | RUNNING | 本地结束：调用方断开、超时、慢消费者、本地错误（§14.4 单一终止决策） | 发送 `task.cancel {reason}` | DRAINING |
| R2 | RUNNING | 收到按序的数据帧 | 持久化、交付、确认；若是终止帧，任务结束并忘记该任务 | RUNNING；终止帧后为未知 |
| R3 | RUNNING | 收到跳号的数据帧 | 任务以 `INTERNAL` 失败，发送 `task.cancel {reason: "protocol_error"}` | DRAINING |
| D1 | DRAINING | 收到非终止数据帧 | 确认，不交付，不报协议错误 | DRAINING |
| D2 | DRAINING | 收到终止帧 | 确认，忘记该任务 | 未知 |
| D3 | DRAINING | 本地保留的 DRAINING 状态超过上限被淘汰（参考实现每设备 1024 个） | — | 未知 |
| F1 | 未知（任务已结束） | 终止帧之后又收到该任务的数据帧 | 同 U1 | 未知 |

设备侧：

| 行 | 设备侧状态 | 事件 | 动作 |
|---|---|---|---|
| N1 | 执行中 | `task.cancel`（`unknown_task` 以外的原因） | SHOULD 尽快中止模型调用，发送 `task.error`（`CANCELLED`）作为终止帧；未确认的帧照常保留直到被确认 |
| N2 | 已结束或未知 | `task.cancel`（`unknown_task` 以外的原因） | MUST 忽略 |
| N3 | 任意 | `task.cancel {reason: "unknown_task"}` | MUST 停止该任务；MAY 丢弃该任务的未确认帧 |
| N4 | 任意 | `task.ack {seq}` | 释放该任务 `seq` 及以前的未确认帧（协商了 `flow` 时还有窗口）；终止帧已被确认时 MUST 忘记该任务。未协商 `flow`、`resume` 时同样如此 |

conformance 的 S1（U1）、S2（R2、F1）、S3（D1、D2、F1）、S4（R2 的确认，未协商 flow）、S5（R3）与 E7 检查本表。

---

## 9. 错误

`error` 和 `task.error` 的 `data` 为 `{code, message, retryable?}`。`code` 格式为 `^[A-Z][A-Z0-9_]{1,63}$`。对于不认识的 `code`，接收方 MUST 按不可重试处理，除非 `retryable` 为 `true`。

| code | 含义 | 建议 HTTP 状态码 | 默认可重试 |
|---|---|---|---|
| `UNAUTHENTICATED` | 令牌或证明无效 | 401 | 否 |
| `FORBIDDEN` | 无权访问，或被本机策略拒绝 | 403（资源归属问题用 404） | 否 |
| `BAD_REQUEST` | 消息格式或参数错误 | 400 | 否 |
| `BAD_SIGNATURE` | `task.run` 签名无效 | 502 | 否 |
| `VERSION_UNSUPPORTED` | 协议版本不支持 | 400 | 否 |
| `DEVICE_OFFLINE` | 设备不在线或中途断开 | 503 | 是 |
| `DEVICE_BUSY` | 设备已达并发上限 | 429 | 是 |
| `MODEL_NOT_FOUND` | 模型不存在 | 404 | 否 |
| `UPSTREAM_ERROR` | 本机模型出错 | 502 | 视情况 |
| `TIMEOUT` | 任务超时 | 504 | 是 |
| `CANCELLED` | 任务已取消 | —（流已关闭） | 否 |
| `RATE_LIMITED` | 请求过于频繁 | 429 | 是 |
| `INTERNAL` | 网关内部错误或协议违规 | 500 / 502 | 视情况 |
| `OUTCOME_UNKNOWN` | 任务已下发但结果未知（断线未续传） | 502 | 否 |
| `FLOW_CONTROL` | 超出对方通告的窗口（§15） | —（断开连接） | 否 |
| `SLOW_CONSUMER` | SSE 调用方长时间不读取（§15.4） | —（流已关闭） | 否 |
| `CAPABILITY_UNSUPPORTED` | 模型或设备不支持请求的能力 | 400 | 否 |
| `PAYLOAD_TOO_LARGE` | 附件超出限制 | 413 | 否 |
| `IDEMPOTENCY_KEY_REUSED` | 同一 `Idempotency-Key` 用于不同请求体 | 422 | 否 |
| `E2EE_DECRYPT_FAILED` | 设备无法解密或校验密封请求 | 400 / 502 | 否 |
| `CONSENT_DENIED` | 配对未获用户同意：本机用户在同意页拒绝，或 SaaS 侧用户拒绝（OAuth `access_denied` 映射为此码），§19.3 | 403 | 否 |

OAuth 接口的错误值沿用 RFC 6749/8628：`invalid_request`、`invalid_grant`、`unsupported_grant_type`、`authorization_pending`、`slow_down`、`access_denied`、`expired_token`、`server_error`。

---

## 10. 超时与限制

以下每项只有一个规范值；三个阶段都按它检查：API 入参（请求体、条数）、签名载荷（JWS）、编码后的帧。共享边界用例见 conformance `Z6*`。

| 项目 | 值 | 级别 |
|---|---|---|
| hello 截止时间 | 连接后 15 秒 | MUST |
| 读超时（无任何数据） | 60 秒 | SHOULD |
| 心跳间隔 | 20 秒（以 `welcome.heartbeat_seconds` 为准） | SHOULD |
| 单帧大小 `max_frame_bytes` | 262144 字节（256 KiB）。按**编码后整帧的 UTF-8 字节数**计（不是字符数），双向适用；超限的设备帧由网关以 1009 关闭连接，设备 MUST 以同一上限读取网关帧 | MUST |
| 访问令牌 TTL | ≤ 15 分钟（推荐），≤ 60 分钟（上限） | SHOULD / MUST |
| 令牌过期后的宽限 | 30 秒 | MUST |
| 证明 JWT 时钟偏差 | ±60 秒 | MUST |
| 断言有效期 | ≤ 300 秒 | MUST |
| device_code 有效期 | 10 分钟（推荐） | SHOULD |
| 初始轮询间隔 | ≥ 1 秒；每次 `slow_down` 加 5 秒 | MUST |
| `task.run` 有效期（exp - iat） | ≤ 60 秒 | SHOULD |
| 任务总时长 | 10 分钟（推荐） | SHOULD |
| `max_concurrency` | 1–16 的整数；越界拒绝，不截断（§7.4）；`welcome` 取 min(声明值, 网关上限) | MUST |
| 模型列表 | ≤ 500 项；`model_names` 显示名 1–128 字符 | MUST |
| `messages` | 1–200 条；201 条起 400 `BAD_REQUEST` | MUST |
| 已签名 `task.run` | JWS ≤ 262144 字节，且编码后的 `task.run` 帧 ≤ `max_frame_bytes`；超限时网关在存储/排队前返回 413 `PAYLOAD_TOO_LARGE`（大内容改用图片/附件，走 `blob.chunk`） | MUST |
| chat 请求体 | ≤ 1 MiB | SHOULD |
| 字符串长度 | 按码点计（§4.1）：`device_name` ≤ 100，`stop`/`stop_sequences` 每项 ≤ 256；`X-End-User` 1–128、`Idempotency-Key` 1–255 可打印 ASCII | MUST |
| `tool_calls[].index` | 0–127；越界时网关让任务以 `INTERNAL` 失败（HTTP 502）并发送 `task.cancel`（`protocol_error`），MUST NOT 截断或合并到其他调用 | MUST |
| 单任务输出 | 一个任务全部 `task.delta` 的 `data` 编码后累计 ≤ 64 MiB（67108864 字节），明文与 E2EE 密封任务相同；超限处理同上一行 | MUST |
| 设备授权 | 每个客户端地址每分钟 ≤ 60 次；每租户有效的待确认配对 ≤ 1000 个；超限 429（§6.2） | MUST（数值为参考值） |
| 确认失败 | 每个终端用户每分钟 10 次（§6.4） | MUST |

| 续传窗口 | 30 秒（`welcome.resume_window_seconds`） | SHOULD |
| 流控窗口 | 默认每任务 1 MiB、每连接 4 MiB；hello 提供的 `task_window` MUST ≥ `max_frame_bytes`，`conn_window` MUST ≥ `task_window`，否则网关拒绝 hello（不发 welcome） | SHOULD / MUST |
| 单个附件 / 单任务附件 | ≤ 20 MiB / ≤ 32 MiB | MUST |
| 内联 data: URI 阈值 | 16 KiB，超过即转为 blob | SHOULD |
| E2EE 请求有效期 | `iat` 起 300 秒 | MUST |
| 并发排队 | 设备槽位满时 FIFO 等待 ≤ 15 秒，然后 429 | SHOULD |

**背压**：网关 MUST NOT 为单个任务无限缓冲数据。协商了 `flow` 时由 §15 的窗口限制发送速率；无论是否协商，单任务输出上限（上表）都 MUST 生效，E2EE 任务按密文字节计数。

---

## 11. 版本与能力协商

- **版本号**：本规范为 LMBP 2.0。WebSocket 子协议名固定为 `lmbp`，所有版本相同、不带版本号；主版本只由信封的 `v`（整数，本版本为 `2`）表示。网关元数据的 `protocol_versions` 以 `"主.次"` 字符串列出网关实现的全部版本（本版本为 `["2.0"]`），配对链接的 `v` 参数是主版本（`v=2`）。
- **主版本**：不兼容的变更 MUST 递增信封的 `v`（同时更新 `protocol_versions` 和配对链接的 `v`），子协议名仍为 `lmbp`；新旧对端在 `hello`/`welcome` 中按 `v` 区分（下一条）。次版本只增加兼容扩展，不改变 `v`。
- **1.x 对端**：2.0 实现 MUST NOT 降级到 1.x。网关：1.x 设备同样以子协议 `lmbp` 升级，升级照常成功；它的 `hello`（`v ≠ 2`）得到 `error`（`VERSION_UNSUPPORTED`，`id` 同 hello），随后网关断开连接（§7.4）；握手后 `v ≠ 2` 的帧见 §7.2。设备：网关选择的子协议不是 `lmbp`、或 `welcome.v ≠ 2`、或 hello 得到 `VERSION_UNSUPPORTED` 时 MUST 断开；`protocol_versions` 不含 `"2.0"` 的网关 MUST NOT 配对；`v` 不是 `2` 的配对链接 MUST 拒绝并提示需要 LMBP 2.0。
- **兼容扩展**（新增可选成员、新增消息类型、新增错误码）不改变主版本。接收方 MUST 忽略不认识的成员。收到不认识的 `type` 时，网关 MUST 回复 `error`（`BAD_REQUEST`）且 MUST NOT 断开连接；设备 MUST 忽略不认识的 `type`。
- **能力**：`hello.capabilities` 列出设备支持的能力，`welcome.capabilities` MUST 是它与网关所支持能力的交集。双方 MUST 只使用交集中的能力。本版本定义的能力：

| 能力 | 含义 |
|---|---|
| `session.token` | 连接内续期令牌（§7.7） |
| `models.update` | 连接内更新模型列表 |
| `resume` | 断线续传（§14） |
| `flow` | 字节窗口流量控制（§15）；`task.ack` 本身属于 Core，不需要此能力 |
| `tools` | function calling（§16.1） |
| `multimodal` | 内容片段与 `blob.chunk`（§16.2–§16.3） |
| `e2ee` | 端到端加密（§17） |

- 厂商私有的能力名和消息类型 SHOULD 以 `x-` 开头（消息类型用 `x.`），以免与将来的标准名冲突。

---

## 12. 安全要求

1. **传输**：生产环境 MUST 使用 TLS（`https`/`wss`）。设备 MUST 验证证书。
2. **最小凭据**：设备只持有自己的私钥。访问令牌短期有效，并与私钥绑定；令牌泄露后，没有私钥也无法建立会话或续期。
3. **网关被冒充**：设备 MUST 只执行用固定的网关公钥（配对时得到，或来自 TLS 保护的 JWKS）签名的 `task.run`。
4. **重放**：证明 JWT 的 `jti`、断言的 `jti`、`task.run` 的 `nonce` 都 MUST 做去重；`device_code` 只能使用一次。设备的 `nonce` 与 E2EE `rid` 去重记录若不持久化，设备 MUST 拒绝 `iat` 早于本进程启动时间（参考实现允许 2 秒误差）的 `task.run` 与密封请求，使重启不会重新打开重放窗口。
5. **租户隔离**：每个查询 MUST 同时按 `tenant` 和 `X-End-User` 过滤。访问别人的资源返回 404。
6. **配对码**：只有已登录的终端用户才能通过租户后端确认配对码；网关 MUST NOT 提供匿名查询配对码的接口。确认失败 MUST 按终端用户限速（§6.4）。网关 MUST NOT 向任何租户用户列出尚未确认的配对（包括设备名与指纹）：配对只能由用户输入（或由本机打开的 `pairing_uri` 带入）设备上显示的配对码来确认，否则未认证的设备可以把诱导文字推送到每个用户的界面上。
7. **本机策略**：设备 MUST 只执行用户允许的模型，并 MUST 执行本地并发上限。
8. **静态数据**：网关 SHOULD 加密存储提示词和输出（参考实现使用 AES-256-GCM），并按保留期清理；`device_code` 和租户 Key 只保存哈希。
9. **日志**：MUST NOT 记录访问令牌、证明、断言、`device_code`、租户 Key 或提示词原文。
10. **浏览器**：`/lmbp/v1/connect` 拒绝带 `Origin` 的请求；租户 Key 不得出现在前端代码中。

---

## 13. 一致性配置与测试

### 13.1 配置（profile）
实现按配置声明一致性。网关 MUST 在元数据 `profiles`（§18.2）中列出它满足的配置，MUST 包含 `core`；只能列出全部检查都通过的配置。设备侧的一致性以能力（§11）协商，`profiles` 只描述网关。

| 配置 | 范围 | 依赖的能力 |
|---|---|---|
| `core` | §4–§10、§18–§19：配对、令牌、握手、帧、`task.run`、取消与确认状态表（§8.6）、数据帧编号与确认（§14.1） | `session.token`、`models.update` |
| `reliable` | §14.2–§14.4 断线续传、§15 流量控制窗口 | `resume`、`flow` |
| `tools` | §16.1 | `tools` |
| `multimodal` | §16.2–§16.3 | `multimodal` |
| `e2ee` | §17 | `e2ee` |
| `openai` | §6.5、§16.4–§16.5 OpenAI 兼容接口 | — |
| `anthropic` | §6.7 Anthropic Messages 兼容接口 | — |

设备的一致性：能验证 `spec/testvectors` 中所有正例、拒绝所有反例，并实现 §7.4–§7.7 与 §8.6 设备侧各行。

conformance 从元数据读取 `profiles`：core 与已声明配置的检查必须通过，未声明配置的检查报告为 SKIP，不计失败；任何检查都不会因前面的步骤失败而被静默跳过（没跑到的检查记为失败）。只实现 core 的网关只协商 `session.token`、`models.update`；参考网关的 `avora server -core-only` 就是这种配置（`profiles: ["core", "openai"]`，调用方接口仍需 openai），用于证明 Core 可以单独通过。

### 13.2 需求 ID 与检查
每条需求有稳定的 ID，ID 一经发布不再改变含义，退役的 ID 不复用（REL-07 已并入 CORE-22）；conformance 检查编号同样稳定（以 E 开头的检查最早来自 1.0 勘误，编号保留）。下表与 `go run ./cmd/lmbp-conformance -list` 的输出一致（`spec/validate.sh` 校验）。

<!-- catalog:begin -->
| 需求 ID | 条款 | 配置 | 要求 | conformance 检查 |
|---|---|---|---|---|
| CORE-01 | §5.2 | core | JWS 严格校验：头只含 alg/typ/kid，alg 为 EdDSA，typ 匹配用途，kid 为公钥指纹，声明类型正确 | Z4a Z4b |
| CORE-02 | §6.1、§18.2 | core | 发现与元数据：JWKS、issuer 同源且来自配置（伪造 Host 不改变 issuer）、protocol_versions 含 2.0、profiles 含 core | S0 D1 M1 M2 M3 M6 M8 M9 |
| CORE-03 | §19.1 | core | 带 ?tenant= 的元数据带网关签名的 SaaS 身份 | M4 M5 M7 |
| CORE-04 | §6.2 | core | 设备授权：表单编码、user_code 格式、no-store、device_name ≤ 100 码点且不含控制与双向格式字符、未注册租户 invalid_client | P1 P2 P3 L1 L4 P9 |
| CORE-05 | §6.3 | core | 令牌端点：先验证明再透露状态，device_code 一次性，无视 slow_down 超过 10 次后 expired_token | P4 P5 T5 P13 |
| CORE-06 | §6.4 | core | 租户确认配对：未知码 404，jkt 不符 409，忽略大小写与分隔符；待确认配对从不列出，确认一次性，失败按终端用户计数 | P6 P7 P8 P10 P11 P12 |
| CORE-07 | §5.3、§18.3 | core | 访问令牌：at+jwt，iss/aud/tenant/sub/cnf.jkt 正确，与 JWKS、元数据一致 | T1 T2 T3 T4 I1 I2 |
| CORE-08 | §5.5 | core | 客户端断言：aud 为本网关令牌端点，jti 防重放 | T6 T7 I3 |
| CORE-09 | §7.1 | core | WebSocket 升级：要求子协议 lmbp（名字不带版本号，带版本号的变体被拒绝），令牌无效 401，选择 lmbp | W1 W2 W4 W8 |
| CORE-10 | §7.4、§11 | core | 1.x 对端被拒：子协议仍为 lmbp，v 为 1 的 hello 回 error VERSION_UNSUPPORTED 后断开 | W9 |
| CORE-11 | §7.4 | core | hello 校验：证明绑定本连接令牌，符合 hello.json，max_concurrency 越界拒绝不截断 | W3 W10 W11 |
| CORE-12 | §7.4、§11 | core | welcome：同 id，能力取交集（任意交集都合法），max_concurrency 在 1 与声明值之间 | W5 W6 W12 X1 |
| CORE-13 | §7.2、§7.3 | core | 帧：只发文本帧，符合 envelope.json，未知 type 不断开，握手后 v≠2 的帧回 BAD_REQUEST | F0 F1 F2 W7 |
| CORE-14 | §7.4 | core | models.update：不符合 models.update.json 时整帧拒绝、不生效；提高 max_concurrency 立即按 FIFO 启动排队请求 | W13 Q1 |
| CORE-15 | §5.6、§7.5 | core | task.run：无 data，JWS 可验证，载荷正确，envelope seq 为 1 | R1 R2 R3 |
| CORE-16 | §7.7 | core | 连接内续期 session.token | K1 |
| CORE-17 | §8.2 | core | 吊销立即断开会话，之后不能取得令牌；进行中的任务以 502 OUTCOME_UNKNOWN 结束 | V1 V2 V3 |
| CORE-18 | §6.6 | core | 在线设备未声明的模型返回 404 MODEL_NOT_FOUND | E1 |
| CORE-19 | §6 | core | JSON 响应带 Cache-Control: no-store | E2 |
| CORE-20 | §10 | core | 限制：messages 1–200 条，帧按 UTF-8 字节计、≤ 262144，单任务输出 ≤ 64 MiB（超出 task.cancel(protocol_error)） | Z6a Z6b Z6c Z6d Z6e Z6f Z6g Z9 |
| CORE-21 | §4.1 | core | X-End-User 为 1–128 个可打印 ASCII 字符 | L2 |
| CORE-22 | §8.6 | core | 确认属于 Core，不依赖 flow：按序数据帧累计确认，跳号让任务失败，本地结束的任务迟到帧照常确认直到终止帧；未知或已结束任务的数据帧回 task.cancel(unknown_task)，不确认 | S1 S2 S3 S4 S5 E7 |
| CORE-23 | §16.1 | core | model_names 只用于展示，未声明模型的条目被忽略 | X-N1 |
| CORE-24 | §8.6 | core | 设备数据帧先校验信封与正文（task.done/task.error 须符合各自 Schema），再接受序号、持久化和确认；非法终止帧让任务失败（task.cancel protocol_error），不确认 | S6 |
| REL-01 | §14、§15 | reliable | 协商 resume 与 flow；协商后确认同样覆盖全部数据帧，网关数据帧（含 blob.chunk）连续编号，续传后跳号仍让任务失败 | X1r X-F1 X-F2 X-F3 |
| REL-02 | §14.2–§14.3 | reliable | 断线续传：重传不重复、不丢失，续传参数有界 | X-R1 X-R2 Z3 |
| REL-03 | §14.4 | reliable | SSE 事件带 id，Last-Event-ID 精确重放 | X-H2 X-H3 |
| REL-04 | §14.4 | reliable | 幂等：同键同体接回，异体 422，按租户和终端用户隔离，排队中的重复请求接回，键为 1–255 个可打印 ASCII | X-H1 X-H4 Z1 Z1b Z7 L3 |
| REL-05 | §14.4 | reliable | 保留期清理已结束任务及其幂等记录 | E6 |
| REL-06 | §15 | reliable | 流量控制：窗口 ≥ max_frame_bytes，并发下不超窗 | Z2 Z6h Z6i |
| TOOLS-01 | §16.1 | tools | tools：协商 tools，每模型能力、签名载荷携带、tool_calls 合并、缺能力 400，index 超出 0–127 让任务失败 | X1t X-T1 X-T2 X-T3 X-T4 X-T5 |
| MM-01 | §16.2–§16.3 | multimodal | 内容片段与 blob：协商 multimodal，缺 vision 400，大 data: URI 走 blob.chunk | X1m X-M1 X-M2 |
| MM-02 | §16.2 | multimodal | 远程图片原样转发，设备不支持时调用方得到 400 CAPABILITY_UNSUPPORTED | E4 |
| E2EE-01 | §17 | e2ee | 端到端加密：协商 e2ee，密钥声明、JWE 原样转发、密封输出 | X1e X-E1 X-E2 X-E3 X-E4 X-E5 |
| OAI-01 | §6.5 | openai | /v1/models 与 SSE 输出 | O1 O2 |
| OAI-02 | §6.5 | openai | 调用方断开（流式与非流式）后向设备发送 task.cancel | C1 E3 |
| OAI-03 | §6.5 | openai | 请求参数校验，共享向量 params.json（长度按码点） | Z8a Z8b Z8c |
| OAI-04 | §16.4 | openai | 声明了 params 的模型：未声明的参数 400 CAPABILITY_UNSUPPORTED | Z8d |
| OAI-05 | §16.5 | openai | 被忽略的字段不写入 task.run | E5 |
| ANT-01 | §6.7 | anthropic | Anthropic Messages 兼容接口 | A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 Z5 E1b |
<!-- catalog:end -->

### 13.3 验证方法
```bash
# 1) JOSE 实现对照测试向量，并校验本文与契约中的示例
spec/validate.sh
# 2) 黑盒测试网关
LMBP_TENANT_KEY=<租户 key> go run ./cmd/lmbp-conformance \
  -gateway https://your-gateway -tenant <tenant> -schemas spec/schemas \
  [-issuer https://public-origin]   # 网关位于反向代理后、访问地址与 issuer 不同时
```
`lmbp-conformance` 依次扮演设备和租户后端，共 138 项检查，按上表的配置分组统计结果（E6 需用 `-retention <网关保留期>` 启用，否则记为跳过）。它还会用 JSON Schema 校验网关发出的每一帧。

---

## 14. 断线续传（能力 `resume`）

### 14.1 数据帧与确认
本节的编号与确认属于 Core（§8.6），不依赖 `resume` 或 `flow`。
- 数据帧：`task.run`、`blob.chunk`（网关→设备）、`task.delta`、`task.done`、`task.error`（设备→网关）。其余为控制帧，不带 `seq`、不重传。
- 发送方对每个任务的数据帧按 1、2、3… 编号，保留尚未被确认的帧。接收方用 `task.ack {seq}` 确认“该任务 `seq` 及以前的所有帧”（累计确认）。
- 接收方 MUST 丢弃 `seq ≤ 已收最大连续 seq` 的帧（重复）；遇到跳号 MUST 让任务失败（§7.5），MUST NOT 静默接受。

### 14.2 握手
1. `welcome` 带 `resume_token`（不透明，≥ 128 比特）和 `resume_window_seconds`。
2. 断线后，设备在窗口内重连，`hello.resume = {token, tasks:[{task_id, recv_seq}]}`，`recv_seq` 是该任务已从网关收到的最大连续 `seq`。仍须提供新的证明 JWT（§7.4），令牌规则不变。
3. 网关验证 token 属于该设备且未过期后，回复 `welcome.resume = {resumed: true, tasks:[{task_id, recv_seq}]}`，`recv_seq` 是网关已收到的设备帧。新的 `welcome` 同时给出新的 `resume_token`（旧 token 作废）。
4. 双方随后 MUST 按顺序重传对方 `recv_seq` 之后的所有未确认帧，然后才发送新帧（重传帧不得被新帧超越）。
5. 设备未列出的进行中任务，网关 MUST 以 `OUTCOME_UNKNOWN` 结束；token 无效或过期时 `resumed: false`，所有旧任务按 §7.5 失败。

### 14.3 网关侧任务保留
设备断开后，网关在 `resume_window_seconds` 内保留任务和未确认帧，调用方的 SSE 连接保持打开（发送 keep-alive）。窗口到期仍未续传，任务按 §7.5 失败。

### 14.4 HTTP 侧续传
- 每个 SSE 事件 MUST 带 `id:`：角色前导事件为 `0`，其后为对应设备数据帧的 `seq`（单调递增）。
- 调用方 MAY 带 `Idempotency-Key`（1–255 个可打印 ASCII 字符，§4.1）。同一租户、同一终端用户内，相同 key + 相同请求体（按 SHA-256 比较）MUST 接回已有任务而不是再次执行；请求体不同 MUST 返回 422 `IDEMPOTENCY_KEY_REUSED`。key 至少保留 24 小时。
- 保留期：网关 SHOULD 定期清理已结束的任务（§12 第 8 条）。清理以任务结束时间为准，超过网关保留期（生产环境 MUST ≥ 24 小时，参考实现与各 SDK 默认 7 天，可配置，负值表示不清理）的已结束任务连同其事件、它的 `Idempotency-Key` 记录一起删除，同时删除已过期的配对授权记录；未结束的任务 MUST NOT 被清理。幂等记录 MUST NOT 比它的任务活得更久：保留期内用同一 key 重放接回原任务，清理之后用同一 key 和同一请求体再次请求会作为新任务执行（不是 404，也不是 `IDEMPOTENCY_KEY_REUSED`）。
- 幂等记录、任务记录、排队等待设备并发槽位与网关内存中的任务登记 MUST 构成一个整体：从幂等记录可见的那一刻起，任务即处于“待执行（pending）”状态，此时到达的重复请求 MUST 接回这个待执行任务（等待并得到同一结果），MUST NOT 返回 404、`OUTCOME_UNKNOWN` 或再次执行。任务在排队阶段失败（如 `DEVICE_BUSY`、`DEVICE_OFFLINE`）时，网关 MUST 把该错误记录为任务的终止事件，此后用同一 key 重放得到同一错误；要重新执行，调用方使用新的 key。
- 持久化先于确认：网关 MUST 先把设备数据帧（终止帧还包括任务终止状态）写入存储，再向订阅者发布并发送覆盖该帧的 `task.ack`。写入失败时 MUST NOT 确认该帧（设备保留在续传缓冲区中），MUST 通知设备取消任务，并以 `INTERNAL` 结束任务，不得把未持久化的结果作为成功返回给调用方。
- 终止原子性：终止事件（`task.done` / `task.error`）与任务终止状态（SUCCEEDED / FAILED / CANCELLED）MUST 在同一个事务中提交，要么都写入，要么都不写入。每个任务最多有一个终止事件；`seq` MUST NOT 复用，已有终止状态 MUST NOT 被覆盖。终止写入失败时，网关以 `INTERNAL` 结束任务，这个本地错误使用同一 `seq`（失败的事务没有占用它）。
- 单一终止决策：设备的 `task.done`/`task.error`、超时、客户端取消、慢消费者和网关本地错误这些终止路径 MUST 先竞争同一个"只决定一次"的决策（CAS/锁）。只有胜出者提交终止事务，再把同一结果发布给调用方；失败者什么都不做，也 MUST NOT 在决策之前发布任何终止事件。决策之后到达的设备帧（包括迟到的 `task.done`）丢弃。网关本地终止事件的 `seq` 取已见过的最大设备 `seq` + 1。这样调用方看到的结果、存储的结果和重启后重放的结果始终一致。
- 幂等记录原子性：`Idempotency-Key` 记录与任务行 MUST 在同一个事务中写入（Go `Store.CreateTask(ctx, task, idem)`，Node `createTask(task, idem)`，Python `create_task(task, idem)`）。不存在"有键无任务"的状态：创建失败时两者都不写入，用同一个键重试会重新执行。
- 恢复判定：从存储重放已结束的任务时，网关 MUST 只在最后一个事件为终止事件、且存储的状态与之一致（done ↔ SUCCEEDED，error ↔ FAILED/CANCELLED）时按原结果重放；否则（没有终止事件，或旧数据中两者不一致）MUST 报告 `OUTCOME_UNKNOWN`。这个事件只用于响应、不写入存储，使用下一个未用的 `seq`。同一个幂等请求因此不会在故障前后得到相反的结果。
- 重新接入时带 `Last-Event-ID: <n>`（POST 同一 key，或 `GET /lmbp/v1/tenant/tasks/{id}/events`），网关 MUST 只发送 `id > n` 的事件；已结束的任务从存储重放。`n` 等于或大于终止事件的 seq 时没有可发送的事件，但网关 MUST 仍以终止符结束流（Chat Completions 为 `data: [DONE]`，Messages 为 `event: message_stop`），不得返回空流。
- **截断判定（客户端）**：流只有在读到终止符（`data: [DONE]`、`message_stop` 或错误事件）后才算完整。在终止符之前遇到 EOF 或连接中断 MUST 视为不完整（SDK：Go `ErrIncompleteStream` / `*IncompleteStreamError`，Node `IncompleteStreamError`，Python `IncompleteStreamError`，均带 `taskId` 与最后一个完整事件的 id），调用方据此续传；末尾缺少空行的半个事件 MUST 丢弃。
- 带 key 的请求，调用方断开后网关 SHOULD 保留任务 30 秒再取消；不带 key 时按 §6.5 立即取消。

---

## 15. 流量控制（能力 `flow`）

### 15.1 窗口
`hello.flow`（设备授予网关）和 `welcome.flow`（网关授予设备）各为 `{task_window, conn_window}`，单位是**已发送、未确认数据帧的序列化字节数**（即 WebSocket 文本消息长度）。两值 MUST ≥ 64 KiB 且 ≥ `max_frame_bytes`；缺省为 1 MiB / 4 MiB。

### 15.2 接收方
- 接收方在交付（网关：写给 SSE 订阅者；设备：交给执行器/重组缓冲）后发送 `task.ack`。网关 MUST 以所有在线订阅者中最慢的位置作为确认位置——这是端到端背压的来源。
- 收到会使未确认字节超出所通告窗口的帧（且该窗口非空）时，接收方 MUST 发送 `error`（`FLOW_CONTROL`）并断开连接。

### 15.3 发送方
发送 n 字节的数据帧，当且仅当 `task_used + n ≤ task_window`（或 `task_used == 0`）**且** `conn_used + n ≤ conn_window`（或 `conn_used == 0`）。不满足时 MUST 等待确认；多个等待的任务 SHOULD 按 FIFO 获得窗口，以保证公平。窗口为空时总允许发送一帧，防止死锁。测试向量 `flow` 给出了发送与接收两侧的逐步判定。

### 15.4 慢消费者
网关 SHOULD 对长期不读取的 SSE 调用方设置上限（参考实现 60 秒），超时后以 `SLOW_CONSUMER` 结束任务并向设备发送 `task.cancel`。

### 15.5 迟到帧与窗口回收
网关在本地结束任务后，设备已发出或仍在发出的数据帧照常被确认，直到该任务的终止帧，从而释放设备的续传缓冲和窗口；网关 MUST NOT 对这些帧回复 `task.cancel(unknown_task)`。逐行规则见 §8.6（D1–D3、F1）。

---

## 16. tools 与多模态（能力 `tools`、`multimodal`）

### 16.1 tools
- `hello`/`models.update` 的 `model_capabilities` 为每个模型声明 `tools`、`vision`、`audio` 中的若干项。`GET /v1/models` MUST 返回每个模型的 `capabilities`。
- `hello`/`models.update` 可选携带 `model_names`：`{模型 id: 显示名}`（显示名 1–128 字符，例如桌面端的方案名；超长时整帧按模式拒绝，§7.4）。本字段仅用于展示，网关 SHOULD 在 `GET /v1/models` 条目中以 `display_name` 返回（Anthropic 形状的 `display_name` 也用它，缺省为 id），在设备列表中以 `model_names` 返回；请求 MUST 仍使用模型 id。网关 MUST 忽略未出现在 `models` 中的条目；省略该字段时不返回显示名。
- 请求带 `tools` 而目标模型未声明 `tools`、或设备未协商 `tools` 能力时，网关 MUST 返回 400 `CAPABILITY_UNSUPPORTED`，MUST NOT 下发任务。
- `tools`、`tool_choice` 原样放入签名的 `task.run`。设备在 `task.delta.tool_calls` 中按 OpenAI 流式格式回报（`index` 区分调用，取值 0–127；`arguments` 可分片），以 `finish_reason: "tool_calls"` 结束。网关 MUST 透传为 SSE `delta.tool_calls`；非流式响应 MUST 按 `index` 合并成 `message.tool_calls`。`index` 越界时网关 MUST 按 §10 让任务失败，MUST NOT 按 `index` 分配内存、截断或把它并入其他调用。
- 后续请求中的 `role: "assistant"`+`tool_calls` 和 `role: "tool"`+`tool_call_id` 消息 MUST 原样转给设备。
- 适配器映射（参考实现）：OpenAI 兼容直通；Anthropic 映射为 `tool_use`/`tool_result` 内容块与 `input_schema`；Ollama 映射为 `tools` 与 `message.tool_calls`（arguments 为对象）；Codex、Grok Build、Antigravity CLI 不支持（不声明能力）。

### 16.2 内容片段
`content` 可为片段数组：`{type:"text",text}`、`{type:"image_url",image_url:{url,detail?}}`（需 `vision`）、`{type:"input_audio",input_audio:{data,format}}`（需 `audio`）。缺少能力时 400 `CAPABILITY_UNSUPPORTED`。`image_url.url` 允许 `https://`（原样转发，由设备自行获取）与 `data:`；`http://` MUST 拒绝。

远程图片：网关 MUST NOT 下载 `https://` 图片，也 MUST NOT 改写该 URL；Anthropic `image` 块的 `source.type: "url"` 同样原样转发（§6.7）。设备或其上游模型不能获取远程图片时，设备 MUST 返回 `task.error`（`CAPABILITY_UNSUPPORTED`，消息说明不支持远程图片 URL），网关把它作为 400 `CAPABILITY_UNSUPPORTED` 返回给调用方（流式请求在流中发送错误事件）。设备 MUST NOT 静默丢弃该图片后继续执行。

### 16.3 blob
- 大于 16 KiB 的 data: URI 和音频数据，网关 MUST 移入 blob：`task.run.blobs` 列出 `{id, size, sha256(base64url), media_type}`，片段中改写为 `lmbp-blob:<id>`。
- `task.run`（seq 1）之后，网关按偏移顺序发送 `blob.chunk {blob_id, offset, data(base64url, ≤ 96 KiB 原始字节), last}` 数据帧，它们同样受 §15 窗口约束。
- 设备 MUST 在全部 blob 到齐且 `size`、`sha256` 与签名载荷一致后才执行；不一致时 `task.error`（`BAD_REQUEST`）。单 blob ≤ 20 MiB，单任务 ≤ 32 MiB，超出时网关返回 413 `PAYLOAD_TOO_LARGE`。

### 16.4 请求参数能力
- `model_capabilities` 还可以声明请求参数支持：`params` 是声明标记，表示该模型的参数支持已列出；`temperature`、`top_p`、`stop`、`max_tokens` 各自出现才表示设备会把对应参数交给上游模型。
- 模型带 `params` 时，网关 MUST 以 400 `CAPABILITY_UNSUPPORTED` 拒绝该模型未声明的参数（消息中给出参数名；Messages 接口的 `stop_sequences` 对应 `stop`），且不发送 `task.run`，与 tools、图片、音频的处理一致。例外：`/v1/messages` 要求必须携带 `max_tokens`，模型未声明 `max_tokens` 时网关 MUST 不把它放进 `task.run`，而不是拒绝请求。
- 模型不带 `params` 时，参数支持未声明（旧版设备）：网关照常转发，由设备自行检查。设备收到不支持的参数时 MUST 返回 `task.error`（`CAPABILITY_UNSUPPORTED`），MUST NOT 静默忽略。
- E2EE 请求的参数在密文中，网关无法检查，由设备负责。
- 参考实现（Go 连接器）各适配器的参数表：

| 适配器 | temperature | top_p | stop | max_tokens | 声明的能力 |
|---|---|---|---|---|---|
| OpenAI 兼容 | `temperature` | `top_p` | `stop` | `max_tokens` | `params temperature top_p stop max_tokens` |
| Anthropic 兼容 | `temperature` | `top_p` | `stop_sequences` | `max_tokens` | 同上 |
| Ollama | `options.temperature` | `options.top_p` | `options.stop` | `options.num_predict` | 同上 |
| Codex（app-server） | 不支持 | 不支持 | 不支持 | 不支持 | `params` |
| Grok Build（CLI） | 不支持 | 不支持 | 不支持 | 不支持 | `params` |
| Antigravity CLI | 不支持 | 不支持 | 不支持 | 不支持 | `params` |

- Codex app-server 没有采样、停止序列和输出长度控制，也没有消息角色：连接器把对话合并成一段带角色标签的文本（`[system]`、`[user]`、`[assistant]` 各自成段），Codex 收到的是这一段文本，而不是分角色的消息。一轮正常完成即 `finish_reason: "stop"`（Codex 不会因长度截断）；中断、失败分别映射为 `CANCELLED`、上游错误。

- Grok Build 与 Antigravity CLI 也将消息合并为带角色标签的文本，不向远端开放本地代理工具。停止原因的映射见 [本地后端架构](backend-architecture.md#cli-后端)。仅在收到明确成功终态且进程成功退出后发送 `task.done`。

### 16.5 忽略与拒绝的请求字段
本节把 §6.5、§6.7、§16.1–§16.4 分散的规则汇总成一张表，不新增要求。“忽略”指网关接受请求、照常执行，但该字段 MUST NOT 写入 `task.run`；“拒绝”指网关在存储、排队或签名之前返回错误，MUST NOT 下发任务。

| 接口 | 字段 / 内容 | 处理 |
|---|---|---|
| chat | §6.5 参数表中的字段取值非法 | 拒绝：400 `BAD_REQUEST`（带 `param`） |
| chat | `n` ≠ 1 | 拒绝：400 `BAD_REQUEST` |
| chat | `response_format`、`seed`、`logprobs`、`top_logprobs`、`presence_penalty`、`frequency_penalty`、`logit_bias`、`user`、`parallel_tool_calls`、`stream_options`、`service_tier`、`store`、`metadata` 以及其他未列出的字段 | 忽略 |
| messages | §6.7 校验规则中的字段取值非法 | 拒绝：400 `invalid_request_error`（带 `lmbp_param`） |
| messages | `lmbp_e2ee`；未列出的内容块类型；服务端工具（`tools[].type` 不是 `custom`） | 拒绝：400 |
| messages | `thinking`、`metadata`、`service_tier`、`top_k`、`container` 以及其他未列出的顶层字段；`thinking`/`redacted_thinking` 内容块 | 忽略（内容块丢弃） |
| 两者 | `tools`，而模型未声明 `tools` 或设备未协商 `tools` 能力 | 拒绝：400 `CAPABILITY_UNSUPPORTED`（§16.1） |
| 两者 | 图片 / 音频，而模型未声明 `vision` / `audio` | 拒绝：400 `CAPABILITY_UNSUPPORTED`（§16.2） |
| 两者 | `http://` 或其他非 `https://`、非 `data:image/*;base64,` 的图片 URL | 拒绝：400 `BAD_REQUEST`（§16.2） |
| 两者 | 模型带 `params` 但未声明的参数 | 拒绝：400 `CAPABILITY_UNSUPPORTED`（§16.4；`/v1/messages` 的 `max_tokens` 例外，改为不写入 `task.run`） |
| 两者 | 附件或已签名 `task.run` 超出 §10 的限制 | 拒绝：413 `PAYLOAD_TOO_LARGE` |

被“忽略”的字段对结果没有任何影响。例如 `response_format: {type: "json_object"}` 不会让设备保证输出 JSON；需要这种保证的调用方应在提示词中说明，或改用能声明相应能力的后续协议版本。

---

## 17. 端到端加密（能力 `e2ee`）

目标：租户后端与设备之间的提示词和输出对网关不可见（网关只看到路由信息、用量和结束原因）。

### 17.1 设备密钥声明
设备生成 X25519 密钥对（RFC 7748），用身份私钥签发 JWS（`typ: lmbp-e2ee-key+jwt`，`kid` 为设备公钥指纹），载荷 `{iss, sub: device_id, iat, exp, jwk:{kty:"OKP", crv:"X25519", x, kid:<RFC 7638 指纹>, use:"enc", alg:"ECDH-ES"}}`，`exp - iat` ≤ 30 天。声明放在 `hello.e2ee_key`（或 `models.update.e2ee_key`），网关存储并通过 `GET /lmbp/v1/tenant/devices` 原样提供。

### 17.2 信任锚
网关可能被攻破，因此租户 MUST NOT 只凭网关返回的公钥信任设备。设备在本机显示/在 `verification_uri_complete` 中携带其身份公钥指纹 `jkt`；用户确认时由租户后端记录（钉住）该 `jkt` 并随 `devices/approvals` 提交（不符时网关返回 409）。之后租户 MUST 用钉住的 `jkt` 校验 `public_key` 与密钥声明签名，并检查 `sub`、`exp` 与 X25519 `kid`。

### 17.3 密封请求
租户构造 `{rid, iat, model, messages, tools?, tool_choice?, max_tokens?, temperature?, response_key}`（`response_key` 为新随机 32 字节，`rid` 唯一），按 RFC 7516 JWE 紧凑序列化加密：`alg: "ECDH-ES"`（直接密钥协商，RFC 7518 §4.6，X25519 按 RFC 8037）、`enc: "A256GCM"`、`kid`、`cty: "lmbp-request+json"`；encrypted key 段为空；`zip`、`crit` MUST NOT 出现。通过 `lmbp_e2ee` 字段提交，此时 MUST NOT 带明文 `messages`/`tools`（否则 400）。

### 17.4 网关与设备处理
- 网关把 JWE 作为 `media_type: application/jose` 的 blob 下发，`task.run.e2ee = {blob}`，`task.run.model` 为路由模型，不含明文消息。网关 MUST NOT 尝试解密，日志和存储中只出现密文。
- 设备 MUST：拒绝 `alg`/`enc` 以外的取值、`zip`；用 X25519 私钥解密；检查 `now - iat ≤ 300`、`rid` 未在窗口内出现过、密封的 `model` 等于 `task.run.model`。任一失败回复 `task.error`（`E2EE_DECRYPT_FAILED`，消息不得包含明文）。

### 17.5 密封输出
- 每个结果帧用 `response_key` 以 AES-256-GCM 加密：nonce = 4 字节 0 ‖ BE64(seq)，AAD = UTF-8 `"lmbp-e2ee/v1|" + rid + "|" + type + "|" + seq`。`task.delta.data = {e2ee: base64url(密文‖tag)}`，明文为 `{text?, tool_calls?}`，MUST NOT 同时带明文字段；`task.done` 保留明文 `finish_reason`、`usage`（计费需要），另带密封的 `{finish_reason}`。
- 网关的 SSE 块带 `lmbp_e2ee: {seq, type, data}`；租户用 `response_key` 解开。`seq`、`type`、`rid` 都绑定在 AAD 中，所以网关无法修改单帧的序号或类型、跨请求拼接或伪造帧。
- 单帧解密是无状态的：只靠它，察觉不到网关对整条响应重排、重复、丢帧或截断。租户 MUST 按顺序读取整条响应：每帧 `seq` MUST 等于上一帧加 1（首帧为 1，续传时从已读的最后一帧之后开始），`type` 只能是 `task.delta` 或 `task.done`，密封 `task.done` 之后 MUST NOT 再接受帧；响应结束时若没有读到密封 `task.done`，MUST 视为截断。参考 SDK 的响应读取器（Go `E2EESealed.Reader`/`ReaderAfter`，Node `sealed.reader()`，Python `sealed.reader()`）实现这些检查。

### 17.6 威胁模型
| 威胁 | 结果 |
|---|---|
| 网关读取提示词/输出 | 防御：只有密文 |
| 网关替换设备公钥 | 防御：租户用配对时钉住的 jkt 校验 |
| 网关重放请求 | 防御：`iat` 300 秒 + `rid` 去重 |
| 网关重排/重复/删改/截断输出帧 | 防御：AAD 绑定 seq/type/rid（单帧），租户按序读取（seq 连续、以密封 `task.done` 结束）发现重排、重复、丢帧和截断 |
| 网关拒绝服务、观察元数据（模型名、时间、长度、用量） | 不防御 |
| 设备或租户本身被攻破 | 不在范围 |
不提供前向保密之外的保证：X25519 设备密钥泄露会暴露用该密钥加密的历史请求，设备 SHOULD 定期轮换（`models.update.e2ee_key`）。

---

## 18. 网关身份绑定

### 18.1 issuer
- 每个网关 MUST 配置唯一的 **issuer**：它对外的 https origin（`scheme://host[:port]`，小写，无路径、查询、userinfo，默认端口省略）。仅开发环境的回环地址允许 `http`。
- issuer 是访问令牌的 `iss`、所有受众的基准，也是元数据文档的 `issuer`。网关 MUST 显式配置 issuer，MUST NOT 从请求的 `Host` 推导：否则网关会为请求方任意指定的 origin 签发 `signed_metadata` 与令牌，任何转发流量的代理都能冒充网关。参考实现通过 `server -issuer https://…` 配置，各 SDK 未配置 issuer 时拒绝启动。

### 18.2 元数据：`GET /.well-known/lmbp`
参照 RFC 8414（授权服务器元数据）。响应 `application/json`，可缓存（SHOULD ≤ 300 秒）：

| 字段 | 要求 |
|---|---|
| `issuer` | REQUIRED，§18.1 |
| `jwks_uri` | REQUIRED，MUST 与 issuer 同源 |
| `device_authorization_endpoint`、`token_endpoint` | REQUIRED，同源 |
| `connect_endpoint` | REQUIRED，`wss://<host>/lmbp/v1/connect`（开发环境 `ws://`） |
| `chat_completions_endpoint` | OPTIONAL |
| `protocol_versions` | REQUIRED，`"主.次"` 字符串数组，2.0 网关 MUST 包含 `"2.0"` |
| `profiles` | REQUIRED，网关满足的配置（§13.1），MUST 包含 `core` |
| `capabilities` | REQUIRED，网关支持的扩展 |
| `scopes_supported` | REQUIRED，§19.2 的作用域 |
| `tenant`、`audience`、`saas`、`requested_models`、`requested_scopes`、`iat`、`exp`、`signed_metadata` | 仅 `?tenant=` 时出现，§19.1 |

未知租户 MUST 返回 404。

### 18.3 令牌受众
- 访问令牌：`iss = <issuer>`，`aud = <issuer>/tenants/<tenant>`，`tenant` 声明同值。为租户 A 签发的令牌在租户 B 或其他网关处都无效。
- 设备断言（§5.5）：`aud = <issuer>/lmbp/v1/token`。网关 MUST 拒绝其他 `aud`（`invalid_grant`）。
- 令牌响应 SHOULD 带 `issuer` 字段，设备 MUST 校验它与元数据一致。

### 18.4 设备侧校验
设备在配对时记录 `issuer` 和 `audience`，并作为身份的一部分持久化。之后每次取得访问令牌，设备 MUST 用固定的网关公钥验证签名，并检查 `iss`、`aud`、`tenant`、`sub = device_id`、`cnf.jkt = 自身公钥指纹`。任何一项不符 MUST 拒绝该令牌并停止重连（参考实现返回 `ErrGatewayIdentity`），不得退而使用该令牌。

## 19. 配对同意

### 19.1 签名元数据
`GET /.well-known/lmbp?tenant=<id>` 返回 §18.2 的字段，外加：

| 字段 | 说明 |
|---|---|
| `tenant`、`audience` | 租户 ID 与 `<issuer>/tenants/<tenant>` |
| `saas` | `{name (REQUIRED), logo_uri, homepage_uri, policy_uri（隐私政策）, tos_uri, pairing_uri（用户确认配对码的页面）}` |
| `requested_models` | SaaS 打算使用的模型（可为空：由本机配置决定） |
| `requested_scopes` | §19.2 中的作用域，至少一个 |
| `iat`、`exp` | `exp - iat` MUST ≤ 24 小时 |
| `signed_metadata` | 上述全部字段（不含自身）的紧凑 JWS，`typ: lmbp-metadata+jwt`，`alg: EdDSA`，`kid` = 网关签名密钥指纹，密钥 MUST 在 `jwks_uri` 中 |

与 RFC 8414 §2.1 一致：设备 MUST 只使用 `signed_metadata` 内的值。

设备 MUST：从期望的 issuer（深链接或发现文档给出的网关 origin）读取元数据；`jwks_uri` 同源；用 JWKS 中 `kid` 对应的 Ed25519 密钥验证签名；`issuer`、`tenant`、`audience` 与期望一致；`saas.name` 非空；未过期；各端点同源；`pairing_uri` 为 https（开发环境回环除外）。任何一步失败 MUST NOT 显示同意页。配对完成后，令牌响应中的 `gateway_key` MUST 等于签名元数据的密钥，否则中止。

### 19.2 作用域注册表
| scope | 含义 |
|---|---|
| `lmbp.chat` | 文本对话（默认） |
| `lmbp.tools` | 函数调用（§16.1） |
| `lmbp.vision` | 图片输入 |
| `lmbp.audio` | 音频输入 |

作用域用于同意页展示；本机的策略引擎仍以本地配置为准。

### 19.3 同意流程
1. 设备通过深链接或 SaaS 地址得到 `(issuer, tenant)`，按 §19.1 校验签名元数据。
2. 设备 MUST 展示：SaaS 名称、logo、主页、隐私政策、网关 origin、租户、请求的模型与作用域、网关密钥指纹。
3. 用户 MUST 显式点击“同意”或“拒绝”。没有默认同意；超时视为拒绝。
4. 拒绝：设备不向网关发送任何请求，本地 API 返回 `CONSENT_DENIED`。
5. 同意：设备才生成设备密钥并调用 `device_authorize`（§6.2），在本机显示 `user_code`，并打开 `pairing_uri?user_code=…&jkt=…`。
6. SaaS 侧用户拒绝时，令牌端点返回 `access_denied`，设备将其映射为 `CONSENT_DENIED`。
7. 被拒绝（`deny: true`）的 `user_code` 在过期前不可再被批准：网关对再次提交的 `/lmbp/v1/tenant/devices/approvals` 返回 403 Problem Details，`code` 为 `CONSENT_DENIED`。

只用于自动化（测试、脚本、`connector -yes`）的实现 MAY 跳过第 2–3 步，但交互式应用 MUST NOT。

### 19.4 深链接 `lmbp://pair`
```
lmbp://pair?v=2&gateway=<https issuer origin>&tenant=<tenant id>[&remote=<SaaS origin>]
```
- `v` REQUIRED，当前为 `2`；设备 MUST 拒绝其他值（1.0 的 `v=1` 链接提示需要 LMBP 2.0）；`gateway` REQUIRED，按 §18.1 规范化；`tenant` 匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`；参数不得重复。
- 链接 MUST NOT 携带秘密或展示信息；展示的一切都来自签名元数据，因此伪造的链接最多只能把用户引到另一个真实的、已签名的身份上。
- 桌面应用 SHOULD 注册 `lmbp` URL scheme；不能注册时，用户可以粘贴链接。

## 20. 本机审计日志与用量统计（桌面端，非线协议）

本节约束桌面实现，不影响互通。

- 每个执行完毕的任务记录一行：`connection_id`（device_id）、`gateway`（issuer）、`tenant`、`saas_name`、`task_id`、`model`、`adapter`、开始时间、`status`（`ok | error | cancelled`）、`error_code`、`prompt_tokens`、`completion_tokens`、`usage_reported`（运行时是否给出用量）、`latency_ms`、`ttft_ms`、`e2ee`、`tools`、图片数。
- MUST NOT 记录 prompt、输出、工具参数或附件内容。
- 统计：按 `saas`、`model`、`day`、`hour`、`status`、`connection` 任意组合聚合请求数、失败数、prompt/completion/total tokens、平均与最大延迟、未计量请求数；时间桶默认 UTC，可选本地时区。
- 保留期默认 90 天，MUST 定期清理；用户可以手动清理。只有保留期清理和用户的手动清理（`audit_purge`）会删除记录；删除方案（adapter）、连接或其他配置 MUST NOT 删除审计记录。
- 参考实现：`internal/audit`（SQLite `audit.db`）；本地 API `audit_list`、`usage_stats`、`audit_purge`；CLI `avora usage`、`avora audit`。

## 21. 尚未定义的内容

- 网关多实例部署时的会话路由和共享去重/续传存储（参考实现为单进程）；
- E2EE 的多设备/群组密钥与密钥透明日志；
- 网关侧的按租户用量计费接口；
- 按 SaaS 的本机策略（配额、时间窗）与 `QUOTA_EXCEEDED` / `POLICY_DENIED` 错误码。

密钥轮换、同意与作用域、严格模式、RFC/IANA 注册、许可与治理的方向见非规范草案 [`docs/lmbp-2-p2-draft.md`](lmbp-2-p2-draft.md)，它不构成 2.0 的要求。

---

## 附录 A. 相对 1.0 的变更

2.0 与 1.x 不互通（§11）。下表列出全部线上变更；E1–E7 是 1.0 勘误，已并入正文，检查编号不变。

| 变更 | 1.0 | 2.0 | 条款 |
|---|---|---|---|
| 版本标识 | 子协议 `lmbp`，`v: 1`，`["1.0"]`，`v=1` 链接 | 子协议仍为 `lmbp`；`v: 2`，`["2.0"]`，`v=2` 链接；1.x 对端在 hello 时被明确拒绝（`VERSION_UNSUPPORTED` 后断开） | §7.1、§7.4、§11、§19.4 |
| `task.run` 的 `seq` | 只在协商 `resume`/`flow` 时出现，正文与模式不一致 | 必填，恒为 1 | §7.2 |
| `max_concurrency` | 越界截断到 1–16 | `hello` 越界拒绝；`models.update` 整帧拒绝；`welcome` 取 min(声明值, 网关上限) | §7.4、§10 |
| hello / models.update | 只检查部分字段 | 按 `hello.json` / `models.update.json` 整体校验，检查顺序固定 | §7.3、§7.4 |
| 字符串长度 | 各语言分别按字节、码点或 UTF-16 计；`stop` 按字节 | 一律按码点；`X-End-User`、`Idempotency-Key` 限可打印 ASCII | §4.1、§10 |
| 握手后的 `v ≠ 2` 帧 | 未定义 | `error BAD_REQUEST`，丢弃该帧，会话保持 | §7.2 |
| 取消与确认 | 分散在 §7.6、§15.5 | §8.6 状态转换表 | §8.6 |
| 配置与需求 ID | 4 个等级 | 7 个配置，元数据 `profiles`，需求 ID 映射到检查 | §13 |
| E1 | 在线设备未声明模型返回 503 | 404 `MODEL_NOT_FOUND` | §6.6 |
| E2 | 部分实现缺缓存头 | JSON 响应 `Cache-Control: no-store`（公开发现文档除外） | §6 |
| E3 | 只要求流式请求 | 非流式请求断开同样发送 `task.cancel` | §6.5 |
| E4 | 未定义 | 网关不下载远程图片，设备不支持时 400 `CAPABILITY_UNSUPPORTED` | §16.2 |
| E5 | 规则分散 | 忽略与拒绝字段汇总表 | §16.5 |
| E6 | 未定义 | 保留期清理任务及其幂等记录 | §14.4 |
| E7 | 未定义 | 本地结束的任务，迟到帧照常确认 | §8.6、§15.5 |
