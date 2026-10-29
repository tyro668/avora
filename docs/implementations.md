# 各语言实现与成熟度

规范见 [lmbp-spec.md](lmbp-spec.md)。下表如实说明每个实现和 Go 参考实现的关系。

| 实现 | 位置 | 成熟度 |
|---|---|---|
| Go | `internal/lmbp`、`avora server`、`sdk/go` | **参考实现**：`sdk/go` 内嵌参考网关 `internal/lmbp/gateway`，与 `avora server` 是同一份代码。行为以它为准。 |
| Node.js | `sdk/node`（`mock/node` 是它的命令行外壳） | **独立重新实现**，与 Go 不共享代码，存在真实的行为差异。例如：JWKS 返回 `application/json`（Go 为 `application/jwk-set+json`）；`Store` 接口是同步的、没有 `context`，Go 的接口返回 `error`；HTTP/WebSocket 栈、超时与默认参数的实现细节不同。 |
| Python | `sdk/python`（`mock/python` 是它的命令行外壳） | **独立重新实现**（纯 ASGI，自带 HTTP/SSE 渲染），同样与 Go 存在真实差异：`Store` 是同步 Protocol；WebSocket 依赖 uvicorn 的 `websockets` 实现；时间参数以秒为单位，等等。 |
| Rust | `mock/rust`（模拟网关）、`spec/examples/rust`（协议示例骨架） | `mock/rust` 是 Node 引擎的**模拟网关移植**：通过 `lmbp-conformance`、连接器端到端、官方客户端与聊天页 E2E，但状态只在内存（无持久化存储）、HTTP/WebSocket 为手写最小实现，**不是 SDK，不面向生产**。`spec/examples/rust` 仍只是 JOSE/E2EE/流控骨架。 |
| Java | `sdk/java`（SDK：`lmbp-core` + `lmbp-spring-boot-starter`，示例 `examples/spring-boot-demo`）、`mock/java`（模拟网关） | `sdk/java` 的引擎是从 `mock/java`（Node 引擎的逐段移植）**抽取并重构**而来，不与 Go 共享代码，存在真实差异：`Store` 接口是同步的、由引擎单锁串行调用；Spring 适配基于 Servlet（Tomcat 已验证），Servlet API 只在写入失败时才报告客户端断开，所以 SSE 空闲保活默认 1 秒；非流式请求在 Tomcat 上由 starter 注册的 `TomcatDisconnectProbe`（Valve）主动探测连接关闭（其他 Servlet 容器上仍只能在写结果时发现断开）；`JdbcStore` 只在 SQLite 上验证过，单实例。演示应用通过 `lmbp-conformance`（内存与 SQLite 两种存储）、连接器端到端与官方 openai/anthropic 客户端。需要 JDK 21、Spring Boot 3.5。`mock/java` 仍是只依赖 JDK 的模拟网关，**不面向生产**；实现指南里的 Java 片段（Jackson 写法）仍是未编译的示意代码。 |

> **通过共享 Schema、测试向量（含 `spec/testvectors/jose.json` 的负例）和 `lmbp-conformance`，不等于符合规范。** 它们只说明：实现在被检查的那些点上，与参考实现和彼此一致。黑盒检查覆盖不到的路径，例如存储写入失败、并发竞态、资源上限和错误恢复，仍然可能不同。2026-10 审查发现的问题（包括 ACK 先于持久化、排队期间重复请求被判为 `OUTCOME_UNKNOWN`）在修复前都“全部通过”了当时的一致性测试。全量矩阵见 [`scripts/verify-all.sh`](../scripts/verify-all.sh)（14 步，任何失败或跳过都判失败）。

### 跨实现一致的行为（2026-10 一致性审查后）

以下各项在 Go（参考实现与 `sdk/go`）、`sdk/node`、`sdk/python`、`sdk/java` 上行为相同，由 conformance 与差分测试覆盖（LMBP 2.0）：

| 行为 | 规范 | 说明 |
|---|---|---|
| 在线设备未声明模型 → 404 `MODEL_NOT_FOUND`；设备离线 → 503 `DEVICE_OFFLINE` | §6.6（E1） | 此前所有实现都返回 503 |
| JSON 响应 `Cache-Control: no-store`；JWKS 与 `/.well-known/lmbp` 为 `public, max-age=300` | §6（E2） | Node/Express、Python/FastAPI、Java 此前不带该头 |
| 非流式请求的调用方断开 → 2 秒内 `task.cancel(client_disconnected)` | §6.5（E3） | Java（Spring/Tomcat）此前不发送；Spring 在非 Tomcat 容器上仍有此限制 |
| 子协议 `lmbp`（不带版本）、信封 `v: 2`、`protocol_versions: ["2.0"]`、`profiles`；1.x 对端的 hello 得到 `VERSION_UNSUPPORTED` 后断开 | §7.1、§7.4、§11 | 2.0 起 |
| `hello` 按 `hello.json` 校验，`max_concurrency` 越界拒绝；`models.update` 不合法整帧拒绝 | §7.4 | 1.0 截断到 1–16 |
| 字符串长度按码点；`X-End-User`、`Idempotency-Key` 限可打印 ASCII | §4.1 | 1.0 各语言分别按字节、码点、UTF-16 计 |
| 未知任务 / 已结束任务 / 本地结束任务的帧 | §8.6 | 状态表 U1、R2、D1–D3、F1 |
| 保留期清理：默认 7 天，已结束任务与事件、幂等记录、过期配对授权一起删除；负值不清理 | §14.4（E6） | 内存与 SQLite/JDBC 存储都实现了。配置：Go `Options.Retention`，Node `retention`（毫秒），Python `retention`（秒），Java `retentionMillis` / `lmbp.retention-seconds`；命令行外壳与示例为 `--retention-seconds` / `LMBP_RETENTION_SECONDS`。自定义 `Store` 不实现 `purge` 时不清理 |

## 常用命令

- Go 参考网关：`avora server -issuer https://<网关公网地址> [-tenant-profiles profiles.json]`。`profiles.json` 配置每个租户在桌面端同意页上显示的身份，格式见 [mock/tenant-profiles.example.json](../mock/tenant-profiles.example.json)。
- 黑盒一致性测试（138 项，按配置统计；`-list` 输出需求表）：`LMBP_TENANT_KEY=... go run ./cmd/lmbp-conformance -gateway <url> -tenant <id> [-retention <网关保留期>]`。E6（保留期清理）只在给出 `-retention` 时运行，网关需以同样的短保留期启动（例如 `--retention-seconds 2`），否则记为跳过。`scripts/mock-interop.sh` 默认让每个网关（含 `mock/java`、`mock/rust`）以 2 秒保留期启动并运行 E6；设 `LMBP_RETENTION_SECONDS=` 为空可恢复默认保留期。只检查网关在元数据 `profiles` 中声明的配置，未声明配置的检查记为跳过。
- Core-only 网关：`avora server -core-only ...` 只协商 `session.token`、`models.update`，声明 `profiles: ["core", "openai"]`；`scripts/mock-interop.sh go-core` 验证它单独通过全部 Core 检查。
- 契约与测试向量校验：`spec/validate.sh`。
