# LMBP 服务端 Java SDK（`lmbp-core` + `lmbp-spring-boot-starter`）

让 Java SaaS 后端使用**用户自己电脑上的模型**（经 Avora 桌面端）。业务代码只做两件事：

1. **配对**：展示配对链接，批准用户在桌面端看到的配对码；
2. **调用模型**：标准 OpenAI（`/v1/chat/completions`、`/v1/models`）或 Anthropic（`/v1/messages`）请求，直接用官方 `openai` / `anthropic` 客户端，或用 SDK 的进程内客户端。

配对、iss/aud 绑定、`signed_metadata`、JWKS、WebSocket 子协议 `lmbp`、按字节的流控、断线续传（seq/ack/`Last-Event-ID`）、`Idempotency-Key`、E2EE 透传、Problem Details、各类上限、单一终态裁决（终态事件与状态在一次存储调用里原子提交）、按模型的参数能力表，全部在 SDK 内部。

需要 **JDK 21**（虚拟线程）。Starter 基于 **Spring Boot 3.5（Servlet 栈）**，已用内嵌 Tomcat 验证。

> **成熟度（如实说明）**：`lmbp-core` 的引擎是从 `mock/java`（Node SDK 引擎的逐段移植）**抽取并重构**而来：HTTP/WebSocket 改为可插拔的传输接口，存储改为可插拔接口，并新增进程内客户端。它不与 Go 参考网关共享代码，存在真实差异（见下文“限制”）。通过共享测试向量和 `lmbp-conformance` 只说明在被检查的点上一致，不等于符合规范，见[各实现与成熟度](../../docs/implementations.md)。

## 模块

| 模块 | 内容 | 依赖 |
|---|---|---|
| `lmbp-core` | 与框架无关的协议引擎、`MemoryStore`、`JdbcStore`、进程内客户端、仅用 JDK 的 `StandaloneServer`（测试/演示用） | 只有 JDK |
| `lmbp-spring-boot-starter` | 自动配置：`LMBPServer` Bean、协议路由过滤器、`/lmbp/v1/connect` WebSocket、可注入的 `LmbpClient` | `spring-boot-starter-web`、`spring-boot-starter-websocket` |
| [`examples/spring-boot-demo`](../../examples/spring-boot-demo) | 最小 Spring Boot 应用 | starter、`sqlite-jdbc`（运行时） |

```bash
cd sdk/java && mvn install            # 构建三个模块并运行单元测试
TENANT_API_KEY=$(openssl rand -hex 24) java -jar ../../examples/spring-boot-demo/target/spring-boot-demo-0.1.0-SNAPSHOT.jar
```

## Spring Boot

```xml
<dependency>
  <groupId>dev.avora</groupId>
  <artifactId>lmbp-spring-boot-starter</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```properties
lmbp.issuer=https://saas.example.com      # 必填：网关公网 origin；为空时启动失败，绝不从请求 Host 推导
lmbp.tenant=acme
lmbp.api-key=${TENANT_API_KEY}            # ≥ 32 字符，服务端密钥
lmbp.signing-seed=${LMBP_SIGNING_SEED:}   # 可选，32 字节 hex；留空则首次启动生成并保存在 store 中
lmbp.store=jdbc:sqlite:lmbp.db            # memory（默认）| jdbc（使用应用的 DataSource）| jdbc: URL
```

其他属性：`lmbp.display-name`、`lmbp.profile-file`（与 `mock/tenant-profiles.example.json` 同格式）、`lmbp.max-concurrency`（默认 16）、`lmbp.keepalive-ms`（默认 1000，见限制）、`lmbp.sse-timeout-ms`、`lmbp.jdbc-text-type`、`lmbp.chat-ui-dir`。

```java
@Bean LmbpUserResolver users() { return req -> currentUserId(req); }   // 你的登录决定谁是终端用户

@RestController class Ai {
  private final LmbpClient lmbp;
  Ai(LmbpClient lmbp) { this.lmbp = lmbp; }

  @GetMapping("/app/pair") Map<String, Object> pair() { return Map.of("link", lmbp.pairLink(lmbp.currentUser())); }
  @PostMapping("/app/pair/approve") Pairing.Decision approve(@RequestBody Map<String, String> b) { return lmbp.approve(lmbp.currentUser(), b.get("user_code")); }
  @PostMapping("/app/ask") Map<String, Object> ask(@RequestBody Map<String, Object> req) { return lmbp.chat(req); }          // OpenAI 形状
  @PostMapping("/app/ask/stream") SseEmitter stream(@RequestBody Map<String, Object> req) { return lmbp.stream(req); }   // 浏览器 SSE
}
```

Starter 注册的路由：`/.well-known/lmbp`、`/.well-known/jwks.json`、`/lmbp/**`、`/v1/**`、`/healthz`（在 Spring MVC 之前由过滤器处理；应用自己不要再占用 `/v1/**`），以及 WebSocket `/lmbp/v1/connect`（子协议 `lmbp`，单条消息上限 256 KiB）。任何 Bean 都可以用自己的同类型 Bean 覆盖。

`LmbpClient`：`pairLink(userId)`、`lookup(userId, code)`、`approve(userId, code)`、`deny`、`devices(userId)`、`revoke`、`models(userId)`、`chat([userId,] req)`、`stream([userId,] req) → SseEmitter`、`cancel(userId, taskId)`、`resume(userId, taskId, lastEventId) → SseEmitter`、`forUser(userId) → InProcessClient`。不带 `userId` 的方法通过 `LmbpUserResolver` 解析当前请求的用户。`stream` 每个 OpenAI chunk 发一个 `data:` 事件（事件 id 是续传游标），最后发 `data: [DONE]`；失败时改发 `event: error`（`{"code","message","task_id","last_event_id"}`）。浏览器断开或超时会取消任务。

## 不用 Spring：`lmbp-core`

```java
LMBPServer lmbp = LMBPServer.builder()
    .issuer("https://saas.example.com")
    .tenant("acme", System.getenv("TENANT_API_KEY"), Map.of("display_name", "Acme CRM"))
    .store(JdbcStore.open("jdbc:sqlite:lmbp.db"))      // 默认 MemoryStore
    .build();

String link = lmbp.pairing().link("acme");                              // 1. 配对
lmbp.pairing().approve("acme", userId, userCode);

InProcessClient c = lmbp.client("acme", userId);                        // 2. 调用
Map<String, Object> r = c.call(Map.of("model", model, "messages", msgs));
try (LmbpStream st = c.stream(Map.of("model", model, "messages", msgs))) {
  for (Map<String, Object> chunk : st) { ... }   // 结束于 [DONE]；错误事件抛 LmbpApiException；截断抛 IncompleteStreamException
}
c.cancel(taskId);  c.resume(taskId, lastEventId);
```

| 分类 | API |
|---|---|
| 构造 | `LMBPServer.builder()`：`issuer`、`tenant(id, apiKey[, profile])`、`store`、`signingSeed` / `signingSeedHex`、`maxConcurrency`、`taskTimeoutMillis`、`keepaliveMillis`、`chatUiDir`、`logger`；`close()` |
| 接入 Web 框架 | `handles(path)`、`handle(HttpRequest, HttpSink)`（阻塞到响应结束；客户端断开时调用 `HttpRequest.abort()`）、`handshake(HttpRequest) → WebSocketHandshake`（被拒时返回状态码与 problem 正文；通过时 `accept(WebSocketPeer) → WebSocketSession`，传输层把收到的消息交给它） |
| 密钥 | `kid()`、`jwks()`、`LMBPServer.generateSigningSeed()`、`generateTenantKey()` |
| 配对 | `pairing().link(tenant)`、`lookup(tenant, user, code)`（错误码按最终用户计入每分钟 10 次的上限）、`approve(tenant, user, code[, jkt])`、`deny`、`listDevices`、`revokeDevice`；失败抛 `PairingException`（`code`：`BAD_REQUEST` / `NOT_FOUND` / `FORBIDDEN` / `CONSENT_DENIED` / `RATE_LIMITED`） |
| 进程内客户端 | `client(tenant, user)`：`models()`、`call`、`stream`、`messages`、`messagesStream`、`resume`、`cancel`；`Options.idempotent(key)` |
| 存储 | `Store` 接口；`MemoryStore`、`JdbcStore(DataSource[, textType])`、`JdbcStore.open(url)` |

每条终止路径都有确定的结果并释放资源：正常结束、设备报错、取消、超时、设备离线（已下发的任务记为 `OUTCOME_UNKNOWN`）、客户端断开、消费过慢（60 秒未消费，`SLOW_CONSUMER`）。终态只裁决一次，先写存储再对外可见。进程内流的缓冲有上限（64 个写入块）：消费者不读时引擎写入阻塞，设备的流控窗口随之填满。

## 官方客户端原样可用

```python
openai = OpenAI(base_url="https://saas.example.com/v1", api_key=TENANT_API_KEY, default_headers={"X-End-User": user_id})
claude = Anthropic(base_url="https://saas.example.com", api_key=TENANT_API_KEY, default_headers={"X-End-User": user_id})
```

## 测试

```bash
cd sdk/java && mvn install                              # JUnit：JOSE 共享向量（含全部负例）、存储契约（内存 / SQLite）、
                                                        # 用脚本化假设备跑配对/调用/流/取消/提前关闭/续传/截断/非法参数，starter 装配
scripts/mock-interop.sh spring-boot spring-boot-sqlite  # 演示应用上跑 lmbp-conformance+ Go 连接器端到端 + 官方 openai/anthropic 客户端
```

截至提交时：演示应用在内存与 SQLite 两种存储下 `lmbp-conformance` 全部通过、无跳过；`scripts/verify-all.sh` 包含这两个变体和 Maven 单元测试步骤（严格模式，任何跳过都判失败）。

## 限制

- **单实例**：在线会话、任务分发、JTI 防重放都在进程内存里；一个存储只能对应一个网关进程，不能水平扩展。
- **`JdbcStore`**：只在 SQLite（xerial `sqlite-jdbc`）上验证过；SQL 是通用写法，其他数据库未测试。任务事件不会清理，表会随流式输出持续增长。字节数据以 base64url 文本存储。每次调用一个短事务。
- **客户端断开检测**：Servlet 容器只有在写入失败时才知道客户端走了。流式响应在空闲时每 `lmbp.keepalive-ms`（默认 1 秒）写一条 SSE 注释（Anthropic 流写 `ping` 事件），所以放弃的流会在约 1–3 秒内被取消；**非流式请求在等待设备期间无法发现断开**，任务会继续直到完成或超时。
- 只验证了 Spring Boot 3.5 + 内嵌 Tomcat；Jetty / Undertow、WebFlux（响应式栈）未适配或未测试。
- 引擎用一把全局锁串行化（沿用 Node 单线程语义），阻塞等待会释放锁；单进程吞吐没有做过压测。
- 未提供二维码生成（Python SDK 有）；把 `pairLink` 交给前端生成二维码。
- `/v1/messages` 不支持 E2EE；Anthropic 模型列表的 `display_name`、`created_at` 为占位值（与其他 SDK 相同）。
- 尚未发布到 Maven Central，需要从源码 `mvn install`。
