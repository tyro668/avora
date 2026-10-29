# lmbp 实现指南：用 Java、Node.js、Python、Go、Rust 实现网关

本指南面向要用自己的语言实现 lmbp **网关**（也适用于租户后端或设备端）的团队。规范以 [`docs/lmbp-spec.md`](lmbp-spec.md) 为准，本文只讲实现方法和常见陷阱。

## 0. 先看这几份材料

| 材料 | 用途 |
|---|---|
| `spec/schemas/*.json` | JSON Schema 2020-12，可直接用来校验每一帧 |
| `spec/openapi.yaml` | HTTP 接口，可用于生成服务端桩代码或客户端 |
| `spec/asyncapi.yaml` | WebSocket 通道和消息 |
| `spec/testvectors/vectors.json` | 固定密钥、期望签名和 JWT、正例与反例，以及合法和非法的帧 |
| `spec/examples/{python,node,rust}` | 关键路径的骨架代码，**都已用测试向量实际运行通过** |
| `cmd/lmbp-conformance` | 黑盒测试你的网关，共 138 项检查，按 7 个配置统计（规范 §13）；`-list` 输出需求 ID 与检查的对应表 |
| `spec/validate.sh` | 一键校验所有契约，并运行示例骨架 |

### 代码片段的验证状态

| 语言 | 状态 |
|---|---|
| Go | 参考实现（`internal/lmbp`）。`go test` 覆盖测试向量、Schema 和一致性测试 |
| Python | `spec/examples/python`：已在 Python 3.13 + cryptography 上运行，305 项全部通过（含 `jose.json` 全部正反例） |
| Node.js | `spec/examples/node`：已在 Node 20 上运行，只用 `node:crypto`，Schema 校验用 ajv，345 项全部通过（含 `jose.json` 全部正反例） |
| Rust | `spec/examples/rust`：已在 rustc 1.85 + ed25519-dalek 2 上运行，`cargo test` 通过（含 `jose.json` 全部正反例）。完整的模拟网关见 `mock/rust`（不是 SDK） |
| Java | 现成 SDK：`sdk/java`（`lmbp-core` 引擎 + `lmbp-spring-boot-starter`，JDK 21），通过 `spec/testvectors/jose.json`（含全部负例）与 `lmbp-conformance`，见 [sdk/java/README.md](../sdk/java/README.md)。下文 Java 片段（Jackson/Spring 写法）**仍仅为示意，未编译**；自己实现时请用测试向量验证。JDK-only 模拟网关 `mock/java` 也可参考 |

本文中 Go、Python、Node、Rust 的片段摘自上述已运行的文件，或是它们的精简版。

---

## 1. 推荐库

| 能力 | Java | Node.js | Python | Go | Rust |
|---|---|---|---|---|---|
| HTTP 服务 | Spring Boot / Quarkus / Javalin | Fastify / Express / `node:http` | FastAPI / Starlette | `net/http` | axum |
| WebSocket（需支持子协议选择） | Jakarta WebSocket（Tyrus）、Spring WebSocket、Netty | `ws`（用 `handleProtocols` 选择 `lmbp`） | `websockets`（`subprotocols=["lmbp"]`）、Starlette `websocket.accept(subprotocol="lmbp")` | `gorilla/websocket`（`Upgrader.Subprotocols`）、`coder/websocket` | `axum::extract::ws`（`.protocols(["lmbp"])`）、`tokio-tungstenite` |
| Ed25519 | JDK 15+ `Signature.getInstance("Ed25519")`；BouncyCastle | `node:crypto`（`sign(null, …)`） | `cryptography` | `crypto/ed25519` | `ed25519-dalek` 2（用 `verify_strict`） |
| JWS/JWT（EdDSA） | Nimbus JOSE+JWT（`Ed25519Signer`/`Ed25519Verifier`，需 Tink）、jose4j | `jose`（panva），或像骨架那样直接用 `node:crypto` | `joserfc`、PyJWT[crypto]（`algorithms=["EdDSA"]`） | 自己实现（参考实现约 80 行）、`go-jose` v4、`lestrrat-go/jwx` v2 | `josekit`、`jsonwebtoken` 9（支持 EdDSA），或像骨架那样手写 |
| JSON Schema 2020-12 | `com.networknt:json-schema-validator` | `ajv`（`ajv/dist/2020`） | `jsonschema` + `referencing` | `santhosh-tekuri/jsonschema` v6 | `jsonschema` crate |
| SSE | Spring `SseEmitter`、WebFlux `Flux<ServerSentEvent>` | `res.write("data: …\n\n")`，处理 `drain` 事件 | `StreamingResponse`、`sse-starlette` | `http.Flusher` | `axum::response::sse::Sse` |
| SQLite / Postgres | `sqlite-jdbc`；PostgreSQL JDBC + HikariCP | `better-sqlite3`；`pg` | `sqlite3`/`aiosqlite`；`asyncpg`/`psycopg` 3 | `modernc.org/sqlite`；`pgx` | `sqlx`（sqlite/postgres） |
| AES-GCM（静态加密） | `Cipher.getInstance("AES/GCM/NoPadding")` | `crypto.createCipheriv('aes-256-gcm')` | `cryptography` AESGCM | `crypto/cipher` | `aes-gcm` |

**不推荐**：
- python-jose：已停止维护，曾出现算法混淆漏洞；
- 任何"自动从 JWT 头读取 alg"的验证 API：必须固定 `alg=EdDSA`；
- 依赖库默认行为的 base64 解码（见 §2.2）。

---

## 2. 跨语言陷阱

### 2.1 JSON
- **签名不依赖 JSON 序列化**。lmbp 一律对**收到的字节**验签，然后再解析 JSON。不要先解析再重新序列化后验签。不同语言的序列化结果互不相同：
  - Go 的 `json.Marshal` 默认把 `<`、`>`、`&` 转义为 `\u003c` 等；
  - Python 的 `json.dumps` 默认 `ensure_ascii=True`，会把中文转成 `\uXXXX`；
  - JavaScript 会把 `1.0` 输出为 `1`；
  - Java Jackson 的键顺序取决于字段声明顺序。
  
  测试向量里的 `task_run` 载荷故意包含中文、emoji、引号、反斜杠和 `</script>`，用来暴露这类问题。
- **重复键**：Go 和 Python 取最后一个值，Jackson 默认也是。安全敏感的实现 SHOULD 开启严格模式：Jackson 用 `StreamReadFeature.STRICT_DUPLICATE_DETECTION`，Python 用 `object_pairs_hook` 检查。
- **Go 的大小写不敏感匹配**：`encoding/json` 匹配字段名时**不区分大小写**，`{"Device_ID": …}` 也会被解析到 `DeviceID` 字段。需要严格匹配时，先解析到 `map` 再检查。
- **数字**：所有整数都 ≤ 2^53-1，因此 JavaScript 的 `number` 足够。不要输出 `1.0`、`1e3`。Python 的 `json.loads` 默认接受 `NaN`/`Infinity`，应该用 `parse_constant` 拒绝。
- **Unicode**：只接受合法 UTF-8。单独的代理项（`"\ud800"`）应该拒绝：Python 默认接受，Go 会替换成 U+FFFD。

### 2.2 base64url
- 编码时**不带填充**：
  - Java：`Base64.getUrlEncoder().withoutPadding()`
  - Node：`Buffer.toString('base64url')`
  - Python：`urlsafe_b64encode(...).rstrip(b"=")`
  - Go：`base64.RawURLEncoding`
  - Rust：`URL_SAFE_NO_PAD`
- 解码时要**严格**：
  - Node 的 `Buffer.from(s, 'base64url')` 会静默忽略非法字符；
  - Python 的 `urlsafe_b64decode` 要求补齐填充，且会忽略部分非法字符；
  - Java 的 `getUrlDecoder()` 接受带填充的输入。
  
  这三种语言都要先用正则 `^[A-Za-z0-9_-]*$` 检查，并拒绝长度模 4 余 1 的输入。Go 的 `RawURLEncoding` 和 Rust 的 `URL_SAFE_NO_PAD` 本身就是严格的。

### 2.3 Ed25519 与 JWS
- 固定 `alg == "EdDSA"`，同时检查 `typ`（四种类型，见规范 §5.2）。测试向量覆盖了 `alg_none`、`alg_hs256`、类型混淆和 `crit` 等反例。
- Ed25519 是确定性签名：同一个种子对同一个 `signing_input` 的签名必须与测试向量**逐字节相同**。可以借此检查私钥加载是否正确。
- 私钥格式：
  - Java PKCS#8 的 DER 前缀为 `302e020100300506032b657004220420`，后面跟 32 字节种子；
  - Node 可以用 JWK 导入（`{kty:'OKP',crv:'Ed25519',d,x}`）；
  - Python 用 `Ed25519PrivateKey.from_private_bytes(seed)`；
  - Go 用 `ed25519.NewKeyFromSeed`；
  - Rust 用 `SigningKey::from_bytes`。
- RFC 7638 指纹：哈希的输入是 `{"crv":"Ed25519","kty":"OKP","x":"…"}`，**成员按字典序排列，不含空白**。不要用 JSON 库序列化 JWK 对象来生成这个输入，直接拼接字符串最可靠。

### 2.4 时钟偏差
- 访问令牌允许 ±30 秒偏差，证明 JWT 允许 ±60 秒。服务器必须用 NTP 同步时钟。
- `jti` 去重表的保留时间要大于允许偏差加有效期（参考实现保留 3 分钟）。多实例部署时，去重表要放在 Redis 等共享存储里，例如 `SET jti NX EX 180`。

### 2.5 背压与并发
- 每个 WebSocket 连接只能有一个写入者。各语言都需要加写锁或使用发送队列：Go 用 `sync.Mutex`；Node 的 `ws` 自带队列，但要关注 `bufferedAmount`；Python 用 `asyncio.Lock`；Rust 用 `mpsc` 通道。
- 每个任务的缓冲区要有上限。SSE 客户端跟不上时，取消任务或断开会话，**不要无限缓冲**。Node 中 `res.write` 返回 `false` 时要等待 `drain` 事件。
- 只要 HTTP 客户端断开，就必须发送 `task.cancel`：Node 监听 `req.on('close')`，Starlette 检查 `await request.is_disconnected()`，Go 监听 `r.Context().Done()`，Spring 用 `SseEmitter.onCompletion`/`onError`（注意：Servlet 容器通常只在写入失败时才发现客户端断开，等待设备期间要定期写 SSE 注释作保活，`sdk/java` 的 Spring 适配默认每 1 秒一次）。非流式请求在任务结束前不写任何字节，同样要主动检测断开（规范 §6.5）：`sdk/java` 在 Tomcat 上用一个 Valve 探测连接是否已关闭。

### 2.6 长度与 ASCII 头
- 字符串长度一律按 Unicode 码点计（规范 §4.1）：Go `utf8.RuneCountInString`，Node `[...s].length`，Python `len(s)`，Java `s.codePointCount(0, s.length())`，Rust `s.chars().count()`。不要用 JavaScript/Java 的 `.length`（UTF-16 码元）或字节数。
- `X-End-User`、`Idempotency-Key` 只接受可打印 ASCII（0x20–0x7E），其余返回 400。

### 2.7 反向代理
- Nginx 需要设置 `proxy_set_header Upgrade/Connection`、`proxy_read_timeout 75s`；SSE 需要 `proxy_buffering off`（或在响应头加 `X-Accel-Buffering: no`）。
- 如果代理对 `Sec-WebSocket-Protocol` 头做了改写或过滤，子协议协商会失败。

---

## 3. 最小网关实现步骤

1. **存储**：建四张表。
   - `tenants(id, api_key_sha256)`
   - `device_auth(device_code_sha256, user_code, tenant, public_key, status, expires_at, interval, last_poll, device_id, owner)`
   - `devices(id, tenant, owner, name, public_key, status, created_at)`
   - `tasks(id, tenant, owner, device_id, state, request_enc, …)`
2. **密钥**：从环境变量或 KMS 加载 32 字节的网关 Ed25519 种子，计算 `kid = RFC7638(pub)`。实现 `GET /.well-known/jwks.json`。
3. **`POST /lmbp/v1/device/authorize`**：解析表单参数，检查公钥是否为 32 字节，生成 `device_code`（只存哈希）和 `user_code`，返回结果并带上 `Cache-Control: no-store`。
4. **`POST /lmbp/v1/tenant/devices/approvals`**：用租户 Key 的哈希查出租户。在租户内按 `user_code` 查找待确认记录。确认后创建设备记录，归属 `X-End-User`。失败要计数限速。
5. **`POST /lmbp/v1/token`**：
   - device_code 授权：先验证证明，再看状态，最后标记为已使用（规范 §6.3 的顺序）；
   - jwt-bearer 授权：用设备公钥验证断言，并对 `jti` 去重。
   - 签发 `at+jwt`，内含 `cnf.jkt`。
6. **`GET /lmbp/v1/connect`**：
   1. 检查子协议：没有 `lmbp` 时返回 400 `VERSION_UNSUPPORTED`（子协议名不带版本；1.x 设备也带 `lmbp`，由 hello 的 `v` 拒绝）；
   2. 拒绝带 `Origin` 的请求；
   3. 验证访问令牌，并核对设备状态和 `cnf.jkt`；
   4. 升级连接，选择 `lmbp`；
   5. 15 秒内读取 `hello`，按规范 §7.4 的顺序检查：`v == 2` → `hello.json` 模式（`max_concurrency` 越界直接拒绝，不要截断）→ 证明（`ath` 绑定本次连接的令牌）→ 扩展语义；
   6. 回复 `welcome`，`capabilities` 取交集，`max_concurrency = min(声明值, 网关上限)`；
   7. 记录 `sessions[device_id]`，并关闭该设备的旧会话。
7. **读循环**：
   - `task.delta`/`task.done`/`task.error`：检查 `seq` 连续后，转发到任务通道；
   - `session.token`：验证后回复；
   - `models.update`：先按 `models.update.json` 校验，不合法就回复 `error BAD_REQUEST`、整帧不生效；
   - `ping`：回复 `pong`；
   - 其他类型、`v ≠ 2` 或无法解析的帧：回复 `error BAD_REQUEST`，但不断开；
   - 未知任务的数据帧、已在本地结束的任务的迟到帧：按规范 §8.6 的状态表处理（回复 `task.cancel unknown_task`，或照常确认）。
   - 定时发送 WebSocket ping，并检查令牌是否已过期超过 30 秒。
8. **`POST /v1/chat/completions`**：
   1. 认证租户；
   2. 解析模型路由；
   3. 检查设备并发；
   4. 构造 `task.run` 载荷，签名后发送 `{v:2,type:"task.run",task_id,seq:1,jws}`（`seq` 恒为 1，与是否协商 `resume`/`flow` 无关）；
   5. 把设备回报转换成 SSE；
   6. 客户端断开或超时时发送 `task.cancel`；
   7. 设备断线时任务失败（`DEVICE_OFFLINE`）。
9. **吊销**：把设备状态改为 `revoked`，并关闭在线会话。
10. **验证**：先跑测试向量，再执行 `lmbp-conformance -gateway http://localhost:PORT`，直到 138 项全部通过（E6 需加 `-retention`，否则记为跳过）。

---

## 4. 各语言关键代码片段

下面每种语言都覆盖四个关键点：**验证 hello**、**签发令牌**、**签名 task.run**、**输出 SSE 块**。

### 4.1 Python（已运行：`spec/examples/python/lmbp.py`）
```python
def verify_hello(gw_pub, device_pub_of, frame, access_token, aud="https://gw.example.com/tenants/acme", now=None):
    claims = verify_access_token(gw_pub, access_token, aud, now)          # typ=at+jwt, aud, exp/iat ±30s
    dev_pub = device_pub_of(claims["sub"])                                # 查库，且 status == active
    if claims.get("cnf", {}).get("jkt") != thumbprint(dev_pub):
        raise LmbpError("token not bound to this device key")
    if frame.get("v") != 2 or frame.get("type") != "hello" or frame["data"].get("device_id") != claims["sub"]:
        raise LmbpError("bad hello")
    verify_proof(dev_pub, frame["data"]["proof"], claims["sub"], "lmbp:hello", access_token, now)
    return claims   # 调用方还要对 proof 的 jti 去重

def issue_access_token(gw_key, kid, device_id, tenant, device_pub, ttl=900, now=None, jti=None):
    now = int(time.time()) if now is None else now
    claims = {"iss": issuer, "sub": device_id, "aud": f"{issuer}/tenants/{tenant}", "tenant": tenant, "iat": now,
              "exp": now + ttl, "jti": jti or "jti_" + secrets.token_hex(16), "cnf": {"jkt": thumbprint(device_pub)}}
    return sign_jws(gw_key, "at+jwt", json_bytes(claims), kid)

def sign_task_run(gw_key, kid, payload):
    return {"v": 2, "type": "task.run", "task_id": payload["task_id"], "seq": 1,
            "jws": sign_jws(gw_key, "lmbp-task+jws", json_bytes(payload), kid)}

def sse_chunk(task_id, model, created, text=None, finish=None):
    delta = {"content": text} if text is not None else {}
    obj = {"id": "chatcmpl-" + task_id, "object": "chat.completion.chunk", "created": created, "model": model,
           "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    return b"data: " + json_bytes(obj) + b"\n\n"
```
FastAPI 中接入 WebSocket（示意）：`await ws.accept(subprotocol="lmbp")`，在此之前先检查 `ws.headers["sec-websocket-protocol"]`、`Authorization` 以及是否带有 `Origin`。

### 4.2 Node.js（已运行：`spec/examples/node/lmbp.mjs`）
```js
export function verifyHello(gwPub, devicePubOf, frame, accessToken, { aud = 'https://gw.example.com/tenants/acme', now } = {}) {
  const claims = verifyAccessToken(gwPub, accessToken, aud, now);
  const devPub = devicePubOf(claims.sub);
  if (claims.cnf?.jkt !== thumbprint(devPub)) throw new Error('token not bound to device key');
  if (frame.v !== 2 || frame.type !== 'hello' || frame.data?.device_id !== claims.sub) throw new Error('bad hello');
  verifyProof(devPub, frame.data.proof, { iss: claims.sub, aud: 'lmbp:hello', credential: accessToken }, now);
  return claims;
}
export function issueAccessToken(gwKey, kid, { deviceId, tenant, devicePub, ttl = 900, now = Math.floor(Date.now() / 1000), jti }) {
  const claims = { iss: issuer, sub: deviceId, aud: `${issuer}/tenants/${tenant}`, tenant, iat: now, exp: now + ttl,
    jti: jti ?? `jti_${randomBytes(16).toString('hex')}`, cnf: { jkt: thumbprint(devicePub) } };
  return signJws(gwKey, 'at+jwt', jsonBytes(claims), kid);
}
export const signTaskRun = (gwKey, kid, payload) =>
  ({ v: 2, type: 'task.run', task_id: payload.task_id, seq: 1, jws: signJws(gwKey, 'lmbp-task+jws', jsonBytes(payload), kid) });
export async function writeSseChunk(res, { taskId, model, created, text, finish = null }) {
  const obj = { id: `chatcmpl-${taskId}`, object: 'chat.completion.chunk', created, model,
    choices: [{ index: 0, delta: text === undefined ? {} : { content: text }, finish_reason: finish }] };
  if (!res.write(`data: ${JSON.stringify(obj)}\n\n`)) await new Promise((r) => res.once('drain', r));
}
```
使用 `ws` 库接入（示意）：
```js
const wss = new WebSocketServer({ noServer: true, handleProtocols: (ps) => (ps.has('lmbp') ? 'lmbp' : false) });
server.on('upgrade', (req, sock, head) => {
  if (req.headers.origin) return sock.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  // 在这里验证 Authorization 中的令牌，失败时返回 401
  wss.handleUpgrade(req, sock, head, (ws) => onSession(ws, token));
});
```

### 4.3 Go（参考实现：`internal/lmbp`、`internal/lmbp/gateway`）
```go
// 验证 hello（gateway.go）
claims, err := lmbp.VerifyJWT(g.pub, tok, lmbp.TypAccessToken, Audience, time.Now())
// ……查设备，检查 status == active，且 claims.Cnf["jkt"] == lmbp.Thumbprint(dev.PublicKey)
pc, err := lmbp.VerifyProof(dev.PublicKey, hello.Proof, dev.ID, lmbp.ProofHello, tok, time.Now())
if err != nil || !g.useJTI(pc.Jti, time.Now().Add(3*time.Minute)) { /* error UNAUTHENTICATED，然后断开 */ }

// 签发令牌
c := lmbp.Claims{Iss: Issuer, Sub: d.ID, Aud: Audience, Tenant: d.TenantID, Iat: now.Unix(), Exp: now.Add(ttl).Unix(),
	Jti: lmbp.RandomID("jti_"), Cnf: map[string]string{"jkt": lmbp.Thumbprint(d.PublicKey)}}
at := lmbp.SignJWT(signingKey, lmbp.TypAccessToken, kid, c)

// 签名 task.run
jws := lmbp.SignTaskRun(signingKey, kid, lmbp.TaskRun{TaskID: id, Iat: now, Exp: now + 60, Nonce: lmbp.RandomID("n_"), DeviceID: dev, Model: m, Messages: msgs})
s.send(lmbp.Envelope{V: 2, Type: lmbp.TypeTaskRun, TaskID: id, JWS: jws})

// SSE
fmt.Fprintf(w, "data: %s\n\n", chunkJSON); w.(http.Flusher).Flush()
```

### 4.4 Rust（已运行：`spec/examples/rust/src/lib.rs`）
```rust
pub fn verify_hello(gw: &[u8], device_pub_of: impl Fn(&str) -> Vec<u8>, frame: &Value, token: &str, now: i64) -> Result<Value> {
    let c = verify_access_token(gw, token, &format!("{ISSUER}/tenants/acme"), now)?;
    let sub = c["sub"].as_str().ok_or("sub")?.to_string();
    let dev = device_pub_of(&sub);
    if c["cnf"]["jkt"] != thumbprint(&dev).as_str() { return Err("token not bound to device key".into()); }
    if frame["v"] != 2 || frame["type"] != "hello" || frame["data"]["device_id"] != sub.as_str() { return Err("bad hello".into()); }
    verify_proof(&dev, frame["data"]["proof"].as_str().ok_or("proof")?, &sub, "lmbp:hello", token, now)?;
    Ok(c)
}
pub fn issue_access_token(gw: &SigningKey, kid: &str, device_id: &str, tenant: &str, device_pub: &[u8], now: i64, ttl: i64, jti: &str) -> String {
    let c = json!({"iss":ISSUER,"sub":device_id,"aud":format!("{ISSUER}/tenants/{tenant}"),"tenant":tenant,"iat":now,"exp":now+ttl,"jti":jti,"cnf":{"jkt":thumbprint(device_pub)}});
    sign_jws(gw, TYP_ACCESS_TOKEN, c.to_string().as_bytes(), Some(kid))
}
pub fn sign_task_run(gw: &SigningKey, kid: &str, payload: &Value) -> Value {
    json!({"v":2,"type":"task.run","task_id":payload["task_id"],"seq":1,"jws":sign_jws(gw, TYP_TASK, payload.to_string().as_bytes(), Some(kid))})
}
pub fn sse_chunk(task_id: &str, model: &str, created: i64, text: &str) -> String {
    format!("data: {}\n\n", json!({"id":format!("chatcmpl-{task_id}"),"object":"chat.completion.chunk","created":created,"model":model,
        "choices":[{"index":0,"delta":{"content":text},"finish_reason":null}]}))
}
```
axum 接入（示意）：`ws.protocols(["lmbp"]).on_upgrade(...)`。升级前先从 `HeaderMap` 中验证令牌，并拒绝带 `Origin` 的请求。SSE 用 `Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))`。

### 4.5 Java（**示意，未编译**；JDK 17+，只用 JDK 自带的 EdDSA 与 Jackson）
```java
static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
static byte[] unb64(String s) {
  if (!s.matches("[A-Za-z0-9_-]*") || s.length() % 4 == 1) throw new IllegalArgumentException("base64url");
  return Base64.getUrlDecoder().decode(s);
}
// 由 32 字节种子得到私钥：PKCS#8 = 固定前缀 + 种子
static PrivateKey privFromSeed(byte[] seed) throws Exception {
  byte[] p = HexFormat.of().parseHex("302e020100300506032b657004220420");
  return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(p, seed)));
}
static PublicKey pubFromRaw(byte[] x) throws Exception {   // X.509 = 固定前缀 + 32 字节
  byte[] p = HexFormat.of().parseHex("302a300506032b6570032100");
  return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(p, x)));
}
static String thumbprint(byte[] x) throws Exception {
  String in = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + B64.encodeToString(x) + "\"}";
  return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(in.getBytes(UTF_8)));
}
static String signJws(PrivateKey k, String typ, String kid, byte[] payload) throws Exception {
  String h = kid == null ? "{\"alg\":\"EdDSA\",\"typ\":\"" + typ + "\"}" : "{\"alg\":\"EdDSA\",\"kid\":\"" + kid + "\",\"typ\":\"" + typ + "\"}";
  String in = B64.encodeToString(h.getBytes(UTF_8)) + "." + B64.encodeToString(payload);
  Signature s = Signature.getInstance("Ed25519"); s.initSign(k); s.update(in.getBytes(US_ASCII));
  return in + "." + B64.encodeToString(s.sign());
}
static JsonNode verifyJws(PublicKey pub, String jws, String typ) throws Exception {
  String[] p = jws.split("\\.", -1);
  if (p.length != 3) throw new SecurityException("malformed");
  JsonNode h = STRICT_MAPPER.readTree(unb64(p[0]));   // 开启 STRICT_DUPLICATE_DETECTION
  if (!"EdDSA".equals(h.path("alg").asText()) || !typ.equals(h.path("typ").asText()) || h.has("crit")) throw new SecurityException("header");
  Signature s = Signature.getInstance("Ed25519"); s.initVerify(pub); s.update((p[0] + "." + p[1]).getBytes(US_ASCII));
  if (!s.verify(unb64(p[2]))) throw new SecurityException("signature");
  return STRICT_MAPPER.readTree(unb64(p[1]));
}
// verifyHello：verifyJws(gw, token, "at+jwt") → 检查 aud/exp/iat → 查设备并比对 cnf.jkt
//              → verifyJws(dev, proof, "lmbp-proof+jwt") → 检查 aud="lmbp:hello"、iss、ath=b64(sha256(token))、|now-iat|≤60，并对 jti 去重
// signTaskRun：signJws(gwKey, "lmbp-task+jws", kid, mapper.writeValueAsBytes(payload))
// SSE（Spring MVC）：emitter.send(SseEmitter.event().data(chunkJson, MediaType.APPLICATION_JSON))；结束时 emitter.send("[DONE]")
```
接入 Spring WebSocket 时，在 `HandshakeInterceptor` 中验证令牌和 `Origin`，并在 `DefaultHandshakeHandler` 中选择子协议 `lmbp`（`setSupportedProtocols("lmbp")`）。**用 Java 实现前，请先把上面的函数对照 `vectors.json` 跑一遍**：要求签名逐字节一致，所有反例都被拒绝。

---

## 4.6 扩展：断线续传、流量控制、tools/多模态、端到端加密

规范见 lmbp-spec.md §14–§17；测试向量 `e2ee`、`flow`、`resume` 三节和 `valid_frames` 中的扩展帧覆盖全部密码学与判定细节。

### JWE / HPKE / X25519 推荐库

| 语言 | X25519 + AES-GCM（直接实现，推荐） | JOSE 库（可选） | 状态 |
|---|---|---|---|
| Python | `cryptography`（`X25519PrivateKey`、`AESGCM`） | `joserfc`、`jwcrypto` | 已运行：`spec/examples/python/lmbp_ext.py` |
| Node.js | `node:crypto`（`diffieHellman`、`aes-256-gcm`，Node ≥ 18） | `jose`（panva）`compactDecrypt` 并限定 `keyManagementAlgorithms:['ECDH-ES']` | 已运行：`spec/examples/node/lmbp_ext.mjs` |
| Rust | `x25519-dalek`（`static_secrets`）+ `aes-gcm` + `sha2` | `josekit` | 已运行：`spec/examples/rust/src/ext.rs` |
| Go | `crypto/ecdh`、`crypto/aes`+`cipher.NewGCM`（标准库） | `go-jose/v4` | 参考实现 `internal/lmbp/e2ee.go` |
| Java | JDK 11+ `KeyAgreement("X25519")`、`Cipher("AES/GCM/NoPadding")` | Nimbus JOSE+JWT（`X25519Decrypter`，需 Tink） | 未编写示例 |

HPKE（RFC 9180）在设计上更现代，但 2026 年各语言 JOSE 生态对 JOSE-HPKE 草案支持不一，故本协议选用 RFC 7518 ECDH-ES + A256GCM：Concat KDF 只是一轮 SHA-256（`00000001 ‖ Z ‖ len("A256GCM") ‖ "A256GCM" ‖ 0 ‖ 0 ‖ 00000100`），二十行内即可手写并用向量 `concat_kdf_input_hex`/`cek_b64url` 自检。

### 陷阱
- **JOSE 库默认算法过宽**：务必固定 `alg=ECDH-ES`、`enc=A256GCM`，拒绝 `zip`（压缩预言攻击）和 `ECDH-ES+A*KW`（向量 `jwe_key_wrap_alg`、`jwe_zip`）。
- **AAD 是受保护头的 base64url 字符串本身**（ASCII 字节），不是解码后的 JSON。
- **结果帧 nonce 由 seq 决定**：每个 `response_key` 只用于一个请求，否则 nonce 重复会彻底破坏 GCM。
- **E2EE 帧的 seq 必须先分配再封装**；重传时发送**同一字节**，不要重新加密（参考实现的 `Outbox.SendFunc` 要求 build 函数对 seq 确定性）。
- **流控字节数 = 发送的整条 WebSocket 文本消息长度**，包含信封；两侧必须一致，否则会误报 `FLOW_CONTROL`。
- **重连后先重传、后发新帧**：参考实现最初就因此出过一次丢帧（新帧在重传完成前写出导致接收端判定跳号）；现由 `Outbox` 在 `Attach` 后暂停任务直到 `Retransmit`。
- **网关只按最慢订阅者确认**，所以 SSE 写失败/阻塞会自然传导到设备，不要在网关内用无界队列“兜底”。
- **tools 增量**：`arguments` 是字符串分片，非流式响应需按 `index` 拼接；Ollama 的 `arguments` 是对象，需序列化。

## 5. 设备端（如果你也要实现）

设备端只需要以下几步：
1. 生成并保存 Ed25519 私钥（存入系统密钥库）；
2. 通过发现文档完成 RFC 8628 配对，每次轮询都用新的证明；
3. 用 jwt-bearer 断言换取令牌，建立 WSS 连接，发送 `hello`（附证明）；
4. 验证每个 `task.run`，依次检查 JWS、`task_id`、`device_id`、`exp`、`nonce`、模型允许列表和并发数；
5. 流式回报结果，`seq` 从 1 开始连续递增；
6. 在到期前通过 `session.token` 续期；
7. 断线后按指数退避重连；收到 `invalid_grant` 后停止，提示用户重新配对。

Go 设备端参考实现见 `internal/lmbp/client`。


## 网关身份绑定与配对同意（§18–§19）对接清单

**网关（任何语言）**
1. 配置 issuer = 对外 https origin（例如 `https://gw.example.com`），不要用主机名推导。
2. 访问令牌：`iss = issuer`，`aud = issuer + "/tenants/" + tenant`；验证时两项都要比对。设备断言的 `aud = issuer + "/lmbp/v1/token"`。
3. 提供 `GET /.well-known/lmbp`；带 `?tenant=` 时用 JWKS 中的 Ed25519 密钥签 `signed_metadata`（`typ: lmbp-metadata+jwt`，`kid` = RFC 7638 指纹），载荷是除 `signed_metadata` 外的全部字段，`exp - iat ≤ 24h`。结构见 `spec/schemas/gateway-metadata.json`。
4. 令牌响应带 `issuer`。

**设备（桌面端）**
1. 入口是深链接 `lmbp://pair?v=2&gateway=…&tenant=…`（`v=1` 的旧链接要明确拒绝），或 SaaS 地址 → `/.well-known/avora`。
2. 拉取元数据和 JWKS（必须同源），校验签名、issuer、tenant、audience、有效期；失败就不显示同意页。
3. 同意页显示 `saas.*`、网关 origin、请求的模型和作用域、密钥指纹。用户拒绝时不发任何请求，返回 `CONSENT_DENIED`。
4. 用户同意后才调用 `device_authorize`。令牌响应的 `gateway_key` 必须等于签名元数据的密钥。
5. 持久化 `issuer` 和 `audience`。之后每个令牌都要检查 `iss`、`aud`、`tenant`、`sub`、`cnf.jkt`，不符就停止连接。

**常见坑**
- issuer 末尾的 `/`、大写主机名、显式 `:443`：先按 §18.1 规范化，再比较。
- 网关在反向代理后面：issuer 填公网 origin；运行一致性测试时加 `-issuer`。
- 测试向量 `spec/testvectors/vectors.json` 的 `identity` 段包含：origin 规范化用例、签名元数据的正例和 7 个反例、深链接的正例和反例，以及一个“签名有效但 issuer 不同、必须拒绝”的令牌。
