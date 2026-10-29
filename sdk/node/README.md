# lmbp-server：LMBP 服务端 Node.js SDK

让你的 SaaS 后端使用**用户自己电脑上的模型**（经 Avora 桌面端）。业务代码只做两件事：

1. **配对**：展示配对链接 / 二维码，批准用户在桌面端看到的配对码；
2. **调用模型**：标准 OpenAI（`/v1/chat/completions`、`/v1/models`）或 Anthropic（`/v1/messages`）请求，直接用官方 `openai` / `@anthropic-ai/sdk`，或用 SDK 的进程内客户端。

WebSocket 会话、JOSE、续传、流控、大图分块、E2EE 透传全部在 SDK 内部。TypeScript 编写，ESM，自带类型声明。需要 Node ≥ 18.17。

> **成熟度**：本 SDK 是 LMBP 网关的**独立重新实现**，不与 Go 参考网关共享代码，存在真实的行为差异。例如 JWKS 返回 `application/json`（Go 为 `application/jwk-set+json`）；`Store` 接口是同步的；默认参数和时间单位（毫秒）也不同。
> 通过共享 Schema、测试向量和 `lmbp-conformance` 不等于符合规范，只说明在被检查的点上一致；见[各实现与成熟度](../../docs/implementations.md)。

## 安装

```bash
npm install lmbp-server            # 仓库内：npm install ../../sdk/node
npm install better-sqlite3         # 可选：SqliteStore
```

## 快速开始（Express）

```js
import http from 'node:http';
import express from 'express';
import { LMBPServer, SqliteStore, PairingError } from 'lmbp-server';

const lmbp = new LMBPServer({
  tenants: [{ id: 'acme', apiKey: process.env.TENANT_API_KEY, profile: { display_name: 'Acme CRM' } }],
  issuer: 'https://saas.example.com',    // 必填：网关公网 origin，绝不从请求 Host 推导
  store: new SqliteStore('lmbp.db'),     // 默认 MemoryStore
});

const app = express();
app.use(lmbp.middleware());               // 协议路径 + /v1/*，其余 next()
app.use(express.json());
// 1. 配对
app.get('/app/pair', (req, res) => res.json(lmbp.pairing.create('acme')));   // { link, qrSVG, qrDataURL }
app.post('/app/pair/approve', (req, res) => res.json(lmbp.pairing.approve('acme', req.user.id, req.body.user_code)));
// 2. 调用模型
app.post('/app/ask', async (req, res) => {
  const c = lmbp.client('acme', req.user.id);
  const [m] = await c.models();
  const msg = await c.messages.create({ model: m.id, max_tokens: 512, messages: [{ role: 'user', content: req.body.prompt }] });
  res.json(msg);
});

const server = http.createServer(app);
lmbp.attach(server);                      // /lmbp/v1/connect 的 WebSocket 升级
server.listen(3000);
```

完整示例：[`examples/express/server.mjs`](../../examples/express/server.mjs)。

其他框架：

- 原生 `node:http`：`http.createServer(lmbp.handler)` 后 `lmbp.attach(server)`，或直接 `await lmbp.listen(8080)`。
- Fastify：`await app.register(lmbp.fastifyPlugin)`（自动注册路由和 WebSocket 升级）。
- Koa / Connect 等：使用 `lmbp.middleware()`，或按 `PATHS` 显式转发到 `lmbp.handler`。

## API

| 分类 | API |
|---|---|
| 构造 | `new LMBPServer({ tenants, issuer, store, signingSeed, maxConcurrency, chatUIDir, log, tuning })` |
| 挂载 | `handler`、`middleware()`、`fastifyPlugin`、`attach(server)`、`listen(port, host)`、`close()`、`PATHS` |
| 密钥 | `keys.kid()`、`keys.publicJWK()`、`keys.jwks()`；`LMBPServer.generateSigningSeed()`、`LMBPServer.generateTenantKey()`。未传 `signingSeed` 时种子保存在 Store 中 |
| 配对 | `pairing.link(tenant)`、`pairing.create(tenant) → { link, qrSVG, qrDataURL }`、`pairing.lookup(tenant, user, code)`、`pairing.approve(tenant, user, code, { jkt })`、`pairing.deny(...)`、`pairing.listDevices(tenant, user)`、`pairing.revokeDevice(tenant, user, id)`；失败抛 `PairingError`（`code`：`BAD_REQUEST` / `NOT_FOUND` / `FORBIDDEN` / `RATE_LIMITED`；每个最终用户每分钟 10 次错误码后锁定，`lookup` 与 HTTP 批准接口共用计数；`deviceName` 是设备自报名称，只能按纯文本显示并标注来源） |
| 进程内客户端 | `client(tenant, user)` → `models()`、`chat.completions.create/stream`、`messages.create/stream`（`stream` 返回 `LMBPStream`：async iterable，`lastEventId` 是续传游标，`taskId` 是任务 ID；选项 `signal`、`idempotencyKey`、`lastEventId`；`chat.completions.resume(taskId, lastEventId)` 接着读）；失败抛 `LMBPAPIError{status, code}`；终止符（`[DONE]`/`message_stop`）前流就结束则抛 `IncompleteStreamError{code: 'INCOMPLETE_STREAM', taskId, lastEventId}`，用其游标续传 |
| E2EE | `sealE2EERequest(device, pinnedJkt, { model, messages })` → `{ jwe, rid, open(frame) }`；请求用 `{ model, lmbp_e2ee: sealed.jwe }`，响应帧 `chunk.lmbp_e2ee` 依次交给 `const rd = sealed.reader()` 的 `rd.next()` 解密（要求 seq 连续递增、`task.done` 之后不再有帧），结束时调用 `rd.finish()`（缺少密封 `task.done` 即视为截断并抛错），再用 `decodeE2EEDelta()` 解析 `task.delta`。`sealed.open()` 只校验单帧，无法发现重排、重复、丢帧或截断。`device` 来自 `listDevices()`（带 `publicKey`、`e2eeKey`） |
| 存储 | `MemoryStore`、`SqliteStore(path \| db)`（better-sqlite3）；自定义存储实现 `Store` 接口（同步方法） |
| 工具 | `anthropic.*`：Anthropic ↔ OpenAI 请求/响应转换函数 |

## 官方客户端原样可用

```js
const openai = new OpenAI({ baseURL: 'https://saas.example.com/v1', apiKey: TENANT_API_KEY, defaultHeaders: { 'X-End-User': userId } });
const claude = new Anthropic({ baseURL: 'https://saas.example.com', apiKey: TENANT_API_KEY, defaultHeaders: { 'X-End-User': userId } });
```

模型 ID 形如 `dev_xxx/qwen3-8b`，从 `models()` 获取。

## 测试

```bash
cd sdk/node && npm test                              # SDK 单元测试（协议、配对、存储、框架、进程内客户端）
scripts/mock-interop.sh node node-sqlite express     # lmbp-conformance + 连接器端到端 + 官方客户端
```

## 限制

- 尚无 Redis 存储（Store 接口为同步，Redis 客户端为异步）；存储为单实例。
- `/v1/messages` 不支持 E2EE。
- Anthropic 模型列表的 `display_name`、`created_at` 为占位值。
