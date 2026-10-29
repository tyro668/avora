# lmbp-server：LMBP 服务端 Python SDK（ASGI）

让你的 SaaS 后端使用**用户自己电脑上的模型**（经 Avora 桌面端）。业务代码只做两件事：

1. **配对**：展示配对链接 / 二维码，批准用户在桌面端看到的配对码；
2. **调用模型**：标准 OpenAI（`/v1/chat/completions`、`/v1/models`）或 Anthropic（`/v1/messages`）请求，直接用官方 `openai` / `anthropic` 包，或用 SDK 的异步进程内客户端。

WebSocket 会话、JOSE、续传、流控、大图分块、E2EE 透传全部在 SDK 内部。纯 ASGI（不依赖 aiohttp），带类型标注（`py.typed`）。需要 Python ≥ 3.10。

> **成熟度**：本 SDK 是 LMBP 网关的**独立重新实现**（纯 ASGI，自带 HTTP/SSE 渲染），不与 Go 参考网关共享代码，存在真实的行为差异。例如 `Store` 是同步 Protocol，时间参数以秒为单位，WebSocket 依赖 uvicorn 的 `websockets` 实现。
> 通过共享 Schema、测试向量和 `lmbp-conformance` 不等于符合规范，只说明在被检查的点上一致；见[各实现与成熟度](../../docs/implementations.md)。

## 安装

```bash
pip install lmbp-server[server]          # 仓库内：pip install -e sdk/python[server]
```

运行时依赖只有 `cryptography` 与 `segno`（二维码）；`[server]` 附带 uvicorn。uvicorn 请使用 `--ws websockets`，这样 WebSocket 握手被拒时能返回 401/403。

## 快速开始（FastAPI）

```python
from fastapi import FastAPI
from lmbp_server import LMBPServer, LMBPMiddleware, SQLiteStore, TenantConfig

lmbp = LMBPServer(
    tenants=[TenantConfig("acme", os.environ["TENANT_API_KEY"], {"display_name": "Acme CRM"})],
    issuer="https://saas.example.com",       # 必填：网关公网 origin，绝不从请求 Host 推导
    store=SQLiteStore("lmbp.db"),            # 默认 MemoryStore
)
app = FastAPI()
app.add_middleware(LMBPMiddleware, server=lmbp)   # 协议路径 + /v1/*，其余交给 FastAPI

@app.get("/app/pair")                            # 1. 配对
def pair():
    info = lmbp.pairing.create("acme")            # info.link / info.qr_svg
    return {"link": info.link, "qr_svg": info.qr_svg}

@app.post("/app/pair/approve")
def approve(body: dict, user=Depends(current_user)):
    return lmbp.pairing.approve("acme", user.id, body["user_code"])

@app.post("/app/ask")                            # 2. 调用模型
async def ask(body: dict, user=Depends(current_user)):
    c = lmbp.client("acme", user.id)
    model = (await c.models())[0]["id"]
    return await c.messages.create(model=model, max_tokens=512, messages=[{"role": "user", "content": body["prompt"]}])
```

```bash
uvicorn app:app --ws websockets
```

完整示例：[`examples/fastapi/app.py`](../../examples/fastapi/app.py)。

其他框架：任何 ASGI 应用都可以用 `lmbp.asgi(app)` 包一层（未知路径交给 `app`），或用 `LMBPMiddleware`（Starlette / FastAPI）；独立运行用 `lmbp.run(host, port)`。

## API

| 分类 | API |
|---|---|
| 构造 | `LMBPServer(tenants, issuer, store=None, signing_seed=None, max_concurrency=16, chat_ui_dir="", log=None, **tuning)`；租户可为 `TenantConfig` 或 dict |
| 挂载 | `asgi(app=None)`、`LMBPMiddleware(app, server=...)`、`run(host, port, app=None)` |
| 密钥 | `keys.kid()`、`keys.public_jwk()`、`keys.jwks()`；`LMBPServer.generate_signing_seed()`、`LMBPServer.generate_tenant_key()`。未传 `signing_seed` 时种子保存在 Store 中 |
| 配对 | `pairing.link(tenant)`、`pairing.create(tenant) → PairingInfo(link, qr_svg)`、`pairing.lookup(tenant, end_user, code) → PendingPairing \| None`、`pairing.approve(tenant, user, code, jkt=None) → ApproveResult`、`pairing.deny(...)`、`pairing.list_devices(tenant, user) → list[DeviceInfo]`、`pairing.revoke_device(tenant, user, id)`；失败抛 `PairingError`（`code`：`BAD_REQUEST` / `NOT_FOUND` / `FORBIDDEN` / `RATE_LIMITED`；每个最终用户每分钟 10 次错误码后锁定，`lookup` 与 HTTP 批准接口共用计数；`device_name` 是设备自报名称，只能按纯文本显示并标注来源） |
| 进程内客户端 | `client(tenant, user)` → `await models()`、`await chat.completions.create(**req)`、`async for chunk in chat.completions.stream(**req)`、`messages.create / stream`（均支持 `idempotency_key=`；`stream` 返回 `LMBPStream`，`last_event_id` 是续传游标，`task_id` 是任务 ID，还支持 `last_event_id=`；`chat.completions.resume(task_id, last_event_id)` 接着读）；失败抛 `LMBPAPIError(status, code)`；终止符（`[DONE]`/`message_stop`）前流就结束则抛 `IncompleteStreamError`（`code="INCOMPLETE_STREAM"`、`task_id`、`last_event_id`），用其游标续传 |
| E2EE | `seal_e2ee_request(device, pinned_jkt, {"model", "messages"})` → `E2EESealed(jwe, rid, response_key)`；请求用 `lmbp_e2ee=sealed.jwe`，响应帧 `chunk["lmbp_e2ee"]` 依次交给 `rd = sealed.reader()` 的 `rd.next()` 解密（要求 seq 连续递增、`task.done` 之后不再有帧），结束时调用 `rd.finish()`（缺少密封 `task.done` 即视为截断并抛错），再用 `decode_e2ee_delta()` 解析 `task.delta`。`sealed.open()` 只校验单帧，无法发现重排、重复、丢帧或截断。`device` 来自 `list_devices()`（带 `public_key`、`e2ee_key`） |
| 存储 | `MemoryStore()`、`SQLiteStore(path)`（标准库 sqlite3）；自定义存储实现 `Store` Protocol（同步方法） |
| 工具 | `lmbp_server.anthropic`：Anthropic ↔ OpenAI 转换函数 |

## 官方客户端原样可用

```python
openai = OpenAI(base_url="https://saas.example.com/v1", api_key=TENANT_API_KEY, default_headers={"X-End-User": user_id})
claude = Anthropic(base_url="https://saas.example.com", api_key=TENANT_API_KEY, default_headers={"X-End-User": user_id})
```

模型 ID 形如 `dev_xxx/qwen3-8b`，从 `models()` 获取。

## 测试

```bash
cd sdk/python && python3 -m venv .venv && .venv/bin/pip install -e '.[test]' && .venv/bin/pytest
scripts/mock-interop.sh python python-sqlite fastapi   # lmbp-conformance + 连接器端到端 + 官方客户端
```

## 限制

- 尚无 Redis 存储；存储为单实例（单进程 uvicorn worker）。
- uvicorn 的 `websockets` 实现已被标记为弃用，但目前只有它支持握手阶段返回 HTTP 响应。
- `/v1/messages` 不支持 E2EE；Anthropic 模型列表的 `display_name`、`created_at` 为占位值。
