# Node.js LMBP 模拟网关

`gateway.mjs` 是 LMBP（[docs/lmbp-spec.md](../../docs/lmbp-spec.md)）网关的 Node.js 命令行外壳：协议实现全部在服务端 SDK [`sdk/node`](../../sdk/node/README.md)（包名 `lmbp-server`）里，这里只解析参数、注册租户并调用 `new LMBPServer(...).listen()`。可替代 Go 参考网关给连接器、SaaS 后端或其他语言实现做互通测试。

## 运行

> 一键启动（假模型 + 网关 + 聊天页，并打印登录信息和配对命令）：`scripts/mock-start.sh node`，停止用 `scripts/mock-stop.sh`。详见 [mock/README.md](../README.md)。

```bash
cd mock/node
npm ci                      # 通过 file:../../sdk/node 引用 SDK，会自动构建
export LMBP_TENANT_KEY_ACME=$(openssl rand -hex 24)   # 租户 API Key（≥ 32 字符）
export LMBP_SIGNING_SEED=$(openssl rand -hex 32)     # 可选：固定网关签名密钥
node gateway.mjs --listen 127.0.0.1:8080 --tenant acme:LMBP_TENANT_KEY_ACME
# 或带 SaaS 展示身份（同意页显示的名称、链接、请求的模型与作用域）：
node gateway.mjs --listen 127.0.0.1:8080 --tenant-profiles ../tenant-profiles.example.json
```

| 参数 / 环境变量 | 说明 |
|---|---|
| `--listen` / `LMBP_LISTEN` | 监听地址，默认 `127.0.0.1:8080` |
| `--issuer` / `LMBP_ISSUER` | 网关 issuer origin（https；回环地址可用 http）。不设置时：`--listen` 为回环地址则用 `http://<listen>`，否则拒绝启动；issuer 从不取自请求 Host |
| `--tenant id:ENV` | 注册租户，API Key 从环境变量读取（可重复） |
| `--tenant-profiles F` / `LMBP_TENANT_PROFILES` | 租户 JSON 文件，格式见 `../tenant-profiles.example.json` |
| `LMBP_SIGNING_SEED` | 32 字节十六进制 Ed25519 种子；不设置则每次启动随机生成 |
| `--db FILE` / `LMBP_DB` | 用 SQLite（better-sqlite3）持久化配对、设备、任务与签名密钥；默认内存 |
| `--max-concurrency` | 每设备并发上限，默认 16 |
| `--web-dir` / `LMBP_WEB_DIR` | 聊天页目录，默认 `../web`；在 `/` 与 `/chat` 提供，见 [../web/README.md](../web/README.md) |
| `--no-chat-ui` | 不提供聊天页 |

Docker：

```bash
docker build -f mock/node/Dockerfile -t lmbp-mock-node .   # 在仓库根目录构建，镜像内含聊天页
docker run --rm -p 8080:8080 -e LMBP_TENANT_KEY_ACME -e LMBP_SIGNING_SEED lmbp-mock-node \
  --issuer http://127.0.0.1:8080 --tenant acme:LMBP_TENANT_KEY_ACME
```

连接 Go 连接器：`avora connector -pair-link 'lmbp://pair?v=2&gateway=http://127.0.0.1:8080&tenant=acme' ...`，然后用租户 Key 调用 `POST /lmbp/v1/tenant/devices/approvals` 批准显示的配对码（或直接打开本网关自带的聊天页 http://127.0.0.1:8080/chat ，见 [../web/README.md](../web/README.md)）。

单元测试：`npm test`（聊天页与 CSP）；协议单元测试在 `sdk/node`（`cd sdk/node && npm test`）。

## 代码结构

- `gateway.mjs`：CLI（参数、租户文件、`SqliteStore`），约 60 行。
- 协议引擎、Store、配对 API、OpenAI/Anthropic 兼容层：见 [`sdk/node`](../../sdk/node/README.md)。

## 功能

与 Go 参考网关行为一致（差异见 [docs/implementations.md](../../docs/implementations.md)）。协议能力和 API 见 [`sdk/node`](../../sdk/node/README.md)，接口细节以 [规范](../../docs/lmbp-spec.md) 为准。默认状态在内存中，重启后需重新配对；加 `--db` 后持久化到 SQLite。

## 验证

```bash
# 在仓库根目录：对 Node、Python 和 Go 参考网关分别跑 lmbp-conformance 和 Go 连接器端到端测试
scripts/mock-interop.sh node node-sqlite python python-sqlite go sdk-go
```

端到端测试（`mock/external`）用真实的桌面连接器通过 `lmbp://pair` 链接配对（校验签名元数据、本地拒绝、SaaS 拒绝），再跑流式对话、tools、40 KiB 图片、E2EE、本地审计日志和吊销。
