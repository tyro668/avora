// Express SaaS example: the lmbp-server SDK mounted next to your own routes.
//
// What the business code does (and nothing else):
//   1. pairing   GET /app/pair → link + QR; POST /app/pair/approve {user_code}; devices list/revoke
//   2. LLM calls the official `openai` / `@anthropic-ai/sdk` clients with baseURL pointed at this
//                server, or the SDK's in-process client.
// Everything protocol-related (/lmbp/v1/*, /.well-known/*, /v1/*) is served by lmbp.middleware().
//
//   TENANT_API_KEY=$(openssl rand -hex 24) node server.mjs
import fs from 'node:fs';
import http from 'node:http';
import express from 'express';
import OpenAI from 'openai';
import Anthropic from '@anthropic-ai/sdk';
import { LMBPServer, SqliteStore, PairingError } from 'lmbp-server';

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
const tenant = process.env.TENANT_ID || 'acme';
const apiKey = process.env.TENANT_API_KEY;
if (!apiKey) throw new Error('set TENANT_API_KEY (>= 32 chars; server-side secret)');
const profile = process.env.TENANT_PROFILE_FILE ? JSON.parse(fs.readFileSync(process.env.TENANT_PROFILE_FILE, 'utf8'))[tenant]
  : { display_name: 'Acme Chat (Express)', requested_scopes: ['lmbp.chat', 'lmbp.tools', 'lmbp.vision'] };

// The gateway's public origin (iss of every token): configuration, never the request's Host header.
const issuer = process.env.LMBP_ISSUER || (host === '127.0.0.1' || host === 'localhost' ? `http://${host}:${port}` : '');
if (!issuer) throw new Error('set LMBP_ISSUER (e.g. https://saas.example.com)');
const lmbp = new LMBPServer({
  tenants: [{ id: tenant, apiKey, profile }],
  issuer,
  store: process.env.LMBP_DB ? new SqliteStore(process.env.LMBP_DB) : undefined,
  // finished tasks + idempotency records: 7 days unless set (negative disables)
  retention: process.env.LMBP_RETENTION_SECONDS ? Number(process.env.LMBP_RETENTION_SECONDS) * 1000 : undefined,
});

const app = express();
app.use(lmbp.middleware());            // protocol endpoints + /v1/chat/completions, /v1/models, /v1/messages
app.use(express.json());

// Your own login decides who the end user is. Demo: a header.
const user = (req) => req.get('x-demo-user') || 'demo-user';

// ---- 1. pairing ----
app.get('/app/pair', (req, res) => res.json(lmbp.pairing.create(tenant)));
app.post('/app/pair/approve', (req, res) => {
  try { res.json(lmbp.pairing.approve(tenant, user(req), req.body.user_code)); } catch (e) {
    if (e instanceof PairingError) return res.status(e.code === 'NOT_FOUND' ? 404 : 400).json({ error: e.message });
    throw e;
  }
});
app.get('/app/devices', (req, res) => res.json(lmbp.pairing.listDevices(tenant, user(req))));
app.post('/app/devices/:id/revoke', (req, res) => res.json({ revoked: lmbp.pairing.revokeDevice(tenant, user(req), req.params.id) }));

// ---- 2. LLM calls with the official clients, unchanged ----
const openai = new OpenAI({ baseURL: `http://127.0.0.1:${port}/v1`, apiKey });
const claude = new Anthropic({ baseURL: `http://127.0.0.1:${port}`, apiKey });

app.post('/app/ask', async (req, res, next) => {
  try {
    const r = await openai.chat.completions.create({ model: req.body.model, messages: [{ role: 'user', content: req.body.prompt }] },
      { headers: { 'X-End-User': user(req) } });
    res.json({ answer: r.choices[0].message.content });
  } catch (e) { next(e); }
});
app.post('/app/ask/claude', async (req, res, next) => {
  try {
    const m = await claude.messages.create({ model: req.body.model, max_tokens: 512, messages: [{ role: 'user', content: req.body.prompt }] },
      { headers: { 'X-End-User': user(req) } });
    res.json({ answer: m.content.filter((b) => b.type === 'text').map((b) => b.text).join('') });
  } catch (e) { next(e); }
});
// ...or without an HTTP hop:
app.post('/app/ask/inprocess', async (req, res, next) => {
  try {
    const m = await lmbp.client(tenant, user(req)).messages.create({ model: req.body.model, max_tokens: 512, messages: [{ role: 'user', content: req.body.prompt }] });
    res.json({ answer: m.content.filter((b) => b.type === 'text').map((b) => b.text).join('') });
  } catch (e) { next(e); }
});
app.use((err, _req, res, _next) => res.status(err.status || 500).json({ error: err.message }));

const server = http.createServer(app);
lmbp.attach(server);                   // WebSocket upgrades for /lmbp/v1/connect
server.listen(port, host, () => console.error(`express example on http://${host}:${port} (tenant ${tenant})`));
