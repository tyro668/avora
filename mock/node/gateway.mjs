#!/usr/bin/env node
// LMBP mock SaaS gateway (Node.js): a thin CLI over the lmbp-server SDK
// (sdk/node). All protocol behaviour lives in the SDK; this file only parses
// flags, registers tenants and serves the shared chat page (mock/web).
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { LMBPServer, SqliteStore } from 'lmbp-server';
import { Gateway } from 'lmbp-server/engine';

export { Gateway, LMBPServer };

// loopbackIssuer is the default issuer for a loopback --listen address; any
// other address needs an explicit --issuer (spec §18.1).
function loopbackIssuer(listen) {
  const i = listen.lastIndexOf(':');
  const h = listen.slice(0, i).replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || /^127\./.test(h)) return `http://${listen}`;
  console.error(`--issuer (or LMBP_ISSUER) is required when listening on ${listen}`);
  process.exit(2);
}

async function main() {
  const { values: o } = parseArgs({ options: {
    listen: { type: 'string', default: process.env.LMBP_LISTEN || '127.0.0.1:8080' },
    issuer: { type: 'string', default: process.env.LMBP_ISSUER || '' },
    tenant: { type: 'string', multiple: true, default: [] },
    'tenant-profiles': { type: 'string', default: process.env.LMBP_TENANT_PROFILES || '' },
    'signing-key-env': { type: 'string', default: 'LMBP_SIGNING_SEED' },
    'max-concurrency': { type: 'string', default: '16' },
    db: { type: 'string', default: process.env.LMBP_DB || '' },
    'retention-seconds': { type: 'string', default: process.env.LMBP_RETENTION_SECONDS || '' },
    'web-dir': { type: 'string', default: process.env.LMBP_WEB_DIR || new URL('../web', import.meta.url).pathname },
    'no-chat-ui': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h' },
  } });
  if (o.help) {
    console.log(`usage: node gateway.mjs [--listen host:port] [--issuer https://gw.example] [--tenant id:ENV_VAR]... [--tenant-profiles profiles.json] [--db lmbp.db]
  --issuer URL          public origin of the gateway (LMBP_ISSUER); required unless --listen is a loopback address,
                        where it defaults to http://<listen>. Never derived from a request's Host header.
  --tenant id:ENV       register tenant <id> whose API key (>= 32 chars) is read from env var ENV
  --tenant-profiles F   JSON {"<tenant>": {"api_key_env": "...", "display_name": "...", "requested_scopes": [...], ...}}
  --db FILE             persist state in SQLite (better-sqlite3); default in memory
  --retention-seconds N keep finished tasks and idempotency records N seconds (default 7 days; negative disables)
  --web-dir DIR         directory with the shared chat page (default ../web); served at / and /chat
  --no-chat-ui          do not serve the chat page
  LMBP_SIGNING_SEED     hex Ed25519 seed (32 bytes); ephemeral key if unset`);
    return;
  }
  const seedHex = process.env[o['signing-key-env']];
  if (!seedHex && !o.db) console.error('warning: no signing key; using an ephemeral key (tokens do not survive restarts)');
  const tenants = [];
  for (const t of o.tenant) {
    const [id, env] = t.split(':');
    if (!process.env[env]) throw new Error(`tenant ${id}: env ${env} is empty`);
    tenants.push({ id, apiKey: process.env[env] });
  }
  if (o['tenant-profiles']) {
    for (const [id, p] of Object.entries(JSON.parse(fs.readFileSync(o['tenant-profiles'], 'utf8')))) {
      const key = process.env[p.api_key_env || ''];
      if (!key) throw new Error(`tenant ${id}: api_key_env ${p.api_key_env} is empty`);
      tenants.push({ id, apiKey: key, profile: p });
    }
  }
  if (!tenants.length) console.error('warning: no tenants registered (use --tenant id:ENV_VAR)');
  const lmbp = new LMBPServer({ tenants, issuer: o.issuer || loopbackIssuer(o.listen), signingSeed: seedHex ? Buffer.from(seedHex, 'hex') : undefined,
    maxConcurrency: Number(o['max-concurrency']), chatUIDir: o['no-chat-ui'] ? '' : o['web-dir'], store: o.db ? new SqliteStore(o.db) : undefined,
    retention: o['retention-seconds'] ? Number(o['retention-seconds']) * 1000 : undefined });
  const i = o.listen.lastIndexOf(':');
  const addr = await lmbp.listen(Number(o.listen.slice(i + 1)), o.listen.slice(0, i) || '0.0.0.0');
  console.error(`lmbp node mock gateway listening on ${addr.address}:${addr.port} issuer=${lmbp.engine.cfg.issuer} kid=${lmbp.keys.kid()}`);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('gateway.mjs')) main().catch((e) => { console.error(e.message); process.exit(1); });
