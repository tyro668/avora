// SDK consistency review (2026-10, main@52f48ae): behaviours that diverged
// from the Go reference gateway. Each test drives the real HTTP surface.
//   P2-1 retention: finished tasks and their Idempotency-Key records are purged
//        (default 7 days); a replay after the purge runs again.
//   P2-2 a model the named online device does not declare is 404, not 503.
//   P3-1 every JSON response carries Cache-Control: no-store.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { LMBPServer, MemoryStore, SqliteStore } from '../dist/index.js';
import { RETENTION_DEFAULT, retentionEvery } from '../dist/engine/gateway.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const hasSqlite = (() => { try { createRequire(import.meta.url)('better-sqlite3'); return true; } catch { return false; } })();

async function rig(opts = {}) {
  const runs = [];
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {}, ...opts });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const { ws, deviceId } = await pairAndConnect(lmbp, base, 'acme', 'u1', { onRun: (r) => runs.push(r.task_id) });
  const call = (p, body, hdr = {}) => fetch(base + p, { method: body ? 'POST' : 'GET', body: body && JSON.stringify(body),
    headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', ...hdr } });
  const close = async () => { ws.close(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); await lmbp.close(); };
  return { lmbp, base, deviceId, runs, call, close };
}

for (const kind of ['memory', 'sqlite']) {
  test(`retention (${kind}): a keyed task is purged with its idempotency record; the replay runs again`, { skip: kind === 'sqlite' && !hasSqlite }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-ret-'));
    const store = kind === 'memory' ? new MemoryStore() : new SqliteStore(path.join(dir, 'x.db'));
    const r = await rig({ store, retention: 60_000 });
    try {
      const body = { model: `${r.deviceId}/m1`, messages: [{ role: 'user', content: 'keep me' }] };
      const hdr = { 'Idempotency-Key': 'ret-1' };
      const a = await (await r.call('/v1/chat/completions', body, hdr)).json();
      const b = await (await r.call('/v1/chat/completions', body, hdr)).json();
      assert.equal(r.runs.length, 1, 'the immediate replay re-attached');
      assert.equal(b.id, a.id);
      const taskID = r.runs[0];
      assert.equal(r.lmbp.engine.purge(Date.now()), 0, 'nothing is older than the retention yet');
      assert.ok(store.getIdempotency('acme', 'u1', 'ret-1'));
      assert.equal(r.lmbp.engine.purge(Date.now() + 61_000), 1, 'the finished task is purged after the retention');
      assert.equal(store.getTask(taskID), undefined, 'task survived the purge');
      assert.equal(store.getIdempotency('acme', 'u1', 'ret-1'), undefined, 'idempotency record survived its task');
      const c = await r.call('/v1/chat/completions', body, hdr);
      assert.equal(c.status, 200);
      assert.equal(r.runs.length, 2, 'the replay after the purge did not run again');
      assert.notEqual(r.runs[1], taskID);
    } finally { await r.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
}

test('retention: defaults to 7 days, negative disables, and the timer purges on its own', async () => {
  assert.equal(RETENTION_DEFAULT, 7 * 24 * 3600_000);
  assert.equal(retentionEvery(RETENTION_DEFAULT), 3600_000);
  assert.equal(retentionEvery(2000), 1000);
  const lmbpPort = await freePort();
  const off = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY }], log: () => {}, retention: -1 });
  assert.equal(off.engine.retentionTimer, undefined, 'negative retention still schedules purges');
  await off.close();
  const r = await rig({ retention: 1500 });
  try {
    const body = { model: `${r.deviceId}/m1`, messages: [{ role: 'user', content: 'timer' }] };
    await (await r.call('/v1/chat/completions', body, { 'Idempotency-Key': 'ret-timer' })).json();
    assert.equal(r.lmbp.engine.cfg.retention, 1500);
    await new Promise((ok) => setTimeout(ok, 3500));
    assert.equal(r.lmbp.store.getIdempotency('acme', 'u1', 'ret-timer'), undefined, 'timer did not purge');
  } finally { await r.close(); }
});

test('a model the named online device does not declare is 404 MODEL_NOT_FOUND; an offline device stays 503', async () => {
  const r = await rig();
  try {
    let res = await r.call('/v1/chat/completions', { model: `${r.deviceId}/nope`, messages: [{ role: 'user', content: 'x' }] });
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error.code, 'MODEL_NOT_FOUND');
    res = await r.call('/v1/messages', { model: `${r.deviceId}/nope`, max_tokens: 5, messages: [{ role: 'user', content: 'x' }] }, { 'Anthropic-Version': '2023-06-01' });
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error.type, 'not_found_error');
    for (const ds of r.lmbp.engine.devs.values()) ds.drop('DEVICE_OFFLINE', 'test');
    r.lmbp.engine.devs.clear();
    res = await r.call('/v1/chat/completions', { model: `${r.deviceId}/nope`, messages: [{ role: 'user', content: 'x' }] });
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error.code, 'DEVICE_OFFLINE');
  } finally { await r.close(); }
});

test('every JSON response carries Cache-Control: no-store (discovery documents keep their own policy)', async () => {
  const r = await rig();
  try {
    const got = {};
    got.models = (await r.call('/v1/models')).headers.get('cache-control');
    got.devices = (await r.call('/lmbp/v1/tenant/devices')).headers.get('cache-control');
    got.chat = (await r.call('/v1/chat/completions', { model: `${r.deviceId}/m1`, messages: [{ role: 'user', content: 'x' }] })).headers.get('cache-control');
    got.error = (await r.call('/v1/chat/completions', { model: `${r.deviceId}/m1`, messages: [] })).headers.get('cache-control');
    got.unauth = (await fetch(r.base + '/v1/models')).headers.get('cache-control');
    got.healthz = (await fetch(r.base + '/healthz')).headers.get('cache-control');
    for (const [k, v] of Object.entries(got)) assert.equal(v, 'no-store', `${k}: Cache-Control ${v}`);
    assert.equal((await fetch(r.base + '/.well-known/jwks.json')).headers.get('cache-control'), 'public, max-age=300');
  } finally { await r.close(); }
});
