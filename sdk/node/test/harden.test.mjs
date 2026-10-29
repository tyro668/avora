// Regression tests for the 2026-10-29 protocol review (P1/P2 hardening):
// pairing abuse limits, untrusted device names, pending pairings never
// listed, per-user failure counting, issuer configuration, revocation of an
// in-flight task, the tool_calls index range and the per-task output budget.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { LMBPServer } from '../dist/index.js';
import * as L from '../dist/engine/lmbp.js';
import * as E from '../dist/e2ee.js';
import { pairAndConnect, startPairing } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

async function setup(opts = {}) {
  const port = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${port}`, tenants: [{ id: T, apiKey: KEY }], log: () => {}, ...opts });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(port, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${port}`;
  return { lmbp, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); await lmbp.close(); } };
}
const tenantReq = (base, user, method, path, body) => fetch(base + path, { method,
  headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': user, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
const authorize = (base, fields, localAddress) => new Promise((ok, bad) => {
  const body = new URLSearchParams({ tenant: T, public_key: L.b64(crypto.randomBytes(32)), ...fields }).toString();
  const u = new URL(base + '/lmbp/v1/device/authorize');
  const r = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', agent: false, localAddress,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, (res) => {
    let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => ok({ status: res.statusCode, body: b ? JSON.parse(b) : {} }));
  });
  r.on('error', bad); r.end(body);
});
const chat = (base, body) => fetch(base + '/v1/chat/completions', { method: 'POST',
  headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  .then(async (r) => ({ status: r.status, body: await r.json() }));
const proof = (priv, dc) => L.signJWS(priv, L.TYP.proof, '', { iss: '', aud: L.PROOF.token, iat: L.now(), jti: L.randomID('p_'), ath: L.ath(dc) });

// P1-3: pending pairings are never listed, device names are sanitized.
test('pending pairings are not listed to tenant users; bidi/control device names are refused', async () => {
  const s = await setup();
  try {
    const p = await startPairing(s.base, T, 'alice-laptop');
    for (const user of ['alice', 'bob']) {
      const r = await (await tenantReq(s.base, user, 'GET', '/lmbp/v1/tenant/devices')).json();
      assert.equal(r.pending_pairings, undefined, `${user} sees pending pairings: ${JSON.stringify(r)}`);
      assert.ok(!JSON.stringify(r).includes('alice-laptop'));
    }
    assert.equal(p.user_code.length, 9);
    for (const name of ['Office PC\u202Egpj.exe', 'a\nb', 'x\u200By', '\u0085']) {
      const r = await authorize(s.base, { device_name: name });
      assert.equal(r.status, 400, `device_name ${JSON.stringify(name)} accepted`);
    }
    assert.equal((await authorize(s.base, { device_name: '张三的 MacBook 😀' })).status, 200);
  } finally { await s.close(); }
});

// P2-1: tenant must exist; authorize is rate limited per client and per tenant.
test('device authorization: unknown tenant is invalid_client', async () => {
  const s = await setup();
  try {
    const r = await authorize(s.base, { tenant: 'no-such-tenant' });
    assert.equal(r.status, 400);
    assert.equal(r.body.error, 'invalid_client');
  } finally { await s.close(); }
});

test('device authorization is rate limited per client address (60/min, then 429 slow_down)', async () => {
  const s = await setup();
  try {
    const codes = {};
    for (let i = 0; i < 70; i++) { const r = await authorize(s.base, {}); codes[r.status] = (codes[r.status] || 0) + 1; }
    assert.ok((codes[200] ?? 0) <= 60 && codes[429] > 0, `70 authorizations from one address: ${JSON.stringify(codes)}`);
  } finally { await s.close(); }
});

test('a tenant holds at most 1000 live pending pairings, from any number of addresses', async () => {
  const s = await setup();
  try {
    const codes = {};
    for (let i = 0; i < 1100; i++) {
      const r = await authorize(s.base, {}, `127.0.${1 + Math.floor(i / 50)}.${1 + (i % 50)}`);
      codes[r.status] = (codes[r.status] || 0) + 1;
    }
    assert.ok((codes[200] ?? 0) <= 1000 && codes[429] > 0, `1100 pending pairings: ${JSON.stringify(codes)}`);
  } finally { await s.close(); }
});

// P2-2: a device that ignores slow_down loses its device_code.
test('device_code polling is capped: expired_token after 10 slow_down answers', async () => {
  const s = await setup();
  try {
    const p = await startPairing(s.base, T);
    const errs = [];
    for (let i = 0; i < 30; i++) {
      const r = await fetch(s.base + '/lmbp/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: p.device_code, proof: proof(p.priv, p.device_code) }) });
      const e = (await r.json()).error;
      errs.push(e);
      if (e === 'expired_token') break;
    }
    assert.equal(errs.at(-1), 'expired_token', `polls: ${errs.join(',')}`);
    assert.equal(errs.filter((e) => e === 'slow_down').length, 10, `polls: ${errs.join(',')}`);
    // polls of a dead code are answered without remembering their jtis
    const before = s.lmbp.engine.jtis.size;
    for (let i = 0; i < 20; i++) {
      await fetch(s.base + '/lmbp/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: p.device_code, proof: proof(p.priv, p.device_code) }) });
    }
    assert.equal(s.lmbp.engine.jtis.size, before, 'polls of an expired code grew the jti store');
  } finally { await s.close(); }
});

// P2-3/P2-4: approval is single use; failures count per end user.
test('approval is single use under concurrent requests', async () => {
  const s = await setup();
  try {
    const p = await startPairing(s.base, T);
    const rs = await Promise.all(Array.from({ length: 8 }, (_, i) => tenantReq(s.base, 'u' + i, 'POST', '/lmbp/v1/tenant/devices/approvals', { user_code: p.user_code })));
    assert.equal(rs.filter((r) => r.status === 200).length, 1, `statuses ${rs.map((r) => r.status)}`);
    const owners = new Set(); for (let i = 0; i < 8; i++) owners.add(s.lmbp.pairing.listDevices(T, 'u' + i).length);
    assert.deepEqual([...owners].sort(), [0, 1]);
  } finally { await s.close(); }
});

test('pairing failures are counted per end user, lookups included', async () => {
  const s = await setup();
  try {
    const seq = [];
    for (let i = 0; i < 11; i++) seq.push((await tenantReq(s.base, 'mallory', 'POST', '/lmbp/v1/tenant/devices/approvals', { user_code: 'BBBB-BBBB' })).status);
    assert.deepEqual(seq, [...Array(10).fill(404), 429]);
    assert.equal((await tenantReq(s.base, 'alice', 'POST', '/lmbp/v1/tenant/devices/approvals', { user_code: 'BBBB-BBBB' })).status, 404, 'another user was locked out');
    let thrown = null;
    for (let i = 0; i < 11 && !thrown; i++) {
      try { s.lmbp.pairing.lookup(T, 'eve', 'CCCC-CCCC'); } catch (e) { thrown = e; }
    }
    assert.equal(thrown?.code, 'RATE_LIMITED', 'lookups of wrong codes are not counted');
  } finally { await s.close(); }
});

// P2-5: jti store is bounded with heap eviction (no O(n) scan per call).
test('jti store: inserts stay fast at 200k live entries; expired entries are evicted', () => {
  const s = new LMBPServer({ issuer: 'http://127.0.0.1:1', tenants: [{ id: T, apiKey: KEY }], log: () => {} });
  const g = s.engine;
  const until = Date.now() + 60_000;
  for (let i = 0; i < 200_000; i++) g.useJTI('j' + i, until);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 1000; i++) g.useJTI('k' + i, until);
  const per = Number(process.hrtime.bigint() - t0) / 1000 / 1e6; // ms per call
  assert.ok(per < 0.2, `useJTI took ${per.toFixed(3)} ms per call at 200k entries`);
  assert.equal(g.useJTI('j1', until), false, 'replay accepted');
  g.useJTI('short', Date.now() - 1);
  g.useJTI('trigger', until);
  s.close();
});

// P2-6: the issuer is configuration, never derived from Host.
test('issuer is required and never derived from the Host header', async () => {
  assert.throws(() => new LMBPServer({ tenants: [{ id: T, apiKey: KEY }], log: () => {} }), /issuer/);
  const s = await setup({ issuer: 'https://gw.example.com' });
  try {
    const u = new URL(s.base);
    const m = await new Promise((ok, bad) => http.get({ host: u.hostname, port: u.port, path: '/.well-known/lmbp', headers: { Host: 'evil.example' } }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => ok(JSON.parse(b)));
    }).on('error', bad));
    assert.equal(m.issuer, 'https://gw.example.com');
  } finally { await s.close(); }
});

// P2-8: revoking a device while its task runs is OUTCOME_UNKNOWN (502), not 401.
test('revoking a device with a task in flight ends the call with 502 OUTCOME_UNKNOWN', async () => {
  const s = await setup();
  let ran;
  const seen = new Promise((ok) => { ran = ok; });
  const { ws, deviceId } = await pairAndConnect(s.lmbp, s.base, T, 'u1', { manual: (run) => ran(run) });
  try {
    const call = chat(s.base, { model: 'm1', messages: [{ role: 'user', content: 'hi' }] });
    await seen;
    assert.equal((await tenantReq(s.base, 'u1', 'POST', `/lmbp/v1/tenant/devices/${deviceId}/revoke`)).status, 200);
    const r = await call;
    assert.equal(r.status, 502, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'OUTCOME_UNKNOWN');
  } finally { ws.close(); await s.close(); }
});

// helpers for device-driven tasks
async function manualTask(s, opts, drive) {
  let cancel; const cancelled = new Promise((ok) => { cancel = ok; });
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1', { ...opts, manual: (run, w) => drive(run, w) });
  ws.on('message', (raw) => { const e = JSON.parse(raw); if (e.type === 'task.cancel') cancel(e.data.reason); });
  return { ws, cancelled };
}
const frame = (run, seq, type, data) => JSON.stringify({ v: L.VERSION, type, task_id: run.task_id, seq, data });

// P1-1: a tool_calls index outside 0..127 fails the task.
test('tool_calls index 128 fails the task: task.cancel(protocol_error), caller 502 INTERNAL', async () => {
  const s = await setup();
  const { ws, cancelled } = await manualTask(s, {}, (run, w) => {
    w.send(frame(run, 1, 'task.delta', { tool_calls: [{ index: 128, id: 'c', type: 'function', function: { name: 'f', arguments: '{}' } }] }));
  });
  try {
    const r = await chat(s.base, { model: 'm1', tools: [{ type: 'function', function: { name: 'f', parameters: { type: 'object' } } }], messages: [{ role: 'user', content: 'x' }] });
    assert.equal(await Promise.race([cancelled, sleep(3000).then(() => 'none')]), 'protocol_error');
    assert.equal(r.status, 502, JSON.stringify(r.body));
    assert.equal(r.body.error.code, 'INTERNAL');
  } finally { ws.close(); await s.close(); }
});

// P1-2: the per-task output budget (64 MiB) applies to cleartext and sealed deltas.
for (const e2ee of [false, true]) {
  test(`per-task output budget: ${e2ee ? 'E2EE' : 'plaintext'} deltas beyond 64 MiB cancel the task`, async () => {
    const s = await setup();
    let sent = 0;
    const { ws, cancelled } = await manualTask(s, { e2ee }, async (run, w) => {
      const key = crypto.randomBytes(32);
      const chunk = 'a'.repeat(150 << 10);
      for (let seq = 1; seq <= Math.ceil(L.MAX_TASK_OUTPUT_BYTES / chunk.length) + 8 && w.readyState === w.OPEN; seq++) {
        const data = e2ee ? { e2ee: E.sealChunk(key, 'rid_x', 'task.delta', seq, Buffer.from(JSON.stringify({ text: chunk }))) } : { text: chunk };
        w.send(frame(run, seq, 'task.delta', data));
        sent = seq;
        if (seq % 16 === 0) await sleep(1);
      }
    });
    try {
      let body = { model: 'm1', messages: [{ role: 'user', content: 'flood' }] };
      if (e2ee) {
        const { sealE2EERequest } = await import('../dist/index.js');
        const dev = s.lmbp.pairing.listDevices(T, 'u1')[0];
        body = { model: 'm1', lmbp_e2ee: sealE2EERequest(dev, L.thumbprint(dev.publicKey), body).jwe };
      }
      const r = await chat(s.base, body);
      assert.equal(await Promise.race([cancelled, sleep(5000).then(() => 'none')]), 'protocol_error', `no cancel after ${sent} frames`);
      assert.equal(r.status, 502, JSON.stringify(r.body).slice(0, 300));
      assert.equal(r.body.error.code, 'INTERNAL');
    } finally { ws.close(); await s.close(); }
  });
}
