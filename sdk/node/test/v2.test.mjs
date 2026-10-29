// LMBP 2.0 (spec §4.1, §7.1, §7.4, §11, §18.2): version identifiers, 1.x
// refusal, hello/models.update schema validation without clamping, code-point
// lengths and printable-ASCII headers. Each case failed on the 1.0 engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import WebSocket from 'ws';
import { LMBPServer, MemoryStore } from '../dist/index.js';
import * as L from '../dist/engine/lmbp.js';
import { pairAndConnect, connect, startPairing } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';
async function setup() {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], store: new MemoryStore(), log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { lmbp, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); } };
}
const api = (base, method, p, body, headers = {}) => fetch(base + p, { method, body: body && JSON.stringify(body),
  headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', ...headers } });
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

test('metadata advertises 2.0 and the profiles', async () => {
  const s = await setup();
  try {
    const m = await (await fetch(s.base + '/.well-known/lmbp')).json();
    assert.deepEqual(m.protocol_versions, ['2.0']);
    assert.ok(m.profiles.includes('core') && m.profiles.length === 7, JSON.stringify(m.profiles));
    assert.equal(L.VERSION, 2);
    assert.equal(L.SUBPROTOCOL, 'lmbp');
  } finally { await s.close(); }
});

test('subprotocol is unversioned: only lmbp.2 gets 400 VERSION_UNSUPPORTED; a 1.x hello (lmbp, v 1) gets error VERSION_UNSUPPORTED', async () => {
  const s = await setup();
  try {
    const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    d.ws.close();
    const status = await new Promise((ok) => {
      const ws = new WebSocket(s.base.replace(/^http/, 'ws') + '/lmbp/v1/connect', 'lmbp.2', { headers: { Authorization: 'Bearer ' + d.tok.access_token } });
      ws.on('unexpected-response', (_q, res) => ok(res.statusCode));
      ws.on('open', () => ok('opened'));
      ws.on('error', () => {});
    });
    assert.equal(status, 400);
    const err = await connect(s.base, d.pairing, d.tok, ['m1'], { envPatch: { v: 1 } }).then(() => null, (e) => e);
    assert.match(String(err?.message), /VERSION_UNSUPPORTED/);
  } finally { await s.close(); }
});

test('hello max_concurrency 0, 17, missing or "2" is rejected (no clamping); model_names of 129 code points is rejected', async () => {
  const s = await setup();
  try {
    const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    d.ws.close();
    await sleep(30);
    for (const patch of [{ max_concurrency: 0 }, { max_concurrency: 17 }, { max_concurrency: undefined }, { max_concurrency: '2' }, { model_names: { m1: '😀'.repeat(129) } }]) {
      const err = await connect(s.base, d.pairing, d.tok, ['m1'], { helloPatch: patch }).then(() => null, (e) => e);
      assert.match(String(err?.message), /BAD_REQUEST/, JSON.stringify(patch));
    }
    const ws = await connect(s.base, d.pairing, d.tok, ['m1'], { maxConcurrency: 16, helloPatch: { model_names: { m1: '😀'.repeat(128) } } });
    ws.close();
  } finally { await s.close(); }
});

test('models.update with max_concurrency 99 is rejected whole and not applied', async () => {
  const s = await setup();
  try {
    const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    const frames = [];
    d.ws.on('message', (m) => frames.push(JSON.parse(m)));
    d.ws.send(JSON.stringify({ v: L.VERSION, type: 'models.update', id: 'mu1', data: { models: ['m1', 'zzz'], max_concurrency: 99 } }));
    await sleep(100);
    const e = frames.find((f) => f.type === 'error');
    assert.equal(e?.data?.code, 'BAD_REQUEST', JSON.stringify(frames));
    const list = await (await api(s.base, 'GET', '/v1/models')).json();
    assert.ok(!list.data.some((m) => m.id.endsWith('/zzz')), 'models.update was applied');
    const devs = await (await api(s.base, 'GET', '/lmbp/v1/tenant/devices')).json();
    assert.ok(devs.devices.every((x) => x.max_concurrency !== 16 && x.max_concurrency !== 99), JSON.stringify(devs));
    d.ws.close();
  } finally { await s.close(); }
});

test('device_name counts code points; X-End-User and Idempotency-Key must be printable ASCII', async () => {
  const s = await setup();
  try {
    const auth = (name) => fetch(s.base + '/lmbp/v1/device/authorize', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tenant: T, public_key: L.b64(Buffer.alloc(32, 7)), device_name: name }) });
    assert.equal((await auth('😀'.repeat(100))).status, 200);
    assert.equal((await auth('设'.repeat(101))).status, 400);
    assert.ok(await startPairing(s.base, T, '😀'.repeat(100)));
    const r = await api(s.base, 'GET', '/v1/models', null, { 'X-End-User': Buffer.from('张三').toString('latin1') });
    assert.equal(r.status, 400);
    assert.equal((await api(s.base, 'GET', '/v1/models', null, { 'X-End-User': 'a'.repeat(129) })).status, 400);
    assert.equal((await api(s.base, 'GET', '/v1/models', null, { 'X-End-User': 'a'.repeat(128) })).status, 200);
    const chat = { model: 'm1', messages: [{ role: 'user', content: 'hi' }] };
    assert.equal((await api(s.base, 'POST', '/v1/chat/completions', chat, { 'Idempotency-Key': 'k'.repeat(256) })).status, 400);
    assert.equal((await api(s.base, 'POST', '/v1/chat/completions', chat, { 'Idempotency-Key': Buffer.from('键').toString('latin1') })).status, 400);
    assert.throws(() => s.lmbp.pairing.approve(T, '张三', 'BCDF-GHJK'), /printable ASCII/);
  } finally { await s.close(); }
});
