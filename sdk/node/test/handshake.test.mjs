// Review7 #2/#3: hello handling on the Node gateway.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LMBPServer, MemoryStore, SqliteStore } from '../dist/index.js';
import { pairAndConnect, connect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';
async function setup(store) {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], store, log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { lmbp, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); } };
}
const api = (base, method, p, body) => fetch(base + p, { method, body: body && JSON.stringify(body),
  headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' } });
async function chatOK(base) {
  const r = await api(base, 'POST', '/v1/chat/completions', { model: 'm1', messages: [{ role: 'user', content: 'hi' }] });
  return r.status === 200 && /echo/.test(await r.text());
}

for (const [name, mk] of [['memory', () => new MemoryStore()], ['sqlite', () => new SqliteStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-hs-')), 'g.db'))]]) {
  test(`revoke while the gateway awaits the hello cannot resurrect the device (${name})`, async () => {
    const st = mk();
    const s = await setup(st);
    try {
      const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
      d.ws.close();
      await new Promise((ok) => setTimeout(ok, 50));
      // a new connection passes the upgrade check, then the device is revoked
      // before its (E2EE) hello arrives
      const err = await connect(s.base, d.pairing, d.tok, ['m1'], { e2ee: true, beforeHello: async () => {
        const r = await api(s.base, 'POST', `/lmbp/v1/tenant/devices/${d.deviceId}/revoke`);
        assert.equal(r.status, 200);
      } }).then(() => null, (e) => e);
      assert.ok(err, 'session was activated for a revoked device');
      assert.match(String(err.message), /UNAUTHENTICATED|revoked/);
      assert.equal(st.getDevice(d.deviceId).status, 'revoked', 'E2EE metadata write resurrected the device');
    } finally { await s.close(); st.close?.(); }
  });
}

test('malformed hello.resume is rejected without crashing the gateway', async () => {
  const s = await setup(new MemoryStore());
  try {
    const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    d.ws.close();
    await new Promise((ok) => setTimeout(ok, 50));
    for (const resume of [{ token: 'x', tasks: [null] }, { token: 'x', tasks: 'oops' }, { token: 'x', tasks: [{ task_id: 1, recv_seq: 'a' }] }, 'str']) {
      const err = await connect(s.base, d.pairing, d.tok, ['m1'], { extraCaps: ['resume'], helloPatch: { resume } }).then(() => null, (e) => e);
      assert.ok(err && /BAD_REQUEST/.test(err.message), `resume ${JSON.stringify(resume)}: ${err?.message}`);
    }
    // the gateway still serves (a fresh, valid connection works)
    const ws = await connect(s.base, d.pairing, d.tok, ['m1']);
    for (let i = 0; i < 50 && !(await chatOK(s.base)); i++) await new Promise((ok) => setTimeout(ok, 20));
    const r = await api(s.base, 'POST', '/v1/chat/completions', { model: 'm1', messages: [{ role: 'user', content: 'hi' }] });
    const body = await r.text();
    assert.ok(r.status === 200 && /echo/.test(body), r.status + ' ' + body);
    ws.close();
  } finally { await s.close(); }
});

test('an old connection closing late does not take a newer one offline', async () => {
  const s = await setup(new MemoryStore());
  try {
    const d = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    const ws2 = await connect(s.base, d.pairing, d.tok, ['m1']); // new, not resumed
    d.ws.close(); // the old socket's close arrives after the new session
    await new Promise((ok) => setTimeout(ok, 100));
    const r = await api(s.base, 'POST', '/v1/chat/completions', { model: 'm1', messages: [{ role: 'user', content: 'hi' }] });
    const body = await r.text();
    assert.ok(r.status === 200 && /echo/.test(body), r.status + ' ' + body);
    ws2.close();
  } finally { await s.close(); }
});

test('E2EE task replayed after a restart stays sealed (review7 #6)', async () => {
  const { sealE2EERequest } = await import('../dist/index.js');
  const st = new SqliteStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-e2r-')), 'g.db'));
  const s = await setup(st);
  const { ws, jkt } = await pairAndConnect(s.lmbp, s.base, T, 'u1', { e2ee: true });
  try {
    const dev = s.lmbp.pairing.listDevices(T, 'u1')[0];
    const sealed = sealE2EERequest(dev, jkt, { model: 'm1', messages: [{ role: 'user', content: 'secret' }] });
    const post = () => fetch(s.base + '/v1/chat/completions', { method: 'POST', body: JSON.stringify({ model: 'm1', lmbp_e2ee: sealed.jwe }),
      headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', 'Idempotency-Key': 'e2r-1' } }).then(async (r) => ({ status: r.status, body: await r.json() }));
    const first = await post();
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.ok(first.body.lmbp_e2ee, 'first response sealed');
    s.lmbp.engine.tasks.delete(first.body.id.replace(/^chatcmpl-/, '')); // restart: only storage is left
    s.lmbp.engine.tasks.clear();
    const again = await post();
    assert.equal(again.status, 200);
    assert.deepEqual(again.body.lmbp_e2ee, first.body.lmbp_e2ee, 'replay lost the E2EE frames: ' + JSON.stringify(again.body));
  } finally { ws.close(); await s.close(); st.close(); }
});

test('a caller disconnecting while queued records CANCELLED; replay reports it (review7 #10/#15)', async () => {
  const st = new MemoryStore();
  const s = await setup(st);
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1', { maxConcurrency: 1, delayMs: 1500 });
  try {
    const body = { model: 'm1', messages: [{ role: 'user', content: 'hi' }] };
    const hog = api(s.base, 'POST', '/v1/chat/completions', body).then((r) => r.text());
    await new Promise((r) => setTimeout(r, 200));
    const hs = { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', 'Idempotency-Key': 'q-gone' };
    await assert.rejects(fetch(s.base + '/v1/chat/completions', { method: 'POST', body: JSON.stringify(body), headers: hs, signal: AbortSignal.timeout(300) }));
    let rec;
    for (let i = 0; i < 100; i++) {
      rec = await st.getIdempotency(T, 'u1', 'q-gone');
      if (rec && (await st.getTask(rec.taskID))?.state !== 'QUEUED') break;
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.ok(rec, 'idempotency record');
    assert.equal((await st.getTask(rec.taskID)).state, 'CANCELLED');
    await hog;
    const again = await (await fetch(s.base + '/v1/chat/completions', { method: 'POST', body: JSON.stringify(body), headers: hs })).text();
    assert.match(again, /CANCELLED/);
    assert.doesNotMatch(again, /DEVICE_BUSY/);
  } finally { ws.close(); await s.close(); }
});
