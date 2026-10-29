// Regression tests for the 2026-10 audit findings (see reports/LMBP审查问题修复报告.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LMBPServer, MemoryStore, SqliteStore } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';

export async function setup(opts = {}) {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {}, ...opts });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { lmbp, srv, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); } };
}
const chat = (base, user, body, hdr = {}) => fetch(base + '/v1/chat/completions', {
  method: 'POST', headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': user, 'Content-Type': 'application/json', ...hdr }, body: JSON.stringify(body) });

// Finding 1: (user a, key b|c) must not collide with (user a|b, key c).
test('idempotency store keys are unambiguous (a, "b|c") vs ("a|b", "c")', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'idem-'));
  for (const st of [new MemoryStore(), new SqliteStore(path.join(dir, 'i.db'))]) {
    const task = (id) => ({ id, tenant: T, owner: 'a', device: 'd', model: 'm', state: 'QUEUED', events: [] });
    st.createTask(task('task_a'), { tenant: T, owner: 'a', key: 'b|c', rec: { tenant: T, owner: 'a', taskID: 'task_a', bodyHash: 'h' } });
    assert.equal(st.getIdempotency(T, 'a|b', 'c'), undefined, st.constructor.name);
    assert.equal(st.getIdempotency(T, 'a', 'b|c').taskID, 'task_a');
    assert.throws(() => st.createTask(task('task_other'), { tenant: T, owner: 'a', key: 'b|c', rec: { tenant: T, owner: 'a', taskID: 'task_other', bodyHash: 'h' } }), /taken/);
    assert.equal(st.getIdempotency(T, 'a', 'b|c').taskID, 'task_a', 'first writer wins');
    assert.equal(st.getTask('task_other'), undefined, 'no task row for the losing key');
    st.close?.();
  }
});

test('idempotent replay never crosses users (gateway, exact audit example)', async () => {
  const s = await setup();
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'a');
  try {
    const body = { model: 'm1', messages: [{ role: 'user', content: 'secret-of-a' }] };
    const r1 = await chat(s.base, 'a', body, { 'Idempotency-Key': 'b|c' });
    assert.equal(r1.status, 200);
    assert.match(await r1.text(), /secret-of-a/);
    const r2 = await chat(s.base, 'a|b', body, { 'Idempotency-Key': 'c' });
    const t2 = await r2.text();
    assert.notEqual(r2.status, 200, t2);
    assert.doesNotMatch(t2, /secret-of-a/);
    const r3 = await chat(s.base, 'a', body, { 'Idempotency-Key': 'b|c' });
    assert.equal(r3.status, 200);
    assert.equal(r3.headers.get('x-task-id'), r1.headers.get('x-task-id'));
  } finally { ws.close(); await s.close(); }
});

// Finding 10: the pairing lockout lives in the shared engine, so the
// in-process API (approve/deny) cannot brute-force codes past it and both
// paths share one counter.
test('in-process pairing is rate limited and shares the HTTP lockout', async () => {
  const s = await setup();
  try {
  const codes = [];
  for (let i = 0; i < 12; i++) {
    try { s.lmbp.pairing.approve(T, 'u1', `WRONG-${String(i).padStart(4, '0')}`); codes.push('ok'); }
    catch (e) { codes.push(e.code); }
  }
  assert.deepEqual(codes.slice(10), ['RATE_LIMITED', 'RATE_LIMITED'], codes.join(','));
  assert.throws(() => s.lmbp.pairing.deny(T, 'u1', 'WRONG-0000'), (e) => e.code === 'RATE_LIMITED');
  const r = await fetch(s.base + '/lmbp/v1/tenant/devices/approvals', { method: 'POST',
    headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: 'WRONG-0000' }) });
  assert.equal(r.status, 429);
  } finally { await s.close(); }
});

// Finding 7: SSE cursor + resume + idempotent replay from the in-process client.
test('client stream exposes lastEventId/taskId and resumes after the cursor', async () => {
  const s = await setup();
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  try {
    const c = s.lmbp.client(T, 'u1');
    const req = { model: 'm1', messages: [{ role: 'user', content: 'hello' }] };
    const st = c.chat.completions.stream(req, { idempotencyKey: 'k-1' });
    const ids = []; const parts = [];
    for await (const ch of st) { ids.push(st.lastEventId); parts.push(ch.choices.map((x) => x.delta.content || '').join('')); }
    assert.ok(st.taskId && ids.length >= 3 && ids[0] === '0', `ids ${ids} task ${st.taskId}`);
    const text = parts.join('');
    assert.equal(text, 'echo: hello');
    let rest = '';
    for await (const ch of c.chat.completions.resume(st.taskId, ids[1])) rest += ch.choices.map((x) => x.delta.content || '').join('');
    assert.equal(rest, parts.slice(2).join(''));
    assert.notEqual(rest, text);
    const again = c.chat.completions.stream(req, { idempotencyKey: 'k-1' });
    let replay = '';
    for await (const ch of again) replay += ch.choices.map((x) => x.delta.content || '').join('');
    assert.equal(replay, text);
    assert.equal(again.taskId, st.taskId);
    await assert.rejects(c.chat.completions.create(req, { idempotencyKey: 'k-1' }), (e) => e.code === 'IDEMPOTENCY_KEY_REUSED');
    for await (const _ of c.chat.completions.resume(st.taskId, '999')) assert.fail('events after the terminal one');
  } finally { ws.close(); await s.close(); }
});

// Finding 7: E2EE from business code (seal to the pinned device, open the sealed frames).
test('client E2EE: sealE2EERequest + open sealed stream frames', async () => {
  const { sealE2EERequest, decodeE2EEDelta } = await import('../dist/index.js');
  const s = await setup();
  const { ws, jkt } = await pairAndConnect(s.lmbp, s.base, T, 'u1', { e2ee: true });
  try {
    const dev = s.lmbp.pairing.listDevices(T, 'u1')[0];
    assert.ok(dev.e2eeKey && dev.publicKey.length === 32);
    assert.throws(() => sealE2EERequest(dev, 'not-the-pinned-jkt', { model: 'm1', messages: [] }));
    const sealed = sealE2EERequest(dev, jkt, { model: 'm1', messages: [{ role: 'user', content: 'secret' }] });
    assert.ok(!sealed.jwe.includes('secret'));
    const c = s.lmbp.client(T, 'u1');
    let text = ''; let frames = 0;
    const rd = sealed.reader();
    for await (const ch of c.chat.completions.stream({ model: 'm1', lmbp_e2ee: sealed.jwe })) {
      if (!ch.lmbp_e2ee) continue;
      frames++;
      const p = rd.next(ch.lmbp_e2ee);
      if (ch.lmbp_e2ee.type === 'task.delta') text += decodeE2EEDelta(p).text ?? '';
      assert.throws(() => sealed.open({ ...ch.lmbp_e2ee, seq: ch.lmbp_e2ee.seq + 1 }), 'reordered frame must not open');
    }
    rd.finish();
    assert.equal(text, 'echo:secret');
    assert.ok(frames >= 2);
  } finally { ws.close(); await s.close(); }
});

// Reliability 1: never ACK a device frame (or the terminal frame) that was
// not persisted; the caller gets INTERNAL instead of an unpersisted result.
for (const mode of ['event', 'state']) {
  test(`no ACK without persisted ${mode}; caller sees INTERNAL`, async () => {
    const st = new MemoryStore();
    const logs = [];
    const append = st.appendEvent.bind(st);
    // Terminal states are written with their event by finishTask (atomic).
    if (mode === 'event') st.appendEvent = (id, ev) => { if (ev.seq === 2 && ev.type !== 'task.error') throw new Error('disk full'); return append(id, ev); };
    else st.finishTask = () => { throw new Error('disk full'); };
    const s = await setup({ store: st, log: (...a) => logs.push(a.join(' ')) });
    const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    try {
      const r = await chat(s.base, 'u1', { model: 'm1', messages: [{ role: 'user', content: 'hello' }] });
      const body = await r.text();
      assert.notEqual(r.status, 200, body);
      assert.match(body, /INTERNAL/);
      await new Promise((ok) => setTimeout(ok, 100));
      const t = s.lmbp.engine.tasks.get(r.headers.get('x-task-id'));
      assert.ok(t, 'task in memory');
      assert.ok(t.acked < (mode === 'event' ? 2 : 3), `ACKed ${t.acked} without persistence`);
      assert.match(logs.join('\n'), /disk full/);
    } finally { ws.close(); await s.close(); }
  });
}

// Reliability 2: idempotency record + task + queue + in-memory hub behave as
// one unit: a duplicate during queueing attaches to the pending task, and a
// queueing failure is recorded so replays get the same error.
async function slowRig(tuning = {}) {
  const s = await setup({ tuning });
  const dev = await pairAndConnect(s.lmbp, s.base, T, 'u1', { maxConcurrency: 1, delayMs: 400 });
  return { s, dev };
}
const result = async (p) => { const r = await p; return { status: r.status, task: r.headers.get('x-task-id'), body: await r.text() }; };
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
const body1 = (text) => ({ model: 'm1', messages: [{ role: 'user', content: text }] });

test('idempotent duplicate while queued attaches to the pending task', async () => {
  const { s, dev } = await slowRig();
  try {
    const hold = result(chat(s.base, 'u1', body1('hold the slot')));
    await sleep(100);
    const a = result(chat(s.base, 'u1', body1('queued call'), { 'Idempotency-Key': 'k-queue' }));
    await sleep(100);
    const b = await result(chat(s.base, 'u1', body1('queued call'), { 'Idempotency-Key': 'k-queue' }));
    const ra = await a; await hold;
    assert.equal(ra.status, 200, ra.body);
    assert.equal(b.status, 200, b.body);
    assert.equal(b.task, ra.task);
    assert.equal(b.body, ra.body);
  } finally { dev.ws.close(); await s.close(); }
});

test('idempotent queue failure is recorded and replayed (not OUTCOME_UNKNOWN)', async () => {
  const { s, dev } = await slowRig({ queueTimeout: 150 });
  try {
    const hold = result(chat(s.base, 'u1', body1('hold the slot')));
    await sleep(100);
    const first = await result(chat(s.base, 'u1', body1('busy'), { 'Idempotency-Key': 'k-busy' }));
    const again = await result(chat(s.base, 'u1', body1('busy'), { 'Idempotency-Key': 'k-busy' }));
    await hold;
    assert.equal(first.status, 429, first.body);
    assert.match(first.body, /DEVICE_BUSY/);
    assert.equal(again.status, 429, again.body);
    assert.match(again.body, /DEVICE_BUSY/);
    assert.equal(again.task, first.task);
  } finally { dev.ws.close(); await s.close(); }
});
