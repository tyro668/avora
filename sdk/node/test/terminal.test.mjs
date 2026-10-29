// Third audit #1: the terminal event and the terminal task state are written
// in ONE transaction. Scenario: the done event is written, the status write
// fails, the caller gets INTERNAL; after a restart a retry with the same
// Idempotency-Key must get the same outcome (never success), and storage holds
// exactly one terminal event whose state agrees.
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
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
async function setup(store) {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], store, log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { lmbp, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); } };
}
const BODY = { model: 'm1', messages: [{ role: 'user', content: 'hello' }] };
async function idemChat(base, key) {
  const r = await fetch(base + '/v1/chat/completions', { method: 'POST', body: JSON.stringify(BODY),
    headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', 'Idempotency-Key': key } });
  return { status: r.status, task: r.headers.get('x-task-id'), body: await r.text() };
}
const outcome = ({ status, body }) => {
  if (status === 200 && !/"error"/.test(body)) return 'success';
  return (body.match(/INTERNAL|OUTCOME_UNKNOWN/) ?? ['other:' + body])[0];
};
function singleTerminal(store, id) {
  const rec = store.getTask(id);
  const seqs = rec.events.map((e) => e.seq);
  assert.equal(new Set(seqs).size, seqs.length, `seq reused: ${seqs}`);
  const terms = rec.events.filter((e) => e.type === 'task.done' || e.type === 'task.error');
  assert.equal(terms.length, 1, `terminal events: ${JSON.stringify(rec.events)} state ${rec.state}`);
  const ok = terms[0].type === 'task.done' ? rec.state === 'SUCCEEDED' : ['FAILED', 'CANCELLED'].includes(rec.state);
  assert.ok(ok, `terminal ${terms[0].type} disagrees with state ${rec.state}`);
  return terms[0].type;
}

test('SQLite: status write fails after the done event; restart; idempotent retry has the same outcome', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-term-'));
  const file = path.join(dir, 'g.db');
  const st = new SqliteStore(file);
  // Fault injection inside the database: any write making the task SUCCEEDED fails.
  for (const ev of ['INSERT', 'UPDATE']) {
    st.db.exec(`CREATE TRIGGER fail_${ev} BEFORE ${ev} ON lmbp_tasks WHEN json_extract(NEW.doc,'$.state')='SUCCEEDED' BEGIN SELECT RAISE(ABORT,'injected status write failure'); END`);
  }
  const s = await setup(st);
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  let first;
  try {
    first = await idemChat(s.base, 'k-term');
    assert.notEqual(outcome(first), 'success', 'status write failed but the caller got success');
    await sleep(200);
  } finally { ws.close(); await s.close(); }
  st.db.exec('DROP TRIGGER fail_INSERT; DROP TRIGGER fail_UPDATE');
  st.close();
  // Restart over the same file.
  const st2 = new SqliteStore(file);
  const s2 = await setup(st2);
  try {
    const second = await idemChat(s2.base, 'k-term');
    assert.equal(second.task, first.task);
    assert.equal(outcome(second), outcome(first), `before restart ${first.status} ${first.body}\nafter ${second.status} ${second.body}`);
    assert.equal(singleTerminal(st2, first.task), 'task.error');
  } finally { await s2.close(); st2.close(); }
});

test('memory store: one-shot status write failure; replay from the store has the same outcome', async () => {
  const st = new MemoryStore();
  let armed = true;
  const putTask = st.putTask.bind(st);
  st.putTask = (rec) => { if (rec.state === 'SUCCEEDED' && armed) { armed = false; throw new Error('disk full'); } return putTask(rec); };
  if (st.finishTask) {
    const fin = st.finishTask.bind(st);
    st.finishTask = (id, ev, state) => { if (state === 'SUCCEEDED' && armed) { armed = false; throw new Error('disk full'); } return fin(id, ev, state); };
  }
  const s = await setup(st);
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  try {
    const first = await idemChat(s.base, 'k-mem');
    await sleep(200);
    s.lmbp.engine.tasks.delete(first.task); // drop the hub: replay from the store
    const second = await idemChat(s.base, 'k-mem');
    assert.equal(outcome(second), outcome(first), `first ${first.status} ${first.body}\nreplay ${second.status} ${second.body}`);
    assert.notEqual(outcome(second), 'success');
    singleTerminal(st, first.task);
  } finally { ws.close(); await s.close(); }
});

test('recovery: a legacy row whose done event disagrees with its state is OUTCOME_UNKNOWN, nothing written', async () => {
  const st = new MemoryStore();
  st.putTask({ id: 'task_x', tenant: T, owner: 'u1', device: 'd', model: 'm1', state: 'FAILED',
    events: [{ seq: 1, type: 'task.delta', data: { content: 'hi' } }, { seq: 2, type: 'task.done', data: { finish_reason: 'stop' } }] });
  const s = await setup(st);
  try {
    const r = await fetch(s.base + '/lmbp/v1/tenant/tasks/task_x/events', { headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1' } });
    const body = await r.text();
    assert.match(body, /OUTCOME_UNKNOWN/, body);
    assert.doesNotMatch(body, /task\.done|"finish_reason":"stop"/, body);
    assert.equal(st.getTask('task_x').events.length, 2);
  } finally { await s.close(); }
});

test('finishTask contract: atomic, no seq reuse, no second terminal (memory + SQLite)', async () => {
  const { StoreConflict, StoreNotFound } = await import('../dist/index.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-fin-'));
  const sq = new SqliteStore(path.join(dir, 'f.db'));
  for (const st of [new MemoryStore(), sq]) {
    st.putTask({ id: 't1', tenant: T, owner: 'u', device: 'd', model: 'm', state: 'RUNNING', events: [] });
    st.appendEvent('t1', { seq: 1, type: 'task.delta', data: {} });
    assert.throws(() => st.appendEvent('t1', { seq: 1, type: 'task.delta', data: {} }), StoreConflict);
    assert.throws(() => st.finishTask('t1', { seq: 1, type: 'task.done', data: {} }, 'SUCCEEDED'), StoreConflict);
    assert.equal(st.getTask('t1').state, 'RUNNING');
    st.finishTask('t1', { seq: 2, type: 'task.done', data: {} }, 'SUCCEEDED');
    assert.throws(() => st.finishTask('t1', { seq: 3, type: 'task.error', data: {} }, 'FAILED'), StoreConflict);
    assert.throws(() => st.finishTask('nope', { seq: 1, type: 'task.done', data: {} }, 'SUCCEEDED'), StoreNotFound);
    const rec = st.getTask('t1');
    assert.equal(rec.state, 'SUCCEEDED');
    assert.deepEqual(rec.events.map((e) => e.seq), [1, 2]);
  }
  sq.putTask({ id: 't2', tenant: T, owner: 'u', device: 'd', model: 'm', state: 'RUNNING', events: [] });
  sq.db.exec(`CREATE TRIGGER f BEFORE UPDATE ON lmbp_tasks WHEN json_extract(NEW.doc,'$.state')='SUCCEEDED' BEGIN SELECT RAISE(ABORT,'injected'); END`);
  assert.throws(() => sq.finishTask('t2', { seq: 1, type: 'task.done', data: {} }, 'SUCCEEDED'));
  assert.deepEqual(sq.getTask('t2').events, []);
  assert.equal(sq.getTask('t2').state, 'RUNNING');
  sq.close();
});
