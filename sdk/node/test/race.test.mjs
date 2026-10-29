// Fourth audit A1: one decide-once terminal decision drives both what is
// stored and what callers see; the idempotency record and the task row are
// one atomic write. Races are reproduced deterministically with raceHooks.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LMBPServer, MemoryStore, SqliteStore } from '../dist/index.js';
import { raceHooks } from '../dist/engine/gateway.js';
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
async function chat(base, key, content = 'hello') {
  const r = await fetch(base + '/v1/chat/completions', { method: 'POST', body: JSON.stringify({ model: 'm1', messages: [{ role: 'user', content }] }),
    headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json', 'Idempotency-Key': key } });
  return { status: r.status, task: r.headers.get('x-task-id'), body: await r.text() };
}
const success = ({ status, body }) => status === 200 && !/"error"/.test(body);
function stored(st, id) {
  const rec = st.getTask(id);
  const terms = rec.events.filter((e) => e.type === 'task.done' || e.type === 'task.error');
  assert.equal(terms.length, 1, `terminal events ${JSON.stringify(rec.events)} state ${rec.state}`);
  assert.ok(terms[0].type === 'task.done' ? rec.state === 'SUCCEEDED' : ['FAILED', 'CANCELLED'].includes(rec.state), `${terms[0].type} vs ${rec.state}`);
  return terms[0].type === 'task.done';
}

for (const [name, code] of [['timeout', 'TIMEOUT'], ['client cancel', 'CANCELLED'], ['slow consumer', 'SLOW_CONSUMER']]) {
  test(`decide-once: ${name} fires after the device's done was committed, before it was published`, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-race-'));
    const st = new SqliteStore(path.join(dir, 'g.db'));
    const s = await setup(st);
    const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    let fired = false;
    raceHooks.hook = (t, point) => {
      if (point === 'device-terminal-committed' && !fired) { fired = true; t.failLocal(code, 'injected ' + name); }
    };
    try {
      const first = await chat(s.base, 'k-' + code);
      assert.ok(fired, 'hook fired');
      await sleep(150);
      assert.equal(success(first), stored(st, first.task), `caller ${first.status} ${first.body} vs storage`);
      s.lmbp.engine.tasks.delete(first.task); // drop the hub: replay from storage
      const again = await chat(s.base, 'k-' + code);
      assert.equal(success(again), success(first), `replay ${again.status} ${again.body} vs caller ${first.body}`);
    } finally { raceHooks.hook = null; ws.close(); await s.close(); st.close(); }
  });
}

test('decide-once: a local timeout decides first; late device frames are dropped', async () => {
  const st = new MemoryStore();
  const s = await setup(st);
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  let fired = false;
  raceHooks.hook = (t, point) => { if (point === 'device-frame' && !fired) { fired = true; t.failLocal('TIMEOUT', 'injected timeout'); } };
  try {
    const first = await chat(s.base, 'k-local-first', 'a b c d');
    assert.ok(fired && !success(first) && /TIMEOUT/.test(first.body), first.body);
    await sleep(200);
    assert.equal(stored(st, first.task), false);
    assert.equal(st.getTask(first.task).events.at(-1).type, 'task.error');
  } finally { raceHooks.hook = null; ws.close(); await s.close(); }
});

test('idempotency record and task row are one atomic write', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-idem-'));
  const st = new SqliteStore(path.join(dir, 'g.db'));
  // crash while creating the task row (whichever API the store uses)
  let armed = true;
  for (const m of ['putTask', 'createTask']) {
    if (!st[m]) continue;
    const orig = st[m].bind(st);
    st[m] = (...a) => { if (armed && a[0]?.state === 'QUEUED') { armed = false; if (m === 'createTask') throw new Error('injected crash'); orig({ ...a[0], id: '__never' }); st.db.exec("DELETE FROM lmbp_tasks WHERE id='__never'"); throw new Error('injected crash'); } return orig(...a); };
  }
  const s = await setup(st);
  const { ws } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  try {
    const first = await chat(s.base, 'k-atomic');
    assert.equal(first.status, 500, first.body);
    const rec = st.getIdempotency(T, 'u1', 'k-atomic');
    assert.ok(!rec || st.getTask(rec.taskID), `key stored without its task: ${JSON.stringify(rec)}`);
    const again = await chat(s.base, 'k-atomic');
    assert.ok(success(again), `retry after the failed create: ${again.status} ${again.body}`);
  } finally { ws.close(); await s.close(); st.close(); }
});
