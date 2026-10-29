// audit3 P2-6: a device terminal frame is validated (envelope + body against
// task.done.json / task.error.json) BEFORE its seq is accepted, persisted or
// ACKed. Was: task.done {} / null / wrong types were stored as SUCCEEDED,
// ACKed, and the caller got a 200 with an empty finish_reason.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import * as L from '../dist/engine/lmbp.js';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const CASES = [
  ['task.done', {}], ['task.done', null], ['task.done', { finish_reason: 5 }],
  ['task.done', { finish_reason: 'stop', usage: 'lots' }], ['task.done', []],
  ['task.error', {}], ['task.error', { code: 7, message: 'x' }],
];

test('an invalid task.done / task.error body never becomes a stored success and is not ACKed', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const acks = new Map(); // task_id -> highest acked seq
  let bad = null;
  let lastRun = '';
  const manual = (run, ws) => {
    lastRun = run.task_id;
    const send = (type, seq, data) => ws.send(JSON.stringify({ v: L.VERSION, type, task_id: run.task_id, seq, data }));
    send('task.delta', 1, { text: 'almost' });
    send(bad[0], 2, bad[1]);
  };
  const d = await pairAndConnect(lmbp, base, 'acme', 'u1', { manual });
  d.ws.on('message', (raw) => {
    const e = JSON.parse(raw);
    if (e.type === 'task.ack') acks.set(e.task_id, Math.max(acks.get(e.task_id) ?? 0, e.data.seq));
  });
  try {
    for (const c of CASES) {
      bad = c;
      const res = await fetch(base + '/v1/chat/completions', { method: 'POST',
        headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'm1', messages: [{ role: 'user', content: 'hi' }] }) });
      const body = await res.json();
      const label = `${c[0]} ${JSON.stringify(c[1])}`;
      assert.notEqual(res.status, 200, `${label}: answered 200 ${JSON.stringify(body)}`);
      const id = lastRun;
      assert.ok(id, `${label}: never dispatched`);
      await new Promise((r) => setTimeout(r, 100));
      {
        const t = lmbp.engine.store.getTask(id);
        assert.notEqual(t?.state, 'SUCCEEDED', `${label}: stored as SUCCEEDED`);
        assert.ok(!(acks.get(id) >= 2), `${label}: invalid terminal frame was ACKed`);
        assert.equal(t?.events.at(-1)?.type, 'task.error', `${label}: last event ${JSON.stringify(t?.events.at(-1))}`);
      }
    }
  } finally {
    d.ws.terminate(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); await lmbp.close();
  }
});
