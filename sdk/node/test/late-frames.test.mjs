// Review8 P1-a: the gateway ends a task locally (the caller goes away) while
// the device is still running. The device's late frames, including its
// terminal frame, must be ACKed so its reliable buffer and connection flow
// credit come back; they must not be answered with unknown_task only. The
// decided outcome (CANCELLED) stays as it was.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import * as L from '../dist/engine/lmbp.js';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const until = async (cond, ms, what) => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out: ' + (typeof what === 'function' ? what() : what)); await new Promise((r) => setTimeout(r, 10)); }
};

test('local cancel: late device frames and terminal frame are ACKed (credit returned)', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const runs = new Map(); // task id → { acked, cancels: [], sent }
  const manual = (run, ws) => {
    const st = { acked: 0, cancels: [], sent: 0 };
    runs.set(run.task_id, st);
    const send = (type, data) => ws.send(JSON.stringify({ v: L.VERSION, type, task_id: run.task_id, seq: ++st.sent, data }));
    ws.on('message', (raw) => {
      const e = JSON.parse(raw);
      if (e.task_id !== run.task_id) return;
      if (e.type === 'task.ack') st.acked = Math.max(st.acked, e.data.seq);
      if (e.type === 'task.cancel') {
        st.cancels.push(e.data.reason);
        if (st.cancels.length === 1) setTimeout(() => { // the device only notices a bit later
          send('task.delta', { text: 'late 1' });
          send('task.delta', { text: 'late 2' });
          send('task.error', { code: 'CANCELLED', message: 'cancelled', retryable: false });
        }, 50);
      }
    });
    send('task.delta', { text: 'hello ' });
    send('task.delta', { text: 'world' });
  };
  const { ws } = await pairAndConnect(lmbp, base, 'acme', 'u1', { manual });
  try {
    const N = 5;
    for (let i = 0; i < N; i++) {
      const c = lmbp.client('acme', 'u1');
      const ac = new AbortController();
      const st = c.chat.completions.stream({ model: 'm1', messages: [{ role: 'user', content: 'go' }] }, { signal: ac.signal });
      await st.next();
      ac.abort(); // caller gone: the gateway ends the task locally
      await st.next().catch(() => {});
    }
    await until(() => runs.size === N && [...runs.values()].every((r) => r.sent === 5 && r.acked === 5), 5000,
      () => 'device frames ACKed: ' + JSON.stringify([...runs.values()]));
    for (const [id, r] of runs) {
      assert.ok(!r.cancels.includes('unknown_task'), `task ${id} late frames got unknown_task: ${r.cancels}`);
    }
    // bounded cleanup state is gone once each device terminal arrived
    const ds = [...lmbp.engine.devs.values()][0];
    assert.equal(ds.reclaimed.size, 0, 'late-frame records left behind');
    // the decided outcome is unchanged
    for (const id of runs.keys()) {
      const t = lmbp.store.getTask(id);
      assert.ok(t, `task ${id} not stored`);
      assert.equal(t.state, 'CANCELLED', `task ${id} state ${t.state}`);
    }
  } finally {
    ws.close(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok));
  }
});
