// audit3 P1: a chunked request waits for connection credit, the device
// drops, the task ends (cancel) inside the resume window, the device
// resumes. Ending the task must not let its queued blob.chunk sends
// re-create outbox state: that state holds connection credit no resume
// returns, and in strict FIFO the stuck send blocks every later task.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect, connect } from '../test-support/simdevice.mjs';
import * as L from '../dist/engine/lmbp.js';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const until = async (cond, ms, what) => {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error('timed out: ' + (typeof what === 'function' ? what() : what)); await new Promise((r) => setTimeout(r, 10)); }
};
const WIN = L.MAX_FRAME_BYTES; // smallest legal windows: one blob chunk at a time
const image = () => 'data:image/png;base64,' + crypto.randomBytes(300 * 1024).toString('base64'); // 4 chunks

test('cancel while chunks wait for credit, then resume: no connection credit leaks', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  let token = '';
  let answer = false; // second connection: ACK and answer
  const wire = (ws) => ws.on('message', (raw) => {
    const e = JSON.parse(raw);
    if (!answer || (e.type !== 'task.run' && e.type !== 'blob.chunk')) return;
    ws.send(JSON.stringify({ v: L.VERSION, type: 'task.ack', task_id: e.task_id, data: { seq: e.seq } }));
    if (e.type === 'blob.chunk' && e.data.last) {
      ws.send(JSON.stringify({ v: L.VERSION, type: 'task.delta', task_id: e.task_id, seq: 1, data: { text: 'seen' } }));
      ws.send(JSON.stringify({ v: L.VERSION, type: 'task.done', task_id: e.task_id, seq: 2, data: { finish_reason: 'stop', usage: { prompt_tokens: 1, completion_tokens: 1 } } }));
    }
  });
  const opts = { manual: () => {}, extraCaps: ['flow', 'resume', 'multimodal'],
    helloPatch: { flow: { task_window: WIN, conn_window: WIN }, model_capabilities: { m1: ['tools', 'vision'] } }, onWelcome: (w) => { token = w.data.resume_token; } };
  const d = await pairAndConnect(lmbp, base, 'acme', 'u1', opts);
  wire(d.ws);
  const ds = [...lmbp.engine.devs.values()][0];
  const msgs = () => [{ role: 'user', content: [{ type: 'text', text: 'look' }, { type: 'image_url', image_url: { url: image() } }] }];
  try {
    const ac = new AbortController();
    const c = lmbp.client('acme', 'u1');
    const st = c.chat.completions.stream({ model: 'm1', messages: msgs() }, { signal: ac.signal });
    const first = st.next().catch(() => {});
    await until(() => ds.out.waiters.length === 1, 5000, 'a blob.chunk send waiting for credit');
    const [id] = [...ds.tasks.keys()];
    d.ws.terminate();
    await until(() => !ds.ws, 5000, 'gateway noticed the disconnect');
    ac.abort(); // the caller goes away inside the resume window: task ends locally
    await first;
    await until(() => !ds.tasks.has(id), 5000, 'task ended');
    await new Promise((r) => setImmediate(r));
    assert.equal(ds.out.tasks.has(id), false, 'ended task re-created its outbox entry');
    assert.equal(ds.out.connUsed, 0, 'connection credit still held by the ended task');
    assert.equal(ds.out.waiters.length, 0, 'ended task still queued for credit');
    // resume, then a new chunked task must get the full window
    answer = true;
    const ws2 = await connect(base, d.pairing, d.tok, ['m1'], { ...opts, helloPatch: { ...opts.helloPatch, resume: { token, tasks: [] } } });
    wire(ws2);
    const st2 = lmbp.client('acme', 'u1').chat.completions.stream({ model: 'm1', messages: msgs() });
    let text = '';
    const done = (async () => { for await (const ch of st2) text += ch.choices.map((x) => x.delta.content || '').join(''); })();
    await Promise.race([done, new Promise((_, bad) => setTimeout(() => bad(new Error(`new chunked task blocked (connUsed ${ds.out.connUsed}, waiters ${ds.out.waiters.length})`)), 5000))]);
    assert.equal(text, 'seen');
    ws2.close();
  } finally {
    for (const x of lmbp.engine.devs.values()) x.ws?.terminate();
    srv.closeAllConnections(); await new Promise((ok) => srv.close(ok));
  }
});
