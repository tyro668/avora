// audit3 P2-8: LMBPStream.return()/throw() fire an independent cancel signal
// synchronously. An async generator queues return() behind a pending next();
// with a silent model that next() never settles, so return() hung and the
// gateway task (and its concurrency slot) stayed alive.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const within = (p, ms, what) => Promise.race([p, new Promise((_, bad) => setTimeout(() => bad(new Error('timed out: ' + what)), ms))]);

async function rig() {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const runs = [];
  const d = await pairAndConnect(lmbp, base, 'acme', 'u1', { manual: (run) => runs.push(run.task_id) }); // silent model
  const cancels = [];
  d.ws.on('message', (raw) => { const e = JSON.parse(raw); if (e.type === 'task.cancel') cancels.push(e.task_id); });
  const close = async () => { d.ws.terminate(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); await lmbp.close(); };
  return { lmbp, runs, cancels, close };
}

for (const how of ['return', 'throw']) {
  for (const api of ['chat', 'messages']) {
    test(`${api}: ${how}() with a pending next() on a silent model ends the stream and cancels the task`, async () => {
      const r = await rig();
      try {
        const c = r.lmbp.client('acme', 'u1');
        const st = api === 'chat'
          ? c.chat.completions.stream({ model: 'm1', messages: [{ role: 'user', content: 'hi' }] })
          : c.messages.stream({ model: 'm1', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }] });
        // drain what the gateway sends on its own (role preamble / message_start) until next() pends
        let pending;
        for (;;) {
          pending = st.next();
          const v = await Promise.race([pending, new Promise((ok) => setTimeout(() => ok('pending'), 500))]);
          if (v === 'pending') break;
          assert.equal(v.done, false, 'stream ended before the model answered');
        }
        assert.equal(r.runs.length, 1, 'task not dispatched');
        const ended = how === 'return' ? st.return() : st.throw(new Error('consumer gave up')).catch((e) => e);
        await within(ended, 2000, `${how}() hung behind the pending next()`);
        const p = await within(pending, 2000, 'pending next() never settled');
        assert.equal(p.done, true);
        const end = Date.now() + 2000;
        while (!r.cancels.includes(r.runs[0]) && Date.now() < end) await new Promise((ok) => setTimeout(ok, 20));
        assert.ok(r.cancels.includes(r.runs[0]), 'the gateway never sent task.cancel to the device');
      } finally { await r.close(); }
    });
  }
}
