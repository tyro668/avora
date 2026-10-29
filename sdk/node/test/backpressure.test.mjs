// B2: an in-process caller that stops reading must stop the device (via the
// §15 window: acks follow delivery), so gateway memory stays bounded.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
test('slow in-process consumer: device output is bounded by the window', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const stats = { sent: 0 };
  const N = 256, SIZE = 32 * 1024; // 8 MiB total, window 1 MiB
  const { ws } = await pairAndConnect(lmbp, base, 'acme', 'u1', { flood: { n: N, size: SIZE, stats } });
  try {
    const c = lmbp.client('acme', 'u1');
    const st = c.chat.completions.stream({ model: 'm1', messages: [{ role: 'user', content: 'go' }] });
    const first = await st.next(); // read one chunk, then stall
    await new Promise((ok) => setTimeout(ok, 1500));
    const stalled = stats.sent;
    assert.ok(stalled < 3 * (1 << 20), `device sent ${stalled} bytes to a stalled consumer (want < 3 MiB of 8 MiB)`);
    // drain: everything still arrives, in order, ending with the terminator
    let text = (first.value.choices[0]?.delta?.content || '').length;
    for await (const ch of st) text += (ch.choices[0]?.delta?.content || '').length;
    assert.equal(text, N * SIZE);
    assert.equal(stats.sent > stalled, true);
  } finally {
    ws.close(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok));
  }
});
