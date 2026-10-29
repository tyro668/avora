// Review9 P2-new-1: registering the Fastify plugin must not change how the
// host SaaS parses its own request bodies. The plugin used to replace the
// application/json and text/plain parsers with raw-Buffer ones and set
// skip-override, so the change leaked into the parent instance: the host's
// JSON POST routes then saw a Buffer (req.body.prompt undefined) and body
// schema validation failed.
import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);

async function hostApp(withPlugin, order) {
  const app = Fastify();
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: 'acme', apiKey: KEY }], log: () => {} });
  const routes = () => {
    app.post('/app/generate', {
      schema: { body: { type: 'object', required: ['prompt'], properties: { prompt: { type: 'string' }, n: { type: 'integer' } } } },
    }, async (req) => ({ isBuffer: Buffer.isBuffer(req.body), prompt: req.body.prompt, n: req.body.n ?? null }));
    app.post('/app/text', async (req) => ({ type: typeof req.body, isBuffer: Buffer.isBuffer(req.body), body: String(req.body) }));
    app.post('/app/device', async (req) => ({ user_code: req.body?.user_code ?? null }));
  };
  if (withPlugin && order === 'before') await app.register(lmbp.fastifyPlugin);
  routes();
  if (withPlugin && order === 'after') await app.register(lmbp.fastifyPlugin);
  await app.listen({ port: lmbpPort, host: '127.0.0.1' });
  return { app, lmbp, base: `http://127.0.0.1:${app.server.address().port}` };
}

async function probe(base) {
  const post = async (p, type, body) => { const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': type }, body }); return [r.status, await r.json()]; };
  return {
    ok: await post('/app/generate', 'application/json', JSON.stringify({ prompt: 'hi', n: 2 })),
    invalid: (await post('/app/generate', 'application/json', JSON.stringify({ n: 'x' })))[0],
    text: await post('/app/text', 'text/plain', 'plain body'),
    device: await post('/app/device', 'application/json; charset=utf-8', JSON.stringify({ user_code: 'ABCD-EFGH' })),
  };
}

test('fastify plugin: host JSON / text POST routes behave the same with and without the plugin', async () => {
  const { app: plain, base: b0 } = await hostApp(false);
  let want;
  try { want = await probe(b0); } finally { await plain.close(); }
  assert.deepEqual(want.ok, [200, { isBuffer: false, prompt: 'hi', n: 2 }]);
  assert.equal(want.invalid, 400);
  for (const order of ['before', 'after']) {
    const { app, lmbp, base } = await hostApp(true, order);
    try {
      assert.deepEqual(await probe(base), want, `plugin registered ${order} the host routes changed host body parsing`);
      // the protocol routes still get the raw body and work end to end
      const { ws } = await pairAndConnect(lmbp, base, 'acme', 'u1');
      const r = await (await fetch(base + '/v1/chat/completions', { method: 'POST',
        headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'm1', messages: [{ role: 'user', content: 'scoped' }] }) })).json();
      assert.equal(r.choices[0].message.content, 'echo: scoped');
      ws.close();
    } finally { await app.close(); }
  }
});
