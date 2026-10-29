import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import Fastify from 'fastify';
import express from 'express';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';
const chat = (base, body, path = '/v1/chat/completions') => fetch(base + path, { method: 'POST',
  headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('fastify plugin: protocol routes, WebSocket upgrade and chat next to app routes', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], log: () => {} });
  const app = Fastify();
  await app.register(lmbp.fastifyPlugin);
  app.get('/app/hello', async () => ({ hi: true }));
  await app.listen({ port: lmbpPort, host: '127.0.0.1' });
  const base = `http://127.0.0.1:${app.server.address().port}`;
  try {
    assert.deepEqual(await (await fetch(base + '/app/hello')).json(), { hi: true });
    const { ws } = await pairAndConnect(lmbp, base, T, 'u1');
    const r = await (await chat(base, { model: 'm1', messages: [{ role: 'user', content: 'fast' }] })).json();
    assert.equal(r.choices[0].message.content, 'echo: fast');
    const m = await (await chat(base, { model: 'm1', max_tokens: 8, messages: [{ role: 'user', content: 'msg' }] }, '/v1/messages')).json();
    assert.equal(m.content[0].text, 'echo: msg');
    ws.close();
  } finally { await app.close(); }
});

test('express: middleware before and after express.json()', async () => {
  for (const order of ['before', 'after']) {
    const lmbpPort = await freePort();
    const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], log: () => {} });
    const app = express();
    if (order === 'after') app.use(express.json());
    app.use(lmbp.middleware());
    if (order === 'before') app.use(express.json());
    app.post('/app/echo', (req, res) => res.json(req.body));
    const srv = http.createServer(app);
    lmbp.attach(srv);
    await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      const { ws } = await pairAndConnect(lmbp, base, T, 'u1');
      const r = await (await chat(base, { model: 'm1', messages: [{ role: 'user', content: order }] })).json();
      assert.equal(r.choices[0].message.content, 'echo: ' + order, order);
      assert.deepEqual(await (await fetch(base + '/app/echo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"a":1}' })).json(), { a: 1 });
      ws.close();
    } finally { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); }
  }
});
