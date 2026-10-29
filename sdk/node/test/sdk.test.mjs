import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LMBPServer, SqliteStore, PairingError, anthropic } from '../dist/index.js';
import { pairAndConnect, startPairing } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';

async function setup(opts = {}) {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY, profile: { display_name: 'Acme' } }], log: () => {}, ...opts });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  return { lmbp, srv, base, close: async () => { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); } };
}

test('anthropic.toOpenAI maps system, blocks, tools and tool_choice', () => {
  const o = anthropic.toOpenAI({ model: 'm', max_tokens: 10, system: [{ type: 'text', text: 'a' }, { type: 'text', text: 'b' }],
    tools: [{ name: 'f', input_schema: { type: 'object' } }], tool_choice: { type: 'tool', name: 'f' },
    messages: [{ role: 'user', content: [{ type: 'text', text: 'hi' }, { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }] },
      { role: 'assistant', content: [{ type: 'text', text: 'x' }, { type: 'tool_use', id: 't1', name: 'f', input: { a: 1 } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: 'r' }], is_error: true }] }] });
  assert.deepEqual(o.messages[0], { role: 'system', content: 'a\n\nb' });
  assert.equal(o.messages[1].content[1].image_url.url, 'data:image/png;base64,AAAA');
  assert.deepEqual(o.messages[2].tool_calls[0], { id: 't1', type: 'function', function: { name: 'f', arguments: '{"a":1}' } });
  assert.deepEqual(o.messages[3], { role: 'tool', tool_call_id: 't1', content: 'Error: r' });
  assert.deepEqual(o.tool_choice, { type: 'function', function: { name: 'f' } });
  assert.equal(o.tools[0].function.parameters.type, 'object');
  assert.throws(() => anthropic.toOpenAI({ model: 'm', messages: [{ role: 'user', content: 'x' }] }), /max_tokens/);
  assert.throws(() => anthropic.toOpenAI({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: [{ type: 'document' }] }] }), /unsupported/);
  assert.equal(anthropic.errorType(503), 'overloaded_error');
  assert.equal(anthropic.stopReason('tool_calls'), 'tool_use');
});

test('pairing API: link/QR, lookup, approve, list, revoke', async () => {
  const s = await setup({ issuer: 'https://gw.example.com' });
  try {
    const info = s.lmbp.pairing.create(T);
    assert.equal(info.link, 'lmbp://pair?v=2&gateway=https%3A%2F%2Fgw.example.com&tenant=acme');
    assert.match(info.qrSVG, /^<svg/);
    assert.match(info.qrDataURL, /^data:image\/gif;base64,/);
    const p = await startPairing(s.base, T, 'my-laptop');
    const pend = s.lmbp.pairing.lookup(T, 'u1', p.user_code.toLowerCase().replace('-', ''));
    assert.equal(pend.deviceName, 'my-laptop');
    assert.equal(pend.status, 'pending');
    assert.throws(() => s.lmbp.pairing.approve(T, 'u1', 'BBBB-BBBB'), PairingError);
    const ok = s.lmbp.pairing.approve(T, 'u1', p.user_code, { jkt: pend.jkt });
    assert.equal(ok.status, 'approved');
    assert.throws(() => s.lmbp.pairing.approve(T, 'u1', p.user_code), /already used/);
    const ds = s.lmbp.pairing.listDevices(T, 'u1');
    assert.equal(ds.length, 1);
    assert.equal(ds[0].deviceId, ok.deviceId);
    assert.equal(s.lmbp.pairing.listDevices(T, 'someone-else').length, 0);
    assert.equal(s.lmbp.pairing.revokeDevice(T, 'u2', ok.deviceId), false);
    assert.equal(s.lmbp.pairing.revokeDevice(T, 'u1', ok.deviceId), true);
    assert.equal(s.lmbp.pairing.listDevices(T, 'u1')[0].status, 'revoked');
    const p2 = await startPairing(s.base, T);
    assert.equal(s.lmbp.pairing.deny(T, 'u1', p2.user_code).status, 'denied');
    assert.equal(s.lmbp.keys.jwks().keys[0].kid, s.lmbp.keys.kid());
  } finally { await s.close(); }
});

test('in-process client: OpenAI and Anthropic, streaming and not', async () => {
  const s = await setup();
  try {
    const { ws, deviceId } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
    const c = s.lmbp.client(T, 'u1');
    const models = await c.models();
    assert.equal(models[0].id, `${deviceId}/m1`);
    const r = await c.chat.completions.create({ model: 'm1', messages: [{ role: 'user', content: 'hello' }] });
    assert.equal(r.choices[0].message.content, 'echo: hello');
    let txt = '';
    for await (const ch of c.chat.completions.stream({ model: 'm1', messages: [{ role: 'user', content: 'streamed' }] })) txt += ch.choices[0]?.delta?.content ?? '';
    assert.equal(txt, 'echo: streamed');
    const m = await c.messages.create({ model: 'm1', max_tokens: 16, system: 's', messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(m.content[0].text, 'echo: hi');
    assert.equal(m.usage.output_tokens, 4);
    const tools = [{ name: 'get_weather', input_schema: { type: 'object' } }];
    const tu = await c.messages.create({ model: 'm1', max_tokens: 16, tools, messages: [{ role: 'user', content: 'weather?' }] });
    assert.equal(tu.stop_reason, 'tool_use');
    assert.deepEqual(tu.content[0], { type: 'tool_use', id: 'call_1', name: 'get_weather', input: { city: 'Paris' } });
    const names = [];
    let out = '';
    for await (const e of c.messages.stream({ model: 'm1', max_tokens: 16, tools, messages: [{ role: 'user', content: 'weather?' }, { role: 'assistant', content: tu.content },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'call_1', content: 'sunny' }] }] })) {
      names.push(e.type);
      if (e.type === 'content_block_delta') out += e.delta.text;
    }
    assert.equal(out, 'echo: tool said sunny');
    assert.deepEqual([names[0], names.at(-2), names.at(-1)], ['message_start', 'message_delta', 'message_stop']);
    await assert.rejects(c.messages.create({ model: 'nope', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] }), (e) => e.status === 404 && e.code === 'MODEL_NOT_FOUND');
    await assert.rejects(s.lmbp.client('nope', 'u1').models(), (e) => e.status === 401);
    ws.close();
  } finally { await s.close(); }
});

test('middleware falls through to next() for unknown paths', async () => {
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], log: () => {} });
  const mw = lmbp.middleware();
  const srv = http.createServer((req, res) => mw(req, res, () => { res.end('app'); }));
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    assert.equal(await (await fetch(base + '/my/app')).text(), 'app');
    assert.equal((await (await fetch(base + '/healthz')).json()).status, 'ok');
    const r = await fetch(base + '/v1/messages', { method: 'POST', headers: { 'x-api-key': 'bad', 'content-type': 'application/json' }, body: '{}' });
    assert.equal(r.status, 401);
    assert.equal((await r.json()).error.type, 'authentication_error');
  } finally { srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); }
});

test('SqliteStore persists signing key, devices and finished tasks across restarts', async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-')), 'gw.db');
  let s = await setup({ store: new SqliteStore(file) });
  const kid = s.lmbp.keys.kid();
  const { ws, deviceId } = await pairAndConnect(s.lmbp, s.base, T, 'u1');
  const r = await s.lmbp.client(T, 'u1').chat.completions.create({ model: 'm1', messages: [{ role: 'user', content: 'persist me' }] });
  ws.close();
  await s.close();
  s.lmbp.store.close();
  s = await setup({ store: new SqliteStore(file) });
  try {
    assert.equal(s.lmbp.keys.kid(), kid);
    const ds = s.lmbp.pairing.listDevices(T, 'u1');
    assert.equal(ds.length, 1);
    assert.equal(ds[0].deviceId, deviceId);
    const taskID = r.id.replace('chatcmpl-', '');
    const ev = await fetch(`${s.base}/lmbp/v1/tenant/tasks/${taskID}/events`, { headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1' } });
    assert.equal(ev.status, 200);
    assert.match(await ev.text(), /persist me/);
  } finally { await s.close(); s.lmbp.store.close(); }
});
