// Third audit #2: request parameters are validated against the protocol
// before anything is signed. spec/testvectors/params.json is shared by Go,
// Node, Python and the conformance tool (Z8).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { LMBPServer } from '../dist/index.js';
import { pairAndConnect } from '../test-support/simdevice.mjs';
import { freePort } from './_port.mjs';

const KEY = 'k'.repeat(40);
const T = 'acme';
const V = JSON.parse(fs.readFileSync(new URL('../../../spec/testvectors/params.json', import.meta.url)));

function body(c, model) {
  const m = { ...V.base[c.endpoint], model };
  Object.assign(m, c.set);
  for (const k of c.remove ?? []) delete m[k];
  return m;
}
const errParam = (b) => {
  const e = b?.error ?? {};
  return e.code ? [e.code, e.param] : [e.lmbp_code, e.lmbp_param];
};

test('shared request-parameter vectors (spec/testvectors/params.json)', async () => {
  assert.ok(V.cases.length >= 80);
  const lmbpPort = await freePort();
  const lmbp = new LMBPServer({ issuer: `http://127.0.0.1:${lmbpPort}`, tenants: [{ id: T, apiKey: KEY }], log: () => {} });
  const srv = http.createServer(lmbp.handler);
  lmbp.attach(srv);
  await new Promise((ok) => srv.listen(lmbpPort, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const runs = new Map();
  const { ws } = await pairAndConnect(lmbp, base, T, 'u1', { onRun: (r) => runs.set(r.task_id, r) });
  const failures = [];
  try {
    for (const c of V.cases) {
      const path = c.endpoint === 'chat' ? '/v1/chat/completions' : '/v1/messages';
      const before = runs.size;
      const r = await fetch(base + path, { method: 'POST', body: JSON.stringify(body(c, 'm1')),
        headers: { Authorization: 'Bearer ' + KEY, 'X-End-User': 'u1', 'Content-Type': 'application/json' } });
      const text = await r.text();
      const name = `${c.endpoint}/${c.name}`;
      if (r.status !== c.status) { failures.push(`${name}: status ${r.status}, want ${c.status}: ${text.slice(0, 160)}`); continue; }
      if (c.status !== 200) {
        let j; try { j = JSON.parse(text); } catch { j = null; }
        const [code, param] = errParam(j);
        if (code !== c.code || param !== c.param) failures.push(`${name}: code ${code} param ${param}, want ${c.code} ${c.param}: ${text.slice(0, 160)}`);
        if (runs.size !== before) failures.push(`${name}: rejected request reached the device`);
        continue;
      }
      const run = runs.get(r.headers.get('x-task-id'));
      if (!run) { failures.push(`${name}: no task.run`); continue; }
      for (const [k, want] of Object.entries(c.run ?? {})) {
        try { assert.deepEqual(run[k], want); } catch { failures.push(`${name}: task.run ${k} = ${JSON.stringify(run[k])}, want ${JSON.stringify(want)}`); }
      }
      for (const k of c.run_absent ?? []) if (k in run) failures.push(`${name}: task.run has ${k}`);
    }
  } finally { ws.close(); srv.closeAllConnections(); await new Promise((ok) => srv.close(ok)); }
  assert.deepEqual(failures, [], `${failures.length} of ${V.cases.length} vectors failed:\n` + failures.join('\n'));
});

test('bundled schemas are byte-identical to spec/schemas', () => {
  for (const n of ['defs.json', 'task.run.payload.json']) {
    assert.equal(fs.readFileSync(new URL(`../schemas/${n}`, import.meta.url), 'utf8'),
      fs.readFileSync(new URL(`../../../spec/schemas/${n}`, import.meta.url), 'utf8'), `${n} is stale: copy spec/schemas/${n} to sdk/node/schemas/`);
  }
});

test('the schema validator fails closed on unsupported keywords', async () => {
  const { SchemaSet } = await import('../dist/engine/jsonschema.js');
  assert.throws(() => new SchemaSet([{ $id: 'https://x/a.json', type: 'string', format: 'email' }]), /unsupported keyword format/);
});

test('task.run schema backstop rejects what must never be signed', async () => {
  const { validateTaskRun, ParamError } = await import('../dist/engine/params.js');
  const base = { task_id: 'task_1', iat: 1, exp: 2, nonce: 'n'.repeat(20), device_id: 'dev_1', model: 'm', messages: [{ role: 'user', content: 'hi' }] };
  validateTaskRun(base);
  for (const [param, mut] of Object.entries({
    temperature: { temperature: 3 }, max_tokens: { max_tokens: -1 }, top_p: { top_p: 1.5 },
    stop: { stop: ['a', 'b', 'c', 'd', 'e'] }, messages: { messages: [{ role: 'robot' }] }, nonce: { nonce: 'short' },
  })) {
    assert.throws(() => validateTaskRun({ ...base, ...mut }), (e) => e instanceof ParamError && e.param === param, param);
  }
  assert.throws(() => validateTaskRun({ ...base, messages: undefined }), ParamError); // neither messages nor e2ee
});
