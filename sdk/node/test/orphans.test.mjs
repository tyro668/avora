// audit3 P2-5: a crash leaves QUEUED/RUNNING task rows. A restarted gateway
// stores OUTCOME_UNKNOWN for them (terminal event + FAILED state) so replays
// agree and retention purges the prompt and output. Was: synthesized on
// read only; the rows never became terminal and bypassed retention forever.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { LMBPServer, MemoryStore, SqliteStore } from '../dist/index.js';

for (const [name, mk] of [['memory', () => new MemoryStore()], ['sqlite', () => new SqliteStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lmbp-orphan-')), 'g.db'))]]) {
  test(`restart records orphaned tasks as OUTCOME_UNKNOWN and retention applies (${name})`, () => {
    const store = mk();
    for (const state of ['RUNNING', 'QUEUED']) {
      store.createTask({ id: 'task_orphan_' + state, tenant: 'acme', owner: 'u1', device: 'd', model: 'm', state, events: [], request: { secret: 'prompt' } });
    }
    store.appendEvent('task_orphan_RUNNING', { seq: 1, type: 'task.delta', data: { text: 'partial' } });
    const lmbp = new LMBPServer({ issuer: 'http://127.0.0.1:1', tenants: [{ id: 'acme', apiKey: 'k'.repeat(40) }], store, log: () => {}, retention: 60_000 });
    try {
      for (const state of ['RUNNING', 'QUEUED']) {
        const t = store.getTask('task_orphan_' + state);
        assert.equal(t.state, 'FAILED', `${state} orphan state ${t.state}`);
        const last = t.events.at(-1);
        assert.equal(last.type, 'task.error');
        assert.equal(last.data.code, 'OUTCOME_UNKNOWN');
        if (state === 'RUNNING') assert.equal(last.seq, 2);
      }
      assert.equal(lmbp.engine.purge(Date.now() + 120_000), 2, 'retention did not purge the orphans');
      assert.equal(store.getTask('task_orphan_RUNNING'), undefined);
    } finally { lmbp.close?.(); }
  });
}
