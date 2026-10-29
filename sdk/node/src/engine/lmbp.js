// LMBP primitives: base64url, EdDSA JWS/JWT, proofs, thumbprints, origins and
// the reliable flow-controlled delivery state machines (LMBP spec §8, §15).
import crypto from 'node:crypto';

export const VERSION = 2;
export const SUBPROTOCOL = 'lmbp';
export const PROTOCOL_VERSIONS = ['2.0'];
export const PAIR_LINK_VERSION = '2';
// Conformance profiles (spec §13.1); metadata.profiles lists those this gateway meets.
export const PROFILES = ['core', 'reliable', 'tools', 'multimodal', 'e2ee', 'openai', 'anthropic'];
export const MIN_CONCURRENCY = 1;
export const MAX_CONCURRENCY = 16;
export const VERSION_REQUIRED = 'LMBP 2.0 required: WebSocket subprotocol lmbp and envelope v 2 (LMBP 1.x is not supported)';
/** charLen counts Unicode code points, the unit of every string limit (spec §4.1). */
export const charLen = (s) => [...s].length;
/** Largest task.delta tool_calls[].index (spec §16.1). */
export const MAX_TOOL_CALL_INDEX = 127;
/** Encoded task.delta bytes one task may send, cleartext or sealed (spec §10). */
export const MAX_TASK_OUTPUT_BYTES = 64 << 20;
/** device_name: at most 100 code points (spec §6.2). */
export const MAX_DEVICE_NAME_CHARS = 100;
// Characters that can disguise text: C0/C1 controls, U+00AD, U+061C, U+180E,
// zero-width and directional marks, separators and embedding controls,
// invisible operators, BOM, interlinear annotation controls.
const DEVICE_NAME_FORBIDDEN = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFB]/u;
/** validDeviceName: the spec §6.2 rule for the untrusted, device-reported name. */
export const validDeviceName = (s) => typeof s === 'string' && s.isWellFormed?.() !== false && charLen(s) <= MAX_DEVICE_NAME_CHARS && !DEVICE_NAME_FORBIDDEN.test(s);
/** validHeader: 1..max printable ASCII (0x20-0x7E), for X-End-User and Idempotency-Key (spec §4.1). */
export const validHeader = (s, max) => typeof s === 'string' && s.length >= 1 && s.length <= max && /^[\x20-\x7E]+$/.test(s);
export const CAPABILITIES = ['session.token', 'models.update', 'resume', 'flow', 'tools', 'multimodal', 'e2ee'];
export const SCOPES = ['lmbp.chat', 'lmbp.tools', 'lmbp.vision', 'lmbp.audio'];
export const TENANT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// Normative limits (spec §10). Frame sizes are UTF-8 bytes of the encoded frame.
export const MAX_FRAME_BYTES = 256 << 10;
export const MAX_MESSAGES = 200;
// Encoded size of the task.run frame carrying jws (worst-case seq).
export const taskRunFrameSize = (jws, taskID) => Buffer.byteLength(JSON.stringify({ v: VERSION, type: 'task.run', task_id: taskID, seq: 2 ** 53, jws }));
export const BLOB_CHUNK_BYTES = 96 << 10;
export const MAX_BLOB_BYTES = 20 << 20;
export const MAX_TASK_BLOB_BYTES = 32 << 20;
export const INLINE_DATA_URI_BYTES = 16 << 10;
export const BLOB_SCHEME = 'lmbp-blob:';
export const TYP = { access: 'at+jwt', assertion: 'JWT', proof: 'lmbp-proof+jwt', task: 'lmbp-task+jws', metadata: 'lmbp-metadata+jwt', e2eeKey: 'lmbp-e2ee-key+jwt' };
export const PROOF = { token: 'lmbp:token', hello: 'lmbp:hello', sessionToken: 'lmbp:session.token' };
export const DATA_FRAMES = new Set(['task.run', 'blob.chunk', 'task.delta', 'task.done', 'task.error']);

const B64URL_RE = /^[A-Za-z0-9_-]*$/;
export const b64 = (buf) => Buffer.from(buf).toString('base64url');
export function unb64(s) {
  if (typeof s !== 'string' || !B64URL_RE.test(s) || s.length % 4 === 1) throw new Error('bad base64url');
  return Buffer.from(s, 'base64url');
}
export const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
export const shaHex = (s) => sha256(Buffer.from(s)).toString('hex');
export const randomID = (prefix = '') => prefix + crypto.randomBytes(16).toString('hex');
export const ath = (cred) => b64(sha256(Buffer.from(cred)));
export const thumbprint = (pub) => b64(sha256(Buffer.from(`{"crv":"Ed25519","kty":"OKP","x":"${b64(pub)}"}`)));
export const x25519Thumbprint = (pub) => b64(sha256(Buffer.from(`{"crv":"X25519","kty":"OKP","x":"${b64(pub)}"}`)));
export const publicJWK = (pub) => ({ kty: 'OKP', crv: 'Ed25519', x: b64(pub), kid: thumbprint(pub), alg: 'EdDSA', use: 'sig' });
export const tokenAudience = (iss, tenant) => `${iss}/tenants/${tenant}`;
export const assertionAudience = (iss) => `${iss}/lmbp/v1/token`;
export const now = () => Math.floor(Date.now() / 1000);

// Ed25519 key from a 32-byte seed (PKCS#8 wrapping).
export function signingKey(seed) {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  const pub = unb64(crypto.createPublicKey(priv).export({ format: 'jwk' }).x);
  return { priv, pub };
}
const pubKeyObj = (raw) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64(raw) }, format: 'jwk' });

export function signJWS(priv, typ, kid, payload) {
  const h = { alg: 'EdDSA', typ };
  if (kid) h.kid = kid;
  const input = b64(Buffer.from(JSON.stringify(h))) + '.' + b64(Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)));
  return input + '.' + b64(crypto.sign(null, Buffer.from(input), priv));
}

// verifyJWS: strict compact EdDSA JWS (spec §5.2). The protected header is
// exactly {alg: "EdDSA", typ, kid?}; any other member (crit, b64, jku, ...) is
// rejected; kid, when present, is the verifying key's RFC 7638 thumbprint.
// The payload MUST be a JSON object.
export function verifyJWS(pub, jws, typ) {
  if (typeof jws !== 'string') throw new Error('malformed JWS');
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('malformed JWS');
  let h;
  try { h = JSON.parse(unb64(parts[0]).toString()); } catch { throw new Error('bad JWS header'); }
  if (!isObject(h)) throw new Error('bad JWS header');
  for (const k of Object.keys(h)) if (k !== 'alg' && k !== 'typ' && k !== 'kid') throw new Error(`forbidden JWS header ${k}`);
  if (h.alg !== 'EdDSA') throw new Error('JWS alg must be EdDSA');
  if (h.typ !== typ) throw new Error(`JWS typ must be ${typ}`);
  if ('kid' in h && (typeof h.kid !== 'string' || !pub || pub.length !== 32 || h.kid !== thumbprint(pub))) throw new Error('JWS kid does not match the verifying key');
  const sig = unb64(parts[2]);
  if (!pub || pub.length !== 32 || sig.length !== 64 || !crypto.verify(null, Buffer.from(parts[0] + '.' + parts[1]), pubKeyObj(pub), sig)) throw new Error('bad JWS signature');
  const p = unb64(parts[1]);
  let c;
  try { c = JSON.parse(p.toString()); } catch { throw new Error('bad JWS payload'); }
  if (!isObject(c)) throw new Error('JWS payload must be a JSON object');
  return p;
}

const isObject = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
// A NumericDate is a JSON integer 0..2^53-1. Number.isSafeInteger also
// accepts 1.0 from JSON; the raw-text vectors never use that form.
export const isNumericDate = (x) => Number.isSafeInteger(x) && x >= 0;

// requireClaims: ints are NumericDates, strs non-empty strings, opt strings.
export function requireClaims(c, ints = [], strs = [], opt = []) {
  for (const k of ints) if (!isNumericDate(c[k])) throw new Error(`claim ${k} must be a non-negative integer`);
  for (const k of strs) if (typeof c[k] !== 'string' || c[k] === '') throw new Error(`claim ${k} must be a non-empty string`);
  for (const k of opt) if (typeof c[k] !== 'string') throw new Error(`claim ${k} must be a string`);
}

function timeRange(c) {
  requireClaims(c, ['iat', 'exp']);
  if (c.exp < c.iat) throw new Error('exp before iat');
}

export function verifyJWT(pub, tok, typ, aud, t = now()) {
  const c = JSON.parse(verifyJWS(pub, tok, typ).toString());
  requireClaims(c, [], ['iss', 'sub', 'aud', 'jti']);
  timeRange(c);
  if (c.aud !== aud) throw new Error('wrong audience');
  if (t > c.exp + 30 || t + 30 < c.iat) throw new Error('token expired');
  return c;
}

export function unverifiedClaims(tok) {
  const parts = String(tok || '').split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const c = JSON.parse(unb64(parts[1]).toString());
  if (!c || typeof c !== 'object') throw new Error('bad claims');
  return c;
}

export function verifyProof(pub, proof, deviceID, aud, credential, t = now()) {
  const c = JSON.parse(verifyJWS(pub, proof, TYP.proof).toString());
  requireClaims(c, ['iat'], ['aud', 'jti', 'ath'], ['iss']);
  if (c.aud !== aud || c.iss !== deviceID || !c.jti || c.ath !== ath(credential)) throw new Error('proof claims invalid');
  if (Math.abs(t - c.iat) > 60) throw new Error('proof iat outside allowed skew');
  return c;
}

export function verifyE2EEKey(devicePub, deviceID, stmt, t = now()) {
  const c = JSON.parse(verifyJWS(devicePub, stmt, TYP.e2eeKey).toString());
  requireClaims(c, [], ['iss', 'sub']);
  timeRange(c);
  const k = c.jwk;
  if (c.sub !== deviceID || c.iss !== deviceID || !k || k.kty !== 'OKP' || k.crv !== 'X25519') throw new Error('bad e2ee key statement');
  if (t > c.exp || t + 60 < c.iat) throw new Error('e2ee key statement expired');
  const x = unb64(k.x);
  if (x.length !== 32 || k.kid !== x25519Thumbprint(x)) throw new Error('bad e2ee key');
}

export function isLoopbackHost(h) {
  h = h.replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || /^127\.\d+\.\d+\.\d+$/.test(h);
}

// origin normalizes scheme://host[:port]; http only for loopback (§18.1).
export function origin(raw) {
  const s = String(raw).trim().replace(/\/+$/, '');
  let u;
  try { u = new URL(s); } catch { throw new Error(`not an origin: ${raw}`); }
  if (!u.host || u.username || u.password || u.search || u.hash || (u.pathname !== '' && u.pathname !== '/')) throw new Error(`not an origin: ${raw}`);
  if (u.protocol === 'http:' && !isLoopbackHost(u.hostname)) throw new Error(`issuer ${raw} must use https`);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`unsupported scheme in ${raw}`);
  return u.protocol + '//' + u.host.toLowerCase(); // URL drops default ports
}

export function canSend(flow, taskUsed, connUsed, n) {
  if (!flow) return true;
  return (taskUsed + n <= flow.task_window || taskUsed === 0) && (connUsed + n <= flow.conn_window || connUsed === 0);
}

// Outbox: sending half. send() resolves once the frame is admitted by the
// peer's windows; unacknowledged frames are retransmitted on resume.
const MAX_FORGOTTEN = 4096;
export class Outbox {
  constructor() { this.flow = null; this.connUsed = 0; this.tasks = new Map(); this.waiters = []; this.write = null; this.closed = false; this.forgotten = new Set(); }
  setFlow(f) { this.flow = f; this.wake(); }
  attach(write) { this.write = write; for (const t of this.tasks.values()) t.written = -1; }
  task(id) {
    let t = this.tasks.get(id);
    if (!t) { t = { nextSeq: 0, unacked: [], used: 0, written: 0 }; this.tasks.set(id, t); }
    return t;
  }
  fits(id, n) { return canSend(this.flow, this.task(id).used, this.connUsed, n); }
  // wake admits queued sends in strict FIFO order. Admission and credit
  // reservation are one synchronous step: the seq is assigned, the frame
  // built, recorded unacked and charged to both windows before the waiter is
  // released, so concurrent senders cannot jointly overshoot (audit finding 2).
  wake() {
    while (this.waiters.length) {
      const w = this.waiters[0];
      if (this.closed) { this.waiters.shift(); w.reject(new Error('outbox closed')); continue; }
      if (this.forgotten.has(w.task)) { this.waiters.shift(); w.reject(new Error('task forgotten')); continue; }
      const t = this.task(w.task);
      const seq = t.nextSeq + 1;
      const raw = w.mk(seq);
      const n = Buffer.byteLength(raw);
      if (!this.fits(w.task, n)) return;
      this.waiters.shift();
      t.nextSeq = seq;
      t.unacked.push({ seq, raw, n });
      t.used += n;
      this.connUsed += n;
      w.resolve(seq);
    }
  }
  flush(id) {
    for (;;) {
      const t = this.tasks.get(id);
      if (!t || !this.write || t.written < 0) return;
      const f = t.unacked.find((f) => f.seq > t.written);
      if (!f) return;
      t.written = f.seq;
      try { this.write(f.raw); } catch { return; }
    }
  }
  // build(seq) returns the envelope (without v/task_id/seq); deterministic in seq.
  async send(taskID, build, signal) {
    const mk = (seq) => JSON.stringify({ v: VERSION, ...build(seq), task_id: taskID, seq });
    if (this.closed) throw new Error('outbox closed');
    // A terminal (forgotten) task never re-enters the send queue: its state
    // would sit outside every retransmit list and hold connection credit.
    if (this.forgotten.has(taskID)) throw new Error('task forgotten');
    const seq = await new Promise((resolve, reject) => {
      const w = { task: taskID, mk, resolve, reject };
      this.waiters.push(w);
      signal?.addEventListener('abort', () => {
        const i = this.waiters.indexOf(w);
        if (i >= 0) { this.waiters.splice(i, 1); this.wake(); reject(new Error('aborted')); }
      }, { once: true });
      this.wake(); // commits w synchronously when it is first and fits
    });
    this.flush(taskID);
    return seq;
  }
  ack(id, seq) {
    const t = this.tasks.get(id);
    if (!t) return;
    while (t.unacked.length && t.unacked[0].seq <= seq) { const f = t.unacked.shift(); t.used -= f.n; this.connUsed -= f.n; }
    this.wake();
  }
  retransmit(id, peerRecv) {
    this.ack(id, peerRecv);
    const t = this.tasks.get(id);
    if (t) t.written = peerRecv;
    this.flush(id);
  }
  // forget drops a terminal task for good, atomically: its credit is
  // released and every send of it still queued for credit is failed BEFORE
  // other waiters are woken, so the task can never re-create its outbox
  // entry and re-consume connection credit no resume would ever return
  // (audit3 P1). Later sends for it fail too. Bounded like the Go Outbox.
  forget(id) {
    const t = this.tasks.get(id);
    if (t) { this.connUsed -= t.used; this.tasks.delete(id); }
    if (!this.forgotten.has(id)) {
      this.forgotten.add(id);
      if (this.forgotten.size > MAX_FORGOTTEN) this.forgotten.delete(this.forgotten.values().next().value);
    }
    const kept = [];
    for (const w of this.waiters) {
      if (w.task === id) w.reject(new Error('task forgotten'));
      else kept.push(w);
    }
    this.waiters = kept;
    this.wake();
  }
  close() { this.closed = true; this.wake(); }
}

export const ACCEPTED = 0, DUPLICATE = 1, GAP = 2, OVERFLOW = 3;

// Inbound: receiving half; detects duplicates/gaps and enforces our windows.
export class Inbound {
  constructor(flow) { this.flow = flow; this.connUsed = 0; this.tasks = new Map(); }
  accept(id, seq, size) {
    let t = this.tasks.get(id);
    if (!t) { t = { recv: 0, sizes: [], used: 0 }; this.tasks.set(id, t); }
    if (seq <= t.recv) return DUPLICATE;
    if (seq !== t.recv + 1) return GAP;
    const f = this.flow;
    if (f && ((t.used + size > f.task_window && t.used > 0) || (this.connUsed + size > f.conn_window && this.connUsed > 0))) return OVERFLOW;
    t.recv = seq; t.sizes.push([seq, size]); t.used += size; this.connUsed += size;
    return ACCEPTED;
  }
  acked(id, seq) {
    const t = this.tasks.get(id);
    if (!t) return;
    while (t.sizes.length && t.sizes[0][0] <= seq) { const [, n] = t.sizes.shift(); t.used -= n; this.connUsed -= n; }
  }
  recv(id) { return this.tasks.get(id)?.recv ?? 0; }
  resetWindows() { this.connUsed = 0; for (const t of this.tasks.values()) { t.used = 0; t.sizes = []; } }
  forget(id) { const t = this.tasks.get(id); if (t) { this.connUsed -= t.used; this.tasks.delete(id); } }
}
