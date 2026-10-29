// LMBP gateway engine (Node.js), the core of the lmbp-server SDK.
// Behaviourally equivalent to the Go reference gateway (internal/lmbp/gateway):
// RFC 8628 pairing, EdDSA tokens bound to issuer/tenant audiences, gateway
// metadata + signed_metadata, RFC 7523 refresh, the lmbp WebSocket tunnel
// (seq/ack/resume, credit flow control, tools, multimodal blobs, E2EE relay),
// an OpenAI-compatible API and the Anthropic Messages API (§6.7).
// Durable state goes through a Store (../store.ts); live sessions are in-process.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { WebSocketServer } from 'ws';
import * as L from './lmbp.js';
import { MemoryStore } from '../store.js';
import * as A from '../anthropic.js';
import { validateChatParams, validateAnthropicParams, validateTaskRun, announceProblem, deviceDataProblem, paramErrorBody, ParamError } from './params.js';

const PROBLEM_BASE = 'https://avora.dev/problems/';
const USER_CODE_CHARS = 'BCDFGHJKLMNPQRSTVWXZ';
const STATUS_OF = {
  BAD_REQUEST: 400, CAPABILITY_UNSUPPORTED: 400, PAYLOAD_TOO_LARGE: 413, IDEMPOTENCY_KEY_REUSED: 422, MODEL_NOT_FOUND: 404,
  DEVICE_OFFLINE: 503, DEVICE_BUSY: 429, TIMEOUT: 504, CANCELLED: 499, RATE_LIMITED: 429, UNAUTHENTICATED: 401, FORBIDDEN: 403,
  CONSENT_DENIED: 403,
};
const errStatus = (code) => STATUS_OF[code] ?? 502;
/** Test-only: raceHooks.hook(task, point) is called at named points of the terminal paths (null in production). */
export const raceHooks = { hook: null };
const hook = (t, point) => raceHooks.hook?.(t, point);
const isTerminal = (t) => t === 'task.done' || t === 'task.error';
const TERMINAL_STATES = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED']);
const stateOf = (ev) => ev.type === 'task.done' ? 'SUCCEEDED' : (ev.data?.code === 'CANCELLED' ? 'CANCELLED' : 'FAILED');
const errorBody = (code, message, retryable = false) => ({ code, message, retryable });
export const RETENTION_DEFAULT = 7 * 24 * 3600_000;
/** How often the retention pass runs: half the period, between 1 s and 1 h. */
export const retentionEvery = (ret) => Math.min(3600_000, Math.max(1000, Math.floor(ret / 2)));

/** Pairing abuse limits (spec §6.2–§6.4, §10). */
export const LIMITS = { authorizePerMinute: 60, maxPendingPerTenant: 1000, maxSlowDowns: 10, failuresPerMinute: 10 };
const INITIAL_INTERVAL = 2;

/**
 * JtiCache remembers proof/assertion jtis until they expire. Expired entries
 * leave from the top of a min-heap ordered by expiry (O(log n) per call),
 * never by scanning the whole set.
 */
export class JtiCache {
  constructor() { this.seen = new Map(); this.heap = []; }
  get size() { return this.seen.size; }
  evict(now) {
    const h = this.heap;
    while (h.length && h[0][0] < now) {
      const [at, j] = this.pop();
      if (this.seen.get(j) === at) this.seen.delete(j);
    }
  }
  has(j, now = Date.now()) { this.evict(now); return this.seen.has(j); }
  /** Records j until untilMs; false if it is already recorded. */
  use(j, untilMs, now = Date.now()) {
    this.evict(now);
    if (this.seen.has(j)) return false;
    this.seen.set(j, untilMs);
    const h = this.heap;
    h.push([untilMs, j]);
    for (let i = h.length - 1; i > 0;) {
      const p = (i - 1) >> 1;
      if (h[p][0] <= h[i][0]) break;
      [h[p], h[i]] = [h[i], h[p]]; i = p;
    }
    return true;
  }
  pop() {
    const h = this.heap, top = h[0], last = h.pop();
    if (h.length) {
      h[0] = last;
      for (let i = 0; ;) {
        const l = 2 * i + 1, r = l + 1;
        let m = i;
        if (l < h.length && h[l][0] < h[m][0]) m = l;
        if (r < h.length && h[r][0] < h[m][0]) m = r;
        if (m === i) break;
        [h[m], h[i]] = [h[i], h[m]]; i = m;
      }
    }
    return top;
  }
}

/** windowCounter counts events per key in fixed one-minute windows (the whole map is dropped when the window rolls). */
class WindowCounter {
  constructor() { this.start = 0; this.n = new Map(); }
  allow(key, limit, now = Date.now()) {
    if (now - this.start >= 60_000) { this.start = now; this.n = new Map(); }
    const c = this.n.get(key) || 0;
    if (c >= limit) return false;
    this.n.set(key, c + 1);
    return true;
  }
}

export class Gateway {
  constructor(cfg = {}) {
    // §18.1: the issuer is configuration, never derived from a request's Host.
    if (!cfg.issuer) throw new Error('lmbp: issuer is required (the gateway\'s public origin, e.g. https://gw.example.com)');
    this.cfg = {
      issuer: cfg.issuer ? L.origin(cfg.issuer) : '', codeTTL: 600, tokenTTL: 900, maxConc: 16, pingInterval: 20_000,
      resumeWindow: 30_000, taskTimeout: 10 * 60_000, slowConsumer: 60_000, attachGrace: 30_000, queueTimeout: 15_000,
      flow: { task_window: 1 << 20, conn_window: 4 << 20 }, log: console.error, ...cfg,
    };
    // Retention (spec §14.4, errata E6): 7 days by default, 0/undefined keeps the default, negative disables.
    if (!this.cfg.retention) this.cfg.retention = RETENTION_DEFAULT;
    if (cfg.issuer) this.cfg.issuer = L.origin(cfg.issuer);
    this.store = cfg.store ?? new MemoryStore();
    let seed = cfg.seed;
    if (!seed) {
      seed = this.store.getSecret('gateway_signing_seed');
      if (!seed) { seed = crypto.randomBytes(32); this.store.putSecret('gateway_signing_seed', seed); }
    }
    ({ priv: this.priv, pub: this.pub } = L.signingKey(seed));
    this.kid = L.thumbprint(this.pub);
    this.tenants = new Map();     // id → {id, name, keyHash, profile}
    this.devs = new Map();        // device id → DState (live / resumable)
    this.tasks = new Map();       // task id → Task hub
    this.jtis = new JtiCache();
    this.fails = new Map();       // tenant \0 end user → failure times (last minute)
    this.pending = new Map();     // tenant → Map(device_code hash → expiry ms)
    this.authRate = new WindowCounter();
    this.wss = new WebSocketServer({ noServer: true, maxPayload: L.MAX_FRAME_BYTES, perMessageDeflate: false,
      handleProtocols: (ps) => (ps.has(L.SUBPROTOCOL) ? L.SUBPROTOCOL : false) });
    this.recoverOrphans();
    this.startRetention();
  }

  // recoverOrphans stores OUTCOME_UNKNOWN for tasks a previous process left
  // without a terminal state (crash while QUEUED/RUNNING): this gateway owns
  // no task yet, so all of them are orphans. The persisted terminal event
  // and state make replays agree and let retention purge the prompt and
  // output; without it they bypassed retention forever (audit3 P2-5).
  recoverOrphans() {
    if (typeof this.store.unfinishedTasks !== 'function') return;
    let ids;
    try { ids = this.store.unfinishedTasks(); } catch (e) { this.cfg.log('lmbp: listing unfinished tasks:', e); return; }
    for (const id of ids) {
      try {
        const rec = this.store.getTask(id);
        if (!rec) continue;
        const seq = rec.events.reduce((m, e) => Math.max(m, e.seq), 0) + 1;
        this.store.finishTask(id, { seq, type: 'task.error', data: errorBody('OUTCOME_UNKNOWN', 'gateway restarted; task outcome unknown') }, 'FAILED');
      } catch (e) { this.cfg.log(`lmbp: orphaned task ${id}:`, e); }
    }
    if (ids.length) this.cfg.log(`lmbp: ${ids.length} orphaned task(s) from a previous run recorded as OUTCOME_UNKNOWN`);
  }

  /** Purges finished tasks (with their idempotency records) older than cfg.retention, every retentionEvery(). */
  startRetention() {
    if (this.cfg.retention < 0) return;
    if (typeof this.store.purge !== 'function') { this.cfg.log('lmbp: store has no purge(); retention is disabled'); return; }
    this.retentionTimer = setInterval(() => this.purge(), retentionEvery(this.cfg.retention)).unref();
  }

  stopRetention() { clearInterval(this.retentionTimer); this.retentionTimer = null; }

  /** One retention pass; returns the number of tasks removed from the store. */
  purge(now = Date.now()) {
    const cutoff = now - this.cfg.retention;
    let n = 0;
    try { n = this.store.purge(cutoff); } catch (e) { this.cfg.log('retention purge:', e); return 0; }
    for (const [id, t] of this.tasks) if (t.finishedAt && t.finishedAt < cutoff) this.tasks.delete(id);
    if (n > 0) this.cfg.log(`retention purge: removed ${n} tasks`);
    return n;
  }

  registerTenant(id, apiKey, profile = {}) {
    if (!L.TENANT_ID_RE.test(id)) throw new Error('invalid tenant id ' + id);
    if (!apiKey || apiKey.length < 32) throw new Error('tenant API key must be at least 32 characters');
    for (const s of profile.requested_scopes ?? []) if (!L.SCOPES.includes(s)) throw new Error('unknown scope ' + s);
    this.tenants.set(id, { id, name: profile.display_name || id, keyHash: L.shaHex(apiKey), profile });
  }

  // eslint-disable-next-line no-unused-vars
  issuer(_req) { return this.cfg.issuer; }

  useJTI(j, untilMs) { return this.jtis.use(j, untilMs); }

  verifyAccess(tok, iss) {
    const uc = L.unverifiedClaims(tok);
    const c = L.verifyJWT(this.pub, tok, L.TYP.access, L.tokenAudience(iss, uc.tenant), L.now());
    if (c.iss !== iss) throw new Error('token issuer mismatch');
    return c;
  }

  online(id) { const ds = this.devs.get(id); return ds && ds.connected() ? ds : null; }

  // ---------- HTTP plumbing ----------
  listen(port, host) {
    this.server = http.createServer((req, res) => this.handle(req, res).catch((e) => {
      this.cfg.log('handler error', e);
      if (!res.headersSent) problem(res, 500, 'INTERNAL', 'internal error'); else res.end();
    }));
    this.server.on('upgrade', (req, sock, head) => this.upgrade(req, sock, head).catch(() => sock.destroy()));
    return new Promise((ok) => this.server.listen(port, host, () => ok(this.server.address())));
  }

  // handle serves one request. With next, unknown paths fall through to it
  // (framework middleware); without, they get a 404.
  async handle(req, res, next) {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const err = (s, code, msg) => (p.startsWith('/v1/') ? apiError(res, s, code, msg) : problem(res, s, code, msg));
    if (p === '/healthz') return json(res, 200, { status: 'ok' });
    if (this.cfg.webDir && WEB_FILES[p] && (req.method === 'GET' || req.method === 'HEAD')) return this.serveWeb(res, p);
    if (p === '/.well-known/jwks.json') { res.setHeader('Cache-Control', 'public, max-age=300'); return json(res, 200, { keys: [L.publicJWK(this.pub)] }); }
    if (p === '/.well-known/lmbp') return this.metadata(req, res, u);
    if (p === '/lmbp/v1/device/authorize') return this.authorize(req, res);
    if (p === '/lmbp/v1/token') return this.token(req, res);
    if (p === '/lmbp/v1/connect') return problem(res, 400, 'VERSION_UNSUPPORTED', L.VERSION_REQUIRED);
    if (p === '/lmbp/v1/tenant/devices/approvals') return this.approve(req, res, err);
    if (p === '/lmbp/v1/tenant/devices') return this.listDevices(req, res, err);
    let m;
    if ((m = p.match(/^\/lmbp\/v1\/tenant\/devices\/([^/]+)\/revoke$/))) return this.revoke(req, res, err, decodeURIComponent(m[1]));
    if ((m = p.match(/^\/lmbp\/v1\/tenant\/tasks\/([^/]+)\/events$/)) && req.method === 'GET') return this.taskEvents(req, res, err, m[1]);
    if (p === '/v1/models') return this.models(req, res, err);
    if (p === '/v1/chat/completions') return this.chat(req, res, err);
    if (p === '/v1/messages') return this.messages(req, res);
    if (next) return next();
    return err(404, 'BAD_REQUEST', 'not found');
  }

  // Shared mock SaaS chat page (mock/web): static files only, no secrets.
  serveWeb(res, p) {
    const [file, type] = WEB_FILES[p];
    let b;
    try { b = fs.readFileSync(this.cfg.webDir + '/' + file); } catch { return json(res, 404, { error: 'chat UI not installed' }); }
    res.writeHead(200, { 'Content-Type': type, 'Content-Security-Policy': WEB_CSP, 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-cache', 'Content-Length': b.length });
    return res.end(b);
  }

  tenantAuth(req, err) {
    const ip = req[Symbol.for('lmbp.inProcessTenant')];
    if (ip) {
      const user = req.headers['x-end-user'];
      if (!L.validHeader(user, 128)) { err(400, 'BAD_REQUEST', 'end user must be 1-128 printable ASCII characters'); return null; }
      return { t: ip, user };
    }
    let a = req.headers.authorization || '';
    if (!a && req.headers['x-api-key']) a = 'Bearer ' + req.headers['x-api-key'];
    if (!a.startsWith('Bearer ')) { err(401, 'UNAUTHENTICATED', 'tenant API key required'); return null; }
    const h = L.shaHex(a.slice(7));
    const t = [...this.tenants.values()].find((t) => crypto.timingSafeEqual(Buffer.from(t.keyHash), Buffer.from(h)));
    if (!t) { err(401, 'UNAUTHENTICATED', 'invalid tenant API key'); return null; }
    const user = req.headers['x-end-user'];
    if (!L.validHeader(user, 128)) { err(400, 'BAD_REQUEST', 'X-End-User must be 1-128 printable ASCII characters'); return null; }
    return { t, user };
  }

  // ---------- §18 metadata ----------
  buildMetadata(iss, t) {
    const ws = 'ws' + iss.slice(4);
    const m = { issuer: iss, jwks_uri: iss + '/.well-known/jwks.json', device_authorization_endpoint: iss + '/lmbp/v1/device/authorize',
      token_endpoint: iss + '/lmbp/v1/token', connect_endpoint: ws + '/lmbp/v1/connect', chat_completions_endpoint: iss + '/v1/chat/completions',
      protocol_versions: L.PROTOCOL_VERSIONS, profiles: L.PROFILES, capabilities: L.CAPABILITIES, scopes_supported: L.SCOPES };
    if (!t) return m;
    const p = t.profile || {};
    const saas = { name: p.display_name || t.name };
    for (const k of ['logo_uri', 'homepage_uri', 'policy_uri', 'tos_uri', 'pairing_uri']) if (p[k]) saas[k] = p[k];
    const iat = L.now();
    Object.assign(m, { tenant: t.id, audience: L.tokenAudience(iss, t.id), saas });
    if (p.requested_models?.length) m.requested_models = p.requested_models;
    Object.assign(m, { requested_scopes: p.requested_scopes?.length ? p.requested_scopes : ['lmbp.chat'], iat, exp: iat + 3600 });
    m.signed_metadata = L.signJWS(this.priv, L.TYP.metadata, this.kid, m);
    return m;
  }

  metadata(req, res, u) {
    if (req.method !== 'GET') return problem(res, 405, 'BAD_REQUEST', 'GET required');
    let t = null;
    const id = u.searchParams.get('tenant');
    if (id) {
      t = L.TENANT_ID_RE.test(id) ? this.tenants.get(id) : null;
      if (!t) return problem(res, 404, 'BAD_REQUEST', 'unknown tenant');
    }
    res.setHeader('Cache-Control', 'public, max-age=300');
    return json(res, 200, this.buildMetadata(this.issuer(req), t));
  }

  // ---------- RFC 8628 pairing ----------
  async authorize(req, res) {
    if (req.method !== 'POST') return oauthError(res, 405, 'invalid_request');
    // §6.2: limited per client address (the TCP peer) before anything is parsed or stored.
    if (!this.authRate.allow(req.socket?.remoteAddress || '', LIMITS.authorizePerMinute)) {
      res.setHeader('Retry-After', '60');
      return oauthError(res, 429, 'slow_down');
    }
    const ps = await params(req, 4096);
    if (!ps || !ps.tenant || (ps.device_name !== undefined && !L.validDeviceName(ps.device_name))) return oauthError(res, 400, 'invalid_request');
    let pub;
    try { pub = L.unb64(ps.public_key || ''); } catch { return oauthError(res, 400, 'invalid_request'); }
    if (pub.length !== 32) return oauthError(res, 400, 'invalid_request');
    if (!L.TENANT_ID_RE.test(ps.tenant) || !this.tenants.has(ps.tenant)) return oauthError(res, 400, 'invalid_client');
    const dc = L.randomID('dc_');
    const d = { codeHash: L.shaHex(dc), userCode: userCode(), tenant: ps.tenant, pub, name: ps.device_name || '', status: 'pending',
      expires: Date.now() + this.cfg.codeTTL * 1000, interval: INITIAL_INTERVAL, lastPoll: 0, deviceID: '', owner: '' };
    if (!this.reservePending(d.tenant, d.codeHash, d.expires)) {
      res.setHeader('Retry-After', '60');
      return oauthError(res, 429, 'slow_down');
    }
    try { this.store.putDeviceAuth(d); } catch (e) { this.releasePending(d.tenant, d.codeHash); throw e; }
    res.setHeader('Cache-Control', 'no-store');
    return json(res, 200, { device_code: dc, user_code: d.userCode, expires_in: this.cfg.codeTTL, interval: d.interval });
  }

  // reservePending counts a new pending pairing against its tenant's cap (expired entries are dropped first).
  reservePending(tenant, hash, expires) {
    const now = Date.now();
    let m = this.pending.get(tenant);
    if (!m) this.pending.set(tenant, (m = new Map()));
    for (const [h, at] of m) if (now > at) m.delete(h);
    if (m.size >= LIMITS.maxPendingPerTenant) return false;
    m.set(hash, expires);
    return true;
  }
  releasePending(tenant, hash) {
    const m = this.pending.get(tenant);
    if (m) { m.delete(hash); if (!m.size) this.pending.delete(tenant); }
  }

  // Failures are counted per end user of a tenant (§6.4). Node runs each
  // decision synchronously, so check, decision and record are one step.
  allowAttempt(tenant, user) {
    const key = tenant + '\0' + user;
    const cut = Date.now() - 60_000;
    const keep = (this.fails.get(key) || []).filter((t) => t > cut);
    if (keep.length) this.fails.set(key, keep); else this.fails.delete(key);
    return keep.length < LIMITS.failuresPerMinute;
  }
  recordFailure(tenant, user) {
    const key = tenant + '\0' + user;
    (this.fails.get(key) || this.fails.set(key, []).get(key)).push(Date.now());
  }

  // pairLookup returns the pending pairing for a code the end user typed (to
  // show the device before deciding); a code that is not pending counts as a
  // failure of that user, like a failed decision. Returns { d } or { error }.
  pairLookup(tenant, owner, userCode) {
    if (!this.allowAttempt(tenant, owner)) return { error: { status: 429, code: 'RATE_LIMITED', message: 'too many failed codes; wait a minute' } };
    const code = normCode(userCode);
    const d = code ? this.store.deviceAuthByUserCode(tenant, code) : null;
    if (!d || d.status !== 'pending' || Date.now() > d.expires) {
      this.recordFailure(tenant, owner);
      return { error: { status: 404, code: 'BAD_REQUEST', message: 'code invalid, expired or already used' } };
    }
    return { d };
  }

  async approve(req, res, err) {
    if (req.method !== 'POST') return err(405, 'BAD_REQUEST', 'POST required');
    const a = this.tenantAuth(req, err);
    if (!a) return;
    const body = await readJSON(req, 4096);
    if (!body || typeof body !== 'object') return err(400, 'BAD_REQUEST', 'invalid JSON');
    const r = this.pairDecide(a.t.id, a.user, body.user_code, body.deny === true, body.jkt);
    if (r.error) return err(r.error.status, r.error.code, r.error.message);
    const d = r.d;
    return json(res, 200, { status: d.status, device_id: d.deviceID, device_name: d.name, jkt: L.thumbprint(d.pub) });
  }

  // pairDecide is the one business-layer entry for approving/denying a user
  // code (HTTP handler and in-process SDK API alike): it enforces the
  // per-tenant failed-code lockout and counts every failure, so no path can
  // brute-force codes. Returns { d } or { error: { status, code, message } }.
  pairDecide(tenant, owner, userCode, deny, jkt) {
    const fail = (status, code, message) => { this.recordFailure(tenant, owner); return { error: { status, code, message } }; };
    if (!this.allowAttempt(tenant, owner)) return { error: { status: 429, code: 'RATE_LIMITED', message: 'too many failed codes; wait a minute' } };
    const code = normCode(userCode);
    const d = code ? this.store.deviceAuthByUserCode(tenant, code) : null;
    // §19: a declined pairing cannot be overridden by a later approval.
    if (d && d.status === 'denied' && Date.now() <= d.expires) return fail(403, 'CONSENT_DENIED', 'pairing consent was denied for this code');
    if (!d || d.status !== 'pending' || Date.now() > d.expires) return fail(404, 'BAD_REQUEST', 'code invalid, expired or already used');
    if (jkt && jkt !== L.thumbprint(d.pub)) return fail(409, 'FORBIDDEN', 'device key thumbprint does not match the pairing request');
    return { d: this.decide(d, tenant, owner, deny) };
  }

  // decide approves (binding the device to owner) or denies a pending pairing.
  decide(d, tenant, owner, deny) {
    if (deny) d.status = 'denied';
    else {
      Object.assign(d, { status: 'approved', owner, deviceID: L.randomID('dev_') });
      this.store.putDevice({ id: d.deviceID, tenant, owner, name: d.name, pub: d.pub, status: 'active', created: new Date(), e2eeKey: '' });
    }
    this.store.putDeviceAuth(d);
    this.releasePending(tenant, d.codeHash);
    return d;
  }

  issue(dev, iss) {
    const iat = L.now();
    const c = { iss, sub: dev.id, aud: L.tokenAudience(iss, dev.tenant), tenant: dev.tenant, iat, exp: iat + this.cfg.tokenTTL,
      jti: L.randomID('jti_'), cnf: { jkt: L.thumbprint(dev.pub) } };
    return { access_token: L.signJWS(this.priv, L.TYP.access, this.kid, c), token_type: 'Bearer', expires_in: this.cfg.tokenTTL,
      device_id: dev.id, gateway_key: L.publicJWK(this.pub), issuer: iss };
  }

  async token(req, res) {
    if (req.method !== 'POST') return oauthError(res, 405, 'invalid_request');
    const ps = await params(req, 8192);
    if (!ps) return oauthError(res, 400, 'invalid_request');
    const iss = this.issuer(req);
    if (ps.grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
      const d = this.store.getDeviceAuth(L.shaHex(ps.device_code || ''));
      if (!d) return oauthError(res, 400, 'invalid_grant');
      let pc;
      try {
        pc = L.verifyProof(d.pub, ps.proof, '', L.PROOF.token, ps.device_code);
        if (this.jtis.has(pc.jti)) throw new Error('replay');
      } catch { return oauthError(res, 400, 'invalid_grant'); }
      // A code that can no longer yield a token answers without remembering the proof's jti.
      if (Date.now() > d.expires) return oauthError(res, 400, 'expired_token');
      if (d.status === 'denied') return oauthError(res, 400, 'access_denied');
      if (d.status === 'consumed') return oauthError(res, 400, 'invalid_grant');
      if (!this.useJTI(pc.jti, Date.now() + 180_000)) return oauthError(res, 400, 'invalid_grant');
      if (d.status === 'pending') {
        const t = Date.now();
        const slow = t - d.lastPoll < d.interval * 1000 - 200;
        d.lastPoll = t;
        if (slow) d.interval += 5;
        // §6.3: a device that keeps ignoring slow_down loses its code.
        const dead = Math.floor((d.interval - INITIAL_INTERVAL) / 5) > LIMITS.maxSlowDowns;
        if (dead) { d.expires = t; this.releasePending(d.tenant, d.codeHash); }
        this.store.putDeviceAuth(d);
        return oauthError(res, 400, dead ? 'expired_token' : slow ? 'slow_down' : 'authorization_pending');
      }
      const dev = this.store.getDevice(d.deviceID);
      if (!dev) return oauthError(res, 500, 'server_error');
      d.status = 'consumed';
      this.store.putDeviceAuth(d);
      return json(res, 200, this.issue(dev, iss));
    }
    if (ps.grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
      try {
        const uc = L.unverifiedClaims(ps.assertion);
        const dev = this.store.getDevice(uc.sub);
        if (!dev || dev.status !== 'active') throw new Error('device');
        const c = L.verifyJWT(dev.pub, ps.assertion, L.TYP.assertion, L.assertionAudience(iss));
        if (c.iss !== dev.id || c.exp - c.iat > 300 || !c.jti || !this.useJTI(c.jti, (c.exp + 60) * 1000)) throw new Error('claims');
        return json(res, 200, this.issue(dev, iss));
      } catch { return oauthError(res, 400, 'invalid_grant'); }
    }
    return oauthError(res, 400, 'unsupported_grant_type');
  }

  // ---------- tenant device management ----------
  ownDevices(tenant, owner) { return this.store.listDevices(tenant, owner); }

  listDevices(req, res, err) {
    const a = this.tenantAuth(req, err);
    if (!a) return;
    const out = this.ownDevices(a.t.id, a.user).map((d) => {
      const item = { device_id: d.id, name: d.name, status: d.status, created_at: d.created.toISOString().replace(/\.\d+Z$/, 'Z'), online: false, models: [],
        public_key: L.publicJWK(d.pub), jkt: L.thumbprint(d.pub) };
      if (d.e2eeKey) item.e2ee_key = d.e2eeKey;
      const s = this.online(d.id);
      if (s) Object.assign(item, { online: true, models: [...s.models], model_capabilities: { ...s.modelCaps }, ...(Object.keys(s.modelNames || {}).length ? { model_names: { ...s.modelNames } } : {}), capabilities: [...s.caps], max_concurrency: s.maxConc });
      return item;
    });
    // Pending pairings are never listed (§6.4, §12.6): approval needs the code shown on the device.
    return json(res, 200, { devices: out });
  }

  revoke(req, res, err, id) {
    if (req.method !== 'POST') return err(404, 'BAD_REQUEST', 'not found');
    const a = this.tenantAuth(req, err);
    if (!a) return;
    if (!this.revokeDevice(a.t.id, a.user, id)) return err(404, 'FORBIDDEN', 'device not found');
    return json(res, 200, { device_id: id, status: 'revoked' });
  }

  revokeDevice(tenant, owner, id) {
    const d = this.store.getDevice(id);
    if (!d || d.tenant !== tenant || d.owner !== owner) return false;
    d.status = 'revoked';
    this.store.putDevice(d);
    this.dropDevice(id, 'DEVICE_OFFLINE', 'device revoked'); // in-flight tasks: OUTCOME_UNKNOWN (§7.5)
    return true;
  }

  dropDevice(id, code, msg) {
    const ds = this.devs.get(id);
    if (ds) { this.devs.delete(id); ds.drop(code, msg); }
  }

  // ---------- WebSocket tunnel ----------
  async upgrade(req, sock, head) {
    const u = new URL(req.url, 'http://x');
    const reject = (status, code, msg) => {
      const b = JSON.stringify(problemBody(status, code, msg));
      sock.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nContent-Type: application/problem+json\r\nCache-Control: no-store\r\nContent-Length: ${Buffer.byteLength(b)}\r\nConnection: close\r\n\r\n${b}`);
    };
    if (u.pathname !== '/lmbp/v1/connect') return reject(404, 'BAD_REQUEST', 'not found');
    const protos = String(req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim());
    if (!protos.includes(L.SUBPROTOCOL)) return reject(400, 'VERSION_UNSUPPORTED', L.VERSION_REQUIRED);
    if (req.headers.origin) return reject(403, 'FORBIDDEN', 'browser origins are not allowed');
    const tok = String(req.headers.authorization || '').replace(/^Bearer /, '');
    const iss = this.issuer(req);
    let claims;
    try { claims = this.verifyAccess(tok, iss); } catch (e) { return reject(401, 'UNAUTHENTICATED', e.message); }
    const dev = this.store.getDevice(claims.sub);
    if (!dev || dev.status !== 'active' || dev.tenant !== claims.tenant || claims.cnf?.jkt !== L.thumbprint(dev.pub))
      return reject(403, 'FORBIDDEN', 'device revoked or token not bound to device key');
    this.wss.handleUpgrade(req, sock, head, (ws) => {
      // A frame over maxPayload (or any protocol error) surfaces as an 'error'
      // event; ws then closes with 1009/1002. Without a listener Node would
      // crash the whole gateway (found by conformance Z6g).
      ws.on('error', () => { try { ws.terminate(); } catch { /* already closed */ } });
      this.session(ws, dev, tok, claims, iss);
    });
  }

  session(ws, dev, tok, claims, iss) {
    const helloTimer = setTimeout(() => ws.terminate(), 15_000);
    ws.once('message', (raw, isBinary) => guard(ws, this.cfg.log, () => {
      clearTimeout(helloTimer);
      let env, hello;
      try { env = JSON.parse(raw.toString()); hello = env.data; } catch { return ws.close(); }
      if (isBinary || env?.type !== 'hello' || !hello || typeof hello !== 'object') return ws.close();
      const early = (code, msg) => { ws.send(JSON.stringify(envelope('error', { id: env.id, data: errorBody(code, msg) }))); ws.close(); };
      if (env.v !== L.VERSION) return early('VERSION_UNSUPPORTED', L.VERSION_REQUIRED);
      // §7.4 order: v, schema (BAD_REQUEST), device/proof (UNAUTHENTICATED), extension semantics.
      const schemaBad = announceProblem(hello, true);
      if (schemaBad) return early('BAD_REQUEST', schemaBad);
      try {
        if (hello.device_id !== dev.id) throw new Error('device');
        const pc = L.verifyProof(dev.pub, hello.proof, dev.id, L.PROOF.hello, tok);
        if (!this.useJTI(pc.jti, Date.now() + 180_000)) throw new Error('replay');
      } catch { return early('UNAUTHENTICATED', 'invalid key proof'); }
      let caps = intersect(Array.isArray(hello.capabilities) ? hello.capabilities : [], L.CAPABILITIES);
      if (hello.flow != null && caps.includes('flow') && !validFlow(hello.flow)) return early('BAD_REQUEST', `flow windows must be >= max_frame_bytes (${L.MAX_FRAME_BYTES}) and conn_window >= task_window`);
      const bad = helloProblem(hello);
      if (bad) return early('BAD_REQUEST', bad);
      // The device may have been revoked while we awaited the hello: the
      // upgrade-time snapshot is stale. Re-check before activating (this and
      // attachSession run synchronously, so no revoke can slip in between).
      const cur = this.store.getDevice(dev.id);
      if (!cur || cur.status !== 'active') return early('UNAUTHENTICATED', 'device revoked');
      dev = cur;
      if (hello.e2ee_key && caps.includes('e2ee')) {
        try { L.verifyE2EEKey(dev.pub, dev.id, hello.e2ee_key); } catch { return early('BAD_REQUEST', 'invalid e2ee key statement'); }
        if (!this.saveE2EEKey(dev.id, hello.e2ee_key)) return early('UNAUTHENTICATED', 'device revoked');
        dev.e2eeKey = hello.e2ee_key;
      } else caps = caps.filter((c) => c !== 'e2ee');
      const conc = Math.min(hello.max_concurrency, this.cfg.maxConc); // validated 1..16; the gateway may lower, never raise
      this.attachSession(ws, dev, claims, iss, env, hello, caps, conc);
    }));
  }

  /** Field-only, status-conditional update of a device's E2EE key; false if
   * the device is gone or revoked (never resurrects a revoked record). */
  saveE2EEKey(id, key) {
    if (typeof this.store.setDeviceE2EEKey === 'function') return this.store.setDeviceE2EEKey(id, key) !== false;
    const cur = this.store.getDevice(id); // synchronous read-modify-write
    if (!cur || cur.status !== 'active') return false;
    cur.e2eeKey = key;
    this.store.putDevice(cur);
    return true;
  }

  attachSession(ws, dev, claims, iss, env, hello, caps, conc) {
    const old = this.devs.get(dev.id);
    const resumed = !!(old && hello.resume && caps.includes('resume') && hello.resume.token && hello.resume.token === old.resumeToken);
    if (old && !resumed) { this.devs.delete(dev.id); old.drop('OUTCOME_UNKNOWN', 'device reconnected without resuming'); }
    const ds = resumed ? old : new DState(this, dev);
    if (!resumed) this.devs.set(dev.id, ds);
    const prev = ds.ws;
    const gen = ++ds.gen;
    Object.assign(ds, { ws, models: Array.isArray(hello.models) ? hello.models : [], modelCaps: hello.model_capabilities || {}, modelNames: cleanNames(hello.model_names, hello.models), caps, maxConc: conc,
      tokenExp: claims.exp, issuer: iss, resumeToken: L.randomID('rt_') });
    if (!ds.inb) ds.inb = new L.Inbound(caps.includes('flow') ? this.cfg.flow : null);
    else ds.inb.resetWindows();
    const resumeTasks = [], deviceRecv = new Map(), lost = [];
    if (resumed) {
      for (const rt of hello.resume.tasks || []) deviceRecv.set(rt.task_id, rt.recv_seq | 0);
      for (const [id, t] of ds.tasks) {
        if (!deviceRecv.has(id) && t.sentRun) { lost.push(t); continue; }
        resumeTasks.push({ task_id: id, recv_seq: ds.inb.recv(id) });
      }
    }
    if (prev && prev !== ws) prev.terminate();
    for (const t of lost) t.failOffline('OUTCOME_UNKNOWN', 'device resumed without this task; outcome unknown');
    ds.out.setFlow(caps.includes('flow') ? (validFlow(hello.flow) ? { task_window: hello.flow.task_window, conn_window: hello.flow.conn_window } : { task_window: 1 << 20, conn_window: 4 << 20 }) : null);
    const welcome = { session_id: L.randomID('sess_'), heartbeat_seconds: Math.max(1, Math.floor(this.cfg.pingInterval / 1000)), max_frame_bytes: L.MAX_FRAME_BYTES,
      token_expires_at: claims.exp, capabilities: caps, max_concurrency: conc };
    if (caps.includes('flow')) welcome.flow = this.cfg.flow;
    if (caps.includes('resume')) {
      welcome.resume_token = ds.resumeToken;
      welcome.resume_window_seconds = Math.floor(this.cfg.resumeWindow / 1000);
      if (hello.resume) welcome.resume = { resumed, tasks: resumeTasks };
    }
    ds.control(envelope('welcome', { id: env.id, data: welcome }));
    ds.out.attach((raw) => { if (ws.readyState !== ws.OPEN) throw new Error('closed'); ws.send(raw); });
    if (resumed) {
      for (const rt of resumeTasks) ds.out.retransmit(rt.task_id, deviceRecv.get(rt.task_id) ?? 0);
      this.cfg.log(`device ${dev.id} resumed ${resumeTasks.length} task(s)`);
    } else this.cfg.log(`device ${dev.id} (tenant ${dev.tenant}) online, models=${ds.models} caps=${caps} conc=${conc}`);

    const ping = setInterval(() => {
      if (L.now() > ds.tokenExp + 30) return ws.terminate();
      if (Date.now() - ds.lastSeen > 60_000) return ws.terminate();
      try { ws.ping(); } catch { /* closed */ }
    }, this.cfg.pingInterval);
    ds.lastSeen = Date.now();
    ws.on('pong', () => { ds.lastSeen = Date.now(); });
    ws.on('message', (raw, isBinary) => guard(ws, this.cfg.log, () => {
      ds.lastSeen = Date.now();
      if (isBinary) return ws.close(1003, 'text frames only');
      let inp;
      try { inp = JSON.parse(raw.toString()); } catch { inp = null; }
      if (!inp || typeof inp !== 'object' || inp.v !== L.VERSION) return ds.sendErr(inp?.id, 'BAD_REQUEST', 'malformed frame');
      switch (inp.type) {
        case 'task.delta': case 'task.done': case 'task.error':
          if (!this.onDeviceData(ds, inp, raw.length)) ws.close();
          break;
        case 'task.ack':
          if (inp.data && Number.isInteger(inp.data.seq)) ds.out.ack(inp.task_id, inp.data.seq);
          break;
        case 'session.token':
          if (!this.refreshSession(ds, dev, inp)) { ds.sendErr(inp.id, 'UNAUTHENTICATED', 'session token rejected'); ws.close(); }
          break;
        case 'models.update': {
          const mu = inp.data;
          const muBad = announceProblem(mu, false);
          if (muBad) { ds.sendErr(inp.id, 'BAD_REQUEST', muBad); break; } // rejected whole: nothing applied
          {
            ds.models = mu.models; ds.modelCaps = mu.model_capabilities || {}; ds.modelNames = cleanNames(mu.model_names, mu.models);
            if (mu.max_concurrency !== undefined) { ds.maxConc = Math.min(mu.max_concurrency, this.cfg.maxConc); ds.wakeSlots(); }
            if (mu.e2ee_key && ds.caps.includes('e2ee')) { try { L.verifyE2EEKey(dev.pub, dev.id, mu.e2ee_key); if (this.saveE2EEKey(dev.id, mu.e2ee_key)) dev.e2eeKey = mu.e2ee_key; } catch { /* ignore */ } }
          }
          break;
        }
        case 'ping': ds.control(envelope('pong', { id: inp.id })); break;
        case 'pong': break;
        default: ds.sendErr(inp.id, 'BAD_REQUEST', 'unknown message type ' + inp.type);
      }
    }));
    ws.on('close', () => {
      clearInterval(ping);
      if (ds.gen !== gen) return; // replaced by a newer connection
      ds.out.attach(null);
      ds.ws = null;
      // only drop the registry entry this connection owns (a newer,
      // non-resumed connection has its own DState by now)
      if (!ds.caps.includes('resume') || ds.dropped) {
        if (this.devs.get(dev.id) === ds) return this.dropDevice(dev.id, 'DEVICE_OFFLINE', 'device disconnected');
        return ds.drop('DEVICE_OFFLINE', 'device disconnected');
      }
      setTimeout(() => {
        if (ds.gen === gen && !ds.ws) {
          if (this.devs.get(dev.id) === ds) this.devs.delete(dev.id);
          ds.drop('DEVICE_OFFLINE', 'device did not resume in time');
        }
      }, this.cfg.resumeWindow).unref();
    });
  }

  onDeviceData(ds, inp, size) {
    // Envelope + body validated BEFORE the seq is accepted, persisted or
    // ACKed: an invalid terminal frame (task.done {}) never becomes
    // SUCCEEDED. The task fails as a protocol error (audit3 P2-6).
    const bad = deviceDataProblem(inp);
    if (bad) {
      const tt = ds.tasks.get(inp.task_id);
      this.cfg.log(`lmbp: device ${ds.deviceID} task ${inp.task_id}: ${bad}`);
      if (tt) { tt.cancel('protocol_error'); tt.failLocal('INTERNAL', 'device sent an invalid frame: ' + bad); } else ds.sendErr(inp.id, 'BAD_REQUEST', bad);
      return true;
    }
    const t = ds.tasks.get(inp.task_id);
    if (!t) {
      // Ended here (cancel, timeout, slow consumer, ...) while the device
      // was still running: ACK its late frames so its reliable buffer and
      // flow credit come back. The decided outcome is not touched.
      const acked = ds.reclaimed.get(inp.task_id);
      if (acked !== undefined) {
        const seq = Number(inp.seq) || 0;
        if (seq > acked) ds.reclaimed.set(inp.task_id, seq);
        if (isTerminal(inp.type)) ds.reclaimed.delete(inp.task_id);
        if (seq > acked) ds.control(envelope('task.ack', { task_id: inp.task_id, data: { seq } }));
        return true;
      }
      ds.control(envelope('task.cancel', { task_id: inp.task_id, data: { reason: 'unknown_task' } }));
      return true;
    }
    const verdict = ds.inb.accept(inp.task_id, Number(inp.seq) || 0, size);
    if (verdict === L.ACCEPTED && isTerminal(inp.type)) t.devTerminal = true;
    switch (verdict) {
      case L.DUPLICATE: t.maybeAck(); return true;
      case L.GAP: t.cancel('protocol_error'); t.failLocal('INTERNAL', 'sequence gap from device'); return true;
      case L.OVERFLOW:
        ds.sendErr('', 'FLOW_CONTROL', 'flow-control window exceeded');
        t.failLocal('FLOW_CONTROL', 'device exceeded the flow-control window');
        return false;
    }
    t.onDeviceFrame(inp);
    return true;
  }

  refreshSession(ds, dev, inp) {
    const st = inp.data || {};
    try {
      const c = this.verifyAccess(st.access_token, ds.issuer);
      if (c.sub !== dev.id || c.cnf?.jkt !== L.thumbprint(dev.pub) || this.store.getDevice(dev.id)?.status !== 'active') return false;
      const pc = L.verifyProof(dev.pub, st.proof, dev.id, L.PROOF.sessionToken, st.access_token);
      if (!this.useJTI(pc.jti, Date.now() + 180_000)) return false;
      ds.tokenExp = c.exp;
      ds.control(envelope('session.token', { id: inp.id, data: { token_expires_at: c.exp } }));
      return true;
    } catch { return false; }
  }

  // ---------- OpenAI-compatible surface ----------
  models(req, res, err) {
    const a = this.tenantAuth(req, err);
    if (!a) return;
    const data = [];
    for (const d of this.ownDevices(a.t.id, a.user)) {
      const s = this.online(d.id);
      if (!s || d.status !== 'active') continue;
      for (const m of s.models) {
        const item = { id: `${d.id}/${m}`, object: 'model', owned_by: d.name, capabilities: s.modelCaps[m] || [] };
        if (s.modelNames && s.modelNames[m]) item.display_name = s.modelNames[m];
        data.push(item);
      }
    }
    if (req.headers['anthropic-version']) return json(res, 200, A.modelsList(data));
    return json(res, 200, { object: 'list', data });
  }

  resolve(tenant, user, model) {
    const ds = this.ownDevices(tenant, user);
    let want = model, bare = true, devID = '';
    const i = model.indexOf('/');
    if (i > 0 && model.startsWith('dev_')) { devID = model.slice(0, i); want = model.slice(i + 1); bare = false; }
    let known = false, up = false;
    for (const d of ds) {
      if (d.status !== 'active' || (!bare && d.id !== devID)) continue;
      known = known || !bare;
      const s = this.online(d.id);
      if (s && s.models.includes(want)) return { ds: s, model: want };
      if (s) up = true;
    }
    // §6.6: a named device that is online but lacks the model is 404; only an offline one is 503.
    if (known) return up ? { code: 'MODEL_NOT_FOUND', status: 404 } : { code: 'DEVICE_OFFLINE', status: 503 };
    if (ds.length && bare && !ds.some((d) => this.online(d.id))) return { code: 'DEVICE_OFFLINE', status: 503 };
    return { code: 'MODEL_NOT_FOUND', status: 404 };
  }

  // messages is the Anthropic Messages endpoint: translate, then run chat.
  async messages(req, res) {
    const err = (s, code, msg) => json(res, s, A.errorBody(s, code, msg));
    if (req.method !== 'POST') return err(405, 'BAD_REQUEST', 'POST required');
    if (!this.tenantAuth(req, err)) return;
    const body = await readBody(req, 48 << 20);
    if (!body) return err(413, 'PAYLOAD_TOO_LARGE', 'request body too large');
    let r;
    try { r = JSON.parse(body.toString()); } catch { r = null; }
    if (!r || typeof r !== 'object' || Array.isArray(r)) return err(400, 'BAD_REQUEST', 'invalid JSON body');
    try { validateAnthropicParams(r); } catch (e) {
      if (e instanceof ParamError) return json(res, 400, paramErrorBody(e, true));
      throw e;
    }
    let out;
    try { out = A.toOpenAI(r); } catch (e) { return err(400, 'BAD_REQUEST', e.message); }
    return this.chat(req, res, err, Buffer.from(A.canonicalJSON(out)), true);
  }

  async chat(req, res, err, preBody, anthropic = false) {
    if (req.method !== 'POST') return err(405, 'BAD_REQUEST', 'POST required');
    const a = this.tenantAuth(req, err);
    if (!a) return;
    const body = preBody ?? await readBody(req, 48 << 20);
    if (!body) return err(413, 'PAYLOAD_TOO_LARGE', 'request body too large');
    let r;
    try { r = JSON.parse(body.toString()); } catch { r = null; }
    if (!r || typeof r !== 'object' || Array.isArray(r)) return err(400, 'BAD_REQUEST', 'invalid JSON body');
    // Every parameter is validated before anything is stored, queued or
    // signed (third audit #2; spec/testvectors/params.json).
    let params;
    try { params = validateChatParams(r); } catch (e) {
      if (e instanceof ParamError) return json(res, 400, paramErrorBody(e, anthropic));
      throw e;
    }
    const idemKey = req.headers['idempotency-key'] || '';
    if (idemKey && !L.validHeader(idemKey, 255)) return err(400, 'BAD_REQUEST', 'Idempotency-Key must be 1-255 printable ASCII characters');
    const bodyHash = L.sha256(body).toString('hex');
    const prior = idemKey ? this.store.getIdempotency(a.t.id, a.user, idemKey) : null;
    if (prior && (prior.tenant !== a.t.id || prior.owner !== a.user)) return err(500, 'INTERNAL', 'idempotency store returned a foreign record');
    if (prior) {
      if (prior.bodyHash !== bodyHash) return err(422, 'IDEMPOTENCY_KEY_REUSED', 'Idempotency-Key was used with a different request body');
      return this.reattach(req, res, err, a.t.id, a.user, prior.taskID, r.model, !!r.stream, anthropic);
    }
    const msgs = Array.isArray(r.messages) ? r.messages : [];
    const tools = Array.isArray(r.tools) ? r.tools : [];
    const hasToolChoice = r.tool_choice !== undefined && r.tool_choice !== null;
    if (r.lmbp_e2ee) {
      if (msgs.length || tools.length) return err(400, 'BAD_REQUEST', 'lmbp_e2ee requests must not carry cleartext messages or tools');
    } else {
      if (!msgs.length || msgs.length > L.MAX_MESSAGES) return err(400, 'BAD_REQUEST', `1-${L.MAX_MESSAGES} messages required`);
      for (const m of msgs) {
        if (!m || !['system', 'user', 'assistant', 'tool', 'developer'].includes(m.role)) return err(400, 'BAD_REQUEST', 'unsupported role ' + m?.role);
        if (m.role === 'tool' && !m.tool_call_id) return err(400, 'BAD_REQUEST', 'tool messages need tool_call_id');
      }
    }
    const rs = this.resolve(a.t.id, a.user, r.model);
    if (!rs.ds) return err(rs.status, rs.code, { DEVICE_OFFLINE: 'your device is offline', MODEL_NOT_FOUND: 'model not found on your devices' }[rs.code]);
    const { ds, model } = rs;
    const run = { task_id: '', iat: 0, device_id: ds.deviceID, model };
    let blobs = [];
    if (r.lmbp_e2ee) {
      if (!ds.caps.includes('e2ee')) return err(400, 'CAPABILITY_UNSUPPORTED', 'device does not support end-to-end encryption');
      const jwe = String(r.lmbp_e2ee);
      if (jwe.split('.').length !== 5 || Buffer.byteLength(jwe) > L.MAX_TASK_BLOB_BYTES) return err(400, 'BAD_REQUEST', 'lmbp_e2ee must be a compact JWE');
      const id = L.randomID('blob_');
      const data = Buffer.from(jwe);
      blobs = [{ ref: { id, size: data.length, sha256: L.b64(L.sha256(data)), media_type: 'application/jose' }, data }];
      run.e2ee = { blob: id };
    } else {
      const ex = extractBlobs(msgs);
      if (ex.code) return err(errStatus(ex.code), ex.code, ex.msg);
      blobs = ex.blobs;
      if (tools.length || hasToolChoice) {
        if (!ds.caps.includes('tools') || !(ds.modelCaps[model] || []).includes('tools')) return err(400, 'CAPABILITY_UNSUPPORTED', `model ${model} does not support tools`);
        for (const tl of tools) if (tl?.type !== 'function' || !tl.function?.name) return err(400, 'BAD_REQUEST', 'tools must be type function with a name');
      }
      if ((ex.vision || ex.audio) && !ds.caps.includes('multimodal')) return err(400, 'CAPABILITY_UNSUPPORTED', 'device does not support multimodal input');
      if (ex.vision && !(ds.modelCaps[model] || []).includes('vision')) return err(400, 'CAPABILITY_UNSUPPORTED', `model ${model} does not accept images`);
      if (ex.audio && !(ds.modelCaps[model] || []).includes('audio')) return err(400, 'CAPABILITY_UNSUPPORTED', `model ${model} does not accept audio`);
      run.messages = msgs.map(normMessage);
      if (tools.length) run.tools = tools;
      if (hasToolChoice) run.tool_choice = r.tool_choice;
    }
    if (params.max_tokens) run.max_tokens = params.max_tokens;
    if (params.temperature !== undefined) run.temperature = params.temperature;
    if (params.top_p !== undefined) run.top_p = params.top_p;
    if (params.stop !== undefined) run.stop = params.stop;
    // Per-model parameter support (spec §16.4; see Go gateway.chat): a model
    // that declares it ("params") gets every other parameter rejected; on
    // /v1/messages the mandatory max_tokens is dropped instead.
    const mc = ds.modelCaps[model] || [];
    if (mc.includes('params')) {
      if (run.max_tokens && anthropic && !mc.includes('max_tokens')) delete run.max_tokens;
      for (const flag of ['temperature', 'top_p', 'stop', 'max_tokens']) {
        if (run[flag] !== undefined && !mc.includes(flag)) {
          const name = anthropic && flag === 'stop' ? 'stop_sequences' : flag;
          return err(400, 'CAPABILITY_UNSUPPORTED', `model ${model} does not support the ${name} parameter`);
        }
      }
    }
    if (blobs.length) run.blobs = blobs.map((b) => b.ref);

    const taskID = L.randomID('task_');
    { // limits stage 2/3 (spec §10): the signed task.run frame MUST fit max_frame_bytes
      const iat = L.now();
      const payload = { ...run, task_id: taskID, iat, exp: iat + 60, nonce: L.randomID('n_') };
      const trial = L.signJWS(this.priv, L.TYP.task, this.kid, payload);
      const size = L.taskRunFrameSize(trial, taskID);
      if (size > L.MAX_FRAME_BYTES) return err(413, 'PAYLOAD_TOO_LARGE', `request too large: the signed task.run frame would be ${size} bytes, over max_frame_bytes ${L.MAX_FRAME_BYTES}; send large content as images/attachments`);
      // The payload that will be signed MUST satisfy the published schema.
      try { validateTaskRun(payload); } catch (e) {
        if (e instanceof ParamError) return json(res, 400, paramErrorBody(e, anthropic));
        throw e;
      }
    }
    // Idempotency record, task row and the in-memory hub are created in one
    // synchronous step (no await in between), so from the moment the record
    // exists a duplicate re-attaches to this live, pending task. Every way out
    // of the queue below ends the task with a recorded terminal event, so a
    // replay sees the same outcome instead of OUTCOME_UNKNOWN.
    let task;
    try {
      // One atomic write: a key never exists without its task.
      this.store.createTask({ id: taskID, tenant: a.t.id, owner: a.user, device: ds.deviceID, model, state: 'QUEUED', events: [], e2ee: !!run.e2ee },
        idemKey ? { tenant: a.t.id, owner: a.user, key: idemKey, rec: { tenant: a.t.id, owner: a.user, taskID, bodyHash } } : undefined);
    } catch (e) {
      if (e?.name === 'StoreConflict' && idemKey) { // a concurrent request took the key first
        const won = this.store.getIdempotency(a.t.id, a.user, idemKey);
        if (won?.bodyHash === bodyHash) return this.reattach(req, res, err, a.t.id, a.user, won.taskID, r.model, !!r.stream, anthropic);
        return err(422, 'IDEMPOTENCY_KEY_REUSED', 'Idempotency-Key was used with a different request body');
      }
      this.cfg.log(`lmbp: task ${taskID}: storage error: ${e?.message ?? e}`);
      return err(500, 'INTERNAL', 'storage error');
    }
    task = new Task(this, ds, taskID, a.t.id, a.user, r.model, !!run.e2ee, !!idemKey);
    const abort = new AbortController();
    res.on('close', () => abort.abort());
    const got = await ds.acquire(this.cfg.queueTimeout, abort.signal);
    if (!got || !ds.connected() || task.done) {
      if (got) ds.release();
      res.setHeader('X-Task-Id', taskID);
      // Review7 #10/#15: report only a decided local outcome; a caller gone
      // while queued records CANCELLED; otherwise serve the recorded winner.
      if (!task.done) {
        if (abort.signal.aborted) {
          if (task.failLocal('CANCELLED', 'client disconnected while queued', false)) return;
        } else if (!ds.connected()) {
          if (task.failLocal('DEVICE_OFFLINE', 'device disconnected', true)) return err(503, 'DEVICE_OFFLINE', 'device disconnected');
        } else if (task.failLocal('DEVICE_BUSY', 'device is at max concurrency', true)) {
          res.setHeader('Retry-After', '2');
          return err(429, 'DEVICE_BUSY', 'device is at max concurrency');
        }
      }
      return this.serve(req, res, task, 0, !!r.stream, abort.signal, anthropic);
    }
    task.slot = true;
    this.setTaskState(taskID, 'RUNNING');
    const iat = L.now();
    run.task_id = taskID; run.iat = iat;
    const signed = { ...run, exp: iat + 60, nonce: L.randomID('n_') };
    const jws = L.signJWS(this.priv, L.TYP.task, this.kid, signed);
    this.dispatch(task, jws, blobs);
    res.setHeader('X-Task-Id', taskID);
    return this.serve(req, res, task, 0, !!r.stream, abort.signal, anthropic);
  }

  // Non-terminal states only; terminal states are written with their terminal
  // event by store.finishTask. Never overwrites a terminal state.
  setTaskState(id, state) {
    const rec = this.store.getTask(id);
    if (rec && !TERMINAL_STATES.has(rec.state)) this.store.putTask({ ...rec, state });
  }

  async dispatch(t, jws, blobs) {
    t.sentRun = true;
    try { await t.ds.out.send(t.id, () => ({ type: 'task.run', jws }), t.abort.signal); } catch {
      t.sentRun = false;
      return t.failOffline('DEVICE_OFFLINE', 'device disconnected');
    }
    for (const b of blobs) {
      for (let off = 0; ; off += L.BLOB_CHUNK_BYTES) {
        const end = Math.min(off + L.BLOB_CHUNK_BYTES, b.data.length);
        const data = { blob_id: b.ref.id, offset: off, data: L.b64(b.data.subarray(off, end)) };
        if (end === b.data.length) data.last = true;
        try { await t.ds.out.send(t.id, () => ({ type: 'blob.chunk', data }), t.abort.signal); } catch { return; }
        if (end === b.data.length) break;
      }
    }
  }

  // Every replay re-verifies the stored task's tenant and owner.
  // A live (possibly still queued) task is served from memory first.
  reattach(req, res, err, tenant, owner, taskID, reqModel, stream, anthropic = false) {
    let t = this.tasks.get(taskID);
    if (t && (t.tenant !== tenant || t.owner !== owner)) return err(404, 'BAD_REQUEST', 'task no longer available');
    if (!t) {
      const rec = this.store.getTask(taskID);
      if (!rec || rec.tenant !== tenant || rec.owner !== owner) return err(404, 'BAD_REQUEST', 'task no longer available');
      t = Task.finished(this, rec, reqModel);
    }
    const after = parseInt(req.headers['last-event-id'] || '0', 10) || 0;
    const abort = new AbortController();
    res.on('close', () => abort.abort());
    res.setHeader('X-Task-Id', taskID);
    return this.serve(req, res, t, after, stream, abort.signal, anthropic);
  }

  taskEvents(req, res, err, id) {
    const a = this.tenantAuth(req, err);
    if (!a) return;
    const rec = this.store.getTask(id);
    if (!rec || rec.tenant !== a.t.id || rec.owner !== a.user) return err(404, 'BAD_REQUEST', 'task not found');
    return this.reattach(req, res, err, a.t.id, a.user, id, `${rec.device}/${rec.model}`, true);
  }

  async serve(req, res, t, after, stream, signal, anthropic = false) {
    if (anthropic) return A.serve(res, t, after, stream, signal, json);
    const chunk = (delta, finish, usage, extra) => {
      const m = { id: 'chatcmpl-' + t.id, object: 'chat.completion.chunk', created: t.created, model: t.reqModel, choices: [{ index: 0, delta, finish_reason: finish }] };
      if (usage) m.usage = usage;
      return JSON.stringify(Object.assign(m, extra || {}));
    };
    const sealed = (e) => (typeof e.data?.e2ee === 'string' && e.data.e2ee ? { lmbp_e2ee: { seq: e.seq, type: e.type, data: e.data.e2ee } } : null);
    if (stream) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' });
      if (after === 0) res.write(`id: 0\ndata: ${chunk({ role: 'assistant', content: '' }, null)}\n\n`);
      let wrote = false;
      const ok = await t.stream(after, signal, () => res.write(': keep-alive\n\n'), (e) => {
        wrote = true;
        let b, tail = '';
        if (e.type === 'task.delta') {
          if (t.e2ee) b = chunk({}, null, null, sealed(e));
          else {
            const delta = {};
            if (e.data?.text) delta.content = e.data.text;
            if (e.data?.tool_calls?.length) delta.tool_calls = e.data.tool_calls;
            b = chunk(delta, null);
          }
        } else if (e.type === 'task.done') {
          b = chunk({}, e.data?.finish_reason || 'stop', e.data?.usage, t.e2ee ? sealed(e) : null);
          tail = 'data: [DONE]\n\n';
        } else {
          const eb = e.data || {};
          b = JSON.stringify({ error: { message: eb.message, type: 'lmbp_error', code: eb.code, retryable: !!eb.retryable } });
        }
        return A.writeOrDrain(res, `id: ${e.seq}\ndata: ${b}\n\n${tail}`);
      });
      // Last-Event-ID at or beyond the terminal event: nothing left, but end
      // with the terminator so clients can tell completion from truncation.
      if (ok && !wrote) res.write('data: [DONE]\n\n');
      return res.end();
    }
    let text = '';
    const calls = [], sealedFrames = [];
    let done = null, fail = null;
    const ok = await t.stream(after, signal, null, (e) => {
      if (e.type === 'task.delta') {
        if (t.e2ee) { const s = sealed(e); if (s) sealedFrames.push(s.lmbp_e2ee); return; }
        text += e.data?.text || '';
        for (const c of e.data?.tool_calls || []) {
          const idx = Number.isInteger(c.index) ? c.index : 0;
          while (calls.length <= idx) calls.push({ type: 'function', function: { name: '', arguments: '' } });
          if (c.id) calls[idx].id = c.id;
          calls[idx].function.name += c.function?.name || '';
          calls[idx].function.arguments += c.function?.arguments || '';
        }
      } else if (e.type === 'task.done') {
        done = e.data || {};
        if (t.e2ee) { const s = sealed(e); if (s) sealedFrames.push(s.lmbp_e2ee); }
      } else fail = e.data || {};
    });
    if (!ok) return;
    if (fail) return apiError(res, errStatus(fail.code), fail.code, fail.message);
    const finish = done.finish_reason || 'stop';
    const msg = { role: 'assistant', content: text };
    if (calls.length) {
      msg.tool_calls = calls.map((c) => ({ ...(c.id ? { id: c.id } : {}), type: 'function', function: c.function }));
      if (!text) msg.content = null;
    }
    const out = { id: 'chatcmpl-' + t.id, object: 'chat.completion', created: t.created, model: t.reqModel, choices: [{ index: 0, message: msg, finish_reason: finish }] };
    if (t.e2ee) { out.choices = [{ index: 0, message: { role: 'assistant', content: null }, finish_reason: finish }]; out.lmbp_e2ee = sealedFrames; }
    if (done.usage) out.usage = done.usage;
    return json(res, 200, out);
  }
}

// DState is one device's protocol state; it outlives a socket for the resume window.
const MAX_RECLAIMED = 1024;

class DState {
  constructor(g, dev) {
    Object.assign(this, { g, deviceID: dev.id, tenant: dev.tenant, owner: dev.owner, out: new L.Outbox(), inb: null, ws: null, gen: 0,
      models: [], modelCaps: {}, modelNames: {}, caps: [], maxConc: 1, tokenExp: 0, issuer: '', resumeToken: '', tasks: new Map(), reclaimed: new Map(), slots: 0, slotWait: [], dropped: false, lastSeen: Date.now() });
  }
  connected() { return !!this.ws && !this.dropped; }
  control(e) {
    if (!this.ws || this.ws.readyState !== this.ws.OPEN) return false;
    this.ws.send(JSON.stringify(e));
    return true;
  }
  sendErr(id, code, msg) { this.control(envelope('error', { id, data: errorBody(code, msg) })); }
  acquire(timeoutMs, signal) {
    if (this.slots < this.maxConc && !this.slotWait.length) { this.slots++; return Promise.resolve(true); }
    return new Promise((resolve) => {
      const w = { resolve: (v) => { clearTimeout(timer); resolve(v); } };
      const give = () => { const i = this.slotWait.indexOf(w); if (i >= 0) { this.slotWait.splice(i, 1); resolve(false); } };
      const timer = setTimeout(give, timeoutMs);
      signal?.addEventListener('abort', give, { once: true });
      this.slotWait.push(w);
    });
  }
  // reclaim remembers a locally ended task (task id → highest seq ACKed) so
  // its late frames are ACKed; bounded, oldest dropped first (Map order).
  reclaim(id, acked) {
    this.reclaimed.delete(id);
    this.reclaimed.set(id, acked);
    while (this.reclaimed.size > MAX_RECLAIMED) this.reclaimed.delete(this.reclaimed.keys().next().value);
  }
  release() { this.slots--; this.wakeSlots(); }
  wakeSlots() { while (this.slotWait.length && this.slots < this.maxConc) { this.slots++; this.slotWait.shift().resolve(true); } }
  drop(code, msg) {
    this.dropped = true;
    const ws = this.ws;
    for (const w of this.slotWait.splice(0)) w.resolve(true);
    this.out.close();
    for (const t of [...this.tasks.values()]) t.failOffline(code, msg);
    if (ws) ws.close();
  }
}

// Task is the gateway-side hub of one task: it buffers device frames, fans
// them out to (re-)attached HTTP subscribers and paces task.ack (§8).
class Task {
  constructor(g, ds, id, tenant, owner, reqModel, e2ee, idempotent) {
    Object.assign(this, { g, ds, id, tenant, owner, reqModel, e2ee, idempotent, created: L.now(), sentRun: false, abort: new AbortController(),
      events: [], waiters: [], done: false, subs: new Map(), nextSub: 0, acked: 0, persisted: 0, ackAt: Date.now(), grace: null, slot: false });
    g.tasks.set(id, this);
    if (ds) {
      ds.tasks.set(id, this);
      this.timeout = setTimeout(() => { if (this.cancel('timeout')) this.failLocal('TIMEOUT', 'task timed out'); }, g.cfg.taskTimeout);
      this.watch = setInterval(() => {
        const stalled = this.subs.size > 0 && this.recvSeq() > this.acked && Date.now() - this.ackAt > g.cfg.slowConsumer;
        if (stalled && this.cancel('slow_consumer')) this.failLocal('SLOW_CONSUMER', 'client did not consume the stream in time');
      }, 1000);
    }
  }
  static finished(g, rec, reqModel) {
    const t = Object.create(Task.prototype);
    Object.assign(t, { g, ds: null, id: rec.id, reqModel, e2ee: !!rec.e2ee, replayed: true, created: L.now(), events: [...rec.events], waiters: [], done: true, subs: new Map(), nextSub: 0 });
    // Recovery decides from a consistent terminal state: the last event is
    // terminal AND the stored state agrees (finishTask writes both
    // atomically). Otherwise (no terminal event, or a legacy row whose event
    // and state disagree) the outcome is OUTCOME_UNKNOWN: a synthetic event
    // that is only served, never stored, at the next unused seq.
    const last = t.events.at(-1);
    const lastSeq = last?.seq ?? 0;
    const consistent = last && isTerminal(last.type) && (last.type === 'task.done' ? rec.state === 'SUCCEEDED' : rec.state === 'FAILED' || rec.state === 'CANCELLED');
    if (!consistent) {
      if (last && isTerminal(last.type)) { g.cfg.log(`lmbp: task ${rec.id}: stored terminal ${last.type} disagrees with state ${rec.state}; reporting OUTCOME_UNKNOWN`); t.events.pop(); }
      t.events.push({ seq: lastSeq + 1, type: 'task.error', data: errorBody('OUTCOME_UNKNOWN', 'task outcome unknown') });
    }
    return t;
  }
  recvSeq() { return this.ds?.inb ? this.ds.inb.recv(this.id) : 0; }
  broadcast() { for (const w of this.waiters.splice(0)) w(); }
  // record publishes a gateway-local event; a failed write is logged (a
  // later re-attach then reports OUTCOME_UNKNOWN), there is nothing to ACK.
  // A local terminal event is stored atomically with the terminal state; if
  // that fails nothing is stored and a later re-attach reports
  // OUTCOME_UNKNOWN (an error, never a success).
  // Commit first, then publish: nothing is visible before it is decided and stored.
  record(ev) {
    if (!this.replayed) {
      try { this.g.store.finishTask(this.id, ev, stateOf(ev)); } catch (e) {
        if (e?.name !== 'StoreNotFound') this.g.cfg.log(`lmbp: task ${this.id}: persisting local event failed: ${e?.message ?? e}`);
      }
    }
    this.events.push(ev);
    this.broadcast();
  }
  // decide claims the single terminal decision (see Go gtask.decide): exactly
  // one terminal path (device done/error, timeout, cancel, slow consumer,
  // local error) wins and alone commits and publishes its outcome.
  decide() {
    if (this.done || this.decided) return false;
    this.decided = true;
    return true;
  }
  // Device frames are persisted (and, for the terminal frame, the task state)
  // before they are published or ACKed: an ACK lets the device drop the frame
  // from its resume buffer, so it may only cover frames the gateway can serve
  // after a restart.
  onDeviceFrame(inp) {
    hook(this, 'device-frame');
    if (this.done || this.decided) return this.maybeAck();
    if (inp.seq > (this.seen ?? 0)) this.seen = inp.seq;
    let data = inp.data && typeof inp.data === 'object' ? inp.data : {};
    if (inp.type === 'task.delta' && !this.e2ee && data.e2ee) { data = { ...data }; delete data.e2ee; }
    if (inp.type === 'task.delta') {
      const why = this.checkDelta(data);
      if (why) {
        this.g.cfg.log(`lmbp: task ${this.id}: ${why}`);
        this.cancel('protocol_error');
        this.failLocal('INTERNAL', 'device sent an invalid delta: ' + why);
        return;
      }
    }
    const ev = { seq: inp.seq, type: inp.type, data };
    let state = '';
    if (isTerminal(inp.type)) {
      // Terminal event + terminal state in one transaction: on failure
      // neither is stored, so the local INTERNAL error can take this seq.
      state = stateOf(ev);
      if (!this.decide()) return this.maybeAck(); // another terminal path already decided
      try { this.g.store.finishTask(this.id, ev, state); } catch (e) {
        this.g.cfg.log(`lmbp: task ${this.id}: persisting terminal event and state for seq ${inp.seq} failed: ${e?.message ?? e} (not acknowledged)`);
        this.storeFailed = true; // never ACK frames that were not persisted
        this.sendCancel('internal_error');
        return this.commitLocal('INTERNAL', 'gateway could not persist task output');
      }
      hook(this, 'device-terminal-committed');
    } else {
      try { this.g.store.appendEvent(this.id, ev); } catch (e) { return this.persistFailed(inp.seq, 'event', e); }
    }
    if (this.done || (this.decided && !state)) return; // decided elsewhere meanwhile
    this.events.push(ev);
    this.persisted = inp.seq;
    this.broadcast();
    if (state) return this.finish(state, true, false);
    this.maybeAck();
  }
  persistFailed(seq, what, e) {
    this.storeFailed = true; // never ACK frames that were not persisted
    this.g.cfg.log(`lmbp: task ${this.id}: persisting ${what} for seq ${seq} failed: ${e?.message ?? e} (not acknowledged)`);
    this.cancel('internal_error');
    this.failLocal('INTERNAL', 'gateway could not persist task output');
  }
  maybeAck() {
    if (!this.ds) return;
    let target = Math.min(this.recvSeq(), this.persisted);
    if (!this.done) for (const d of this.subs.values()) target = Math.min(target, d);
    if (target <= this.acked) return;
    this.acked = target; this.ackAt = Date.now();
    this.ds.inb?.acked(this.id, target);
    this.ds.control(envelope('task.ack', { task_id: this.id, data: { seq: target } }));
  }
  cancel(reason) {
    if (this.done || this.decided) return false;
    this.sendCancel(reason);
    return true;
  }
  sendCancel(reason) {
    if (this.ds && this.sentRun) this.ds.control(envelope('task.cancel', { task_id: this.id, data: { reason } }));
  }
  failLocal(code, msg, retryable = false) {
    if (!this.decide()) return false;
    this.commitLocal(code, msg, retryable);
    return true;
  }
  // The caller holds the decision. The seq follows every device seq seen.
  commitLocal(code, msg, retryable = false) {
    hook(this, 'local-terminal-decided');
    const seq = Math.max(this.events.at(-1)?.seq ?? 0, this.seen ?? 0) + 1;
    this.record({ seq, type: 'task.error', data: errorBody(code, msg, retryable) });
    this.finish(code === 'CANCELLED' ? 'CANCELLED' : 'FAILED', false, false);
  }
  // failOffline ends a task whose device session is gone, whatever ended it
  // (disconnect, revocation, replacement): once task.run was sent the device
  // may have run it, so OUTCOME_UNKNOWN (§7.5); before that DEVICE_OFFLINE
  // (retryable).
  failOffline(code, msg) {
    if (this.sentRun) { if (code !== 'OUTCOME_UNKNOWN') msg += '; outcome unknown'; code = 'OUTCOME_UNKNOWN'; } else code = 'DEVICE_OFFLINE';
    this.failLocal(code, msg, code === 'DEVICE_OFFLINE');
  }
  // checkDelta validates a device delta before it is stored or aggregated:
  // the tool-call index range (§16.1) and the task's output budget (§10),
  // which counts every encoded delta body, cleartext or sealed.
  checkDelta(data) {
    if (!this.e2ee) {
      for (const c of Array.isArray(data.tool_calls) ? data.tool_calls : []) {
        if (c && c.index !== undefined && (!Number.isInteger(c.index) || c.index < 0 || c.index > L.MAX_TOOL_CALL_INDEX))
          return `tool call index ${c.index} out of range [0,${L.MAX_TOOL_CALL_INDEX}]`;
      }
    }
    this.outBytes = (this.outBytes || 0) + Buffer.byteLength(JSON.stringify(data));
    if (this.outBytes > L.MAX_TASK_OUTPUT_BYTES) return 'task output exceeds the per-task limit';
    return '';
  }
  finish(state, fromDevice, writeState = true) {
    if (this.done) return;
    this.done = true;
    const slot = this.slot;
    this.slot = false;
    clearTimeout(this.grace); clearTimeout(this.timeout); clearInterval(this.watch);
    this.broadcast();
    const ds = this.ds;
    if (ds) {
      if (fromDevice) this.maybeAck();
      else if (!this.storeFailed) {
        // Ended here while the device may still be sending: ACK what
        // arrived so far and remember the task (bounded) so later frames,
        // including its terminal frame, are ACKed too. Same rule as the Go
        // gateway (finishWith / reclaimLocked). Review8 P1-a.
        const late = this.recvSeq();
        if (late > this.acked) {
          this.acked = late;
          ds.control(envelope('task.ack', { task_id: this.id, data: { seq: late } }));
        }
        if (!this.devTerminal) ds.reclaim(this.id, late);
      }
      ds.tasks.delete(this.id);
      ds.out.forget(this.id);
      ds.inb?.forget(this.id);
      if (slot) ds.release();
    }
    this.abort.abort();
    this.finishedAt = Date.now();
    setTimeout(() => { if (this.g.tasks.get(this.id) === this) this.g.tasks.delete(this.id); }, this.g.cfg.attachGrace + 600_000).unref();
  }
  attach(after) {
    const id = ++this.nextSub;
    this.subs.set(id, after);
    clearTimeout(this.grace); this.grace = null;
    return id;
  }
  detach(id) {
    this.subs.delete(id);
    const left = this.subs.size === 0 && !this.done;
    if (left && this.idempotent) {
      this.grace = setTimeout(() => {
        if (this.subs.size === 0 && this.cancel('client_disconnected')) this.failLocal('CANCELLED', 'client did not re-attach');
      }, this.g.cfg.attachGrace);
    }
    if (left && !this.idempotent) { if (this.cancel('client_disconnected')) this.failLocal('CANCELLED', 'client disconnected'); return; }
    this.maybeAck();
  }
  // stream delivers events with seq > after until the terminal one; false if aborted.
  async stream(after, signal, keepalive, fn) {
    const sub = this.attach(after);
    let keep;
    try {
      for (;;) {
        if (signal?.aborted) return false;
        const batch = this.events.filter((e) => e.seq > after);
        // finished and nothing after the cursor (Last-Event-ID >= terminal seq): end
        if (!batch.length && this.events.length && isTerminal(this.events.at(-1).type)) return true;
        for (const e of batch) {
          const p = fn(e);
          if (p) await p; // slow reader: hold the cursor (and the ack) until it drains
          if (signal?.aborted) return false;
          after = e.seq;
          if (this.subs.has(sub)) this.subs.set(sub, after);
          if (isTerminal(e.type)) return true;
        }
        this.maybeAck();
        if (batch.length) continue;
        await new Promise((resolve) => {
          const wake = () => { clearTimeout(keep); signal?.removeEventListener('abort', wake); resolve(); };
          this.waiters.push(wake);
          signal?.addEventListener('abort', wake, { once: true });
          if (keepalive) keep = setTimeout(() => { try { keepalive(); } catch { /* closed */ } wake(); }, 15_000);
        });
      }
    } finally { clearTimeout(keep); this.detach(sub); }
  }
}

// ---------- helpers ----------
function envelope(type, { id, task_id, data } = {}) {
  const e = { v: L.VERSION, type };
  if (id) e.id = id;
  if (task_id) e.task_id = task_id;
  if (data !== undefined) e.data = data;
  return e;
}
function json(res, status, body) {
  const b = JSON.stringify(body);
  // §6.1: every JSON response is no-store unless the route set its own policy (JWKS/metadata).
  res.writeHead(status, { 'Content-Type': res.getHeader('Content-Type') || 'application/json', 'Cache-Control': res.getHeader('Cache-Control') || 'no-store', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
function problemBody(status, code, detail) {
  return { type: PROBLEM_BASE + code.toLowerCase().replaceAll('_', '-'), title: code, status, detail, code };
}
function problem(res, status, code, detail) {
  res.setHeader('Content-Type', 'application/problem+json');
  res.setHeader('Cache-Control', 'no-store');
  json(res, status, problemBody(status, code, detail));
}
function apiError(res, status, code, message) { json(res, status, { error: { message, type: 'lmbp_error', code } }); }
function oauthError(res, status, error) { res.setHeader('Cache-Control', 'no-store'); json(res, status, { error }); }
function readBody(req, max) {
  // Frameworks that already consumed the stream (express.json/raw, fastify)
  // leave the body on req.body.
  if (req.body !== undefined && req.readableEnded !== false) {
    const b = Buffer.isBuffer(req.body) ? req.body : typeof req.body === 'string' ? Buffer.from(req.body)
      : req.body && typeof req.body === 'object' && String(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')
        ? Buffer.from(new URLSearchParams(req.body).toString()) : Buffer.from(JSON.stringify(req.body ?? null));
    return Promise.resolve(b.length > max ? null : b);
  }
  return new Promise((resolve) => {
    const parts = []; let n = 0, over = false;
    req.on('data', (c) => { n += c.length; if (n > max) over = true; else parts.push(c); });
    req.on('end', () => resolve(over ? null : Buffer.concat(parts)));
    req.on('error', () => resolve(null));
  });
}
async function readJSON(req, max) {
  const b = await readBody(req, max);
  try { return b ? JSON.parse(b.toString()) : null; } catch { return null; }
}
// params reads an OAuth request as form-urlencoded (normative) or JSON (accepted).
async function params(req, max) {
  const b = await readBody(req, max);
  if (!b) return null;
  if (String(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) {
    const out = {};
    for (const [k, v] of new URLSearchParams(b.toString())) { if (k in out) return null; out[k] = v; }
    return out;
  }
  try {
    const m = JSON.parse(b.toString());
    if (!m || typeof m !== 'object') return null;
    return Object.fromEntries(Object.entries(m).filter(([, v]) => typeof v === 'string'));
  } catch { return null; }
}
function userCode() {
  let s = '';
  for (let i = 0; i < 8; i++) s += USER_CODE_CHARS[crypto.randomInt(USER_CODE_CHARS.length)];
  return s.slice(0, 4) + '-' + s.slice(4);
}
function normCode(s) {
  s = String(s || '').trim().replaceAll('-', '').replaceAll(' ', '').toUpperCase();
  return s.length === 8 ? s.slice(0, 4) + '-' + s.slice(4) : '';
}
const intersect = (a, b) => a.filter((x, i) => b.includes(x) && a.indexOf(x) === i);
const validFlow = (f) => f && Number.isSafeInteger(f.task_window) && Number.isSafeInteger(f.conn_window) && f.task_window >= L.MAX_FRAME_BYTES && f.conn_window >= f.task_window && f.conn_window <= 2 ** 31;
function normMessage(m) {
  const o = { role: m.role, content: m.content === undefined ? '' : m.content };
  for (const k of ['name', 'tool_calls', 'tool_call_id']) if (m[k] !== undefined && m[k] !== '' && m[k] !== null) o[k] = m[k];
  return o;
}
// extractBlobs moves large inline binaries (data: URIs, input_audio) into blobs (§16.3).
function extractBlobs(msgs) {
  const blobs = [];
  let total = 0, vision = false, audio = false;
  const add = (data, mt) => {
    if (data.length > L.MAX_BLOB_BYTES || (total += data.length) > L.MAX_TASK_BLOB_BYTES) return null;
    const id = L.randomID('blob_');
    blobs.push({ ref: { id, size: data.length, sha256: L.b64(L.sha256(data)), media_type: mt }, data });
    return L.BLOB_SCHEME + id;
  };
  const strictB64 = (s) => (/^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0 ? Buffer.from(s, 'base64') : null);
  for (const m of msgs) {
    if (!Array.isArray(m.content)) continue;
    for (const p of m.content) {
      switch (p?.type) {
        case 'text': break;
        case 'image_url': {
          vision = true;
          const u = p.image_url?.url;
          if (typeof u !== 'string') return { code: 'BAD_REQUEST', msg: 'image_url part without url' };
          if (u.startsWith('https://')) break;
          if (!u.startsWith('data:')) return { code: 'BAD_REQUEST', msg: 'image_url must be https:// or a data: URI' };
          const comma = u.indexOf(',');
          const meta = comma < 0 ? '' : u.slice(5, comma);
          if (comma < 0 || !meta.endsWith(';base64') || !meta.startsWith('image/')) return { code: 'BAD_REQUEST', msg: 'image data URI must be data:image/*;base64,' };
          if (u.length <= L.INLINE_DATA_URI_BYTES) break;
          const raw = strictB64(u.slice(comma + 1));
          if (!raw) return { code: 'BAD_REQUEST', msg: 'invalid base64 in image data URI' };
          const ref = add(raw, meta.slice(0, -7));
          if (!ref) return { code: 'PAYLOAD_TOO_LARGE', msg: 'image exceeds size limits' };
          p.image_url.url = ref;
          break;
        }
        case 'input_audio': {
          audio = true;
          const a = p.input_audio;
          if (!a || typeof a.data !== 'string' || (a.format !== 'wav' && a.format !== 'mp3')) return { code: 'BAD_REQUEST', msg: 'input_audio needs data and format wav|mp3' };
          if (a.data.length <= L.INLINE_DATA_URI_BYTES) break;
          const raw = strictB64(a.data);
          if (!raw) return { code: 'BAD_REQUEST', msg: 'invalid base64 in input_audio' };
          const ref = add(raw, 'audio/' + a.format);
          if (!ref) return { code: 'PAYLOAD_TOO_LARGE', msg: 'audio exceeds size limits' };
          a.data = ref;
          break;
        }
        default: return { code: 'BAD_REQUEST', msg: 'unsupported content part ' + p?.type };
      }
    }
  }
  return { blobs, vision, audio };
}

// Same paths and CSP as mock/web/web.go.
const WEB_FILES = {
  '/': ['chat.html', 'text/html; charset=utf-8'], '/chat': ['chat.html', 'text/html; charset=utf-8'], '/chat/': ['chat.html', 'text/html; charset=utf-8'],
  '/chat/chat.js': ['chat.js', 'text/javascript; charset=utf-8'], '/chat/qrcode.js': ['qrcode.js', 'text/javascript; charset=utf-8'],
};
const WEB_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export { WEB_FILES, WEB_CSP, Task, errStatus };

// guard isolates a WebSocket message handler: an exception closes only the
// offending connection instead of escaping to the process (uncaught).
function guard(ws, log, fn) {
  try { fn(); } catch (e) {
    try { log(`lmbp: closing connection after handler error: ${e && e.message}`); } catch { /* logger failed */ }
    try { ws.close(1011, 'internal error'); } catch { try { ws.terminate(); } catch { /* gone */ } }
  }
}

const isStr = (v) => typeof v === 'string';
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// helloProblem validates every hello field the gateway reads, before any
// state is touched. Returns a message, or '' when the hello is well-formed.
function helloProblem(h) {
  if (h.models !== undefined && (!Array.isArray(h.models) || h.models.length > 500 || !h.models.every(isStr))) return 'hello.models must be an array of <= 500 strings';
  if (h.model_capabilities !== undefined && !isObj(h.model_capabilities)) return 'hello.model_capabilities must be an object';
  if (h.capabilities !== undefined && (!Array.isArray(h.capabilities) || !h.capabilities.every(isStr))) return 'hello.capabilities must be an array of strings';
  if (h.max_concurrency !== undefined && !Number.isInteger(h.max_concurrency)) return 'hello.max_concurrency must be an integer';
  if (h.e2ee_key !== undefined && h.e2ee_key !== null && !isStr(h.e2ee_key)) return 'hello.e2ee_key must be a string';
  if (h.flow !== undefined && h.flow !== null && !isObj(h.flow)) return 'hello.flow must be an object';
  if (h.resume !== undefined && h.resume !== null) {
    const r = h.resume;
    if (!isObj(r)) return 'hello.resume must be an object';
    if (r.token !== undefined && !isStr(r.token)) return 'hello.resume.token must be a string';
    if (r.tasks !== undefined) {
      if (!Array.isArray(r.tasks) || r.tasks.length > 10000) return 'hello.resume.tasks must be an array';
      for (const t of r.tasks) {
        if (!isObj(t) || !isStr(t.task_id) || !Number.isInteger(t.recv_seq) || t.recv_seq < 0) return 'hello.resume.tasks[] must be {task_id: string, recv_seq: integer >= 0}';
      }
    }
  }
  return '';
}

// cleanNames keeps optional display names (model_names) only for advertised models.
function cleanNames(names, models) {
  const out = {};
  if (!names || typeof names !== 'object' || Array.isArray(names) || !Array.isArray(models)) return out;
  for (const m of models) {
    const n = typeof names[m] === 'string' ? names[m].trim() : '';
    if (n) out[m] = n; // length already bounded by the schema (1-128 code points)
  }
  return out;
}
