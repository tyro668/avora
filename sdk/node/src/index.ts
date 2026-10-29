/**
 * lmbp-server: let your SaaS use models that run on your users' own machines.
 *
 * Business code only does two things:
 *   1. pairing: show a pair link / QR, then approve the user code the user reads off the desktop app;
 *   2. LLM calls: standard OpenAI (/v1/chat/completions, /v1/models) or Anthropic (/v1/messages)
 *      requests, either over HTTP with the official client libraries or with the in-process client.
 * The WebSocket session, JOSE, resume, flow control and E2EE pass-through stay inside the SDK.
 */
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
// @ts-ignore engine is plain JS
import { Gateway } from './engine/gateway.js';
// @ts-ignore
import * as L from './engine/lmbp.js';
import { MemoryStore, SqliteStore, type Store } from './store.js';
import { InProcessClient } from './client.js';

export { MemoryStore, SqliteStore, InProcessClient };
export { StoreConflict, StoreNotFound } from './store.js';
export type { Store, Device, DeviceAuth, TaskRecord, TaskEvent, Idempotency, SqlDatabase } from './store.js';
export * as anthropic from './anthropic.js';
export * from './e2ee.js';
export { LMBPStream, IncompleteStreamError, LMBPAPIError } from './client.js';
export type * from './types.js';
import type { TenantConfig, PairingInfo, DeviceInfo, ApproveResult, PendingPairing } from './types.js';

export interface LMBPServerOptions {
  /** Tenants (SaaS products) served by this gateway. Usually one. */
  tenants: TenantConfig[];
  /** Required: public origin of the gateway (iss of every token), e.g. https://gw.example.com. Never derived from Host (§18.1). */
  issuer: string;
  /** Persistence; defaults to MemoryStore. Use `new SqliteStore('lmbp.db')` to survive restarts. */
  store?: Store;
  /** 32-byte Ed25519 seed. Default: loaded from the store, generated on first start. */
  signingSeed?: Buffer;
  /** Per-device concurrency cap (default 16). */
  maxConcurrency?: number;
  /** Serve the reference chat page from this directory (mock/web) at / and /chat. */
  chatUIDir?: string;
  log?: (...a: unknown[]) => void;
  /**
   * How long finished tasks and their Idempotency-Key records are kept (ms, default 7 days;
   * negative disables purging). Expired pairings go too. Spec §14.4 (errata E6).
   */
  retention?: number;
  /** Advanced engine timings (ms): tokenTTL (s), codeTTL (s), resumeWindow, taskTimeout, attachGrace, slowConsumer, queueTimeout. */
  tuning?: Record<string, number>;
}

type Next = (err?: unknown) => void;
const qrcode = createRequire(import.meta.url)('../vendor/qrcode.cjs');

export class LMBPServer {
  /** The protocol engine (advanced use). */
  readonly engine: any;
  readonly store: Store;
  private server?: http.Server;

  constructor(opts: LMBPServerOptions) {
    this.store = opts.store ?? new MemoryStore();
    if (!opts.issuer) throw new Error('LMBPServerOptions.issuer is required: the gateway\'s public origin (never derived from the Host header)');
    this.engine = new Gateway({ issuer: opts.issuer, store: this.store, seed: opts.signingSeed, maxConc: opts.maxConcurrency ?? 16,
      retention: opts.retention ?? 0, webDir: opts.chatUIDir ?? '', log: opts.log ?? console.error, ...(opts.tuning ?? {}) });
    for (const t of opts.tenants) this.engine.registerTenant(t.id, t.apiKey, t.profile ?? {});
  }

  // ---------------- HTTP mounting ----------------

  /** Plain node:http request listener. Unknown paths get a 404. */
  readonly handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    this.engine.handle(req, res).catch((e: unknown) => this.fail(res, e));
  };

  /** Express / Connect middleware; unknown paths fall through to next(). Mount at the root. */
  middleware() {
    return (req: http.IncomingMessage, res: http.ServerResponse, next: Next) => {
      this.engine.handle(req, res, next).catch((e: unknown) => { if (res.headersSent) res.end(); else next(e); });
    };
  }

  /**
   * Fastify plugin: `await app.register(lmbp.fastifyPlugin)`. Registers the
   * protocol routes and the WebSocket upgrade on app.server.
   *
   * The protocol routes need the raw request body, so they live in their own
   * encapsulated child context with raw-Buffer parsers. The host app's
   * content-type parsers (application/json, text/plain, ...) are never
   * removed or replaced: its own routes keep parsing bodies as before.
   */
  readonly fastifyPlugin = Object.assign(async (app: any) => {
    const raw = (_r: unknown, body: Buffer, done: (e: null, b: Buffer) => void) => done(null, body);
    await app.register(async (scope: any) => {
      // Encapsulated: these parser changes stay inside this child context.
      scope.removeAllContentTypeParsers?.();
      scope.addContentTypeParser('*', { parseAs: 'buffer' }, raw);
      if (!scope.removeAllContentTypeParsers) {
        scope.removeContentTypeParser?.(['application/json', 'text/plain']);
        scope.addContentTypeParser(['application/json', 'text/plain'], { parseAs: 'buffer' }, raw);
      }
      const route = (req: any, reply: any) => {
        reply.hijack();
        const r = req.raw;
        r.body = req.body ?? Buffer.alloc(0);
        this.handler(r, reply.raw);
      };
      for (const p of PATHS) scope.route({ method: ['GET', 'POST', 'HEAD', 'OPTIONS'], url: p, handler: route });
    });
    app.addHook('onReady', async () => { this.attach(app.server); });
  }, { [Symbol.for('skip-override')]: true });

  /** Route WebSocket upgrades for /lmbp/v1/connect on an existing server (express/fastify/http). */
  attach(server: http.Server): this {
    server.on('upgrade', (req, sock, head) => {
      if (!req.url?.startsWith('/lmbp/v1/connect')) return;
      this.engine.upgrade(req, sock, head).catch(() => sock.destroy());
    });
    return this;
  }

  /** Standalone server: listen on port/host with the protocol endpoints only. */
  async listen(port: number, host = '127.0.0.1'): Promise<AddressInfo> {
    const addr = await this.engine.listen(port, host);
    this.server = this.engine.server;
    return addr;
  }

  async close(): Promise<void> {
    this.engine.stopRetention();
    for (const ds of this.engine.devs.values()) ds.drop?.('UNAVAILABLE', 'gateway shutting down');
    if (this.server) await new Promise<void>((ok) => this.server!.close(() => ok()));
    this.server?.closeAllConnections?.();
    this.store.close?.();
  }

  private fail(res: http.ServerResponse, e: unknown) {
    this.engine.cfg.log('lmbp handler error', e);
    if (!res.headersSent) { res.writeHead(500, { 'Content-Type': 'application/problem+json' }); res.end('{"title":"INTERNAL","status":500}'); } else res.end();
  }

  // ---------------- keys ----------------

  readonly keys = {
    /** Key id (RFC 7638 thumbprint) of the gateway signing key. */
    kid: (): string => this.engine.kid,
    /** Public JWK of the gateway signing key. */
    publicJWK: (): Record<string, string> => L.publicJWK(this.engine.pub),
    /** JWKS document served at /.well-known/jwks.json. */
    jwks: () => ({ keys: [L.publicJWK(this.engine.pub)] }),
  };

  /** Generate a new 32-byte Ed25519 seed (store it in your secret manager). */
  static generateSigningSeed(): Buffer { return crypto.randomBytes(32); }
  /** Generate a tenant API key (keep it server-side only). */
  static generateTenantKey(): string { return 'lmbp_' + crypto.randomBytes(24).toString('base64url'); }

  // ---------------- pairing ----------------

  readonly pairing = {
    /** §19.4 deep link for the desktop app, on the configured issuer. */
    link: (tenant: string): string =>
      `lmbp://pair?v=${L.PAIR_LINK_VERSION}&gateway=${encodeURIComponent(this.engine.cfg.issuer)}&tenant=${encodeURIComponent(tenant)}`,
    /** Pair link plus its QR code as an SVG string and a PNG-free data: URL (GIF). */
    create: (tenant: string): PairingInfo => {
      const link = this.pairing.link(tenant);
      const q = qrcode(0, 'M'); q.addData(link); q.make();
      return { link, qrSVG: q.createSvgTag({ cellSize: 4, margin: 2, scalable: true }), qrDataURL: q.createDataURL(4, 2) };
    },
    /**
     * Look up a pending pairing by the user code endUser typed (shown on their desktop), to show the
     * device before approving. deviceName is untrusted text chosen by the device: render it as plain text.
     * A code that is not pending returns null and counts as a failed attempt of endUser (RATE_LIMITED after 10 a minute).
     */
    lookup: (tenant: string, endUser: string, userCode: string): PendingPairing | null => {
      this.checkPairingCaller(tenant, endUser);
      const r = this.engine.pairLookup(tenant, endUser, userCode);
      if (r.error?.status === 429) throw new PairingError(r.error.message, 'RATE_LIMITED');
      if (r.error) return null;
      const d = r.d;
      return { userCode: d.userCode, deviceName: d.name, jkt: L.thumbprint(d.pub), status: d.status, expiresAt: new Date(d.expires) };
    },
    /** Approve the user code for endUser; the desktop app finishes pairing on its next poll. */
    approve: (tenant: string, endUser: string, userCode: string, opts: { jkt?: string } = {}): ApproveResult =>
      this.decide(tenant, endUser, userCode, false, opts.jkt),
    /** Deny the user code. */
    deny: (tenant: string, endUser: string, userCode: string): ApproveResult => this.decide(tenant, endUser, userCode, true),
    /** Devices paired to endUser, with live status. */
    listDevices: (tenant: string, endUser: string): DeviceInfo[] => this.store.listDevices(tenant, endUser).map((d) => {
      const s = this.engine.online(d.id);
      return { deviceId: d.id, name: d.name, status: d.status, createdAt: d.created, jkt: L.thumbprint(d.pub), online: !!s,
        models: s ? [...s.models] : [], modelCapabilities: s ? { ...s.modelCaps } : {}, modelNames: s ? { ...(s.modelNames || {}) } : {}, publicKey: Buffer.from(d.pub), e2eeKey: d.e2eeKey || '' };
    }),
    /** Revoke a device: its session ends immediately and refresh is refused. */
    revokeDevice: (tenant: string, endUser: string, deviceId: string): boolean => this.engine.revokeDevice(tenant, endUser, deviceId),
  };

  private checkPairingCaller(tenant: string, endUser: string) {
    if (!this.engine.tenants.has(tenant)) throw new PairingError('unknown tenant', 'BAD_REQUEST');
    if (!L.validHeader(endUser, 128)) throw new PairingError('endUser must be 1-128 printable ASCII characters (it travels as X-End-User)', 'BAD_REQUEST');
  }

  private decide(tenant: string, endUser: string, userCode: string, deny: boolean, jkt?: string): ApproveResult {
    this.checkPairingCaller(tenant, endUser);
    const r = this.engine.pairDecide(tenant, endUser, userCode, deny, jkt);
    if (r.error) {
      const code = ({ 429: 'RATE_LIMITED', 404: 'NOT_FOUND', 403: 'FORBIDDEN', 409: 'FORBIDDEN' } as Record<number, PairingError['code']>)[r.error.status] || 'BAD_REQUEST';
      throw new PairingError(r.error.message, code);
    }
    const d = r.d;
    return { status: d.status as 'approved' | 'denied', deviceId: d.deviceID, deviceName: d.name, jkt: L.thumbprint(d.pub) };
  }

  // ---------------- in-process client ----------------

  /** Typed client that calls the gateway in-process (no HTTP hop) as endUser of tenant. */
  client(tenant: string, endUser: string): InProcessClient { return new InProcessClient(this, tenant, endUser); }
}

export class PairingError extends Error {
  constructor(message: string, readonly code: 'BAD_REQUEST' | 'NOT_FOUND' | 'FORBIDDEN' | 'RATE_LIMITED') { super(message); }
}


/** Paths the SDK serves (for frameworks that need explicit routes). */
export const PATHS = ['/healthz', '/.well-known/jwks.json', '/.well-known/lmbp', '/lmbp/v1/device/authorize', '/lmbp/v1/token', '/lmbp/v1/connect',
  '/lmbp/v1/tenant/devices/approvals', '/lmbp/v1/tenant/devices', '/lmbp/v1/tenant/devices/:id/revoke', '/lmbp/v1/tenant/tasks/:id/events',
  '/v1/models', '/v1/chat/completions', '/v1/messages'];

export function createLMBPServer(opts: LMBPServerOptions): LMBPServer { return new LMBPServer(opts); }
