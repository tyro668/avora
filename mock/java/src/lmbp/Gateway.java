package lmbp;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LMBP gateway engine (Java port of the Node SDK engine,
 * sdk/node/src/engine/gateway.js): RFC 8628 pairing, EdDSA tokens bound to
 * issuer/tenant audiences, gateway metadata + signed_metadata, RFC 7523
 * refresh, the lmbp WebSocket tunnel (seq/ack/resume, credit flow control,
 * tools, multimodal blobs, E2EE relay), the OpenAI-compatible API and the
 * Anthropic Messages API. State is in memory.
 *
 * Concurrency: the Node engine is single-threaded; this port keeps those
 * semantics with one gateway lock held by every handler, timer and socket
 * reader. Blocking waits release it (Condition), socket writes run unlocked.
 */
final class Gateway {
  static final String PROBLEM_BASE = "https://avora.dev/problems/";
  static final String USER_CODE_CHARS = "BCDFGHJKLMNPQRSTVWXZ";
  static final Map<String, Integer> STATUS_OF = Map.ofEntries(
      Map.entry("BAD_REQUEST", 400), Map.entry("CAPABILITY_UNSUPPORTED", 400), Map.entry("PAYLOAD_TOO_LARGE", 413),
      Map.entry("IDEMPOTENCY_KEY_REUSED", 422), Map.entry("MODEL_NOT_FOUND", 404), Map.entry("DEVICE_OFFLINE", 503),
      Map.entry("DEVICE_BUSY", 429), Map.entry("TIMEOUT", 504), Map.entry("CANCELLED", 499), Map.entry("RATE_LIMITED", 429),
      Map.entry("UNAUTHENTICATED", 401), Map.entry("FORBIDDEN", 403), Map.entry("CONSENT_DENIED", 403));
  static final Set<String> TERMINAL_STATES = Set.of("SUCCEEDED", "FAILED", "CANCELLED");
  static final Set<String> ROLES = Set.of("system", "user", "assistant", "tool", "developer");
  static final Map<String, String[]> WEB_FILES = Map.of(
      "/", new String[] {"chat.html", "text/html; charset=utf-8"}, "/chat", new String[] {"chat.html", "text/html; charset=utf-8"},
      "/chat/", new String[] {"chat.html", "text/html; charset=utf-8"}, "/chat/chat.js", new String[] {"chat.js", "text/javascript; charset=utf-8"},
      "/chat/qrcode.js", new String[] {"qrcode.js", "text/javascript; charset=utf-8"});
  static final String WEB_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
  static final Pattern REVOKE_RE = Pattern.compile("^/lmbp/v1/tenant/devices/([^/]+)/revoke$");
  static final Pattern EVENTS_RE = Pattern.compile("^/lmbp/v1/tenant/tasks/([^/]+)/events$");

  static int errStatus(String code) { Integer s = STATUS_OF.get(code); return s == null ? 502 : s; }
  static boolean isTerminal(String t) { return "task.done".equals(t) || "task.error".equals(t); }
  static String stateOf(Store.Event ev) {
    return ev.type().equals("task.done") ? "SUCCEEDED" : ("CANCELLED".equals(Json.get(ev.data(), "code")) ? "CANCELLED" : "FAILED");
  }
  static Map<String, Object> errorBody(String code, String message, boolean retryable) {
    return Json.obj("code", code, "message", message, "retryable", retryable);
  }

  static final class Abort { volatile boolean aborted; }

  /** Pairing abuse limits (spec §6.2-§6.4, §10). */
  static final int AUTHORIZE_PER_MINUTE = 60, MAX_PENDING_PER_TENANT = 1000, MAX_SLOW_DOWNS = 10, FAILURES_PER_MINUTE = 10, INITIAL_INTERVAL = 2;

  /**
   * Remembers proof/assertion jtis until they expire. Expired entries leave from the top of a
   * min-heap ordered by expiry (O(log n) per call), never by scanning the whole set.
   */
  static final class JtiCache {
    private final Map<String, Long> seen = new HashMap<>();
    private final java.util.PriorityQueue<Object[]> heap = new java.util.PriorityQueue<>((a, b) -> Long.compare((Long) a[0], (Long) b[0]));
    private void evict(long now) {
      while (!heap.isEmpty() && (Long) heap.peek()[0] < now) {
        Object[] e = heap.poll();
        Long at = seen.get((String) e[1]);
        if (at != null && at.equals(e[0])) seen.remove((String) e[1]);
      }
    }
    synchronized boolean has(String j) { evict(System.currentTimeMillis()); return seen.containsKey(j); }
    synchronized boolean use(String j, long untilMs) {
      evict(System.currentTimeMillis());
      if (seen.containsKey(j)) return false;
      seen.put(j, untilMs);
      heap.add(new Object[] {untilMs, j});
      return true;
    }
    synchronized int size() { return seen.size(); }
  }

  /** Counts events per key in fixed one-minute windows (the whole map is dropped when the window rolls). */
  static final class WindowCounter {
    private long start;
    private Map<String, Integer> n = new HashMap<>();
    synchronized boolean allow(String key, int limit) {
      long now = System.currentTimeMillis();
      if (now - start >= 60_000) { start = now; n = new HashMap<>(); }
      int c = n.getOrDefault(key, 0);
      if (c >= limit) return false;
      n.put(key, c + 1);
      return true;
    }
  }

  static final class Config {
    String issuer = "";
    long codeTTL = 600, tokenTTL = 900;
    int maxConc = 16;
    long pingInterval = 20_000, resumeWindow = 30_000, taskTimeout = 10 * 60_000, slowConsumer = 60_000, attachGrace = 30_000, queueTimeout = 15_000;
    Lmbp.Flow flow = new Lmbp.Flow(1 << 20, 4 << 20);
    String webDir = "";
    /** Retention of finished tasks and their idempotency records, ms (default 7 days; negative disables). */
    long retention = 7L * 24 * 3600_000;
  }

  record Tenant(String id, String name, String keyHash, Map<String, Object> profile) {}

  final ReentrantLock lock = new ReentrantLock();
  final Condition cv = lock.newCondition();
  final ScheduledExecutorService sched = Executors.newScheduledThreadPool(2, r -> { Thread t = new Thread(r, "lmbp-timer"); t.setDaemon(true); return t; });
  final Config cfg;
  final Store store = new Store();
  final Lmbp.SigningKey key;
  final String kid;
  final Map<String, Tenant> tenants = new LinkedHashMap<>();
  final Map<String, DState> devs = new HashMap<>();
  final Map<String, Task> tasks = new HashMap<>();
  final JtiCache jtis = new JtiCache();
  final Map<String, List<Long>> fails = new HashMap<>();              // tenant \0 end user -> failure times (last minute)
  final Map<String, Map<String, Long>> pending = new HashMap<>();     // tenant -> device_code hash -> expiry
  final WindowCounter authRate = new WindowCounter();

  Gateway(Config cfg, byte[] seed) {
    this.cfg = cfg;
    // §18.1: the issuer is configuration, never derived from a request's Host.
    if (cfg.issuer == null || cfg.issuer.isEmpty()) throw new IllegalArgumentException("issuer is required (the gateway's public origin, e.g. https://gw.example.com)");
    cfg.issuer = Lmbp.origin(cfg.issuer);
    if (seed == null) { seed = new byte[32]; Lmbp.RNG.nextBytes(seed); }
    key = Lmbp.signingKey(seed);
    kid = Lmbp.thumbprint(key.pub());
  }

  void log(String s) { System.err.println(s); }

  // ---------- locking helpers ----------
  void locked(Runnable r) { lock.lock(); try { r.run(); } finally { lock.unlock(); } }

  /** Run r with the gateway lock fully released (if held), then re-acquire it. */
  void unlocked(Runnable r) {
    int n = lock.getHoldCount();
    for (int i = 0; i < n; i++) lock.unlock();
    try { r.run(); } finally { for (int i = 0; i < n; i++) lock.lock(); }
  }

  void await(long ms) {
    try { cv.await(ms, TimeUnit.MILLISECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
  }

  void wakeAll() { cv.signalAll(); }

  void abortReq(Abort a) { locked(() -> { a.aborted = true; wakeAll(); }); }

  ScheduledFuture<?> later(long ms, Runnable r) {
    return sched.schedule(() -> locked(() -> { try { r.run(); } catch (RuntimeException e) { log("timer error: " + e); } }), ms, TimeUnit.MILLISECONDS);
  }

  ScheduledFuture<?> every(long ms, Runnable r) {
    return sched.scheduleAtFixedRate(() -> locked(() -> { try { r.run(); } catch (RuntimeException e) { log("timer error: " + e); } }), ms, ms, TimeUnit.MILLISECONDS);
  }

  static void cancel(ScheduledFuture<?> f) { if (f != null) f.cancel(false); }

  /** Starts the retention pass: every half the retention period, between 1 s and 1 h (as in every SDK). */
  void startRetention() {
    if (cfg.retention < 0) return;
    every(Math.min(3600_000, Math.max(1000, cfg.retention / 2)), () -> {
      int n = store.purge(System.currentTimeMillis() - cfg.retention);
      if (n > 0) log("retention purge: removed " + n + " tasks");
    });
  }

  // ---------- tenants ----------
  void registerTenant(String id, String apiKey, Map<String, Object> profile) {
    if (!Lmbp.TENANT_ID_RE.matcher(id).matches()) throw new IllegalArgumentException("invalid tenant id " + id);
    if (apiKey == null || apiKey.length() < 32) throw new IllegalArgumentException("tenant API key must be at least 32 characters");
    List<Object> rs = Json.asList(profile.get("requested_scopes"));
    if (rs != null) for (Object s : rs) if (!Lmbp.SCOPES.contains(s)) throw new IllegalArgumentException("unknown scope " + s);
    String name = profile.get("display_name") instanceof String dn && !dn.isEmpty() ? dn : id;
    tenants.put(id, new Tenant(id, name, Lmbp.shaHex(apiKey), profile));
  }

  String issuer(Http.Req req) { return cfg.issuer; }

  boolean useJTI(String j, long untilMs) { return jtis.use(j, untilMs); }

  Map<String, Object> verifyAccess(Object tok, String iss) {
    Map<String, Object> uc = Lmbp.unverifiedClaims(tok);
    Map<String, Object> c = Lmbp.verifyJWT(key.pub(), tok, Lmbp.TYP_ACCESS, Lmbp.tokenAudience(iss, String.valueOf(uc.get("tenant"))), Lmbp.now());
    if (!iss.equals(c.get("iss"))) throw new IllegalArgumentException("token issuer mismatch");
    return c;
  }

  DState online(String id) { DState ds = devs.get(id); return ds != null && ds.connected() ? ds : null; }

  interface Err { void send(int status, String code, String msg); }

  // ---------- HTTP routing ----------
  void handle(Http.Req req, Http.Res res) {
    lock.lock();
    try { route(req, res); } finally { lock.unlock(); }
  }

  void route(Http.Req req, Http.Res res) {
    String p = req.path;
    Err err = (s, code, msg) -> { if (p.startsWith("/v1/")) apiError(res, s, code, msg); else problem(res, s, code, msg); };
    if (p.equals("/healthz")) { json(res, 200, Json.obj("status", "ok")); return; }
    if (!cfg.webDir.isEmpty() && WEB_FILES.containsKey(p) && (req.method.equals("GET") || req.method.equals("HEAD"))) { serveWeb(res, p); return; }
    if (p.equals("/.well-known/jwks.json")) { res.setHeader("Cache-Control", "public, max-age=300"); json(res, 200, Json.obj("keys", List.of(Lmbp.publicJWK(key.pub())))); return; }
    if (p.equals("/.well-known/lmbp")) { metadata(req, res); return; }
    if (p.equals("/lmbp/v1/device/authorize")) { authorize(req, res); return; }
    if (p.equals("/lmbp/v1/token")) { token(req, res); return; }
    if (p.equals("/lmbp/v1/connect")) { problem(res, 400, "VERSION_UNSUPPORTED", Lmbp.VERSION_REQUIRED); return; }
    if (p.equals("/lmbp/v1/tenant/devices/approvals")) { approve(req, res, err); return; }
    if (p.equals("/lmbp/v1/tenant/devices")) { listDevices(req, res, err); return; }
    Matcher m = REVOKE_RE.matcher(p);
    if (m.matches()) { revoke(req, res, err, Http.Req.dec(m.group(1))); return; }
    m = EVENTS_RE.matcher(p);
    if (m.matches() && req.method.equals("GET")) { taskEvents(req, res, err, m.group(1)); return; }
    if (p.equals("/v1/models")) { models(req, res, err); return; }
    if (p.equals("/v1/chat/completions")) { chat(req, res, err, null, false); return; }
    if (p.equals("/v1/messages")) { messages(req, res); return; }
    err.send(404, "BAD_REQUEST", "not found");
  }

  void serveWeb(Http.Res res, String p) {
    String[] f = WEB_FILES.get(p);
    byte[] b;
    try { b = Files.readAllBytes(Path.of(cfg.webDir, f[0])); } catch (IOException e) { json(res, 404, Json.obj("error", "chat UI not installed")); return; }
    res.setHeader("Content-Type", f[1]);
    res.setHeader("Content-Security-Policy", WEB_CSP);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "no-cache");
    res.send(200, f[1], b);
  }

  record Auth(Tenant t, String user) {}

  Auth tenantAuth(Http.Req req, Err err) {
    String a = req.header("authorization");
    if (a.isEmpty() && !req.header("x-api-key").isEmpty()) a = "Bearer " + req.header("x-api-key");
    if (!a.startsWith("Bearer ")) { err.send(401, "UNAUTHENTICATED", "tenant API key required"); return null; }
    byte[] h = Lmbp.shaHex(a.substring(7)).getBytes(StandardCharsets.UTF_8);
    Tenant found = null;
    for (Tenant t : tenants.values()) if (MessageDigest.isEqual(t.keyHash().getBytes(StandardCharsets.UTF_8), h)) found = t;
    if (found == null) { err.send(401, "UNAUTHENTICATED", "invalid tenant API key"); return null; }
    String user = req.headers.get("x-end-user");
    if (!Lmbp.validHeader(user, 128)) { err.send(400, "BAD_REQUEST", "X-End-User must be 1-128 printable ASCII characters"); return null; }
    return new Auth(found, user);
  }

  // ---------- §18 metadata ----------
  Map<String, Object> buildMetadata(String iss, Tenant t) {
    String ws = "ws" + iss.substring(4);
    Map<String, Object> m = Json.obj("issuer", iss, "jwks_uri", iss + "/.well-known/jwks.json", "device_authorization_endpoint", iss + "/lmbp/v1/device/authorize",
        "token_endpoint", iss + "/lmbp/v1/token", "connect_endpoint", ws + "/lmbp/v1/connect", "chat_completions_endpoint", iss + "/v1/chat/completions",
        "protocol_versions", Lmbp.PROTOCOL_VERSIONS, "profiles", Lmbp.PROFILES, "capabilities", Lmbp.CAPABILITIES, "scopes_supported", Lmbp.SCOPES);
    if (t == null) return m;
    Map<String, Object> p = t.profile();
    Map<String, Object> saas = Json.obj("name", p.get("display_name") instanceof String dn && !dn.isEmpty() ? dn : t.name());
    for (String k : new String[] {"logo_uri", "homepage_uri", "policy_uri", "tos_uri", "pairing_uri"}) if (Json.truthy(p.get(k))) saas.put(k, p.get(k));
    long iat = Lmbp.now();
    m.put("tenant", t.id());
    m.put("audience", Lmbp.tokenAudience(iss, t.id()));
    m.put("saas", saas);
    List<Object> rm = Json.asList(p.get("requested_models"));
    if (rm != null && !rm.isEmpty()) m.put("requested_models", rm);
    List<Object> rs = Json.asList(p.get("requested_scopes"));
    m.put("requested_scopes", rs != null && !rs.isEmpty() ? rs : List.of("lmbp.chat"));
    m.put("iat", iat);
    m.put("exp", iat + 3600);
    m.put("signed_metadata", Lmbp.signJWS(key.priv(), Lmbp.TYP_METADATA, kid, m));
    return m;
  }

  void metadata(Http.Req req, Http.Res res) {
    if (!req.method.equals("GET")) { problem(res, 405, "BAD_REQUEST", "GET required"); return; }
    Tenant t = null;
    String id = req.queryParam("tenant");
    if (id != null && !id.isEmpty()) {
      t = Lmbp.TENANT_ID_RE.matcher(id).matches() ? tenants.get(id) : null;
      if (t == null) { problem(res, 404, "BAD_REQUEST", "unknown tenant"); return; }
    }
    res.setHeader("Cache-Control", "public, max-age=300");
    json(res, 200, buildMetadata(issuer(req), t));
  }

  // ---------- RFC 8628 pairing ----------
  void authorize(Http.Req req, Http.Res res) {
    if (!req.method.equals("POST")) { oauthError(res, 405, "invalid_request"); return; }
    // §6.2: limited per client address (the TCP peer) before anything is parsed or stored.
    if (!authRate.allow(req.remoteAddr, AUTHORIZE_PER_MINUTE)) { res.setHeader("Retry-After", "60"); oauthError(res, 429, "slow_down"); return; }
    Map<String, String> ps = params(req, 4096);
    if (ps == null || ps.get("tenant") == null || ps.get("tenant").isEmpty() || (ps.get("device_name") != null && !Lmbp.validDeviceName(ps.get("device_name")))) { oauthError(res, 400, "invalid_request"); return; }
    byte[] pub;
    try { pub = Lmbp.unb64(ps.getOrDefault("public_key", "")); } catch (RuntimeException e) { oauthError(res, 400, "invalid_request"); return; }
    if (pub.length != 32) { oauthError(res, 400, "invalid_request"); return; }
    if (!tenants.containsKey(ps.get("tenant"))) { oauthError(res, 400, "invalid_client"); return; }
    String dc = Lmbp.randomID("dc_");
    Store.DeviceAuth d = new Store.DeviceAuth();
    d.codeHash = Lmbp.shaHex(dc); d.userCode = userCode(); d.tenant = ps.get("tenant"); d.pub = pub; d.name = ps.getOrDefault("device_name", "");
    d.status = "pending"; d.expires = System.currentTimeMillis() + cfg.codeTTL * 1000; d.interval = INITIAL_INTERVAL;
    if (!reservePending(d.tenant, d.codeHash, d.expires)) { res.setHeader("Retry-After", "60"); oauthError(res, 429, "slow_down"); return; }
    try { store.putDeviceAuth(d); } catch (RuntimeException e) { releasePending(d.tenant, d.codeHash); throw e; }
    res.setHeader("Cache-Control", "no-store");
    json(res, 200, Json.obj("device_code", dc, "user_code", d.userCode, "expires_in", cfg.codeTTL, "interval", (long) d.interval));
  }

  /** Counts a new pending pairing against its tenant's cap (expired entries are dropped first). */
  boolean reservePending(String tenant, String hash, long expires) {
    long now = System.currentTimeMillis();
    Map<String, Long> m = pending.computeIfAbsent(tenant, k -> new HashMap<>());
    m.values().removeIf(at -> now > at);
    if (m.size() >= MAX_PENDING_PER_TENANT) return false;
    m.put(hash, expires);
    return true;
  }

  void releasePending(String tenant, String hash) {
    Map<String, Long> m = pending.get(tenant);
    if (m != null) { m.remove(hash); if (m.isEmpty()) pending.remove(tenant); }
  }

  // Failures are counted per end user of a tenant (§6.4). Callers hold the engine lock, so the
  // check, the decision and the record are one atomic step: a code is decided once.
  boolean allowAttempt(String tenant, String user) {
    String key = tenant + "\0" + user;
    long cut = System.currentTimeMillis() - 60_000;
    List<Long> keep = new ArrayList<>();
    for (long t : fails.getOrDefault(key, List.of())) if (t > cut) keep.add(t);
    if (keep.isEmpty()) fails.remove(key); else fails.put(key, keep);
    return keep.size() < FAILURES_PER_MINUTE;
  }

  void recordFailure(String tenant, String user) { fails.computeIfAbsent(tenant + "\0" + user, k -> new ArrayList<>()).add(System.currentTimeMillis()); }


  void approve(Http.Req req, Http.Res res, Err err) {
    if (!req.method.equals("POST")) { err.send(405, "BAD_REQUEST", "POST required"); return; }
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    Object body = req.body != null && req.body.length <= 4096 ? Json.tryParse(new String(req.body, StandardCharsets.UTF_8)) : null;
    if (!(body instanceof Map)) { err.send(400, "BAD_REQUEST", "invalid JSON"); return; }
    Object uc = Json.get(body, "user_code");
    Object jkt = Json.get(body, "jkt");
    PairResult r = pairDecide(a.t().id(), a.user(), uc instanceof String s ? s : (uc == null ? "" : Json.stringify(uc)),
        Boolean.TRUE.equals(Json.get(body, "deny")), Json.truthy(jkt) ? String.valueOf(jkt) : null);
    if (r.status != 0) { err.send(r.status, r.code, r.message); return; }
    Store.DeviceAuth d = r.d;
    json(res, 200, Json.obj("status", d.status, "device_id", d.deviceID, "device_name", d.name, "jkt", Lmbp.thumbprint(d.pub)));
  }

  static final class PairResult { Store.DeviceAuth d; int status; String code, message; }

  /** The one entry for approving/denying a user code; enforces the per-user failed-code lockout. */
  PairResult pairDecide(String tenant, String owner, String userCode, boolean deny, String jkt) {
    PairResult r = new PairResult();
    if (!allowAttempt(tenant, owner)) { r.status = 429; r.code = "RATE_LIMITED"; r.message = "too many failed codes; wait a minute"; return r; }
    String code = normCode(userCode);
    Store.DeviceAuth d = code.isEmpty() ? null : store.deviceAuthByUserCode(tenant, code);
    long now = System.currentTimeMillis();
    // §19: a declined pairing cannot be overridden by a later approval.
    if (d != null && d.status.equals("denied") && now <= d.expires) return fail(r, tenant, owner, 403, "CONSENT_DENIED", "pairing consent was denied for this code");
    if (d == null || !d.status.equals("pending") || now > d.expires) return fail(r, tenant, owner, 404, "BAD_REQUEST", "code invalid, expired or already used");
    if (jkt != null && !jkt.equals(Lmbp.thumbprint(d.pub))) return fail(r, tenant, owner, 409, "FORBIDDEN", "device key thumbprint does not match the pairing request");
    r.d = decide(d, tenant, owner, deny);
    return r;
  }

  PairResult fail(PairResult r, String tenant, String owner, int status, String code, String msg) {
    recordFailure(tenant, owner);
    r.status = status; r.code = code; r.message = msg;
    return r;
  }

  Store.DeviceAuth decide(Store.DeviceAuth d, String tenant, String owner, boolean deny) {
    if (deny) d.status = "denied";
    else {
      d.status = "approved"; d.owner = owner; d.deviceID = Lmbp.randomID("dev_");
      Store.Device dev = new Store.Device();
      dev.id = d.deviceID; dev.tenant = tenant; dev.owner = owner; dev.name = d.name; dev.pub = d.pub; dev.status = "active"; dev.created = Instant.now();
      store.putDevice(dev);
    }
    store.putDeviceAuth(d);
    releasePending(tenant, d.codeHash);
    return d;
  }

  Map<String, Object> issue(Store.Device dev, String iss) {
    long iat = Lmbp.now();
    Map<String, Object> c = Json.obj("iss", iss, "sub", dev.id, "aud", Lmbp.tokenAudience(iss, dev.tenant), "tenant", dev.tenant, "iat", iat,
        "exp", iat + cfg.tokenTTL, "jti", Lmbp.randomID("jti_"), "cnf", Json.obj("jkt", Lmbp.thumbprint(dev.pub)));
    return Json.obj("access_token", Lmbp.signJWS(key.priv(), Lmbp.TYP_ACCESS, kid, c), "token_type", "Bearer", "expires_in", cfg.tokenTTL,
        "device_id", dev.id, "gateway_key", Lmbp.publicJWK(key.pub()), "issuer", iss);
  }

  void token(Http.Req req, Http.Res res) {
    if (!req.method.equals("POST")) { oauthError(res, 405, "invalid_request"); return; }
    Map<String, String> ps = params(req, 8192);
    if (ps == null) { oauthError(res, 400, "invalid_request"); return; }
    String iss = issuer(req);
    String gt = ps.getOrDefault("grant_type", "");
    if (gt.equals("urn:ietf:params:oauth:grant-type:device_code")) {
      Store.DeviceAuth d = store.getDeviceAuth(Lmbp.shaHex(ps.getOrDefault("device_code", "")));
      if (d == null) { oauthError(res, 400, "invalid_grant"); return; }
      String jti;
      try {
        Map<String, Object> pc = Lmbp.verifyProof(d.pub, ps.get("proof"), "", Lmbp.PROOF_TOKEN, ps.get("device_code"));
        jti = String.valueOf(pc.get("jti"));
        if (jtis.has(jti)) throw new IllegalArgumentException("replay");
      } catch (RuntimeException e) { oauthError(res, 400, "invalid_grant"); return; }
      // A code that can no longer yield a token answers without remembering the proof's jti.
      long now = System.currentTimeMillis();
      if (now > d.expires) { oauthError(res, 400, "expired_token"); return; }
      if (d.status.equals("denied")) { oauthError(res, 400, "access_denied"); return; }
      if (d.status.equals("consumed")) { oauthError(res, 400, "invalid_grant"); return; }
      if (!useJTI(jti, now + 180_000)) { oauthError(res, 400, "invalid_grant"); return; }
      if (d.status.equals("pending")) {
        boolean slow = now - d.lastPoll < d.interval * 1000L - 200;
        d.lastPoll = now;
        if (slow) d.interval += 5;
        // §6.3: a device that keeps ignoring slow_down loses its code.
        boolean dead = (d.interval - INITIAL_INTERVAL) / 5 > MAX_SLOW_DOWNS;
        if (dead) { d.expires = now; releasePending(d.tenant, d.codeHash); }
        store.putDeviceAuth(d);
        oauthError(res, 400, dead ? "expired_token" : slow ? "slow_down" : "authorization_pending");
        return;
      }
      Store.Device dev = store.getDevice(d.deviceID);
      if (dev == null) { oauthError(res, 500, "server_error"); return; }
      d.status = "consumed";
      store.putDeviceAuth(d);
      json(res, 200, issue(dev, iss));
      return;
    }
    if (gt.equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
      try {
        Map<String, Object> uc = Lmbp.unverifiedClaims(ps.get("assertion"));
        Store.Device dev = store.getDevice(uc.get("sub") instanceof String s ? s : null);
        if (dev == null || !dev.status.equals("active")) throw new IllegalArgumentException("device");
        Map<String, Object> c = Lmbp.verifyJWT(dev.pub, ps.get("assertion"), Lmbp.TYP_ASSERTION, Lmbp.assertionAudience(iss), Lmbp.now());
        long exp = Json.longOf(c.get("exp")), iat = Json.longOf(c.get("iat"));
        if (!dev.id.equals(c.get("iss")) || exp - iat > 300 || !Json.truthy(c.get("jti")) || !useJTI(String.valueOf(c.get("jti")), (exp + 60) * 1000))
          throw new IllegalArgumentException("claims");
        json(res, 200, issue(dev, iss));
      } catch (RuntimeException e) { oauthError(res, 400, "invalid_grant"); }
      return;
    }
    oauthError(res, 400, "unsupported_grant_type");
  }

  // ---------- tenant device management ----------
  void listDevices(Http.Req req, Http.Res res, Err err) {
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    List<Object> out = new ArrayList<>();
    for (Store.Device d : store.listDevices(a.t().id(), a.user())) {
      Map<String, Object> item = Json.obj("device_id", d.id, "name", d.name, "status", d.status,
          "created_at", d.created.truncatedTo(ChronoUnit.SECONDS).toString(), "online", false, "models", new ArrayList<>(),
          "public_key", Lmbp.publicJWK(d.pub), "jkt", Lmbp.thumbprint(d.pub));
      if (!d.e2eeKey.isEmpty()) item.put("e2ee_key", d.e2eeKey);
      DState s = online(d.id);
      if (s != null) {
        item.put("online", true);
        item.put("models", new ArrayList<>(s.models));
        item.put("model_capabilities", new LinkedHashMap<>(s.modelCaps));
        if (!s.modelNames.isEmpty()) item.put("model_names", new LinkedHashMap<>(s.modelNames));
        item.put("capabilities", new ArrayList<>(s.caps));
        item.put("max_concurrency", (long) s.maxConc);
      }
      out.add(item);
    }
    // Pending pairings are never listed (§6.4, §12.6): approval needs the code shown on the device.
    json(res, 200, Json.obj("devices", out));
  }

  void revoke(Http.Req req, Http.Res res, Err err, String id) {
    if (!req.method.equals("POST")) { err.send(404, "BAD_REQUEST", "not found"); return; }
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    if (!revokeDevice(a.t().id(), a.user(), id)) { err.send(404, "FORBIDDEN", "device not found"); return; }
    json(res, 200, Json.obj("device_id", id, "status", "revoked"));
  }

  boolean revokeDevice(String tenant, String owner, String id) {
    Store.Device d = store.getDevice(id);
    if (d == null || !d.tenant.equals(tenant) || !d.owner.equals(owner)) return false;
    d.status = "revoked";
    store.putDevice(d);
    dropDevice(id, "DEVICE_OFFLINE", "device revoked"); // in-flight tasks: OUTCOME_UNKNOWN (§7.5)
    return true;
  }

  void dropDevice(String id, String code, String msg) {
    DState ds = devs.remove(id);
    if (ds != null) ds.drop(code, msg);
  }

  // ---------- WebSocket tunnel ----------
  void upgrade(Http.Req req, OutputStream out) throws IOException {
    Http.Ws ws;
    lock.lock();
    try {
      String reject = null, code = "";
      int status = 0;
      String tok = req.header("authorization").replaceFirst("^Bearer ", "");
      String iss = issuer(req);
      Map<String, Object> claims = null;
      Store.Device dev = null;
      List<String> protos = new ArrayList<>();
      for (String s : req.header("sec-websocket-protocol").split(",")) protos.add(s.trim());
      if (!req.path.equals("/lmbp/v1/connect")) { status = 404; code = "BAD_REQUEST"; reject = "not found"; }
      else if (!protos.contains(Lmbp.SUBPROTOCOL)) { status = 400; code = "VERSION_UNSUPPORTED"; reject = Lmbp.VERSION_REQUIRED; }
      else if (!req.header("origin").isEmpty()) { status = 403; code = "FORBIDDEN"; reject = "browser origins are not allowed"; }
      else {
        try { claims = verifyAccess(tok, iss); } catch (RuntimeException e) { status = 401; code = "UNAUTHENTICATED"; reject = String.valueOf(e.getMessage()); }
        if (reject == null) {
          dev = store.getDevice(claims.get("sub") instanceof String s ? s : null);
          if (dev == null || !dev.status.equals("active") || !dev.tenant.equals(claims.get("tenant")) || !Lmbp.thumbprint(dev.pub).equals(Json.get(claims.get("cnf"), "jkt"))) {
            status = 403; code = "FORBIDDEN"; reject = "device revoked or token not bound to device key";
          }
        }
      }
      if (reject == null && (req.header("sec-websocket-key").isEmpty() || !req.header("sec-websocket-version").equals("13"))) {
        status = 400; code = "BAD_REQUEST"; reject = "bad WebSocket handshake";
      }
      if (reject != null) {
        byte[] b = Json.bytes(problemBody(status, code, reject));
        String head = "HTTP/1.1 " + status + " " + Http.reason(status) + "\r\nContent-Type: application/problem+json\r\nCache-Control: no-store\r\nContent-Length: "
            + b.length + "\r\nConnection: close\r\n\r\n";
        byte[] all = Lmbp.concat(head.getBytes(StandardCharsets.ISO_8859_1), b);
        unlocked(() -> { try { out.write(all); out.flush(); } catch (IOException e) { /* ignore */ } });
        return;
      }
      String resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + Http.acceptKey(req.header("sec-websocket-key"))
          + "\r\nSec-WebSocket-Protocol: " + Lmbp.SUBPROTOCOL + "\r\n\r\n";
      out.write(resp.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      ws = new Http.Ws(this, req.sock, req.in, out);
      session(ws, dev, tok, claims, iss);
    } finally { lock.unlock(); }
    ws.run(Lmbp.MAX_FRAME_BYTES);
  }

  static Map<String, Object> envelope(String type, String id, String taskID, Object data) {
    Map<String, Object> e = Json.obj("v", (long) Lmbp.VERSION, "type", type);
    if (id != null && !id.isEmpty()) e.put("id", id);
    if (taskID != null && !taskID.isEmpty()) e.put("task_id", taskID);
    if (data != null) e.put("data", data);
    return e;
  }

  static String idOf(Object env) { Object v = Json.get(env, "id"); return v instanceof String s ? s : null; }

  static boolean isVersion(Object v) { return Json.isNumber(v) && ((Number) v).doubleValue() == Lmbp.VERSION; }

  void session(Http.Ws ws, Store.Device dev, String tok, Map<String, Object> claims, String iss) {
    ScheduledFuture<?> helloTimer = later(15_000, ws::terminate);
    ws.onMessage = (raw, binary, size) -> {
      ws.onMessage = null;
      cancel(helloTimer);
      Object env = Json.tryParse(raw);
      Map<String, Object> hello = Json.asObj(Json.get(env, "data"));
      if (binary || !"hello".equals(Json.get(env, "type")) || hello == null) { ws.close(); return; }
      String envID = idOf(env);
      Consumer<String[]> early = cm -> {
        try { ws.send(Json.stringify(envelope("error", envID, null, errorBody(cm[0], cm[1], false)))); } catch (RuntimeException e) { /* closed */ }
        ws.close();
      };
      if (!isVersion(Json.get(env, "v"))) { early.accept(new String[] {"VERSION_UNSUPPORTED", Lmbp.VERSION_REQUIRED}); return; }
      // §7.4 order: v, schema (BAD_REQUEST), device/proof (UNAUTHENTICATED), extension semantics.
      String schemaBad = Params.announceProblem(hello, true);
      if (schemaBad != null) { early.accept(new String[] {"BAD_REQUEST", schemaBad}); return; }
      try {
        if (!dev.id.equals(hello.get("device_id"))) throw new IllegalArgumentException("device");
        Map<String, Object> pc = Lmbp.verifyProof(dev.pub, hello.get("proof"), dev.id, Lmbp.PROOF_HELLO, tok);
        if (!useJTI(String.valueOf(pc.get("jti")), System.currentTimeMillis() + 180_000)) throw new IllegalArgumentException("replay");
      } catch (RuntimeException e) { early.accept(new String[] {"UNAUTHENTICATED", "invalid key proof"}); return; }
      List<String> caps = new ArrayList<>();
      List<Object> hc = Json.asList(hello.get("capabilities"));
      if (hc != null) for (Object c : hc) if (c instanceof String s && Lmbp.CAPABILITIES.contains(s) && !caps.contains(s)) caps.add(s);
      if (hello.get("flow") != null && caps.contains("flow") && !validFlow(hello.get("flow"))) {
        early.accept(new String[] {"BAD_REQUEST", "flow windows must be >= max_frame_bytes (" + Lmbp.MAX_FRAME_BYTES + ") and conn_window >= task_window"});
        return;
      }
      if (Json.truthy(hello.get("e2ee_key")) && caps.contains("e2ee")) {
        try { Lmbp.verifyE2EEKey(dev.pub, dev.id, hello.get("e2ee_key")); } catch (RuntimeException e) { early.accept(new String[] {"BAD_REQUEST", "invalid e2ee key statement"}); return; }
        dev.e2eeKey = (String) hello.get("e2ee_key");
        store.putDevice(dev);
      } else caps.remove("e2ee");
      int conc = Math.min(((Number) hello.get("max_concurrency")).intValue(), cfg.maxConc); // validated 1..16; may lower, never raise
      attachSession(ws, dev, claims, iss, envID, hello, caps, conc);
    };
  }

  /** JavaScript `x | 0`. */
  static long toInt32(Object v) {
    if (!Json.isNumber(v)) return 0;
    double d = ((Number) v).doubleValue();
    if (Double.isNaN(d) || Double.isInfinite(d)) return 0;
    return (int) (long) d;
  }

  static boolean validFlow(Object f) {
    if (!Json.isObj(f)) return false;
    Object tw = Json.get(f, "task_window"), cw = Json.get(f, "conn_window");
    if (!Json.isSafeInteger(tw) || !Json.isSafeInteger(cw)) return false;
    double t = ((Number) tw).doubleValue(), c = ((Number) cw).doubleValue();
    return t >= Lmbp.MAX_FRAME_BYTES && c >= t && c <= 2147483648.0;
  }

  void attachSession(Http.Ws ws, Store.Device dev, Map<String, Object> claims, String iss, String envID, Map<String, Object> hello, List<String> caps, int conc) {
    DState old = devs.get(dev.id);
    Map<String, Object> resume = Json.asObj(hello.get("resume"));
    boolean resumed = old != null && resume != null && caps.contains("resume") && Json.truthy(resume.get("token")) && resume.get("token").equals(old.resumeToken);
    if (old != null && !resumed) { devs.remove(dev.id); old.drop("OUTCOME_UNKNOWN", "device reconnected without resuming"); }
    DState ds = resumed ? old : new DState(this, dev);
    if (!resumed) devs.put(dev.id, ds);
    Http.Ws prev = ds.ws;
    int gen = ++ds.gen;
    ds.ws = ws;
    List<Object> hm = Json.asList(hello.get("models"));
    ds.models = hm != null ? hm : new ArrayList<>();
    Map<String, Object> mcaps = Json.asObj(hello.get("model_capabilities"));
    ds.modelCaps = mcaps != null ? mcaps : new LinkedHashMap<>();
    ds.modelNames = cleanNames(hello.get("model_names"), ds.models);
    ds.caps = caps;
    ds.maxConc = conc;
    ds.tokenExp = Json.longOf(claims.get("exp"));
    ds.issuer = iss;
    ds.resumeToken = Lmbp.randomID("rt_");
    if (ds.inb == null) ds.inb = new Lmbp.Inbound(caps.contains("flow") ? cfg.flow : null);
    else ds.inb.resetWindows();
    List<Object> resumeTasks = new ArrayList<>();
    Map<String, Long> deviceRecv = new HashMap<>();
    List<Task> lost = new ArrayList<>();
    if (resumed) {
      List<Object> rts = Json.asList(resume.get("tasks"));
      if (rts != null) for (Object rt : rts) deviceRecv.put(String.valueOf(Json.get(rt, "task_id")), toInt32(Json.get(rt, "recv_seq")));
      for (Map.Entry<String, Task> e : ds.tasks.entrySet()) {
        Task t = e.getValue();
        if (!deviceRecv.containsKey(e.getKey()) && t.sentRun) { lost.add(t); continue; }
        resumeTasks.add(Json.obj("task_id", e.getKey(), "recv_seq", ds.inb.recv(e.getKey())));
      }
    }
    if (prev != null && prev != ws) prev.terminate();
    for (Task t : lost) t.failOffline("OUTCOME_UNKNOWN", "device resumed without this task; outcome unknown");
    Object hf = hello.get("flow");
    ds.out.setFlow(caps.contains("flow")
        ? (validFlow(hf) ? new Lmbp.Flow(Json.longOf(Json.get(hf, "task_window")), Json.longOf(Json.get(hf, "conn_window"))) : new Lmbp.Flow(1 << 20, 4 << 20))
        : null);
    Map<String, Object> welcome = Json.obj("session_id", Lmbp.randomID("sess_"), "heartbeat_seconds", Math.max(1, cfg.pingInterval / 1000),
        "max_frame_bytes", (long) Lmbp.MAX_FRAME_BYTES, "token_expires_at", ds.tokenExp, "capabilities", caps, "max_concurrency", (long) conc);
    if (caps.contains("flow")) welcome.put("flow", Json.obj("task_window", cfg.flow.taskWindow(), "conn_window", cfg.flow.connWindow()));
    if (caps.contains("resume")) {
      welcome.put("resume_token", ds.resumeToken);
      welcome.put("resume_window_seconds", cfg.resumeWindow / 1000);
      if (resume != null) welcome.put("resume", Json.obj("resumed", resumed, "tasks", resumeTasks));
    }
    ds.control(envelope("welcome", envID, null, welcome));
    ds.out.attach(raw -> { if (!ws.isOpen()) throw new IllegalStateException("closed"); ws.send(raw); });
    if (resumed) {
      for (Object rt : resumeTasks) { String id = (String) Json.get(rt, "task_id"); ds.out.retransmit(id, deviceRecv.getOrDefault(id, 0L)); }
      log("device " + dev.id + " resumed " + resumeTasks.size() + " task(s)");
    } else log("device " + dev.id + " (tenant " + dev.tenant + ") online, models=" + ds.models + " caps=" + caps + " conc=" + conc);

    ScheduledFuture<?> ping = every(cfg.pingInterval, () -> {
      if (Lmbp.now() > ds.tokenExp + 30) { ws.terminate(); return; }
      if (System.currentTimeMillis() - ds.lastSeen > 60_000) { ws.terminate(); return; }
      ws.ping();
    });
    ds.lastSeen = System.currentTimeMillis();
    ws.onPong = () -> ds.lastSeen = System.currentTimeMillis();
    ws.onMessage = (raw, binary, size) -> {
      ds.lastSeen = System.currentTimeMillis();
      if (binary) { ws.close(1003, "text frames only"); return; }
      Object inp = Json.tryParse(raw);
      if (!(inp instanceof Map) || !isVersion(Json.get(inp, "v"))) { ds.sendErr(idOf(inp), "BAD_REQUEST", "malformed frame"); return; }
      Object type = Json.get(inp, "type");
      String ty = type instanceof String s ? s : String.valueOf(type);
      switch (ty) {
        case "task.delta", "task.done", "task.error" -> { if (!onDeviceData(ds, Json.asObj(inp), size)) ws.close(); }
        case "task.ack" -> {
          Object seq = Json.get(Json.get(inp, "data"), "seq");
          if (Json.isInteger(seq)) ds.out.ack(String.valueOf(Json.get(inp, "task_id")), Json.longOf(seq));
        }
        case "session.token" -> {
          if (!refreshSession(ds, dev, Json.asObj(inp))) { ds.sendErr(idOf(inp), "UNAUTHENTICATED", "session token rejected"); ws.close(); }
        }
        case "models.update" -> {
          String muBad = Params.announceProblem(Json.get(inp, "data"), false);
          if (muBad != null) { ds.sendErr(idOf(inp), "BAD_REQUEST", muBad); break; } // rejected whole: nothing applied
          Map<String, Object> mu = Json.asObj(Json.get(inp, "data"));
          List<Object> ml = Json.asList(mu.get("models"));
          {
            ds.models = ml;
            Map<String, Object> mc = Json.asObj(mu.get("model_capabilities"));
            ds.modelCaps = mc != null ? mc : new LinkedHashMap<>();
            ds.modelNames = cleanNames(mu.get("model_names"), ml);
            Object mx = mu.get("max_concurrency");
            if (mx != null) { ds.maxConc = Math.min(((Number) mx).intValue(), cfg.maxConc); ds.wakeSlots(); }
            if (Json.truthy(mu.get("e2ee_key")) && ds.caps.contains("e2ee")) {
              try { Lmbp.verifyE2EEKey(dev.pub, dev.id, mu.get("e2ee_key")); dev.e2eeKey = (String) mu.get("e2ee_key"); store.putDevice(dev); } catch (RuntimeException e) { /* ignore */ }
            }
          }
        }
        case "ping" -> ds.control(envelope("pong", idOf(inp), null, null));
        case "pong" -> { }
        default -> ds.sendErr(idOf(inp), "BAD_REQUEST", "unknown message type " + ty);
      }
    };
    ws.onClose = () -> {
      cancel(ping);
      if (ds.gen != gen) return; // replaced by a newer connection
      ds.out.attach(null);
      ds.ws = null;
      if (!ds.caps.contains("resume") || ds.dropped) { dropDevice(dev.id, "DEVICE_OFFLINE", "device disconnected"); return; }
      later(cfg.resumeWindow, () -> {
        if (ds.gen == gen && ds.ws == null) {
          if (devs.get(dev.id) == ds) devs.remove(dev.id);
          ds.drop("DEVICE_OFFLINE", "device did not resume in time");
        }
      });
    };
  }

  boolean onDeviceData(DState ds, Map<String, Object> inp, int size) {
    String tid = inp.get("task_id") instanceof String s ? s : String.valueOf(inp.get("task_id"));
    // envelope + body validated before the seq is accepted, persisted or ACKed: an invalid
    // terminal frame (task.done {}) never becomes SUCCEEDED
    String bad = Params.deviceDataProblem(inp);
    if (bad != null) {
      Task tt = ds.tasks.get(tid);
      log("lmbp: device " + ds.deviceID + " task " + tid + ": " + bad);
      if (tt != null) {
        tt.cancel("protocol_error");
        tt.failLocal("INTERNAL", "device sent an invalid frame: " + bad, false);
      } else ds.sendErr(inp.get("id") instanceof String i ? i : null, "BAD_REQUEST", bad);
      return true;
    }
    Task t = ds.tasks.get(tid);
    Object sq = inp.get("seq");
    long seq = Json.isNumber(sq) ? (long) ((Number) sq).doubleValue() : 0;
    if (t == null) {
      Long acked = ds.reclaimed.get(tid);
      if (acked != null) {
        if (seq > acked) ds.reclaimed.put(tid, seq);
        if ("task.done".equals(inp.get("type")) || "task.error".equals(inp.get("type"))) ds.reclaimed.remove(tid);
        if (seq > acked) ds.control(envelope("task.ack", null, tid, Json.obj("seq", seq)));
        return true;
      }
      ds.control(envelope("task.cancel", null, tid, Json.obj("reason", "unknown_task")));
      return true;
    }
    switch (ds.inb.accept(tid, seq, size)) {
      case Lmbp.DUPLICATE: t.maybeAck(); return true;
      case Lmbp.GAP: t.cancel("protocol_error"); t.failLocal("INTERNAL", "sequence gap from device", false); return true;
      case Lmbp.OVERFLOW:
        ds.sendErr("", "FLOW_CONTROL", "flow-control window exceeded");
        t.failLocal("FLOW_CONTROL", "device exceeded the flow-control window", false);
        return false;
      default: break;
    }
    t.onDeviceFrame(inp, seq);
    return true;
  }

  boolean refreshSession(DState ds, Store.Device dev, Map<String, Object> inp) {
    Map<String, Object> st = Json.asObj(inp.get("data"));
    if (st == null) st = Json.obj();
    try {
      Map<String, Object> c = verifyAccess(st.get("access_token"), ds.issuer);
      Store.Device cur = store.getDevice(dev.id);
      if (!dev.id.equals(c.get("sub")) || !Lmbp.thumbprint(dev.pub).equals(Json.get(c.get("cnf"), "jkt")) || cur == null || !cur.status.equals("active")) return false;
      Map<String, Object> pc = Lmbp.verifyProof(dev.pub, st.get("proof"), dev.id, Lmbp.PROOF_SESSION_TOKEN, String.valueOf(st.get("access_token")));
      if (!useJTI(String.valueOf(pc.get("jti")), System.currentTimeMillis() + 180_000)) return false;
      ds.tokenExp = Json.longOf(c.get("exp"));
      ds.control(envelope("session.token", idOf(inp), null, Json.obj("token_expires_at", ds.tokenExp)));
      return true;
    } catch (RuntimeException e) { return false; }
  }

  // ---------- OpenAI-compatible surface ----------
  void models(Http.Req req, Http.Res res, Err err) {
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    List<Object> data = new ArrayList<>();
    for (Store.Device d : store.listDevices(a.t().id(), a.user())) {
      DState s = online(d.id);
      if (s == null || !d.status.equals("active")) continue;
      for (Object m : s.models) {
        Object c = s.modelCaps.get(String.valueOf(m));
        Map<String, Object> item = Json.obj("id", d.id + "/" + m, "object", "model", "owned_by", d.name, "capabilities", Json.truthy(c) ? c : new ArrayList<>());
        String dn = s.modelNames.get(String.valueOf(m));
        if (dn != null) item.put("display_name", dn);
        data.add(item);
      }
    }
    if (!req.header("anthropic-version").isEmpty()) { json(res, 200, Anthropic.modelsList(data)); return; }
    json(res, 200, Json.obj("object", "list", "data", data));
  }

  record Resolved(DState ds, String model, String code, int status) {}

  Resolved resolve(String tenant, String user, String model) {
    List<Store.Device> list = store.listDevices(tenant, user);
    String want = model, devID = "";
    boolean bare = true;
    int i = model.indexOf('/');
    if (i > 0 && model.startsWith("dev_")) { devID = model.substring(0, i); want = model.substring(i + 1); bare = false; }
    boolean known = false, up = false;
    for (Store.Device d : list) {
      if (!d.status.equals("active") || (!bare && !d.id.equals(devID))) continue;
      known = known || !bare;
      DState s = online(d.id);
      if (s != null && s.models.contains(want)) return new Resolved(s, want, null, 0);
      if (s != null) up = true;
    }
    // §6.6: a named device that is online but lacks the model is 404; only an offline one is 503.
    if (known) return up ? new Resolved(null, null, "MODEL_NOT_FOUND", 404) : new Resolved(null, null, "DEVICE_OFFLINE", 503);
    boolean anyOnline = false;
    for (Store.Device d : list) if (online(d.id) != null) anyOnline = true;
    if (!list.isEmpty() && bare && !anyOnline) return new Resolved(null, null, "DEVICE_OFFLINE", 503);
    return new Resolved(null, null, "MODEL_NOT_FOUND", 404);
  }

  /** Anthropic Messages endpoint: validate, translate, then run chat. */
  void messages(Http.Req req, Http.Res res) {
    Err err = (s, code, msg) -> json(res, s, Anthropic.errorBody(s, code, msg));
    if (!req.method.equals("POST")) { err.send(405, "BAD_REQUEST", "POST required"); return; }
    if (tenantAuth(req, err) == null) return;
    if (req.body == null) { err.send(413, "PAYLOAD_TOO_LARGE", "request body too large"); return; }
    Map<String, Object> r = Json.asObj(Json.tryParse(new String(req.body, StandardCharsets.UTF_8)));
    if (r == null) { err.send(400, "BAD_REQUEST", "invalid JSON body"); return; }
    try { Params.validateAnthropicParams(r); } catch (Params.ParamError e) { json(res, 400, Params.paramErrorBody(e, true)); return; }
    Map<String, Object> out;
    try { out = Anthropic.toOpenAI(r); } catch (IllegalArgumentException e) { err.send(400, "BAD_REQUEST", e.getMessage()); return; }
    chat(req, res, err, Json.bytes(out), true);
  }

  void chat(Http.Req req, Http.Res res, Err err, byte[] preBody, boolean anthropic) {
    if (!req.method.equals("POST")) { err.send(405, "BAD_REQUEST", "POST required"); return; }
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    byte[] body = preBody != null ? preBody : req.body;
    if (body == null) { err.send(413, "PAYLOAD_TOO_LARGE", "request body too large"); return; }
    Map<String, Object> r = Json.asObj(Json.tryParse(new String(body, StandardCharsets.UTF_8)));
    if (r == null) { err.send(400, "BAD_REQUEST", "invalid JSON body"); return; }
    // Every parameter is validated before anything is stored, queued or signed.
    Params.Sampling params;
    try { params = Params.validateChatParams(r); } catch (Params.ParamError e) { json(res, 400, Params.paramErrorBody(e, anthropic)); return; }
    String idemKey = req.header("idempotency-key");
    if (!idemKey.isEmpty() && !Lmbp.validHeader(idemKey, 255)) { err.send(400, "BAD_REQUEST", "Idempotency-Key must be 1-255 printable ASCII characters"); return; }
    String bodyHash = HexFormat.of().formatHex(Lmbp.sha256(body));
    String tenant = a.t().id(), user = a.user();
    String reqModel = (String) r.get("model");
    boolean stream = Boolean.TRUE.equals(r.get("stream"));
    Store.Idempotency prior = idemKey.isEmpty() ? null : store.getIdempotency(tenant, user, idemKey);
    if (prior != null && (!prior.tenant().equals(tenant) || !prior.owner().equals(user))) { err.send(500, "INTERNAL", "idempotency store returned a foreign record"); return; }
    if (prior != null) {
      if (!prior.bodyHash().equals(bodyHash)) { err.send(422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body"); return; }
      reattach(req, res, err, tenant, user, prior.taskID(), reqModel, stream, anthropic);
      return;
    }
    List<Object> msgs = Json.asList(r.get("messages"));
    if (msgs == null) msgs = new ArrayList<>();
    List<Object> tools = Json.asList(r.get("tools"));
    if (tools == null) tools = new ArrayList<>();
    boolean hasToolChoice = r.get("tool_choice") != null;
    boolean e2ee = Json.truthy(r.get("lmbp_e2ee"));
    if (e2ee) {
      if (!msgs.isEmpty() || !tools.isEmpty()) { err.send(400, "BAD_REQUEST", "lmbp_e2ee requests must not carry cleartext messages or tools"); return; }
    } else {
      if (msgs.isEmpty() || msgs.size() > Lmbp.MAX_MESSAGES) { err.send(400, "BAD_REQUEST", "1-" + Lmbp.MAX_MESSAGES + " messages required"); return; }
      for (Object m : msgs) {
        Object role = Json.get(m, "role");
        if (!(role instanceof String rs) || !ROLES.contains(rs)) { err.send(400, "BAD_REQUEST", "unsupported role " + role); return; }
        if (rs.equals("tool") && !Json.truthy(Json.get(m, "tool_call_id"))) { err.send(400, "BAD_REQUEST", "tool messages need tool_call_id"); return; }
      }
    }
    Resolved rs = resolve(tenant, user, reqModel);
    if (rs.ds() == null) { err.send(rs.status(), rs.code(), rs.code().equals("DEVICE_OFFLINE") ? "your device is offline" : "model not found on your devices"); return; }
    DState ds = rs.ds();
    String model = rs.model();
    Map<String, Object> run = Json.obj("task_id", "", "iat", 0L, "device_id", ds.deviceID, "model", model);
    List<Blob> blobs = new ArrayList<>();
    List<Object> mc = Json.asList(ds.modelCaps.get(model));
    if (mc == null) mc = List.of();
    if (e2ee) {
      if (!ds.caps.contains("e2ee")) { err.send(400, "CAPABILITY_UNSUPPORTED", "device does not support end-to-end encryption"); return; }
      String jwe = r.get("lmbp_e2ee") instanceof String s ? s : Json.stringify(r.get("lmbp_e2ee"));
      if (jwe.split("\\.", -1).length != 5 || Json.utf8Len(jwe) > Lmbp.MAX_TASK_BLOB_BYTES) { err.send(400, "BAD_REQUEST", "lmbp_e2ee must be a compact JWE"); return; }
      String id = Lmbp.randomID("blob_");
      byte[] data = jwe.getBytes(StandardCharsets.UTF_8);
      blobs.add(new Blob(Json.obj("id", id, "size", (long) data.length, "sha256", Lmbp.b64(Lmbp.sha256(data)), "media_type", "application/jose"), data));
      run.put("e2ee", Json.obj("blob", id));
    } else {
      Extracted ex = extractBlobs(msgs);
      if (ex.code != null) { err.send(errStatus(ex.code), ex.code, ex.msg); return; }
      blobs = ex.blobs;
      if (!tools.isEmpty() || hasToolChoice) {
        if (!ds.caps.contains("tools") || !mc.contains("tools")) { err.send(400, "CAPABILITY_UNSUPPORTED", "model " + model + " does not support tools"); return; }
        for (Object tl : tools)
          if (!"function".equals(Json.get(tl, "type")) || !Json.truthy(Json.get(Json.get(tl, "function"), "name"))) { err.send(400, "BAD_REQUEST", "tools must be type function with a name"); return; }
      }
      if ((ex.vision || ex.audio) && !ds.caps.contains("multimodal")) { err.send(400, "CAPABILITY_UNSUPPORTED", "device does not support multimodal input"); return; }
      if (ex.vision && !mc.contains("vision")) { err.send(400, "CAPABILITY_UNSUPPORTED", "model " + model + " does not accept images"); return; }
      if (ex.audio && !mc.contains("audio")) { err.send(400, "CAPABILITY_UNSUPPORTED", "model " + model + " does not accept audio"); return; }
      List<Object> nm = new ArrayList<>();
      for (Object m : msgs) nm.add(normMessage(Json.asObj(m)));
      run.put("messages", nm);
      if (!tools.isEmpty()) run.put("tools", tools);
      if (hasToolChoice) run.put("tool_choice", r.get("tool_choice"));
    }
    if (params.maxTokens != 0) run.put("max_tokens", params.maxTokens);
    if (params.temperature != null) run.put("temperature", params.temperature);
    if (params.topP != null) run.put("top_p", params.topP);
    if (params.stop != null) run.put("stop", params.stop);
    // Per-model parameter support (spec §16.4): a model that declares "params"
    // gets every other parameter rejected; on /v1/messages the mandatory
    // max_tokens is dropped instead.
    if (mc.contains("params")) {
      if (run.containsKey("max_tokens") && anthropic && !mc.contains("max_tokens")) run.remove("max_tokens");
      for (String flag : new String[] {"temperature", "top_p", "stop", "max_tokens"}) {
        if (run.containsKey(flag) && !mc.contains(flag)) {
          String name = anthropic && flag.equals("stop") ? "stop_sequences" : flag;
          err.send(400, "CAPABILITY_UNSUPPORTED", "model " + model + " does not support the " + name + " parameter");
          return;
        }
      }
    }
    if (!blobs.isEmpty()) { List<Object> refs = new ArrayList<>(); for (Blob b : blobs) refs.add(b.ref); run.put("blobs", refs); }

    String taskID = Lmbp.randomID("task_");
    { // limits (spec §10): the signed task.run frame MUST fit max_frame_bytes and satisfy the schema
      long iat = Lmbp.now();
      Map<String, Object> payload = new LinkedHashMap<>(run);
      payload.put("task_id", taskID); payload.put("iat", iat); payload.put("exp", iat + 60); payload.put("nonce", Lmbp.randomID("n_"));
      String trial = Lmbp.signJWS(key.priv(), Lmbp.TYP_TASK, kid, payload);
      int size = Lmbp.taskRunFrameSize(trial, taskID);
      if (size > Lmbp.MAX_FRAME_BYTES) {
        err.send(413, "PAYLOAD_TOO_LARGE", "request too large: the signed task.run frame would be " + size + " bytes, over max_frame_bytes " + Lmbp.MAX_FRAME_BYTES
            + "; send large content as images/attachments");
        return;
      }
      try { Params.validateTaskRun(payload); } catch (Params.ParamError e) { json(res, 400, Params.paramErrorBody(e, anthropic)); return; }
    }
    Store.TaskRecord rec = new Store.TaskRecord();
    rec.id = taskID; rec.tenant = tenant; rec.owner = user; rec.device = ds.deviceID; rec.model = model; rec.state = "QUEUED";
    try { // one atomic write: a key never exists without its task
      store.createTask(rec, idemKey.isEmpty() ? null : idemKey, idemKey.isEmpty() ? null : new Store.Idempotency(tenant, user, taskID, bodyHash));
    } catch (Store.Conflict e) {
      if (!idemKey.isEmpty()) {
        Store.Idempotency won = store.getIdempotency(tenant, user, idemKey);
        if (won != null && won.bodyHash().equals(bodyHash)) { reattach(req, res, err, tenant, user, won.taskID(), reqModel, stream, anthropic); return; }
        err.send(422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body");
        return;
      }
      err.send(500, "INTERNAL", "storage error");
      return;
    }
    Task task = new Task(this, ds, taskID, tenant, user, reqModel, run.containsKey("e2ee"), !idemKey.isEmpty());
    Abort abort = req.abort;
    boolean got = ds.acquire(cfg.queueTimeout, abort);
    if (!got || !ds.connected() || task.done) {
      if (got) ds.release();
      res.setHeader("X-Task-Id", taskID);
      if (!ds.connected()) { task.failLocal("DEVICE_OFFLINE", "device disconnected", true); err.send(503, "DEVICE_OFFLINE", "device disconnected"); return; }
      if (task.done) { serve(res, task, 0, stream, abort, anthropic); return; }
      task.failLocal("DEVICE_BUSY", "device is at max concurrency", true);
      if (abort.aborted) return;
      res.setHeader("Retry-After", "2");
      err.send(429, "DEVICE_BUSY", "device is at max concurrency");
      return;
    }
    task.slot = true;
    setTaskState(taskID, "RUNNING");
    long iat = Lmbp.now();
    run.put("task_id", taskID);
    run.put("iat", iat);
    Map<String, Object> signed = new LinkedHashMap<>(run);
    signed.put("exp", iat + 60);
    signed.put("nonce", Lmbp.randomID("n_"));
    String jws = Lmbp.signJWS(key.priv(), Lmbp.TYP_TASK, kid, signed);
    List<Blob> fb = blobs;
    task.sentRun = true;
    Thread.ofVirtual().start(() -> locked(() -> dispatch(task, jws, fb)));
    res.setHeader("X-Task-Id", taskID);
    serve(res, task, 0, stream, abort, anthropic);
  }

  /** Non-terminal states only; terminal states are written with their terminal event. */
  void setTaskState(String id, String state) {
    Store.TaskRecord rec = store.getTask(id);
    if (rec != null && !TERMINAL_STATES.contains(rec.state)) store.setState(id, state);
  }

  record Blob(Map<String, Object> ref, byte[] data) {}

  void dispatch(Task t, String jws, List<Blob> blobs) {
    t.sentRun = true;
    try { t.ds.out.send(t.id, seq -> Json.obj("type", "task.run", "jws", jws), t.abort); } catch (RuntimeException e) {
      t.sentRun = false;
      t.failOffline("DEVICE_OFFLINE", "device disconnected");
      return;
    }
    for (Blob b : blobs) {
      for (int off = 0;; off += Lmbp.BLOB_CHUNK_BYTES) {
        int end = Math.min(off + Lmbp.BLOB_CHUNK_BYTES, b.data.length);
        Map<String, Object> data = Json.obj("blob_id", b.ref.get("id"), "offset", (long) off, "data", Lmbp.b64(java.util.Arrays.copyOfRange(b.data, off, end)));
        if (end == b.data.length) data.put("last", true);
        try { t.ds.out.send(t.id, seq -> Json.obj("type", "blob.chunk", "data", data), t.abort); } catch (RuntimeException e) { return; }
        if (end == b.data.length) break;
      }
    }
  }

  /** Every replay re-verifies the task's tenant and owner; a live task is served from memory first. */
  void reattach(Http.Req req, Http.Res res, Err err, String tenant, String owner, String taskID, String reqModel, boolean stream, boolean anthropic) {
    Task t = tasks.get(taskID);
    if (t != null && (!t.tenant.equals(tenant) || !t.owner.equals(owner))) { err.send(404, "BAD_REQUEST", "task no longer available"); return; }
    if (t == null) {
      Store.TaskRecord rec = store.getTask(taskID);
      if (rec == null || !rec.tenant.equals(tenant) || !rec.owner.equals(owner)) { err.send(404, "BAD_REQUEST", "task no longer available"); return; }
      t = Task.finished(this, rec, reqModel);
    }
    long after = parseLeadingInt(req.header("last-event-id"));
    res.setHeader("X-Task-Id", taskID);
    serve(res, t, after, stream, req.abort, anthropic);
  }

  /** parseInt(s, 10) || 0. */
  static long parseLeadingInt(String s) {
    Matcher m = Pattern.compile("^\\s*([+-]?\\d{1,15})").matcher(s);
    if (!m.find()) return 0;
    return Long.parseLong(m.group(1));
  }

  void taskEvents(Http.Req req, Http.Res res, Err err, String id) {
    Auth a = tenantAuth(req, err);
    if (a == null) return;
    Store.TaskRecord rec = store.getTask(id);
    if (rec == null || !rec.tenant.equals(a.t().id()) || !rec.owner.equals(a.user())) { err.send(404, "BAD_REQUEST", "task not found"); return; }
    reattach(req, res, err, a.t().id(), a.user(), id, rec.device + "/" + rec.model, true, false);
  }

  static Map<String, String> sseHeaders() {
    Map<String, String> h = new LinkedHashMap<>();
    h.put("Content-Type", "text/event-stream");
    h.put("Cache-Control", "no-cache");
    h.put("X-Accel-Buffering", "no");
    return h;
  }

  void serve(Http.Res res, Task t, long after, boolean stream, Abort signal, boolean anthropic) {
    if (anthropic) { Anthropic.serve(this, res, t, after, stream, signal); return; }
    if (stream) {
      res.writeHead(200, sseHeaders());
      if (after == 0) res.write("id: 0\ndata: " + chunk(t, Json.obj("role", "assistant", "content", ""), null, null, null) + "\n\n");
      boolean[] wrote = {false};
      boolean ok = t.stream(after, signal, () -> res.write(": keep-alive\n\n"), e -> {
        wrote[0] = true;
        String b, tail = "";
        if (e.type().equals("task.delta")) {
          if (t.e2ee) b = chunk(t, Json.obj(), null, null, sealed(e));
          else {
            Map<String, Object> delta = Json.obj();
            if (Json.truthy(Json.get(e.data(), "text"))) delta.put("content", e.data().get("text"));
            List<Object> tc = Json.asList(Json.get(e.data(), "tool_calls"));
            if (tc != null && !tc.isEmpty()) delta.put("tool_calls", tc);
            b = chunk(t, delta, null, null, null);
          }
        } else if (e.type().equals("task.done")) {
          Object fr = Json.get(e.data(), "finish_reason");
          b = chunk(t, Json.obj(), Json.truthy(fr) ? fr : "stop", Json.get(e.data(), "usage"), t.e2ee ? sealed(e) : null);
          tail = "data: [DONE]\n\n";
        } else {
          Map<String, Object> eb = e.data() != null ? e.data() : Json.obj();
          b = Json.stringify(Json.obj("error", Json.obj("message", eb.get("message"), "type", "lmbp_error", "code", eb.get("code"), "retryable", Json.truthy(eb.get("retryable")))));
        }
        return res.write("id: " + e.seq() + "\ndata: " + b + "\n\n" + tail);
      });
      // Last-Event-ID at or beyond the terminal event: end with the terminator.
      if (ok && !wrote[0]) res.write("data: [DONE]\n\n");
      res.end();
      return;
    }
    StringBuilder text = new StringBuilder();
    List<Map<String, Object>> calls = new ArrayList<>();
    List<Object> sealedFrames = new ArrayList<>();
    Object[] done = {null}, fail = {null};
    boolean ok = t.stream(after, signal, null, e -> {
      if (e.type().equals("task.delta")) {
        if (t.e2ee) { Map<String, Object> s = sealed(e); if (s != null) sealedFrames.add(s.get("lmbp_e2ee")); return true; }
        Object tx = Json.get(e.data(), "text");
        if (Json.truthy(tx)) text.append(tx instanceof String s ? s : Json.stringify(tx));
        mergeCalls(calls, Json.asList(Json.get(e.data(), "tool_calls")));
      } else if (e.type().equals("task.done")) {
        done[0] = e.data() != null ? e.data() : Json.obj();
        if (t.e2ee) { Map<String, Object> s = sealed(e); if (s != null) sealedFrames.add(s.get("lmbp_e2ee")); }
      } else fail[0] = e.data() != null ? e.data() : Json.obj();
      return true;
    });
    if (!ok) return;
    if (fail[0] != null) { String code = String.valueOf(Json.get(fail[0], "code")); apiError(res, errStatus(code), code, Json.str(fail[0], "message")); return; }
    Object fr = Json.get(done[0], "finish_reason");
    Object finish = Json.truthy(fr) ? fr : "stop";
    Map<String, Object> msg = Json.obj("role", "assistant", "content", text.toString());
    if (!calls.isEmpty()) {
      List<Object> tcs = new ArrayList<>();
      for (Map<String, Object> c : calls) {
        Map<String, Object> o = Json.obj();
        if (c.get("id") != null) o.put("id", c.get("id"));
        o.put("type", "function");
        o.put("function", c.get("function"));
        tcs.add(o);
      }
      msg.put("tool_calls", tcs);
      if (text.length() == 0) msg.put("content", null);
    }
    Map<String, Object> out = Json.obj("id", "chatcmpl-" + t.id, "object", "chat.completion", "created", t.created, "model", t.reqModel,
        "choices", List.of(Json.obj("index", 0L, "message", msg, "finish_reason", finish)));
    if (t.e2ee) {
      out.put("choices", List.of(Json.obj("index", 0L, "message", Json.obj("role", "assistant", "content", null), "finish_reason", finish)));
      out.put("lmbp_e2ee", sealedFrames);
    }
    Object usage = Json.get(done[0], "usage");
    if (Json.truthy(usage)) out.put("usage", usage);
    json(res, 200, out);
  }

  /** Accumulate OpenAI tool_call deltas by index. */
  static void mergeCalls(List<Map<String, Object>> calls, List<Object> deltas) {
    if (deltas == null) return;
    for (Object c : deltas) {
      Object ix = Json.get(c, "index");
      int idx = Json.isInteger(ix) ? (int) Json.longOf(ix) : 0;
      if (idx < 0 || idx > 1024) idx = 0;
      while (calls.size() <= idx) calls.add(Json.obj("type", "function", "function", Json.obj("name", "", "arguments", "")));
      Map<String, Object> call = calls.get(idx);
      if (Json.truthy(Json.get(c, "id"))) call.put("id", Json.get(c, "id"));
      Map<String, Object> fn = Json.asObj(call.get("function"));
      Object nm = Json.get(Json.get(c, "function"), "name"), ar = Json.get(Json.get(c, "function"), "arguments");
      fn.put("name", fn.get("name") + (Json.truthy(nm) ? String.valueOf(nm) : ""));
      fn.put("arguments", fn.get("arguments") + (Json.truthy(ar) ? String.valueOf(ar) : ""));
    }
  }

  static Map<String, Object> sealed(Store.Event e) {
    Object s = Json.get(e.data(), "e2ee");
    return s instanceof String str && !str.isEmpty() ? Json.obj("lmbp_e2ee", Json.obj("seq", e.seq(), "type", e.type(), "data", str)) : null;
  }

  static String chunk(Task t, Map<String, Object> delta, Object finish, Object usage, Map<String, Object> extra) {
    Map<String, Object> m = Json.obj("id", "chatcmpl-" + t.id, "object", "chat.completion.chunk", "created", t.created, "model", t.reqModel,
        "choices", List.of(Json.obj("index", 0L, "delta", delta, "finish_reason", finish)));
    if (Json.truthy(usage)) m.put("usage", usage);
    if (extra != null) m.putAll(extra);
    return Json.stringify(m);
  }

  // ---------- helpers ----------
  static void json(Http.Res res, int status, Object body) {
    byte[] b = Json.bytes(body);
    // §6.1: every JSON response is no-store unless the route set its own policy (JWKS/metadata).
    if (res.getHeader("Cache-Control") == null) res.setHeader("Cache-Control", "no-store");
    res.send(status, res.getHeader("Content-Type") != null ? res.getHeader("Content-Type") : "application/json", b);
  }

  static Map<String, Object> problemBody(int status, String code, String detail) {
    return Json.obj("type", PROBLEM_BASE + code.toLowerCase().replace('_', '-'), "title", code, "status", (long) status, "detail", detail, "code", code);
  }

  static void problem(Http.Res res, int status, String code, String detail) {
    res.setHeader("Content-Type", "application/problem+json");
    res.setHeader("Cache-Control", "no-store");
    json(res, status, problemBody(status, code, detail));
  }

  static void apiError(Http.Res res, int status, String code, String message) {
    json(res, status, Json.obj("error", Json.obj("message", message, "type", "lmbp_error", "code", code)));
  }

  static void oauthError(Http.Res res, int status, String error) {
    res.setHeader("Cache-Control", "no-store");
    json(res, status, Json.obj("error", error));
  }

  /** OAuth request as form-urlencoded (normative) or JSON (accepted). */
  static Map<String, String> params(Http.Req req, int max) {
    byte[] b = req.body;
    if (b == null || b.length > max) return null;
    String s = new String(b, StandardCharsets.UTF_8);
    Map<String, String> out = new LinkedHashMap<>();
    if (req.header("content-type").startsWith("application/x-www-form-urlencoded")) {
      for (String kv : s.split("&")) {
        if (kv.isEmpty()) continue;
        int i = kv.indexOf('=');
        String k = Http.Req.dec(i < 0 ? kv : kv.substring(0, i)), v = Http.Req.dec(i < 0 ? "" : kv.substring(i + 1));
        if (out.containsKey(k)) return null;
        out.put(k, v);
      }
      return out;
    }
    Map<String, Object> m = Json.asObj(Json.tryParse(s));
    if (m == null) return null;
    for (Map.Entry<String, Object> e : m.entrySet()) if (e.getValue() instanceof String v) out.put(e.getKey(), v);
    return out;
  }

  static String userCode() {
    StringBuilder s = new StringBuilder();
    for (int i = 0; i < 8; i++) s.append(USER_CODE_CHARS.charAt(Lmbp.RNG.nextInt(USER_CODE_CHARS.length())));
    return s.substring(0, 4) + "-" + s.substring(4);
  }

  static String normCode(String s) {
    s = (s == null ? "" : s).trim().replace("-", "").replace(" ", "").toUpperCase();
    return s.length() == 8 ? s.substring(0, 4) + "-" + s.substring(4) : "";
  }

  static Map<String, Object> normMessage(Map<String, Object> m) {
    Map<String, Object> o = Json.obj("role", m.get("role"), "content", m.containsKey("content") ? m.get("content") : "");
    for (String k : new String[] {"name", "tool_calls", "tool_call_id"}) {
      Object v = m.get(k);
      if (v != null && !"".equals(v)) o.put(k, v);
    }
    return o;
  }

  static final class Extracted { List<Blob> blobs = new ArrayList<>(); boolean vision, audio; String code, msg; }

  static final Pattern STRICT_B64 = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

  static byte[] strictB64(String s) {
    if (!STRICT_B64.matcher(s).matches() || s.length() % 4 != 0) return null;
    try { return Base64.getDecoder().decode(s); } catch (IllegalArgumentException e) { return null; }
  }

  /** extractBlobs moves large inline binaries (data: URIs, input_audio) into blobs (§16.3). */
  static Extracted extractBlobs(List<Object> msgs) {
    Extracted x = new Extracted();
    long[] total = {0};
    java.util.function.BiFunction<byte[], String, String> add = (data, mt) -> {
      if (data.length > Lmbp.MAX_BLOB_BYTES || (total[0] += data.length) > Lmbp.MAX_TASK_BLOB_BYTES) return null;
      String id = Lmbp.randomID("blob_");
      x.blobs.add(new Blob(Json.obj("id", id, "size", (long) data.length, "sha256", Lmbp.b64(Lmbp.sha256(data)), "media_type", mt), data));
      return Lmbp.BLOB_SCHEME + id;
    };
    for (Object m : msgs) {
      List<Object> parts = Json.asList(Json.get(m, "content"));
      if (parts == null) continue;
      for (Object p : parts) {
        Object type = Json.get(p, "type");
        String ty = type instanceof String s ? s : "";
        switch (ty) {
          case "text": break;
          case "image_url": {
            x.vision = true;
            Map<String, Object> iu = Json.asObj(Json.get(p, "image_url"));
            Object uo = iu == null ? null : iu.get("url");
            if (!(uo instanceof String u)) { x.code = "BAD_REQUEST"; x.msg = "image_url part without url"; return x; }
            if (u.startsWith("https://")) break;
            if (!u.startsWith("data:")) { x.code = "BAD_REQUEST"; x.msg = "image_url must be https:// or a data: URI"; return x; }
            int comma = u.indexOf(',');
            String meta = comma < 0 ? "" : u.substring(5, comma);
            if (comma < 0 || !meta.endsWith(";base64") || !meta.startsWith("image/")) { x.code = "BAD_REQUEST"; x.msg = "image data URI must be data:image/*;base64,"; return x; }
            if (u.length() <= Lmbp.INLINE_DATA_URI_BYTES) break;
            byte[] raw = strictB64(u.substring(comma + 1));
            if (raw == null) { x.code = "BAD_REQUEST"; x.msg = "invalid base64 in image data URI"; return x; }
            String ref = add.apply(raw, meta.substring(0, meta.length() - 7));
            if (ref == null) { x.code = "PAYLOAD_TOO_LARGE"; x.msg = "image exceeds size limits"; return x; }
            iu.put("url", ref);
            break;
          }
          case "input_audio": {
            x.audio = true;
            Map<String, Object> a = Json.asObj(Json.get(p, "input_audio"));
            if (a == null || !(a.get("data") instanceof String data) || (!"wav".equals(a.get("format")) && !"mp3".equals(a.get("format")))) {
              x.code = "BAD_REQUEST"; x.msg = "input_audio needs data and format wav|mp3"; return x;
            }
            if (data.length() <= Lmbp.INLINE_DATA_URI_BYTES) break;
            byte[] raw = strictB64(data);
            if (raw == null) { x.code = "BAD_REQUEST"; x.msg = "invalid base64 in input_audio"; return x; }
            String ref = add.apply(raw, "audio/" + a.get("format"));
            if (ref == null) { x.code = "PAYLOAD_TOO_LARGE"; x.msg = "audio exceeds size limits"; return x; }
            a.put("data", ref);
            break;
          }
          default: x.code = "BAD_REQUEST"; x.msg = "unsupported content part " + (type == null ? "undefined" : Params.jsStr(type)); return x;
        }
      }
    }
    return x;
  }

  // =====================================================================
  /** DState is one device's protocol state; it outlives a socket for the resume window. */
  static final class DState {
    final Gateway g;
    final String deviceID, tenant, owner;
    final Lmbp.Outbox out;
    Lmbp.Inbound inb;
    Http.Ws ws;
    int gen;
    List<Object> models = new ArrayList<>();
    Map<String, Object> modelCaps = new LinkedHashMap<>();
    Map<String, String> modelNames = new LinkedHashMap<>();
    List<String> caps = new ArrayList<>();
    int maxConc = 1;
    long tokenExp;
    String issuer = "", resumeToken = "";
    final Map<String, Task> tasks = new LinkedHashMap<>();
    // Tasks ended here (cancel, timeout, ...) whose device may still send frames: those late
    // frames are ACKed so the device gets its flow credit back (spec §15.5). Bounded.
    final LinkedHashMap<String, Long> reclaimed = new LinkedHashMap<>();
    int slots;
    final List<SlotWaiter> slotWait = new ArrayList<>();

    void reclaim(String id, long acked) {
      reclaimed.remove(id);
      reclaimed.put(id, acked);
      while (reclaimed.size() > 1024) reclaimed.remove(reclaimed.keySet().iterator().next());
    }
    boolean dropped;
    long lastSeen = System.currentTimeMillis();

    static final class SlotWaiter { boolean resolved, value; }

    DState(Gateway g, Store.Device dev) { this.g = g; deviceID = dev.id; tenant = dev.tenant; owner = dev.owner; out = new Lmbp.Outbox(g); }

    boolean connected() { return ws != null && !dropped; }

    boolean control(Map<String, Object> e) {
      if (ws == null || !ws.isOpen()) return false;
      try { ws.send(Json.stringify(e)); } catch (RuntimeException x) { return false; }
      return true;
    }

    void sendErr(String id, String code, String msg) { control(envelope("error", id, null, errorBody(code, msg, false))); }

    boolean acquire(long timeoutMs, Abort signal) {
      if (slots < maxConc && slotWait.isEmpty()) { slots++; return true; }
      SlotWaiter w = new SlotWaiter();
      slotWait.add(w);
      long deadline = System.currentTimeMillis() + timeoutMs;
      while (!w.resolved) {
        long left = deadline - System.currentTimeMillis();
        if (left <= 0 || (signal != null && signal.aborted)) { slotWait.remove(w); return false; }
        g.await(Math.min(left, 1000));
      }
      return w.value;
    }

    void release() { slots--; wakeSlots(); }

    void wakeSlots() {
      while (!slotWait.isEmpty() && slots < maxConc) { slots++; SlotWaiter w = slotWait.remove(0); w.resolved = true; w.value = true; }
      g.wakeAll();
    }

    void drop(String code, String msg) {
      dropped = true;
      Http.Ws w = ws;
      for (SlotWaiter sw : slotWait) { sw.resolved = true; sw.value = true; }
      slotWait.clear();
      out.close();
      for (Task t : new ArrayList<>(tasks.values())) t.failOffline(code, msg);
      if (w != null) w.close();
      g.wakeAll();
    }
  }

  // =====================================================================
  interface EventFn { boolean apply(Store.Event e); }

  /** Gateway-side hub of one task: buffers device frames, fans them out to (re-)attached HTTP subscribers and paces task.ack (§8). */
  static final class Task {
    final Gateway g;
    final DState ds;
    final String id, tenant, owner, reqModel;
    final boolean e2ee, idempotent;
    final long created = Lmbp.now();
    boolean sentRun, done, decided, replayed, slot;
    final Abort abort = new Abort();
    final List<Store.Event> events = new ArrayList<>();
    final Map<Integer, Long> subs = new LinkedHashMap<>();
    int nextSub;
    long acked, persisted, seen, ackAt = System.currentTimeMillis();
    ScheduledFuture<?> grace, timeout, watch;

    Task(Gateway g, DState ds, String id, String tenant, String owner, String reqModel, boolean e2ee, boolean idempotent) {
      this.g = g; this.ds = ds; this.id = id; this.tenant = tenant; this.owner = owner; this.reqModel = reqModel; this.e2ee = e2ee; this.idempotent = idempotent;
      if (ds == null) return;
      g.tasks.put(id, this);
      ds.tasks.put(id, this);
      timeout = g.later(g.cfg.taskTimeout, () -> { if (cancel("timeout")) failLocal("TIMEOUT", "task timed out", false); });
      watch = g.every(1000, () -> {
        boolean stalled = !subs.isEmpty() && recvSeq() > acked && System.currentTimeMillis() - ackAt > g.cfg.slowConsumer;
        if (stalled && cancel("slow_consumer")) failLocal("SLOW_CONSUMER", "client did not consume the stream in time", false);
      });
    }

    /** A finished task rebuilt from the store; an inconsistent or missing terminal yields OUTCOME_UNKNOWN (served, never stored). */
    static Task finished(Gateway g, Store.TaskRecord rec, String reqModel) {
      Task t = new Task(g, null, rec.id, rec.tenant, rec.owner, reqModel, false, false);
      t.replayed = true;
      t.done = true;
      t.events.addAll(rec.events);
      Store.Event last = t.events.isEmpty() ? null : t.events.get(t.events.size() - 1);
      long lastSeq = last == null ? 0 : last.seq();
      boolean consistent = last != null && isTerminal(last.type())
          && (last.type().equals("task.done") ? rec.state.equals("SUCCEEDED") : rec.state.equals("FAILED") || rec.state.equals("CANCELLED"));
      if (!consistent) {
        if (last != null && isTerminal(last.type())) {
          g.log("lmbp: task " + rec.id + ": stored terminal " + last.type() + " disagrees with state " + rec.state + "; reporting OUTCOME_UNKNOWN");
          t.events.remove(t.events.size() - 1);
        }
        t.events.add(new Store.Event(lastSeq + 1, "task.error", errorBody("OUTCOME_UNKNOWN", "task outcome unknown", false)));
      }
      return t;
    }

    long recvSeq() { return ds != null && ds.inb != null ? ds.inb.recv(id) : 0; }

    void broadcast() { g.wakeAll(); }

    /** Commit first, then publish: nothing is visible before it is decided and stored. */
    void record(Store.Event ev) {
      if (!replayed) {
        try { g.store.finishTask(id, ev, stateOf(ev)); } catch (Store.NotFound e) { /* gone */ } catch (RuntimeException e) {
          g.log("lmbp: task " + id + ": persisting local event failed: " + e.getMessage());
        }
      }
      events.add(ev);
      broadcast();
    }

    /** Claims the single terminal decision: exactly one terminal path wins. */
    boolean decide() {
      if (done || decided) return false;
      decided = true;
      return true;
    }

    void onDeviceFrame(Map<String, Object> inp, long seq) {
      if (done || decided) { maybeAck(); return; }
      if (seq > seen) seen = seq;
      Map<String, Object> data = Json.asObj(inp.get("data"));
      if (data == null) data = Json.obj();
      String type = (String) inp.get("type");
      if (type.equals("task.delta") && !e2ee && Json.truthy(data.get("e2ee"))) { data = new LinkedHashMap<>(data); data.remove("e2ee"); }
      if (type.equals("task.delta")) {
        String why = checkDelta(data);
        if (!why.isEmpty()) {
          g.log("lmbp: task " + id + ": " + why);
          cancel("protocol_error");
          failLocal("INTERNAL", "device sent an invalid delta: " + why, false);
          return;
        }
      }
      Store.Event ev = new Store.Event(seq, type, data);
      String state = "";
      if (isTerminal(type)) {
        state = stateOf(ev);
        if (!decide()) { maybeAck(); return; }
        try { g.store.finishTask(id, ev, state); } catch (RuntimeException e) {
          g.log("lmbp: task " + id + ": persisting terminal event and state for seq " + seq + " failed: " + e.getMessage() + " (not acknowledged)");
          sendCancel("internal_error");
          commitLocal("INTERNAL", "gateway could not persist task output", false);
          return;
        }
      } else {
        try { g.store.appendEvent(id, ev); } catch (RuntimeException e) {
          g.log("lmbp: task " + id + ": persisting event for seq " + seq + " failed: " + e.getMessage() + " (not acknowledged)");
          cancel("internal_error");
          failLocal("INTERNAL", "gateway could not persist task output", false);
          return;
        }
      }
      if (done || (decided && state.isEmpty())) return;
      events.add(ev);
      persisted = seq;
      broadcast();
      if (!state.isEmpty()) { finish(state, true); return; }
      maybeAck();
    }

    void maybeAck() {
      if (ds == null) return;
      long target = Math.min(recvSeq(), persisted);
      if (!done) for (long d : subs.values()) target = Math.min(target, d);
      if (target <= acked) return;
      acked = target;
      ackAt = System.currentTimeMillis();
      if (ds.inb != null) ds.inb.acked(id, target);
      ds.control(envelope("task.ack", null, id, Json.obj("seq", target)));
    }

    boolean cancel(String reason) {
      if (done || decided) return false;
      sendCancel(reason);
      return true;
    }

    void sendCancel(String reason) { if (ds != null && sentRun) ds.control(envelope("task.cancel", null, id, Json.obj("reason", reason))); }

    void failLocal(String code, String msg, boolean retryable) {
      if (!decide()) return;
      commitLocal(code, msg, retryable);
    }

    /** The caller holds the decision. The seq follows every device seq seen. */
    void commitLocal(String code, String msg, boolean retryable) {
      long lastSeq = events.isEmpty() ? 0 : events.get(events.size() - 1).seq();
      long seq = Math.max(lastSeq, seen) + 1;
      record(new Store.Event(seq, "task.error", errorBody(code, msg, retryable)));
      finish(code.equals("CANCELLED") ? "CANCELLED" : "FAILED", false);
    }

    /**
     * Ends a task whose device session is gone, whatever ended it (disconnect, revocation,
     * replacement): once task.run was sent the device may have run it, so OUTCOME_UNKNOWN (§7.5);
     * before that DEVICE_OFFLINE (retryable).
     */
    void failOffline(String code, String msg) {
      if (sentRun) { if (!code.equals("OUTCOME_UNKNOWN")) msg += "; outcome unknown"; code = "OUTCOME_UNKNOWN"; } else code = "DEVICE_OFFLINE";
      failLocal(code, msg, code.equals("DEVICE_OFFLINE"));
    }

    long outBytes;

    /**
     * Validates a device delta before it is stored or aggregated: the tool-call index range
     * (§16.1) and the task's output budget (§10), which counts every encoded delta body, cleartext
     * or sealed.
     */
    String checkDelta(Map<String, Object> data) {
      if (!e2ee && data.get("tool_calls") instanceof List<?> calls) {
        for (Object c : calls) {
          if (!(c instanceof Map<?, ?> m) || !m.containsKey("index")) continue;
          Object ix = m.get("index");
          if (!Json.isInteger(ix) || Json.longOf(ix) < 0 || Json.longOf(ix) > Lmbp.MAX_TOOL_CALL_INDEX)
            return "tool call index " + Json.stringify(ix) + " out of range [0," + Lmbp.MAX_TOOL_CALL_INDEX + "]";
        }
      }
      outBytes += Json.stringify(data).getBytes(StandardCharsets.UTF_8).length;
      return outBytes > Lmbp.MAX_TASK_OUTPUT_BYTES ? "task output exceeds the per-task limit" : "";
    }

    void finish(String state, boolean fromDevice) {
      if (done) return;
      done = true;
      boolean hadSlot = slot;
      slot = false;
      Gateway.cancel(grace); Gateway.cancel(timeout); Gateway.cancel(watch);
      broadcast();
      if (ds != null) {
        if (fromDevice) maybeAck();
        else {
          long late = recvSeq();
          if (late > acked) {
            acked = late;
            ds.control(envelope("task.ack", null, id, Json.obj("seq", late)));
          }
          ds.reclaim(id, late);
        }
        ds.tasks.remove(id);
        ds.out.forget(id);
        if (ds.inb != null) ds.inb.forget(id);
        if (hadSlot) ds.release();
      }
      abort.aborted = true;
      g.wakeAll();
      g.later(g.cfg.attachGrace + 600_000, () -> { if (g.tasks.get(id) == this) g.tasks.remove(id); });
    }

    int attach(long after) {
      int sid = ++nextSub;
      subs.put(sid, after);
      Gateway.cancel(grace);
      grace = null;
      return sid;
    }

    void detach(int sid) {
      subs.remove(sid);
      boolean left = subs.isEmpty() && !done;
      if (left && idempotent) {
        grace = g.later(g.cfg.attachGrace, () -> { if (subs.isEmpty() && cancel("client_disconnected")) failLocal("CANCELLED", "client did not re-attach", false); });
      }
      if (left && !idempotent) { if (cancel("client_disconnected")) failLocal("CANCELLED", "client disconnected", false); return; }
      maybeAck();
    }

    /** Deliver events with seq > after until the terminal one; false if aborted. fn returns false when the client is gone. */
    boolean stream(long after, Abort signal, Runnable keepalive, EventFn fn) {
      int sub = attach(after);
      try {
        long lastActivity = System.currentTimeMillis();
        for (;;) {
          if (signal != null && signal.aborted) return false;
          List<Store.Event> batch = new ArrayList<>();
          for (Store.Event e : events) if (e.seq() > after) batch.add(e);
          // finished and nothing after the cursor (Last-Event-ID >= terminal seq): end
          if (batch.isEmpty() && !events.isEmpty() && isTerminal(events.get(events.size() - 1).type())) return true;
          for (Store.Event e : batch) {
            boolean ok = fn.apply(e); // a slow reader holds the cursor (and the ack) until the write drains
            if (!ok || (signal != null && signal.aborted)) return false;
            after = e.seq();
            if (subs.containsKey(sub)) subs.put(sub, after);
            if (isTerminal(e.type())) return true;
          }
          maybeAck();
          if (!batch.isEmpty()) { lastActivity = System.currentTimeMillis(); continue; }
          long wait = 15_000 - (System.currentTimeMillis() - lastActivity);
          if (wait <= 0) {
            if (keepalive != null) keepalive.run();
            lastActivity = System.currentTimeMillis();
            continue;
          }
          g.await(Math.min(wait, 1000));
        }
      } finally { detach(sub); }
    }
  }

  /** Optional display names (model_names), kept only for advertised models. */
  static Map<String, String> cleanNames(Object names, List<Object> models) {
    Map<String, String> out = new LinkedHashMap<>();
    Map<String, Object> m = Json.asObj(names);
    if (m == null || models == null) return out;
    for (Object id : models) {
      if (m.get(String.valueOf(id)) instanceof String n && !n.isBlank()) {
        String t = n.strip();
        out.put(String.valueOf(id), t); // length bounded by the schema (1-128 code points)
      }
    }
    return out;
  }
}
