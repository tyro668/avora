package dev.avora.lmbp;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * The LMBP gateway for a Java SaaS backend: pairing, the connector WebSocket and the
 * OpenAI (<code>/v1/chat/completions</code>, <code>/v1/models</code>) / Anthropic (<code>/v1/messages</code>)
 * surface, in-process. Framework-agnostic: mount it with a transport adapter
 * ({@code lmbp-spring-boot-starter}, or {@link StandaloneServer} for tests) that feeds
 * {@link #handle(HttpRequest, HttpSink)} and {@link #handshake(HttpRequest)}.
 *
 * <pre>{@code
 * LMBPServer lmbp = LMBPServer.builder()
 *     .issuer("https://saas.example.com")
 *     .tenant("acme", System.getenv("TENANT_API_KEY"), Map.of("display_name", "Acme CRM"))
 *     .store(JdbcStore.open("jdbc:sqlite:lmbp.db"))
 *     .build();
 * String link = lmbp.pairing().link("acme");
 * lmbp.pairing().approve("acme", userId, userCode);
 * Map<String, Object> r = lmbp.client("acme", userId).call(Map.of("model", m, "messages", msgs));
 * }</pre>
 *
 * Thread-safe. One instance per process and store (see {@link Store}).
 */
public final class LMBPServer implements AutoCloseable {
  /** Largest accepted HTTP request body; adapters pass {@code body = null} beyond it. */
  public static final int MAX_BODY_BYTES = 48 << 20;
  /** Largest accepted WebSocket message (spec max_frame_bytes). */
  public static final int MAX_FRAME_BYTES = Lmbp.MAX_FRAME_BYTES;
  /** The WebSocket subprotocol. */
  public static final String SUBPROTOCOL = Lmbp.SUBPROTOCOL;
  /** The connector WebSocket path. */
  public static final String CONNECT_PATH = "/lmbp/v1/connect";

  final Gateway g;
  private final Pairing pairing;

  private LMBPServer(Builder b) {
    Gateway.Config cfg = new Gateway.Config();
    if (b.issuer == null || b.issuer.isEmpty()) throw new IllegalArgumentException("issuer is required: the gateway's public origin (never derived from the Host header)");
    cfg.issuer = b.issuer;
    cfg.maxConc = b.maxConcurrency;
    cfg.webDir = b.chatUiDir == null ? "" : b.chatUiDir;
    if (b.taskTimeoutMs > 0) cfg.taskTimeout = b.taskTimeoutMs;
    if (b.keepaliveMs > 0) cfg.keepalive = b.keepaliveMs;
    if (b.retentionMs != 0) cfg.retention = b.retentionMs;
    if (b.signingSeed != null && b.signingSeed.length != 32) throw new IllegalArgumentException("signing seed must be 32 bytes");
    g = new Gateway(cfg, b.signingSeed == null ? null : b.signingSeed.clone(), b.store == null ? new MemoryStore() : b.store, b.logger);
    for (Object[] t : b.tenants) {
      @SuppressWarnings("unchecked") Map<String, Object> prof = (Map<String, Object>) t[2];
      g.registerTenant((String) t[0], (String) t[1], Json.asObj(Json.parse(Json.stringify(prof))));
    }
    pairing = new Pairing(this);
    g.startRetention();
  }

  public static Builder builder() { return new Builder(); }

  /** Builder with safe defaults: in-memory store, signing key generated once and kept in the store, 16 tasks per device, no chat UI. */
  public static final class Builder {
    private String issuer = "", chatUiDir = "";
    private Store store;
    private byte[] signingSeed;
    private int maxConcurrency = 16;
    private long taskTimeoutMs, keepaliveMs, retentionMs;
    private Consumer<String> logger = s -> System.err.println("lmbp: " + s);
    private final List<Object[]> tenants = new ArrayList<>();

    /** Public origin (e.g. {@code https://saas.example.com}). Empty = dev mode: the request's Host decides (never use in production). */
    public Builder issuer(String origin) { this.issuer = Objects.requireNonNullElse(origin, ""); return this; }
    /** Registers a tenant; {@code apiKey} must be at least 32 characters (server-side secret). */
    public Builder tenant(String id, String apiKey) { return tenant(id, apiKey, Map.of()); }
    /** Profile keys: display_name, logo_uri, homepage_uri, policy_uri, tos_uri, pairing_uri, requested_models, requested_scopes. */
    public Builder tenant(String id, String apiKey, Map<String, ?> profile) { tenants.add(new Object[] {id, apiKey, new LinkedHashMap<>(profile == null ? Map.of() : profile)}); return this; }
    public Builder store(Store store) { this.store = store; return this; }
    /** 32-byte Ed25519 seed. When absent the store's persisted key is used (generated on first start). */
    public Builder signingSeed(byte[] seed) { this.signingSeed = seed; return this; }
    /** Hex form of {@link #signingSeed(byte[])}. */
    public Builder signingSeedHex(String hex) { this.signingSeed = hex == null || hex.isBlank() ? null : HexFormat.of().parseHex(hex.trim()); return this; }
    /** Upper bound on concurrent tasks per device (the device may announce fewer). */
    public Builder maxConcurrency(int n) { if (n < 1) throw new IllegalArgumentException("maxConcurrency >= 1"); this.maxConcurrency = n; return this; }
    /**
     * How long finished tasks and their idempotency records are kept (default 7 days; 0 keeps the
     * default, negative disables purging). Expired pairings are deleted too. Spec §14.4 (errata E6).
     */
    public Builder retentionMillis(long ms) { this.retentionMs = ms; return this; }
    /** Hard limit on one task's duration (default 10 minutes). */
    public Builder taskTimeoutMillis(long ms) { this.taskTimeoutMs = ms; return this; }
    /**
     * Idle interval before an SSE keep-alive (comment, or Anthropic {@code ping}) is written; default 15 s.
     * Servlet containers only notice a vanished client on a write, so adapters lower it (the Spring
     * starter uses 1 s) to cancel abandoned streams promptly.
     */
    public Builder keepaliveMillis(long ms) { this.keepaliveMs = ms; return this; }
    /** Directory with chat.html/chat.js/qrcode.js (mock/web) to serve the demo chat page at /chat; empty disables it. */
    public Builder chatUiDir(String dir) { this.chatUiDir = dir; return this; }
    /** Log sink (default: stderr). Never receives secrets. */
    public Builder logger(Consumer<String> logger) { this.logger = logger; return this; }
    public LMBPServer build() { return new LMBPServer(this); }
  }

  /** True for paths this server answers: <code>/.well-known/lmbp</code>, <code>/.well-known/jwks.json</code>, <code>/lmbp/*</code>, <code>/v1/*</code>, <code>/healthz</code>, and the chat page if enabled. */
  public boolean handles(String path) {
    if (path == null) return false;
    if (path.equals("/.well-known/lmbp") || path.equals("/.well-known/jwks.json") || path.equals("/healthz")) return true;
    if (path.startsWith("/lmbp/") || path.startsWith("/v1/")) return true;
    return !g.cfg.webDir.isEmpty() && Gateway.WEB_FILES.containsKey(path);
  }

  /** Serves one HTTP request; blocks until the response is complete (SSE streams included). */
  public void handle(HttpRequest req, HttpSink sink) { g.handle(req, sink); }

  /** Decides a WebSocket upgrade to {@link #CONNECT_PATH} (auth, subprotocol, origin). */
  public WebSocketHandshake handshake(HttpRequest req) { req.gateway = g; return g.handshake(req); }

  public Pairing pairing() { return pairing; }

  /** In-process client acting as {@code endUser} of {@code tenant}; no HTTP hop, same engine code path. */
  public InProcessClient client(String tenant, String endUser) { return new InProcessClient(this, tenant, endUser); }

  /** Key id (RFC 7638 thumbprint) of the gateway signing key. */
  public String kid() { return g.kid; }

  /** The gateway's public JWK set. */
  public Map<String, Object> jwks() { return Json.obj("keys", List.of(Lmbp.publicJWK(g.key.pub()))); }

  public String issuer() { return g.cfg.issuer; }

  public static byte[] generateSigningSeed() { byte[] b = new byte[32]; new SecureRandom().nextBytes(b); return b; }

  public static String generateTenantKey() { byte[] b = new byte[24]; new SecureRandom().nextBytes(b); return HexFormat.of().formatHex(b); }

  /** Stops timers and drops device sessions; in-flight tasks end with DEVICE_OFFLINE / OUTCOME_UNKNOWN. */
  @Override public void close() { g.close(); }
}
