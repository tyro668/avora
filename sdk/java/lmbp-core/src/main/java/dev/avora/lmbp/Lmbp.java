package dev.avora.lmbp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.LongFunction;
import java.util.regex.Pattern;

/** LMBP primitives: base64url, EdDSA JWS/JWT, proofs, thumbprints, origins (spec §5, §18) and the delivery state machines (§8, §15). */
final class Lmbp {
  private Lmbp() {}

  public static final int VERSION = 2;
  public static final String SUBPROTOCOL = "lmbp";
  public static final List<String> PROTOCOL_VERSIONS = List.of("2.0");
  public static final String PAIR_LINK_VERSION = "2";
  /** Conformance profiles (spec §13.1); metadata.profiles lists those this gateway meets. */
  public static final List<String> PROFILES = List.of("core", "reliable", "tools", "multimodal", "e2ee", "openai", "anthropic");
  public static final String VERSION_REQUIRED = "LMBP 2.0 required: WebSocket subprotocol lmbp and envelope v 2 (LMBP 1.x is not supported)";

  /** Unicode code points, the unit of every string limit (spec §4.1). */
  public static int charLen(String s) { return s.codePointCount(0, s.length()); }

  /** Largest task.delta tool_calls[].index (spec §16.1). */
  public static final int MAX_TOOL_CALL_INDEX = 127;
  /** Encoded task.delta bytes one task may send, cleartext or sealed (spec §10). */
  public static final long MAX_TASK_OUTPUT_BYTES = 64L << 20;
  /** device_name: at most 100 code points (spec §6.2). */
  public static final int MAX_DEVICE_NAME_CHARS = 100;

  /**
   * The spec §6.2 rule for the untrusted, device-reported name: at most 100 code points and none of
   * the characters that can disguise text (C0/C1 controls, U+00AD, U+061C, U+180E, U+200B-U+200F,
   * U+2028-U+202E, U+2060-U+206F, U+FEFF, U+FFF9-U+FFFB, lone surrogates).
   */
  public static boolean validDeviceName(String s) {
    if (s == null || charLen(s) > MAX_DEVICE_NAME_CHARS) return false;
    for (int i = 0; i < s.length(); ) {
      int r = s.codePointAt(i);
      i += Character.charCount(r);
      if (r <= 0x1F || (r >= 0x7F && r <= 0x9F) || r == 0xAD || r == 0x61C || r == 0x180E || (r >= 0x200B && r <= 0x200F)
          || (r >= 0x2028 && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) || r == 0xFEFF || (r >= 0xFFF9 && r <= 0xFFFB)
          || (r >= 0xD800 && r <= 0xDFFF)) return false;
    }
    return true;
  }

  /** 1..max printable ASCII (0x20-0x7E): X-End-User and Idempotency-Key (spec §4.1). */
  public static boolean validHeader(String s, int max) {
    if (s == null || s.isEmpty() || s.length() > max) return false;
    for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x20 || c > 0x7E) return false; }
    return true;
  }
  public static final List<String> CAPABILITIES = List.of("session.token", "models.update", "resume", "flow", "tools", "multimodal", "e2ee");
  public static final List<String> SCOPES = List.of("lmbp.chat", "lmbp.tools", "lmbp.vision", "lmbp.audio");
  public static final Pattern TENANT_ID_RE = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
  public static final int MAX_FRAME_BYTES = 256 << 10;
  public static final int MAX_MESSAGES = 200;
  public static final int BLOB_CHUNK_BYTES = 96 << 10;
  public static final int MAX_BLOB_BYTES = 20 << 20;
  public static final int MAX_TASK_BLOB_BYTES = 32 << 20;
  public static final int INLINE_DATA_URI_BYTES = 16 << 10;
  public static final String BLOB_SCHEME = "lmbp-blob:";
  public static final String TYP_ACCESS = "at+jwt", TYP_ASSERTION = "JWT", TYP_PROOF = "lmbp-proof+jwt", TYP_TASK = "lmbp-task+jws",
      TYP_METADATA = "lmbp-metadata+jwt", TYP_E2EE_KEY = "lmbp-e2ee-key+jwt";
  public static final String PROOF_TOKEN = "lmbp:token", PROOF_HELLO = "lmbp:hello", PROOF_SESSION_TOKEN = "lmbp:session.token";

  static final SecureRandom RNG = new SecureRandom();
  private static final Pattern B64URL_RE = Pattern.compile("^[A-Za-z0-9_-]*$");

  public static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

  public static byte[] unb64(String s) {
    if (s == null || !B64URL_RE.matcher(s).matches() || s.length() % 4 == 1) throw new IllegalArgumentException("bad base64url");
    return Base64.getUrlDecoder().decode(s);
  }

  public static byte[] sha256(byte[] b) {
    try { return MessageDigest.getInstance("SHA-256").digest(b); } catch (Exception e) { throw new RuntimeException(e); }
  }

  public static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

  public static String shaHex(String s) { return HexFormat.of().formatHex(sha256(utf8(s))); }

  public static String randomID(String prefix) {
    byte[] b = new byte[16];
    RNG.nextBytes(b);
    return prefix + HexFormat.of().formatHex(b);
  }

  public static String ath(String cred) { return b64(sha256(utf8(cred))); }

  public static String thumbprint(byte[] pub) { return b64(sha256(utf8("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64(pub) + "\"}"))); }

  public static String x25519Thumbprint(byte[] pub) { return b64(sha256(utf8("{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"" + b64(pub) + "\"}"))); }

  public static Map<String, Object> publicJWK(byte[] pub) {
    return Json.obj("kty", "OKP", "crv", "Ed25519", "x", b64(pub), "kid", thumbprint(pub), "alg", "EdDSA", "use", "sig");
  }

  public static String tokenAudience(String iss, String tenant) { return iss + "/tenants/" + tenant; }

  public static String assertionAudience(String iss) { return iss + "/lmbp/v1/token"; }

  public static long now() { return System.currentTimeMillis() / 1000; }

  // ---------- Ed25519 ----------
  private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");
  private static final byte[] X509_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

  public record SigningKey(PrivateKey priv, byte[] pub) {}

  public static SigningKey signingKey(byte[] seed) {
    try {
      KeyFactory kf = KeyFactory.getInstance("Ed25519");
      byte[] der = concat(PKCS8_PREFIX, seed);
      PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(der));
      // Derive the public key by signing nothing is not possible; use the JDK key pair math via a signature round trip.
      byte[] pub = derivePublic(seed);
      return new SigningKey(priv, pub);
    } catch (Exception e) { throw new RuntimeException(e); }
  }

  // RFC 8032 public key derivation via the JDK's internal EdDSA operations: generate
  // a key pair from a fixed "random" source that yields the seed.
  private static byte[] derivePublic(byte[] seed) throws Exception {
    java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("Ed25519");
    g.initialize(255, new SecureRandom() {
      @Override public void nextBytes(byte[] bytes) { System.arraycopy(seed, 0, bytes, 0, Math.min(seed.length, bytes.length)); }
    });
    byte[] enc = g.generateKeyPair().getPublic().getEncoded();
    return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
  }

  static PublicKey pubKey(byte[] raw) throws Exception {
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, raw)));
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] o = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, o, a.length, b.length);
    return o;
  }

  public static String signJWS(PrivateKey priv, String typ, String kid, Object payload) {
    Map<String, Object> h = Json.obj("alg", "EdDSA", "typ", typ);
    if (kid != null && !kid.isEmpty()) h.put("kid", kid);
    String input = b64(Json.bytes(h)) + "." + b64(payload instanceof String s ? utf8(s) : Json.bytes(payload));
    try {
      Signature sg = Signature.getInstance("Ed25519");
      sg.initSign(priv);
      sg.update(utf8(input));
      return input + "." + b64(sg.sign());
    } catch (Exception e) { throw new RuntimeException(e); }
  }

  /** Strict compact EdDSA JWS (§5.2); returns the payload object. */
  public static Map<String, Object> verifyJWS(byte[] pub, Object jwsObj, String typ) {
    if (!(jwsObj instanceof String jws)) throw new IllegalArgumentException("malformed JWS");
    String[] parts = jws.split("\\.", -1);
    if (parts.length != 3) throw new IllegalArgumentException("malformed JWS");
    Object h;
    try { h = Json.parse(unb64(parts[0])); } catch (RuntimeException e) { throw new IllegalArgumentException("bad JWS header"); }
    Map<String, Object> hm = Json.asObj(h);
    if (hm == null) throw new IllegalArgumentException("bad JWS header");
    for (String k : hm.keySet()) if (!k.equals("alg") && !k.equals("typ") && !k.equals("kid")) throw new IllegalArgumentException("forbidden JWS header " + k);
    if (!"EdDSA".equals(hm.get("alg"))) throw new IllegalArgumentException("JWS alg must be EdDSA");
    if (!typ.equals(hm.get("typ"))) throw new IllegalArgumentException("JWS typ must be " + typ);
    if (hm.containsKey("kid") && (!(hm.get("kid") instanceof String) || pub == null || pub.length != 32 || !hm.get("kid").equals(thumbprint(pub))))
      throw new IllegalArgumentException("JWS kid does not match the verifying key");
    byte[] sig = unb64(parts[2]);
    boolean ok = false;
    if (pub != null && pub.length == 32 && sig.length == 64) {
      try {
        Signature sg = Signature.getInstance("Ed25519");
        sg.initVerify(pubKey(pub));
        sg.update(utf8(parts[0] + "." + parts[1]));
        ok = sg.verify(sig);
      } catch (Exception e) { ok = false; }
    }
    if (!ok) throw new IllegalArgumentException("bad JWS signature");
    Object c;
    try { c = Json.parse(unb64(parts[1])); } catch (RuntimeException e) { throw new IllegalArgumentException("bad JWS payload"); }
    if (!(c instanceof Map)) throw new IllegalArgumentException("JWS payload must be a JSON object");
    return Json.asObj(c);
  }

  public static boolean isNumericDate(Object x) { return Json.isSafeInteger(x) && ((Number) x).doubleValue() >= 0; }

  static void requireClaims(Map<String, Object> c, String[] ints, String[] strs, String[] opt) {
    for (String k : ints) if (!isNumericDate(c.get(k))) throw new IllegalArgumentException("claim " + k + " must be a non-negative integer");
    for (String k : strs) if (!(c.get(k) instanceof String s) || s.isEmpty()) throw new IllegalArgumentException("claim " + k + " must be a non-empty string");
    for (String k : opt) if (!(c.get(k) instanceof String)) throw new IllegalArgumentException("claim " + k + " must be a string");
  }

  static final String[] NONE = {};

  static void timeRange(Map<String, Object> c) {
    requireClaims(c, new String[] {"iat", "exp"}, NONE, NONE);
    if (Json.longOf(c.get("exp")) < Json.longOf(c.get("iat"))) throw new IllegalArgumentException("exp before iat");
  }

  public static Map<String, Object> verifyJWT(byte[] pub, Object tok, String typ, String aud, long t) {
    Map<String, Object> c = verifyJWS(pub, tok, typ);
    requireClaims(c, NONE, new String[] {"iss", "sub", "aud", "jti"}, NONE);
    timeRange(c);
    if (!aud.equals(c.get("aud"))) throw new IllegalArgumentException("wrong audience");
    if (t > Json.longOf(c.get("exp")) + 30 || t + 30 < Json.longOf(c.get("iat"))) throw new IllegalArgumentException("token expired");
    return c;
  }

  public static Map<String, Object> unverifiedClaims(Object tok) {
    String s = tok == null ? "" : String.valueOf(tok);
    String[] parts = s.split("\\.", -1);
    if (parts.length != 3) throw new IllegalArgumentException("malformed token");
    Object c = Json.parse(unb64(parts[1]));
    if (!(c instanceof Map)) throw new IllegalArgumentException("bad claims");
    return Json.asObj(c);
  }

  public static Map<String, Object> verifyProof(byte[] pub, Object proof, String deviceID, String aud, String credential) {
    return verifyProof(pub, proof, deviceID, aud, credential, now());
  }

  public static Map<String, Object> verifyProof(byte[] pub, Object proof, String deviceID, String aud, String credential, long t) {
    Map<String, Object> c = verifyJWS(pub, proof, TYP_PROOF);
    requireClaims(c, new String[] {"iat"}, new String[] {"aud", "jti", "ath"}, new String[] {"iss"});
    if (!aud.equals(c.get("aud")) || !deviceID.equals(c.get("iss")) || !Json.truthy(c.get("jti")) || !ath(credential == null ? "" : credential).equals(c.get("ath")))
      throw new IllegalArgumentException("proof claims invalid");
    if (Math.abs(t - Json.longOf(c.get("iat"))) > 60) throw new IllegalArgumentException("proof iat outside allowed skew");
    return c;
  }

  public static void verifyE2EEKey(byte[] devicePub, String deviceID, Object stmt) { verifyE2EEKey(devicePub, deviceID, stmt, now()); }

  public static void verifyE2EEKey(byte[] devicePub, String deviceID, Object stmt, long t) {
    Map<String, Object> c = verifyJWS(devicePub, stmt, TYP_E2EE_KEY);
    requireClaims(c, NONE, new String[] {"iss", "sub"}, NONE);
    timeRange(c);
    Map<String, Object> k = Json.asObj(c.get("jwk"));
    if (!deviceID.equals(c.get("sub")) || !deviceID.equals(c.get("iss")) || k == null || !"OKP".equals(k.get("kty")) || !"X25519".equals(k.get("crv")))
      throw new IllegalArgumentException("bad e2ee key statement");
    if (t > Json.longOf(c.get("exp")) || t + 60 < Json.longOf(c.get("iat"))) throw new IllegalArgumentException("e2ee key statement expired");
    byte[] x = unb64(Json.str(k, "x"));
    if (x.length != 32 || !x25519Thumbprint(x).equals(k.get("kid"))) throw new IllegalArgumentException("bad e2ee key");
  }

  public static boolean isLoopbackHost(String h) {
    h = h.replaceAll("^\\[|\\]$", "").toLowerCase();
    return h.equals("localhost") || h.equals("::1") || h.matches("^127\\.\\d+\\.\\d+\\.\\d+$");
  }

  /** origin normalizes scheme://host[:port]; http only for loopback (§18.1). */
  public static String origin(String raw) {
    String s = raw.trim().replaceAll("/+$", "");
    URI u;
    try { u = new URI(s); } catch (Exception e) { throw new IllegalArgumentException("not an origin: " + raw); }
    String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
    if (u.getHost() == null || u.getRawUserInfo() != null || u.getRawQuery() != null || u.getRawFragment() != null
        || (u.getRawPath() != null && !u.getRawPath().isEmpty() && !u.getRawPath().equals("/")))
      throw new IllegalArgumentException("not an origin: " + raw);
    if (!scheme.equals("http") && !scheme.equals("https")) throw new IllegalArgumentException("unsupported scheme in " + raw);
    if (scheme.equals("http") && !isLoopbackHost(u.getHost())) throw new IllegalArgumentException("issuer " + raw + " must use https");
    int port = u.getPort();
    if ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443)) port = -1;
    return scheme + "://" + u.getHost().toLowerCase() + (port >= 0 ? ":" + port : "");
  }

  /** Encoded size of the task.run frame carrying jws (worst-case seq). */
  public static int taskRunFrameSize(String jws, String taskID) {
    return Json.utf8Len(Json.stringify(Json.obj("v", (long) VERSION, "type", "task.run", "task_id", taskID, "seq", 9007199254740992L, "jws", jws)));
  }

  // ---------- flow control (§15) ----------
  public record Flow(long taskWindow, long connWindow) {}

  static boolean canSend(Flow f, long taskUsed, long connUsed, long n) {
    if (f == null) return true;
    return (taskUsed + n <= f.taskWindow || taskUsed == 0) && (connUsed + n <= f.connWindow || connUsed == 0);
  }

  /**
   * Outbox: sending half. All methods run under the gateway lock; send()
   * blocks (releasing the lock) until the frame is admitted by the peer's
   * windows. Admission and credit reservation are one step (audit finding 2).
   */
  public static final class Outbox {
    final Gateway g;
    Flow flow;
    long connUsed;
    final Map<String, OTask> tasks = new HashMap<>();
    final List<Waiter> waiters = new ArrayList<>();
    Consumer<String> write;
    boolean closed;
    /** Tasks dropped with forget (bounded, insertion ordered): their sends fail
     *  instead of re-creating state no retransmit list covers. audit3 P1. */
    final java.util.LinkedHashSet<String> forgotten = new java.util.LinkedHashSet<>();
    static final int MAX_FORGOTTEN = 4096;

    Outbox(Gateway g) { this.g = g; }

    static final class OTask { long nextSeq; final List<long[]> sizes = new ArrayList<>(); final List<String> raws = new ArrayList<>(); long used; long written; }

    static final class Waiter { String task; LongFunction<String> mk; long seq; boolean done; String err; }

    void setFlow(Flow f) { flow = f; wake(); }

    void attach(Consumer<String> w) { write = w; for (OTask t : tasks.values()) t.written = -1; }

    OTask task(String id) { return tasks.computeIfAbsent(id, k -> new OTask()); }

    void wake() {
      while (!waiters.isEmpty()) {
        Waiter w = waiters.get(0);
        if (closed) { waiters.remove(0); w.done = true; w.err = "outbox closed"; continue; }
        if (forgotten.contains(w.task)) { waiters.remove(0); w.done = true; w.err = "task forgotten"; continue; }
        OTask t = task(w.task);
        long seq = t.nextSeq + 1;
        String raw = w.mk.apply(seq);
        long n = Json.utf8Len(raw);
        if (!canSend(flow, t.used, connUsed, n)) break;
        waiters.remove(0);
        t.nextSeq = seq;
        t.sizes.add(new long[] {seq, n});
        t.raws.add(raw);
        t.used += n;
        connUsed += n;
        w.seq = seq;
        w.done = true;
      }
      g.cv.signalAll();
    }

    void flush(String id) {
      for (;;) {
        OTask t = tasks.get(id);
        if (t == null || write == null || t.written < 0) return;
        int idx = -1;
        for (int i = 0; i < t.sizes.size(); i++) if (t.sizes.get(i)[0] > t.written) { idx = i; break; }
        if (idx < 0) return;
        t.written = t.sizes.get(idx)[0];
        try { write.accept(t.raws.get(idx)); } catch (RuntimeException e) { return; }
      }
    }

    /** build(seq) returns the envelope without v/task_id/seq; caller holds the lock. */
    long send(String taskID, LongFunction<Map<String, Object>> build, Gateway.Abort abort) {
      if (closed) throw new IllegalStateException("outbox closed");
      if (forgotten.contains(taskID)) throw new IllegalStateException("task forgotten");
      Waiter w = new Waiter();
      w.task = taskID;
      w.mk = seq -> {
        Map<String, Object> m = Json.obj("v", (long) VERSION);
        m.putAll(build.apply(seq));
        m.put("task_id", taskID);
        m.put("seq", seq);
        return Json.stringify(m);
      };
      waiters.add(w);
      wake();
      while (!w.done) {
        if (abort != null && abort.aborted) {
          waiters.remove(w);
          wake();
          throw new IllegalStateException("aborted");
        }
        g.await(1000);
      }
      if (w.err != null) throw new IllegalStateException(w.err);
      flush(taskID);
      return w.seq;
    }

    void ack(String id, long seq) {
      OTask t = tasks.get(id);
      if (t == null) return;
      while (!t.sizes.isEmpty() && t.sizes.get(0)[0] <= seq) {
        long n = t.sizes.remove(0)[1];
        t.raws.remove(0);
        t.used -= n;
        connUsed -= n;
      }
      wake();
    }

    void retransmit(String id, long peerRecv) {
      ack(id, peerRecv);
      OTask t = tasks.get(id);
      if (t != null) t.written = peerRecv;
      flush(id);
    }

    /** Drops a terminal task for good, atomically (caller holds the lock):
     *  its credit is released and every send of it still queued for credit
     *  fails BEFORE the other waiters are woken, so it can never re-create
     *  its entry and re-consume connection credit no resume returns. */
    void forget(String id) {
      OTask t = tasks.remove(id);
      if (t != null) connUsed -= t.used;
      if (forgotten.add(id) && forgotten.size() > MAX_FORGOTTEN) {
        java.util.Iterator<String> it = forgotten.iterator();
        it.next();
        it.remove();
      }
      for (java.util.Iterator<Waiter> it = waiters.iterator(); it.hasNext();) {
        Waiter w = it.next();
        if (w.task.equals(id)) { it.remove(); w.done = true; w.err = "task forgotten"; }
      }
      wake();
    }

    void close() { closed = true; wake(); }
  }

  public static final int ACCEPTED = 0, DUPLICATE = 1, GAP = 2, OVERFLOW = 3;

  /** Inbound: receiving half; detects duplicates/gaps and enforces our windows. */
  public static final class Inbound {
    final Flow flow;
    long connUsed;
    final Map<String, ITask> tasks = new HashMap<>();

    static final class ITask { long recv; final List<long[]> sizes = new ArrayList<>(); long used; }

    Inbound(Flow f) { flow = f; }

    int accept(String id, long seq, long size) {
      ITask t = tasks.computeIfAbsent(id, k -> new ITask());
      if (seq <= t.recv) return DUPLICATE;
      if (seq != t.recv + 1) return GAP;
      Flow f = flow;
      if (f != null && ((t.used + size > f.taskWindow && t.used > 0) || (connUsed + size > f.connWindow && connUsed > 0))) return OVERFLOW;
      t.recv = seq;
      t.sizes.add(new long[] {seq, size});
      t.used += size;
      connUsed += size;
      return ACCEPTED;
    }

    void acked(String id, long seq) {
      ITask t = tasks.get(id);
      if (t == null) return;
      while (!t.sizes.isEmpty() && t.sizes.get(0)[0] <= seq) { long n = t.sizes.remove(0)[1]; t.used -= n; connUsed -= n; }
    }

    long recv(String id) { ITask t = tasks.get(id); return t == null ? 0 : t.recv; }

    void resetWindows() { connUsed = 0; for (ITask t : tasks.values()) { t.used = 0; t.sizes.clear(); } }

    void forget(String id) { ITask t = tasks.remove(id); if (t != null) connUsed -= t.used; }
  }
}
