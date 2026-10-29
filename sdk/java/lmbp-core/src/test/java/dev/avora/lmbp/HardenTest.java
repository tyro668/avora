package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Regression tests for the 2026-10-29 protocol review (P1/P2 hardening): pairing abuse limits,
 * untrusted device names, pending pairings never listed, per-user failure counting, single-use
 * approval, the issuer configuration, revocation of an in-flight task, the tool_calls index range
 * and the per-task output budget. Same cases as the Node, Python and Go suites.
 */
class HardenTest {
  static final String KEY = "k".repeat(40), T = "acme", MODEL = "tiny";
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;
  String base;
  final HttpClient http = HttpClient.newHttpClient();

  void start(String issuer) throws Exception {
    lmbp = LMBPServer.builder().issuer(issuer).tenant(T, KEY, Map.of("display_name", "Acme")).store(new MemoryStore()).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    base = "http://127.0.0.1:" + srv.port();
  }
  void start() throws Exception { start("http://127.0.0.1"); }

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  record Resp(int status, String body) {
    Map<String, Object> json() { return Json.asObj(Json.parse(body)); }
  }

  /** Raw HTTP/1.1 over a socket bound to the given local address, with an explicit Host header. */
  Resp raw(String local, String method, String path, String host, Map<String, String> headers, String body) throws Exception {
    byte[] b = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
    try (Socket s = new Socket()) {
      if (local != null) s.bind(new InetSocketAddress(InetAddress.getByName(local), 0));
      s.connect(new InetSocketAddress("127.0.0.1", srv.port()), 5000);
      s.setSoTimeout(10_000);
      StringBuilder h = new StringBuilder(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nContent-Length: " + b.length + "\r\n");
      headers.forEach((k, v) -> h.append(k).append(": ").append(v).append("\r\n"));
      h.append("\r\n");
      OutputStream o = s.getOutputStream();
      o.write(h.toString().getBytes(StandardCharsets.UTF_8));
      o.write(b);
      o.flush();
      InputStream in = s.getInputStream();
      ByteArrayOutputStream all = new ByteArrayOutputStream();
      in.transferTo(all);
      String r = all.toString(StandardCharsets.UTF_8);
      int status = Integer.parseInt(r.substring(9, 12));
      int i = r.indexOf("\r\n\r\n");
      String rb = i < 0 ? "" : r.substring(i + 4);
      if (r.substring(0, Math.max(i, 0)).toLowerCase().contains("transfer-encoding: chunked")) rb = dechunk(rb);
      return new Resp(status, rb);
    }
  }

  static String dechunk(String s) {
    StringBuilder out = new StringBuilder();
    int p = 0;
    while (p < s.length()) {
      int e = s.indexOf("\r\n", p);
      if (e < 0) break;
      int n = Integer.parseInt(s.substring(p, e).trim(), 16);
      if (n == 0) break;
      out.append(s, e + 2, e + 2 + n);
      p = e + 2 + n + 2;
    }
    return out.toString();
  }

  Resp authorize(String local, String tenant, String name) throws Exception {
    byte[] pub = new byte[32];
    new SecureRandom().nextBytes(pub);
    String form = "tenant=" + FakeDevice.enc(tenant) + "&device_name=" + FakeDevice.enc(name) + "&public_key=" + Lmbp.b64(pub);
    return raw(local, "POST", "/lmbp/v1/device/authorize", "127.0.0.1", Map.of("Content-Type", "application/x-www-form-urlencoded"), form);
  }

  Resp tenantReq(String user, String method, String path, Object body) throws Exception {
    var b = java.net.http.HttpRequest.newBuilder(URI.create(base + path)).header("Authorization", "Bearer " + KEY).header("X-End-User", user)
        .header("Content-Type", "application/json")
        .method(method, body == null ? java.net.http.HttpRequest.BodyPublishers.noBody() : java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(body)));
    HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    return new Resp(r.statusCode(), r.body());
  }

  CompletableFuture<Resp> chat(Map<String, Object> body) {
    var r = java.net.http.HttpRequest.newBuilder(URI.create(base + "/v1/chat/completions")).header("Authorization", "Bearer " + KEY).header("X-End-User", "alice")
        .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(body))).build();
    return http.sendAsync(r, HttpResponse.BodyHandlers.ofString()).thenApply(x -> new Resp(x.statusCode(), x.body()));
  }

  static String code(Resp r) { return String.valueOf(Json.get(r.json().get("error"), "code")); }

  void pairAndConnect(Map<String, Object> helloExtra) throws Exception {
    dev = new FakeDevice(base, T);
    String code = dev.authorize();
    assertEquals("approved", lmbp.pairing().approve(T, "alice", code).status());
    dev.token();
    if (helloExtra != null) dev.helloExtra = helloExtra;
    dev.connect(MODEL);
  }

  void send(String taskId, long seq, String type, Map<String, Object> data) {
    dev.send(Json.obj("v", (long) Lmbp.VERSION, "type", type, "task_id", taskId, "seq", seq, "data", data));
  }

  // P1-3: pending pairings are never listed; device names are sanitized.
  @Test void pendingPairingsAreNotListedAndBidiNamesAreRefused() throws Exception {
    start();
    assertEquals(200, authorize(null, T, "alice-laptop").status());
    for (String user : List.of("alice", "bob")) {
      Resp r = tenantReq(user, "GET", "/lmbp/v1/tenant/devices", null);
      assertEquals(200, r.status());
      assertFalse(r.json().containsKey("pending_pairings"), user + " sees pending pairings: " + r.body());
      assertFalse(r.body().contains("alice-laptop"));
    }
    for (String name : List.of("Office PC\u202Egpj.exe", "a\nb", "x\u200By", "\u0085"))
      assertEquals(400, authorize(null, T, name).status(), "device_name accepted: " + Json.stringify(name));
    assertEquals(200, authorize(null, T, "张三的 MacBook 😀").status());
  }

  // P2: the tenant must exist.
  @Test void unknownTenantIsInvalidClient() throws Exception {
    start();
    Resp r = authorize(null, "no-such-tenant", "pc");
    assertEquals(400, r.status());
    assertEquals("invalid_client", r.json().get("error"));
  }

  // P2: authorize is rate limited per client address.
  @Test void authorizeIsRateLimitedPerAddress() throws Exception {
    start();
    Map<Integer, Integer> codes = new TreeMap<>();
    for (int i = 0; i < 70; i++) codes.merge(authorize("127.0.0.1", T, "pc").status(), 1, Integer::sum);
    assertTrue(codes.getOrDefault(200, 0) <= 60 && codes.getOrDefault(429, 0) > 0, "70 authorizations from one address: " + codes);
  }

  // P2: a tenant holds at most 1000 live pending pairings.
  @Test void pendingPairingsAreCappedPerTenant() throws Exception {
    start();
    Map<Integer, Integer> codes = new TreeMap<>();
    for (int i = 0; i < 1100; i++) codes.merge(authorize("127.0." + (1 + i / 50) + "." + (1 + i % 50), T, "pc").status(), 1, Integer::sum);
    assertTrue(codes.getOrDefault(200, 0) <= 1000 && codes.getOrDefault(429, 0) > 0, "1100 pending pairings: " + codes);
  }

  // P2: a device that ignores slow_down loses its device_code; dead-code polls are not remembered.
  @Test void deviceCodePollingIsCapped() throws Exception {
    start();
    dev = new FakeDevice(base, T);
    dev.authorize();
    String form = "grant_type=" + FakeDevice.enc("urn:ietf:params:oauth:grant-type:device_code") + "&device_code=" + FakeDevice.enc(dev.dc) + "&proof=";
    List<String> errs = new ArrayList<>();
    for (int i = 0; i < 30; i++) {
      String e = String.valueOf(dev.post("/lmbp/v1/token", form + FakeDevice.enc(dev.proof("", Lmbp.PROOF_TOKEN, dev.dc))).get("error"));
      errs.add(e);
      if (e.equals("expired_token")) break;
    }
    assertEquals("expired_token", errs.get(errs.size() - 1), "polls: " + errs);
    assertEquals(10, errs.stream().filter("slow_down"::equals).count(), "polls: " + errs);
    int before = lmbp.g.jtis.size();
    for (int i = 0; i < 20; i++) dev.post("/lmbp/v1/token", form + FakeDevice.enc(dev.proof("", Lmbp.PROOF_TOKEN, dev.dc)));
    assertEquals(before, lmbp.g.jtis.size(), "polls of an expired code grew the jti store");
  }

  // P2: approval is single use under concurrent requests.
  @Test void approvalIsSingleUseUnderConcurrency() throws Exception {
    start();
    dev = new FakeDevice(base, T);
    String code = dev.authorize();
    List<CompletableFuture<Resp>> rs = new ArrayList<>();
    for (int i = 0; i < 8; i++) {
      String user = "u" + i;
      rs.add(CompletableFuture.supplyAsync(() -> {
        try { return tenantReq(user, "POST", "/lmbp/v1/tenant/devices/approvals", Json.obj("user_code", code)); } catch (Exception e) { throw new RuntimeException(e); }
      }));
    }
    List<Integer> st = rs.stream().map(f -> f.join().status()).toList();
    assertEquals(1, st.stream().filter(s -> s == 200).count(), "statuses " + st);
    int owners = 0;
    for (int i = 0; i < 8; i++) owners += lmbp.pairing().listDevices(T, "u" + i).size();
    assertEquals(1, owners);
  }

  // P2: failures are counted per end user, lookups included.
  @Test void pairingFailuresAreCountedPerUser() throws Exception {
    start();
    List<Integer> seq = new ArrayList<>();
    for (int i = 0; i < 11; i++) seq.add(tenantReq("mallory", "POST", "/lmbp/v1/tenant/devices/approvals", Json.obj("user_code", "BBBB-BBBB")).status());
    List<Integer> want = new ArrayList<>(java.util.Collections.nCopies(10, 404));
    want.add(429);
    assertEquals(want, seq);
    assertEquals(404, tenantReq("alice", "POST", "/lmbp/v1/tenant/devices/approvals", Json.obj("user_code", "BBBB-BBBB")).status(), "another user was locked out");
    Pairing.PairingException thrown = null;
    for (int i = 0; i < 11 && thrown == null; i++) {
      try { lmbp.pairing().lookup(T, "eve", "CCCC-CCCC"); } catch (Pairing.PairingException e) { thrown = e; }
    }
    assertNotNull(thrown, "lookups of wrong codes are not counted");
    assertEquals("RATE_LIMITED", thrown.code());
  }

  // P2: the jti store is bounded with heap eviction.
  @Test void jtiStoreStaysFastAndEvicts() {
    Gateway.JtiCache c = new Gateway.JtiCache();
    long until = System.currentTimeMillis() + 60_000;
    for (int i = 0; i < 200_000; i++) c.use("j" + i, until);
    long t0 = System.nanoTime();
    for (int i = 0; i < 1000; i++) c.use("k" + i, until);
    double per = (System.nanoTime() - t0) / 1000.0 / 1e6;
    assertTrue(per < 0.2, String.format("use took %.3f ms per call at 200k entries", per));
    assertFalse(c.use("j1", until), "replay accepted");
    c.use("short", System.currentTimeMillis() - 1);
    c.use("trigger", until);
    assertFalse(c.has("short"), "expired entry kept");
    assertEquals(201_001, c.size());
  }

  // P2: the issuer is configuration, never derived from Host.
  @Test void issuerIsRequiredAndNeverFromHost() throws Exception {
    assertThrows(RuntimeException.class, () -> LMBPServer.builder().tenant(T, KEY).logger(s -> { }).build());
    start("https://gw.example.com");
    Resp m = raw(null, "GET", "/.well-known/lmbp", "evil.example", Map.of(), null);
    assertEquals(200, m.status(), m.body());
    assertEquals("https://gw.example.com", m.json().get("issuer"));
  }

  // P2: revoking a device while its task runs is OUTCOME_UNKNOWN (502), not 401.
  @Test void revokeWithTaskInFlightIsOutcomeUnknown() throws Exception {
    start();
    pairAndConnect(null);
    dev.mode = FakeDevice.Mode.SILENT;
    CompletableFuture<Resp> call = chat(EngineTest.req(dev.deviceId + "/" + MODEL));
    FakeDevice.waitFor(() -> dev.lastRun != null, 5000);
    assertNotNull(dev.lastRun, "task.run never arrived");
    assertEquals(200, tenantReq("alice", "POST", "/lmbp/v1/tenant/devices/" + dev.deviceId + "/revoke", null).status());
    Resp r = call.get(10, java.util.concurrent.TimeUnit.SECONDS);
    assertEquals(502, r.status(), r.body());
    assertEquals("OUTCOME_UNKNOWN", code(r));
  }

  // P1-1: a tool_calls index outside 0..127 fails the task.
  @Test void toolCallIndex128FailsTheTask() throws Exception {
    start();
    pairAndConnect(null);
    dev.script = tid -> send(tid, 1, "task.delta", Json.obj("tool_calls", List.of(Json.obj("index", 128L, "id", "c", "type", "function",
        "function", Json.obj("name", "f", "arguments", "{}")))));
    Map<String, Object> body = EngineTest.req(dev.deviceId + "/" + MODEL);
    body.put("tools", List.of(Json.obj("type", "function", "function", Json.obj("name", "f", "parameters", Json.obj("type", "object")))));
    Resp r = chat(body).get(10, java.util.concurrent.TimeUnit.SECONDS);
    FakeDevice.waitFor(() -> !dev.cancels(dev.lastRun).isEmpty(), 3000);
    assertEquals(List.of("protocol_error"), dev.cancels(dev.lastRun));
    assertEquals(502, r.status(), r.body());
    assertEquals("INTERNAL", code(r));
  }

  // P1-2: the per-task output budget (64 MiB) applies to cleartext and sealed deltas.
  @ParameterizedTest @ValueSource(booleans = {false, true})
  void outputBudgetCancelsTheTask(boolean e2ee) throws Exception {
    start();
    Map<String, Object> extra = null;
    if (e2ee) extra = Json.obj("capabilities", List.of("tools", "e2ee"), "e2ee_key", null);
    dev = new FakeDevice(base, T);
    String code = dev.authorize();
    lmbp.pairing().approve(T, "alice", code);
    dev.token();
    if (e2ee) {
      byte[] x = new byte[32];
      new SecureRandom().nextBytes(x);
      long now = Lmbp.now();
      String stmt = Lmbp.signJWS(dev.key.priv(), Lmbp.TYP_E2EE_KEY, Lmbp.thumbprint(dev.key.pub()), Json.obj("iss", dev.deviceId, "sub", dev.deviceId,
          "iat", now, "exp", now + 3600, "jwk", Json.obj("kty", "OKP", "crv", "X25519", "x", Lmbp.b64(x), "kid", Lmbp.x25519Thumbprint(x))));
      extra.put("e2ee_key", stmt);
      dev.helloExtra = extra;
    }
    dev.connect(MODEL);
    String chunk = "a".repeat(150 << 10);
    long frames = Lmbp.MAX_TASK_OUTPUT_BYTES / chunk.length() + 8;
    long[] sent = {0};
    dev.script = tid -> {
      for (long seq = 1; seq <= frames && dev.cancels(tid).isEmpty(); seq++) {
        Map<String, Object> data = e2ee ? Json.obj("e2ee", Json.obj("ct", Lmbp.b64(chunk.getBytes(StandardCharsets.UTF_8)))) : Json.obj("text", chunk);
        send(tid, seq, "task.delta", data);
        sent[0] = seq;
      }
    };
    Map<String, Object> body = e2ee ? Json.obj("model", dev.deviceId + "/" + MODEL, "lmbp_e2ee", "a.b.c.d.e") : EngineTest.req(dev.deviceId + "/" + MODEL);
    Resp r = chat(body).get(60, java.util.concurrent.TimeUnit.SECONDS);
    FakeDevice.waitFor(() -> dev.lastRun != null && !dev.cancels(dev.lastRun).isEmpty(), 5000);
    assertEquals(List.of("protocol_error"), dev.cancels(dev.lastRun), "no cancel after " + sent[0] + " frames");
    assertEquals(502, r.status(), r.body().substring(0, Math.min(300, r.body().length())));
    assertEquals("INTERNAL", code(r));
  }
}
