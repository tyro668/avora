package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end through StandaloneServer with a scripted fake connector: pairing, call, stream, cancel, resume, errors. */
class EngineTest {
  static final String KEY = "k".repeat(40);
  static final String MODEL = "tiny";
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;

  String start(Store store) throws Exception {
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(store).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    return "http://127.0.0.1:" + srv.port();
  }

  void pairAndConnect(String base) throws Exception {
    dev = new FakeDevice(base, "acme");
    String code = dev.authorize();
    Pairing.Pending p = lmbp.pairing().lookup("acme", "alice", code);
    assertEquals("pending", p.status());
    assertEquals("test-pc", p.deviceName());
    Pairing.Decision d = lmbp.pairing().approve("acme", "alice", code);
    assertEquals("approved", d.status());
    dev.token();
    dev.connect(MODEL);
  }

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  String model() { return dev.deviceId + "/" + MODEL; }

  static Map<String, Object> req(String model) { return Json.obj("model", model, "messages", List.of(Json.obj("role", "user", "content", "hi"))); }

  static String text(Map<String, Object> chunk) {
    Object c = Json.get(Json.get(Json.asList(chunk.get("choices")).get(0), "delta"), "content");
    return c instanceof String s ? s : "";
  }

  @Test void pairCallStreamResume() throws Exception {
    pairAndConnect(start(new MemoryStore()));
    InProcessClient c = lmbp.client("acme", "alice");
    assertEquals(model(), Json.get(c.models().get(0), "id"));
    Map<String, Object> r = c.call(req(model()));
    assertEquals("hello world", Json.get(Json.get(Json.asList(r.get("choices")).get(0), "message"), "content"));
    StringBuilder sb = new StringBuilder();
    String taskId, last;
    try (LmbpStream st = c.stream(req(model()))) {
      for (Map<String, Object> ch : st) sb.append(text(ch));
      taskId = st.taskId();
      last = st.lastEventId();
    }
    assertEquals("hello world", sb.toString());
    assertFalse(taskId.isEmpty());
    assertEquals("3", last);
    StringBuilder rest = new StringBuilder();
    try (LmbpStream st = c.resume(taskId, "1")) { for (Map<String, Object> ch : st) rest.append(text(ch)); }
    assertEquals(" world", rest.toString());
    // another user sees nothing of alice's
    assertTrue(lmbp.client("acme", "bob").models().isEmpty());
    assertEquals(1, lmbp.pairing().listDevices("acme", "alice").size());
    assertTrue(lmbp.pairing().listDevices("acme", "alice").get(0).online());
  }

  @Test void anthropicMessages() throws Exception {
    pairAndConnect(start(new MemoryStore()));
    InProcessClient c = lmbp.client("acme", "alice");
    Map<String, Object> m = c.messages(Json.obj("model", model(), "max_tokens", 16L, "messages", List.of(Json.obj("role", "user", "content", "hi"))));
    assertEquals("hello world", Json.get(Json.asList(m.get("content")).get(0), "text"));
    int events = 0;
    String lastType = "";
    try (LmbpStream st = c.messagesStream(Json.obj("model", model(), "max_tokens", 16L, "messages", List.of(Json.obj("role", "user", "content", "hi"))))) {
      for (Map<String, Object> e : st) { events++; lastType = (String) e.get("type"); }
    }
    assertTrue(events > 3);
    assertEquals("message_stop", lastType);
  }

  @Test void cancelEndsStreamWithDefiniteResult() throws Exception {
    pairAndConnect(start(new MemoryStore()));
    dev.mode = FakeDevice.Mode.HANG;
    InProcessClient c = lmbp.client("acme", "alice");
    try (LmbpStream st = c.stream(req(model()))) {
      assertTrue(st.hasNext());
      st.next(); // role preamble
      assertEquals("partial", text(st.next()));
      assertTrue(c.cancel(st.taskId()));
      assertFalse(c.cancel(st.taskId()), "only one terminal decision");
      LmbpApiException e = assertThrows(LmbpApiException.class, st::hasNext);
      assertEquals("CANCELLED", e.code());
      String id = st.taskId();
      FakeDevice.waitFor(() -> dev.sawCancel(id), 3000);
      assertTrue(dev.sawCancel(id), "device told to stop");
    }
  }

  @Test void closingStreamEarlyCancelsTask() throws Exception {
    pairAndConnect(start(new MemoryStore()));
    dev.mode = FakeDevice.Mode.HANG;
    InProcessClient c = lmbp.client("acme", "alice");
    String id;
    try (LmbpStream st = c.stream(req(model()))) {
      st.next();
      st.next();
      id = st.taskId();
    }
    FakeDevice.waitFor(() -> dev.sawCancel(id), 3000);
    assertTrue(dev.sawCancel(id), "abandoned non-idempotent task is cancelled");
    LmbpApiException e = assertThrows(LmbpApiException.class, () -> { try (LmbpStream st = c.resume(id, "")) { st.forEachRemaining(x -> { }); } });
    assertEquals("CANCELLED", e.code());
  }

  @Test void invalidParamsAndOfflineAreDefiniteErrors() throws Exception {
    start(new MemoryStore());
    InProcessClient c = lmbp.client("acme", "alice");
    Map<String, Object> bad = req("dev_x/tiny");
    bad.put("temperature", 3L);
    LmbpApiException e = assertThrows(LmbpApiException.class, () -> c.call(bad));
    assertEquals(400, e.status());
    e = assertThrows(LmbpApiException.class, () -> c.call(req("dev_x/tiny")));
    assertEquals(404, e.status());
    assertEquals("MODEL_NOT_FOUND", e.code());
    LmbpStream st = c.stream(bad);
    e = assertThrows(LmbpApiException.class, st::hasNext);
    assertEquals(400, e.status());
    Pairing.PairingException pe = assertThrows(Pairing.PairingException.class, () -> lmbp.pairing().approve("acme", "alice", "XXXX-XXXX"));
    assertEquals("NOT_FOUND", pe.code());
  }

  @Test void truncatedStreamIsReported() throws Exception {
    LmbpStream st = new LmbpStream(new HttpRequest("POST", "/v1/chat/completions", "", Map.of(), new byte[0]), false, "");
    st.sink.start(200, Map.of("X-Task-Id", "task_1"));
    st.sink.write("id: 0\ndata: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\nid: 1\ndata: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\nid: 2\ndata: {\"choi".getBytes(StandardCharsets.UTF_8));
    st.end();
    st.next();
    assertEquals("a", text(st.next()));
    IncompleteStreamException e = assertThrows(IncompleteStreamException.class, st::hasNext);
    assertEquals("task_1", e.taskId());
    assertEquals("1", e.lastEventId());
  }

  @Test void httpSurfaceAndJdbcRestart(@TempDir Path dir) throws Exception {
    String url = "jdbc:sqlite:" + dir.resolve("lmbp.db");
    String base = start(JdbcStore.open(url));
    pairAndConnect(base);
    String kid = lmbp.kid(), devId = dev.deviceId;
    HttpClient h = HttpClient.newHttpClient();
    HttpResponse<String> r = h.send(java.net.http.HttpRequest.newBuilder(URI.create(base + "/v1/chat/completions")).header("Authorization", "Bearer " + KEY)
        .header("X-End-User", "alice").header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(req(model())))).build(),
        HttpResponse.BodyHandlers.ofString());
    assertEquals(200, r.statusCode());
    assertTrue(r.body().contains("hello world"));
    r = h.send(java.net.http.HttpRequest.newBuilder(URI.create(base + "/v1/models")).header("Authorization", "Bearer wrong-key-wrong-key-wrong-key-xx").header("X-End-User", "alice").build(),
        HttpResponse.BodyHandlers.ofString());
    assertEquals(401, r.statusCode());
    stop();
    dev = null;
    start(JdbcStore.open(url));
    assertEquals(kid, lmbp.kid(), "signing key persisted in the store");
    List<Pairing.Device> ds = lmbp.pairing().listDevices("acme", "alice");
    assertEquals(1, ds.size());
    assertEquals(devId, ds.get(0).deviceId());
    assertFalse(ds.get(0).online());
    assertTrue(lmbp.pairing().revokeDevice("acme", "alice", devId));
    assertEquals("revoked", lmbp.pairing().listDevices("acme", "alice").get(0).status());
    assertNotNull(lmbp.jwks().get("keys"));
  }

  // Review7 #2: a revoke while the gateway awaits the hello must not be
  // undone by activation (memory and JDBC stores).
  @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"memory", "sqlite"})
  void revokeDuringHandshakeCannotResurrect(String kind, @org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp) throws Exception {
    Store st = kind.equals("memory") ? new MemoryStore() : JdbcStore.open("jdbc:sqlite:" + tmp.resolve("g.db"));
    String base = start(st);
    dev = new FakeDevice(base, "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.beforeHello = () -> assertTrue(lmbp.pairing().revokeDevice("acme", "alice", dev.deviceId));
    assertThrows(Exception.class, () -> dev.connect(MODEL), "session activated for a revoked device");
    assertEquals("revoked", st.getDevice(dev.deviceId).status);
    FakeDevice.waitFor(() -> lmbp.pairing().listDevices("acme", "alice").stream().noneMatch(Pairing.Device::online), 2000);
    assertTrue(lmbp.pairing().listDevices("acme", "alice").stream().noneMatch(Pairing.Device::online));
  }

  // Review7 #10: a caller that disconnects while queued records CANCELLED (the
  // decided outcome), and an idempotent replay reports exactly that.
  @Test void queuedDisconnectRecordsCancelled() throws Exception {
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(new MemoryStore()).maxConcurrency(1).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.connect(MODEL);
    dev.mode = FakeDevice.Mode.HANG;
    InProcessClient c = lmbp.client("acme", "alice");
    LmbpStream hog = c.stream(req(model())); // holds the only slot
    Thread.sleep(200);
    HttpRequest q = new HttpRequest("POST", "/v1/chat/completions", "", Map.of("content-type", "application/json", "idempotency-key", "k-gone"),
        Json.bytes(Json.obj("model", model(), "messages", List.of(Json.obj("role", "user", "content", "hi")), "stream", false)));
    q.trustedTenant = "acme";
    q.trustedUser = "alice";
    int[] st = {0};
    Thread t = Thread.ofVirtual().start(() -> lmbp.handle(q, new HttpSink() {
      @Override public void start(int status, Map<String, String> h) { st[0] = status; }
      @Override public void write(byte[] b) { }
    }));
    Thread.sleep(300);
    q.abort();
    t.join(5000);
    assertFalse(t.isAlive(), "queued request did not exit on disconnect");
    LmbpApiException e = assertThrows(LmbpApiException.class, () -> c.call(req(model()), new InProcessClient.Options("k-gone", null)));
    assertEquals("CANCELLED", e.code(), "replay must report the decided outcome, not DEVICE_BUSY");
    hog.close();
  }
}
