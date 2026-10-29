package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * SDK consistency review (2026-10, main@52f48ae): behaviours that diverged from the Go reference
 * gateway, driven through the real HTTP surface of the bundled StandaloneServer.
 * P2-1 retention purges finished tasks with their idempotency records (memory and JDBC);
 * P2-2 an undeclared model on an online device is 404; P3-1 JSON responses are no-store;
 * P1 a non-streaming caller that disconnects gets its task cancelled.
 */
class ConsistencyTest {
  static final String KEY = "k".repeat(40);
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;
  final HttpClient http = HttpClient.newHttpClient();

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  void start(Store store, long retentionMs) throws Exception {
    LMBPServer.Builder b = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(store).logger(s -> { });
    if (retentionMs != 0) b.retentionMillis(retentionMs);
    lmbp = b.build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.connect("tiny");
  }

  HttpResponse<String> call(String method, String path, Object body, String... hdr) throws Exception {
    HttpRequest.Builder r = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.port() + path))
        .header("Authorization", "Bearer " + KEY).header("X-End-User", "alice").header("Content-Type", "application/json");
    for (int i = 0; i < hdr.length; i += 2) r.header(hdr[i], hdr[i + 1]);
    r.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(Json.stringify(body)));
    return http.send(r.build(), HttpResponse.BodyHandlers.ofString());
  }

  long runs() { return dev.received.stream().filter(m -> "task.run".equals(m.get("type"))).count(); }

  void retention(Store store) throws Exception {
    start(store, 60_000);
    Map<String, Object> body = EngineTest.req(dev.deviceId + "/tiny");
    HttpResponse<String> a = call("POST", "/v1/chat/completions", body, "Idempotency-Key", "ret-1");
    HttpResponse<String> b = call("POST", "/v1/chat/completions", body, "Idempotency-Key", "ret-1");
    assertEquals(200, a.statusCode(), a.body());
    assertEquals(1, runs(), "the immediate replay re-attached");
    assertEquals(Json.get(Json.parse(a.body()), "id"), Json.get(Json.parse(b.body()), "id"));
    String taskId = a.headers().firstValue("X-Task-Id").orElse(null);
    assertEquals(0, lmbp.g.purge(System.currentTimeMillis()), "nothing is older than the retention yet");
    assertNotNull(store.getIdempotency("acme", "alice", "ret-1"));
    assertEquals(1, lmbp.g.purge(System.currentTimeMillis() + 61_000), "the finished task is purged after the retention");
    assertNull(store.getIdempotency("acme", "alice", "ret-1"), "idempotency record survived its task");
    if (taskId != null) assertNull(store.getTask(taskId), "task survived the purge");
    HttpResponse<String> c = call("POST", "/v1/chat/completions", body, "Idempotency-Key", "ret-1");
    assertEquals(200, c.statusCode(), c.body());
    assertEquals(2, runs(), "the replay after the purge did not run again");
    assertNotEquals(Json.get(Json.parse(a.body()), "id"), Json.get(Json.parse(c.body()), "id"));
  }

  @Test void retentionMemory() throws Exception { retention(new MemoryStore()); }

  @Test void retentionJdbc() throws Exception {
    Path dir = Files.createTempDirectory("lmbp-ret");
    retention(JdbcStore.open("jdbc:sqlite:" + dir.resolve("x.db")));
  }

  @Test void retentionDefaultsAndTimer() throws Exception {
    assertEquals(7L * 24 * 3600_000, Gateway.RETENTION_DEFAULT);
    assertEquals(3600_000, Gateway.retentionEvery(Gateway.RETENTION_DEFAULT));
    assertEquals(1000, Gateway.retentionEvery(1500));
    try (LMBPServer off = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY).retentionMillis(-1).logger(s -> { }).build()) {
      assertNull(off.g.retentionTimer, "negative retention still schedules purges");
    }
    MemoryStore store = new MemoryStore();
    start(store, 1500);
    assertEquals(200, call("POST", "/v1/chat/completions", EngineTest.req(dev.deviceId + "/tiny"), "Idempotency-Key", "ret-timer").statusCode());
    FakeDevice.waitFor(() -> store.getIdempotency("acme", "alice", "ret-timer") == null, 5000);
    assertNull(store.getIdempotency("acme", "alice", "ret-timer"), "timer did not purge");
  }

  @Test void undeclaredModelIs404AndJsonIsNoStore() throws Exception {
    start(new MemoryStore(), 0);
    HttpResponse<String> r = call("POST", "/v1/chat/completions", EngineTest.req(dev.deviceId + "/nope"));
    assertEquals(404, r.statusCode(), r.body());
    assertEquals("MODEL_NOT_FOUND", Json.get(Json.get(Json.parse(r.body()), "error"), "code"));
    r = call("POST", "/v1/messages", Json.obj("model", dev.deviceId + "/nope", "max_tokens", 5L, "messages", List.of(Json.obj("role", "user", "content", "x"))), "Anthropic-Version", "2023-06-01");
    assertEquals(404, r.statusCode(), r.body());
    assertEquals("not_found_error", Json.get(Json.get(Json.parse(r.body()), "error"), "type"));
    Map<String, String> got = new java.util.LinkedHashMap<>();
    got.put("404", r.headers().firstValue("Cache-Control").orElse(""));
    got.put("models", call("GET", "/v1/models", null).headers().firstValue("Cache-Control").orElse(""));
    got.put("devices", call("GET", "/lmbp/v1/tenant/devices", null).headers().firstValue("Cache-Control").orElse(""));
    got.put("chat", call("POST", "/v1/chat/completions", EngineTest.req(dev.deviceId + "/tiny")).headers().firstValue("Cache-Control").orElse(""));
    got.put("healthz", http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.port() + "/healthz")).build(), HttpResponse.BodyHandlers.ofString()).headers().firstValue("Cache-Control").orElse(""));
    got.put("unauth", http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.port() + "/v1/models")).build(), HttpResponse.BodyHandlers.ofString()).headers().firstValue("Cache-Control").orElse(""));
    for (var e : got.entrySet()) assertEquals("no-store", e.getValue(), e.getKey() + ": " + got);
    dev.close();
    dev.ws = null;
    FakeDevice.waitFor(() -> lmbp.g.online(dev.deviceId) == null, 5000);
    r = call("POST", "/v1/chat/completions", EngineTest.req(dev.deviceId + "/nope"));
    assertEquals(503, r.statusCode(), r.body());
  }

  @Test void nonStreamingDisconnectCancels() throws Exception {
    start(new MemoryStore(), 0);
    dev.mode = FakeDevice.Mode.HANG;
    CompletableFuture<HttpResponse<String>> f = http.sendAsync(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.port() + "/v1/chat/completions"))
        .header("Authorization", "Bearer " + KEY).header("X-End-User", "alice").header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(Json.stringify(EngineTest.req(dev.deviceId + "/tiny")))).build(), HttpResponse.BodyHandlers.ofString());
    FakeDevice.waitFor(() -> runs() == 1, 5000);
    String tid = dev.received.stream().filter(m -> "task.run".equals(m.get("type"))).map(m -> (String) m.get("task_id")).findFirst().orElseThrow();
    Thread.sleep(300);
    f.cancel(true);
    http.shutdownNow();
    long t0 = System.currentTimeMillis();
    FakeDevice.waitFor(() -> dev.sawCancel(tid), 5000);
    assertTrue(dev.cancels(tid).contains("client_disconnected"), "no task.cancel(client_disconnected): " + dev.cancels(tid));
    assertTrue(System.currentTimeMillis() - t0 < 3000, "cancel took " + (System.currentTimeMillis() - t0) + "ms");
  }
}
