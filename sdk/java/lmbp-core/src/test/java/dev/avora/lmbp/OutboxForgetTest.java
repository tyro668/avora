package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * audit3 P1 (port of Node outbox-forget.test.mjs): a chunked request waits for connection credit,
 * the device drops, the task ends (caller gone) inside the resume window, the device resumes.
 * Ending the task must not let its queued blob.chunk sends re-create outbox state that holds
 * connection credit no resume returns; in strict FIFO that stuck send blocks every later task.
 */
class OutboxForgetTest {
  static final String KEY = "k".repeat(40);
  static final long WIN = Lmbp.MAX_FRAME_BYTES; // smallest legal windows: one blob chunk at a time
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  static Map<String, Object> imageReq(String model) {
    byte[] img = new byte[300 * 1024];
    new SecureRandom().nextBytes(img);
    String url = "data:image/png;base64," + Base64.getEncoder().encodeToString(img);
    return Json.obj("model", model, "messages", List.of(Json.obj("role", "user", "content",
        List.of(Json.obj("type", "text", "text", "look"), Json.obj("type", "image_url", "image_url", Json.obj("url", url))))));
  }

  <T> T underLock(java.util.function.Supplier<T> s) {
    lmbp.g.lock.lock();
    try { return s.get(); } finally { lmbp.g.lock.unlock(); }
  }

  @Test void cancelWhileChunksWaitThenResumeLeaksNoCredit() throws Exception {
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(new MemoryStore()).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    lmbp.pairing().approve("acme", "alice", dev.authorize());
    dev.token();
    Map<String, Object> extra = Json.obj("capabilities", List.of("tools", "flow", "resume", "multimodal"),
        "flow", Json.obj("task_window", WIN, "conn_window", WIN), "model_capabilities", Json.obj("pic", List.of("tools", "vision")));
    dev.helloExtra = extra;
    dev.mode = FakeDevice.Mode.SILENT;
    dev.connect("pic");
    Gateway.DState ds = underLock(() -> lmbp.g.devs.values().iterator().next());
    InProcessClient c = lmbp.client("acme", "alice");
    String model = dev.deviceId + "/pic";
    LmbpStream st = c.stream(imageReq(model));
    FakeDevice.waitFor(() -> underLock(() -> ds.out.waiters.size()) == 1, 5000);
    assertEquals(1, (int) underLock(() -> ds.out.waiters.size()), "a blob.chunk send waiting for credit");
    String id = underLock(() -> ds.tasks.keySet().iterator().next());
    dev.close(); // the device drops; the gateway keeps its state for the resume window
    FakeDevice.waitFor(() -> !underLock(() -> ds.connected()), 5000);
    st.close(); // the caller goes away inside the resume window: the task ends locally
    FakeDevice.waitFor(() -> !underLock(() -> ds.tasks.containsKey(id)), 5000);
    Thread.sleep(100);
    assertFalse(underLock(() -> ds.tasks.containsKey(id)), "task ended");
    assertFalse(underLock(() -> ds.out.tasks.containsKey(id)), "ended task re-created its outbox entry");
    assertEquals(0L, (long) underLock(() -> ds.out.connUsed), "connection credit still held by the ended task");
    assertEquals(0, (int) underLock(() -> ds.out.waiters.size()), "ended task still queued for credit");
    // resume; a new chunked task must get the full window
    Map<String, Object> resumed = new java.util.LinkedHashMap<>(extra);
    resumed.put("resume", Json.obj("token", dev.resumeToken, "tasks", List.of()));
    dev.helloExtra = resumed;
    dev.mode = FakeDevice.Mode.CHUNKS;
    dev.connect("pic");
    CompletableFuture<String> text = CompletableFuture.supplyAsync(() -> {
      StringBuilder sb = new StringBuilder();
      try (LmbpStream s2 = c.stream(imageReq(model))) { for (Map<String, Object> ch : s2) sb.append(EngineTest.text(ch)); }
      return sb.toString();
    });
    String got;
    try { got = text.get(5, TimeUnit.SECONDS); } catch (java.util.concurrent.TimeoutException e) {
      throw new AssertionError("new chunked task blocked (connUsed " + underLock(() -> ds.out.connUsed) + ", waiters " + underLock(() -> ds.out.waiters.size()) + ")");
    }
    assertTrue(got.contains("seen"), got);
  }
}
