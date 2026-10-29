package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * LMBP 2.0 (spec §4.1, §7.1, §7.4, §11, §18.2): version identifiers, 1.x refusal, hello/models.update schema
 * validation without clamping, code-point lengths and printable-ASCII headers. Each case failed on the 1.0 engine.
 */
class V2Test {
  static final String KEY = "k".repeat(40);
  LMBPServer lmbp;
  StandaloneServer srv;
  String base;
  final HttpClient http = HttpClient.newHttpClient();

  FakeDevice paired() throws Exception {
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(new MemoryStore()).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    base = "http://127.0.0.1:" + srv.port();
    FakeDevice d = new FakeDevice(base, "acme");
    lmbp.pairing().approve("acme", "alice", d.authorize());
    d.token();
    return d;
  }

  @AfterEach void stop() throws Exception {
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  /** Opens a WebSocket offering proto; frames land in the queue ("CLOSE" on close). */
  WebSocket open(FakeDevice d, String proto, BlockingQueue<String> q) {
    return http.newWebSocketBuilder().header("Authorization", "Bearer " + d.token).subprotocols(proto)
        .buildAsync(URI.create("ws" + base.substring(4) + "/lmbp/v1/connect"), new WebSocket.Listener() {
          final StringBuilder buf = new StringBuilder();
          @Override public CompletionStage<?> onText(WebSocket w, CharSequence data, boolean last) {
            buf.append(data);
            if (last) { q.add(buf.toString()); buf.setLength(0); }
            w.request(1);
            return null;
          }
          @Override public CompletionStage<?> onClose(WebSocket w, int code, String reason) { q.add("CLOSE"); return null; }
        }).join();
  }

  Map<String, Object> hello(FakeDevice d, Object conc) {
    Map<String, Object> h = Json.obj("device_id", d.deviceId, "client", "t", "models", List.of("m1"),
        "proof", d.proof(d.deviceId, Lmbp.PROOF_HELLO, d.token));
    if (conc != null) h.put("max_concurrency", conc);
    return h;
  }

  static Map<String, Object> next(BlockingQueue<String> q) throws InterruptedException {
    String s = q.poll(5, TimeUnit.SECONDS);
    assertTrue(s != null && !s.equals("CLOSE"), "no frame: " + s);
    return Json.asObj(Json.parse(s));
  }

  /** Raw HTTP/1.1 request so header bytes are sent exactly (UTF-8 included). */
  int status(String method, String path, String extraHeaders, String body) throws Exception {
    try (Socket s = new Socket("127.0.0.1", srv.port())) {
      byte[] b = body.getBytes(StandardCharsets.UTF_8);
      String req = method + " " + path + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: " + b.length + "\r\n" + extraHeaders + "\r\n";
      OutputStream o = s.getOutputStream();
      o.write(req.getBytes(StandardCharsets.UTF_8));
      o.write(b);
      o.flush();
      InputStream in = s.getInputStream();
      String line = new String(in.readNBytes(12), StandardCharsets.ISO_8859_1);
      return Integer.parseInt(line.substring(9, 12));
    }
  }

  @Test void metadataAdvertises20AndProfiles() throws Exception {
    paired();
    Map<String, Object> m = Json.asObj(Json.parse(http.send(java.net.http.HttpRequest.newBuilder(URI.create(base + "/.well-known/lmbp")).build(),
        java.net.http.HttpResponse.BodyHandlers.ofString()).body()));
    assertEquals(List.of("2.0"), m.get("protocol_versions"));
    assertEquals(7, Json.asList(m.get("profiles")).size());
    assertTrue(Json.asList(m.get("profiles")).contains("core"));
    assertEquals("lmbp", Lmbp.SUBPROTOCOL);
  }

  @Test void oneXPeersAreRefused() throws Exception {
    FakeDevice d = paired();
    CompletionException e = assertThrows(CompletionException.class, () -> open(d, "lmbp.2", new LinkedBlockingQueue<>()));
    assertTrue(e.getCause() instanceof WebSocketHandshakeException h && h.getResponse().statusCode() == 400, String.valueOf(e.getCause()));
    BlockingQueue<String> q = new LinkedBlockingQueue<>();
    WebSocket ws = open(d, Lmbp.SUBPROTOCOL, q);
    ws.sendText(Json.stringify(Json.obj("v", 1L, "type", "hello", "id", "h1", "data", hello(d, 2L))), true).join();
    assertEquals("VERSION_UNSUPPORTED", Json.get(next(q).get("data"), "code"));
    assertEquals("CLOSE", q.poll(10, java.util.concurrent.TimeUnit.SECONDS));
  }

  @Test void helloOutOfRangeRejectedNotClamped() throws Exception {
    FakeDevice d = paired();
    for (Object conc : new Object[] {0L, 17L, null, "2"}) {
      BlockingQueue<String> q = new LinkedBlockingQueue<>();
      WebSocket ws = open(d, Lmbp.SUBPROTOCOL, q);
      ws.sendText(Json.stringify(Json.obj("v", 2L, "type", "hello", "id", "h1", "data", hello(d, conc))), true).join();
      Map<String, Object> f = next(q);
      assertEquals("error", f.get("type"), "conc " + conc + ": " + f);
      assertEquals("BAD_REQUEST", Json.get(f.get("data"), "code"));
    }
    BlockingQueue<String> q = new LinkedBlockingQueue<>();
    WebSocket ws = open(d, Lmbp.SUBPROTOCOL, q);
    Map<String, Object> h = hello(d, 2L);
    h.put("model_names", Json.obj("m1", "😀".repeat(129)));
    ws.sendText(Json.stringify(Json.obj("v", 2L, "type", "hello", "id", "h1", "data", h)), true).join();
    assertEquals("BAD_REQUEST", Json.get(next(q).get("data"), "code"));
  }

  @Test void modelsUpdateRejectedWhole() throws Exception {
    FakeDevice d = paired();
    BlockingQueue<String> q = new LinkedBlockingQueue<>();
    WebSocket ws = open(d, Lmbp.SUBPROTOCOL, q);
    ws.sendText(Json.stringify(Json.obj("v", 2L, "type", "hello", "id", "h1", "data", hello(d, 2L))), true).join();
    assertEquals(2L, ((Number) Json.get(next(q).get("data"), "max_concurrency")).longValue());
    ws.sendText(Json.stringify(Json.obj("v", 2L, "type", "models.update", "id", "mu1", "data", Json.obj("models", List.of("m1", "zzz"), "max_concurrency", 99L))), true).join();
    Map<String, Object> f = next(q);
    assertEquals("BAD_REQUEST", Json.get(f.get("data"), "code"), String.valueOf(f));
    List<Object> models = lmbp.client("acme", "alice").models();
    assertFalse(models.stream().anyMatch(m -> String.valueOf(Json.get(m, "id")).endsWith("/zzz")), String.valueOf(models));
    ws.abort();
  }

  @Test void lengthsInCodePointsAndAsciiHeaders() throws Exception {
    paired();
    String pk = Lmbp.b64(new byte[32]).replace('A', 'B');
    String form = "tenant=acme&public_key=" + pk + "&device_name=";
    java.util.function.Function<String, Integer> auth = name -> {
      try {
        return http.send(java.net.http.HttpRequest.newBuilder(URI.create(base + "/lmbp/v1/device/authorize")).header("Content-Type", "application/x-www-form-urlencoded")
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(form + FakeDevice.enc(name))).build(), java.net.http.HttpResponse.BodyHandlers.ofString()).statusCode();
      } catch (Exception e) { throw new RuntimeException(e); }
    };
    assertEquals(200, auth.apply("😀".repeat(100)));
    assertEquals(400, auth.apply("设".repeat(101)));
    String bearer = "Authorization: Bearer " + KEY + "\r\n";
    assertEquals(400, status("GET", "/v1/models", bearer + "X-End-User: 张三\r\n", ""));
    assertEquals(400, status("GET", "/v1/models", bearer + "X-End-User: " + "a".repeat(129) + "\r\n", ""));
    assertEquals(200, status("GET", "/v1/models", bearer + "X-End-User: " + "a".repeat(128) + "\r\n", ""));
    String chat = Json.stringify(Json.obj("model", "m1", "messages", List.of(Json.obj("role", "user", "content", "hi"))));
    assertEquals(400, status("POST", "/v1/chat/completions", bearer + "X-End-User: alice\r\nIdempotency-Key: " + "k".repeat(256) + "\r\n", chat));
    assertEquals(400, status("POST", "/v1/chat/completions", bearer + "X-End-User: alice\r\nIdempotency-Key: 键\r\n", chat));
    assertThrows(Pairing.PairingException.class, () -> lmbp.pairing().approve("acme", "张三", "BCDF-GHJK"));
  }
}
