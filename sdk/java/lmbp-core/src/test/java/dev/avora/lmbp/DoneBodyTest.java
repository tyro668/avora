package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * audit3 P2-6: a device terminal frame is validated (envelope + body against task.done.json /
 * task.error.json) BEFORE its seq is accepted, persisted or ACKed. Was: task.done {} / null /
 * wrong types were stored as SUCCEEDED, ACKed, and the caller got a 200.
 */
class DoneBodyTest {
  static final String KEY = "k".repeat(40);
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  @Test void invalidTerminalBodyIsNotAccepted() throws Exception {
    MemoryStore store = new MemoryStore();
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(store).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.connect("tiny");
    dev.mode = FakeDevice.Mode.BAD;
    Object[][] cases = {
      {"task.done", Json.obj()}, {"task.done", null}, {"task.done", Json.obj("finish_reason", 5L)},
      {"task.done", Json.obj("finish_reason", "stop", "usage", "lots")}, {"task.done", List.of()},
      {"task.error", Json.obj()}, {"task.error", Json.obj("code", 7L, "message", "x")},
    };
    HttpClient http = HttpClient.newHttpClient();
    for (Object[] c : cases) {
      dev.badType = (String) c[0];
      dev.badData = c[1];
      dev.lastRun = null;
      String label = c[0] + " " + Json.stringify(c[1]);
      String body = Json.stringify(Json.obj("model", dev.deviceId + "/tiny", "messages", List.of(Json.obj("role", "user", "content", "hi"))));
      HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + srv.port() + "/v1/chat/completions"))
          .header("Authorization", "Bearer " + KEY).header("X-End-User", "alice").header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
      assertNotEquals(200, r.statusCode(), label + ": answered 200 " + r.body());
      String id = dev.lastRun;
      assertNotNull(id, label + ": never dispatched (" + r.statusCode() + " " + r.body() + ")");
      Thread.sleep(100);
      Store.TaskRecord t = store.getTask(id);
      assertNotEquals("SUCCEEDED", t.state, label + ": stored as SUCCEEDED");
      assertTrue(dev.acked(id) < 2, label + ": invalid terminal frame was ACKed");
      assertEquals("task.error", t.events.get(t.events.size() - 1).type(), label + ": last event " + t.events.get(t.events.size() - 1));
    }
  }
}
