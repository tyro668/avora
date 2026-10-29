package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Review9 P1-1 (port of Node late-frames.test.mjs): the gateway ends a task locally (the caller
 * closes the stream) while the device is still running. The device's late frames, including its
 * terminal frame, must be ACKed so its reliable buffer and connection flow credit come back; they
 * must not be answered with unknown_task only. The decided outcome (CANCELLED) stays.
 */
class LateFramesTest {
  static final String KEY = "k".repeat(40);
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  @Test void localCancelLateFramesAreAcked() throws Exception {
    MemoryStore store = new MemoryStore();
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(store).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.connect("tiny");
    dev.mode = FakeDevice.Mode.LATE;
    InProcessClient c = lmbp.client("acme", "alice");
    List<String> ids = new ArrayList<>();
    for (int i = 0; i < 5; i++) {
      try (LmbpStream st = c.stream(EngineTest.req(dev.deviceId + "/tiny"))) {
        st.next(); // role preamble
        st.next(); // "hello "
        ids.add(st.taskId());
      } // caller gone: the gateway ends the task locally
    }
    FakeDevice.waitFor(() -> ids.stream().allMatch(id -> dev.acked(id) == 5), 5000);
    for (String id : ids) {
      assertEquals(5, dev.acked(id), "task " + id + " ACKed up to; cancels=" + dev.cancels(id));
      assertFalse(dev.cancels(id).contains("unknown_task"), "task " + id + " late frames got unknown_task: " + dev.cancels(id));
    }
    Gateway.DState ds = lmbp.g.devs.values().iterator().next();
    assertTrue(ds.reclaimed.isEmpty(), "late-frame records left behind");
    for (String id : ids) {
      Store.TaskRecord t = store.getTask(id);
      assertNotNull(t, "task " + id + " not stored");
      assertEquals("CANCELLED", t.state, "task " + id);
    }
  }
}
