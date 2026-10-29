package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Review9 P2-8: close() used to clear the queue, which can drop the EOF the engine already put.
 * Once the producer has exited nothing else is ever put, so a reader calling hasNext() after
 * (or while) the stream is closed blocked in q.take() forever. A closed stream must end.
 */
class StreamCloseTest {
  static final String KEY = "k".repeat(40);
  LMBPServer lmbp;
  StandaloneServer srv;
  FakeDevice dev;

  @AfterEach void stop() throws Exception {
    if (dev != null) dev.close();
    if (srv != null) srv.close();
    if (lmbp != null) lmbp.close();
  }

  @Test void closeAfterProducerEndedDoesNotHangReader() throws Exception {
    lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", KEY, Map.of("display_name", "Acme")).store(new MemoryStore()).logger(s -> { }).build();
    srv = StandaloneServer.start(lmbp, "127.0.0.1", 0);
    dev = new FakeDevice("http://127.0.0.1:" + srv.port(), "acme");
    String code = dev.authorize();
    lmbp.pairing().approve("acme", "alice", code);
    dev.token();
    dev.connect("tiny");
    dev.reply = List.of("a", "b", "c");
    InProcessClient c = lmbp.client("acme", "alice");
    LmbpStream st = c.stream(EngineTest.req(dev.deviceId + "/tiny"));
    assertTrue(st.hasNext());
    st.next(); // role preamble; the rest (and the EOF) is queued
    FakeDevice.waitFor(() -> st.producerEnded, 5000);
    assertTrue(st.producerEnded, "engine finished producing");
    st.close(); // drops the queued EOF
    CompletableFuture<Boolean> reader = CompletableFuture.supplyAsync(() -> {
      try { return st.hasNext(); } catch (RuntimeException e) { return false; }
    });
    try {
      assertFalse(reader.get(3, TimeUnit.SECONDS), "a closed stream has no more chunks");
    } catch (TimeoutException e) {
      reader.cancel(true);
      throw new AssertionError("reader blocked forever in q.take() after close()", e);
    }
  }
}
