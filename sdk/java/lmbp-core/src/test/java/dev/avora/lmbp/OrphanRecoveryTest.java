package dev.avora.lmbp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * audit3 P2-5: a crash leaves QUEUED/RUNNING task rows. A restarted gateway stores OUTCOME_UNKNOWN
 * for them (terminal event + FAILED state) so replays agree and retention purges the prompt and
 * output. Was: synthesized on read only; the rows never became terminal and bypassed retention.
 */
class OrphanRecoveryTest {
  void check(Store store) throws Exception {
    for (String state : new String[] {"RUNNING", "QUEUED"}) {
      Store.TaskRecord t = new Store.TaskRecord();
      t.id = "task_orphan_" + state; t.tenant = "acme"; t.owner = "u1"; t.device = "d"; t.model = "m"; t.state = state;
      store.createTask(t, null, null);
    }
    store.appendEvent("task_orphan_RUNNING", new Store.Event(1, "task.delta", Json.obj("text", "partial")));
    LMBPServer lmbp = LMBPServer.builder().issuer("http://127.0.0.1").tenant("acme", "k".repeat(40), Map.of()).store(store).logger(s -> { }).retentionMillis(60_000).build();
    try {
      for (String state : new String[] {"RUNNING", "QUEUED"}) {
        Store.TaskRecord t = store.getTask("task_orphan_" + state);
        assertEquals("FAILED", t.state, state + " orphan state");
        Store.Event last = t.events.get(t.events.size() - 1);
        assertEquals("task.error", last.type());
        assertEquals("OUTCOME_UNKNOWN", last.data().get("code"));
        if (state.equals("RUNNING")) assertEquals(2, last.seq());
      }
      Thread.sleep(5);
      assertEquals(2, lmbp.g.purge(System.currentTimeMillis() + 120_000), "retention did not purge the orphans");
      assertNull(store.getTask("task_orphan_RUNNING"));
    } finally { lmbp.close(); }
  }

  @Test void memory() throws Exception { check(new MemoryStore()); }

  @Test void sqlite() throws Exception {
    Path dir = Files.createTempDirectory("lmbp-orphan");
    check(JdbcStore.open("jdbc:sqlite:" + dir.resolve("g.db")));
  }
}
