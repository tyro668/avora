"""audit3 P2-5: a crash leaves QUEUED/RUNNING task rows. A restarted gateway
stores OUTCOME_UNKNOWN for them (terminal event + FAILED state) so replays
agree and retention purges the prompt and output. Was: synthesized on read
only; the rows never became terminal and bypassed retention forever."""
import time

import pytest

from lmbp_server import LMBPServer, MemoryStore, SQLiteStore, TenantConfig
from conftest import issuer


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_restart_records_orphans_as_outcome_unknown(kind, tmp_path):
    store = MemoryStore() if kind == "memory" else SQLiteStore(str(tmp_path / "g.db"))
    for state in ("RUNNING", "QUEUED"):
        store.create_task({"id": "task_orphan_" + state, "tenant": "acme", "owner": "u1", "device": "d", "model": "m",
                           "state": state, "events": [], "request": {"secret": "prompt"}})
    store.append_event("task_orphan_RUNNING", {"seq": 1, "type": "task.delta", "data": {"text": "partial"}})
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig("acme", "k" * 40)], store=store, log=lambda *a: None, retention=60)
    for state in ("RUNNING", "QUEUED"):
        t = store.get_task("task_orphan_" + state)
        assert t["state"] == "FAILED", f"{state} orphan state {t['state']}"
        last = t["events"][-1]
        assert last["type"] == "task.error" and last["data"]["code"] == "OUTCOME_UNKNOWN", last
        if state == "RUNNING":
            assert last["seq"] == 2
    assert lmbp.engine.purge(time.time() + 120) == 2, "retention did not purge the orphans"
    assert store.get_task("task_orphan_RUNNING") is None
