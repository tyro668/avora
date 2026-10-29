"""Third audit #1: the terminal event and the terminal task state are written
in ONE transaction. The done event is written, the status write fails, the
caller gets INTERNAL; after a restart a retry with the same Idempotency-Key
must get the same outcome (never success), and storage holds exactly one
terminal event whose state agrees."""
import asyncio
import re

import httpx

from lmbp_server import LMBPServer, MemoryStore, SQLiteStore, TenantConfig
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
T = "acme"
BODY = {"model": "m1", "messages": [{"role": "user", "content": "hello"}]}


def new(store):
    return LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=store, log=lambda *a: None)


async def idem_chat(base, key):
    hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1", "Idempotency-Key": key}
    async with httpx.AsyncClient(base_url=base, headers=hs, timeout=30) as h:
        r = await h.post("/v1/chat/completions", json=BODY)
    return r.status_code, r.headers.get("x-task-id"), r.text


def outcome(code, body):
    if code == 200 and '"error"' not in body:
        return "success"
    m = re.search(r"INTERNAL|OUTCOME_UNKNOWN", body)
    return m.group(0) if m else "other:" + body


def single_terminal(store, task_id):
    rec = store.get_task(task_id)
    seqs = [e["seq"] for e in rec["events"]]
    assert len(set(seqs)) == len(seqs), f"seq reused: {seqs}"
    terms = [e for e in rec["events"] if e["type"] in ("task.done", "task.error")]
    assert len(terms) == 1, (rec["events"], rec["state"])
    ok = rec["state"] == "SUCCEEDED" if terms[0]["type"] == "task.done" else rec["state"] in ("FAILED", "CANCELLED")
    assert ok, f"terminal {terms[0]['type']} disagrees with state {rec['state']}"
    return terms[0]["type"]


async def test_sqlite_status_failure_restart_same_outcome(serve_app, tmp_path):
    path = str(tmp_path / "g.db")
    st = SQLiteStore(path)
    # Fault injection inside the database: any write making the task SUCCEEDED fails.
    for ev in ("INSERT", "UPDATE"):
        st.db.execute(f"CREATE TRIGGER fail_{ev} BEFORE {ev} ON lmbp_tasks WHEN json_extract(NEW.doc,'$.state')='SUCCEEDED' "
                      "BEGIN SELECT RAISE(ABORT,'injected status write failure'); END")
    lmbp = new(st)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        c1, tid, b1 = await idem_chat(base, "k-term")
        assert outcome(c1, b1) != "success", "status write failed but the caller got success"
        await asyncio.sleep(0.2)
        await ws.close()
        task.cancel()
    st.db.executescript("DROP TRIGGER fail_INSERT; DROP TRIGGER fail_UPDATE;")
    st.close()
    st2 = SQLiteStore(path)  # restart over the same file
    lmbp2 = new(st2)
    async with serve_app(lmbp2.asgi()) as base:
        c2, tid2, b2 = await idem_chat(base, "k-term")
    assert tid2 == tid
    assert outcome(c2, b2) == outcome(c1, b1), f"before restart {c1} {b1}\nafter {c2} {b2}"
    assert single_terminal(st2, tid) == "task.error"
    st2.close()


async def test_memory_one_shot_status_failure_replay_same_outcome(serve_app):
    st = MemoryStore()
    armed = [True]
    put_task = st.put_task

    def failing_put(rec):
        if rec.get("state") == "SUCCEEDED" and armed[0]:
            armed[0] = False
            raise OSError("disk full")
        return put_task(rec)
    st.put_task = failing_put
    if hasattr(st, "finish_task"):
        fin = st.finish_task

        def failing_finish(tid, ev, state):
            if state == "SUCCEEDED" and armed[0]:
                armed[0] = False
                raise OSError("disk full")
            return fin(tid, ev, state)
        st.finish_task = failing_finish
    lmbp = new(st)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        c1, tid, b1 = await idem_chat(base, "k-mem")
        await asyncio.sleep(0.2)
        lmbp.engine.tasks.pop(tid, None)  # drop the hub: replay from the store
        c2, _, b2 = await idem_chat(base, "k-mem")
        await ws.close()
        task.cancel()
    assert outcome(c2, b2) == outcome(c1, b1), f"first {c1} {b1}\nreplay {c2} {b2}"
    assert outcome(c2, b2) != "success"
    single_terminal(st, tid)


async def test_recovery_inconsistent_legacy_row(serve_app):
    st = MemoryStore()
    st.put_task({"id": "task_x", "tenant": T, "owner": "u1", "device": "d", "model": "m1", "state": "FAILED",
                 "events": [{"seq": 1, "type": "task.delta", "data": {"content": "hi"}},
                            {"seq": 2, "type": "task.done", "data": {"finish_reason": "stop"}}]})
    lmbp = new(st)
    async with serve_app(lmbp.asgi()) as base:
        async with httpx.AsyncClient(base_url=base, headers={"Authorization": "Bearer " + KEY, "X-End-User": "u1"}) as h:
            r = await h.get("/lmbp/v1/tenant/tasks/task_x/events")
    assert "OUTCOME_UNKNOWN" in r.text, r.text
    assert "task.done" not in r.text and '"finish_reason":"stop"' not in r.text, r.text
    assert len(st.get_task("task_x")["events"]) == 2


def test_finish_task_contract(tmp_path):
    import pytest
    from lmbp_server import StoreConflict, StoreNotFound
    sq = SQLiteStore(str(tmp_path / "f.db"))
    for st in (MemoryStore(), sq):
        st.put_task({"id": "t1", "tenant": T, "owner": "u", "device": "d", "model": "m", "state": "RUNNING", "events": []})
        st.append_event("t1", {"seq": 1, "type": "task.delta", "data": {}})
        with pytest.raises(StoreConflict):
            st.append_event("t1", {"seq": 1, "type": "task.delta", "data": {}})
        with pytest.raises(StoreConflict):
            st.finish_task("t1", {"seq": 1, "type": "task.done", "data": {}}, "SUCCEEDED")
        assert st.get_task("t1")["state"] == "RUNNING"
        st.finish_task("t1", {"seq": 2, "type": "task.done", "data": {}}, "SUCCEEDED")
        with pytest.raises(StoreConflict):
            st.finish_task("t1", {"seq": 3, "type": "task.error", "data": {}}, "FAILED")
        with pytest.raises(StoreNotFound):
            st.finish_task("nope", {"seq": 1, "type": "task.done", "data": {}}, "SUCCEEDED")
        rec = st.get_task("t1")
        assert rec["state"] == "SUCCEEDED" and [e["seq"] for e in rec["events"]] == [1, 2], type(st).__name__
    # SQLite: a failing state update inside the transaction rolls back the event.
    sq.put_task({"id": "t2", "tenant": T, "owner": "u", "device": "d", "model": "m", "state": "RUNNING", "events": []})
    sq.db.execute("CREATE TRIGGER f BEFORE UPDATE ON lmbp_tasks WHEN json_extract(NEW.doc,'$.state')='SUCCEEDED' BEGIN SELECT RAISE(ABORT,'injected'); END")
    with pytest.raises(Exception):
        sq.finish_task("t2", {"seq": 1, "type": "task.done", "data": {}}, "SUCCEEDED")
    assert sq.get_task("t2")["events"] == [] and sq.get_task("t2")["state"] == "RUNNING"
