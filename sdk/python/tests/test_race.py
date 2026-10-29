"""Fourth audit A1: one decide-once terminal decision drives both what is
stored and what callers see; the idempotency record and the task row are one
atomic write. Races are reproduced deterministically with engine.race_hook."""
import asyncio

import httpx
import pytest

import lmbp_server.engine as engine
from lmbp_server import LMBPServer, MemoryStore, SQLiteStore, TenantConfig
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
T = "acme"


def new(store):
    return LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=store, log=lambda *a: None)


async def chat(base, key, content="hello"):
    hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1", "Idempotency-Key": key}
    async with httpx.AsyncClient(base_url=base, headers=hs, timeout=30) as h:
        r = await h.post("/v1/chat/completions", json={"model": "m1", "messages": [{"role": "user", "content": content}]})
    return r.status_code, r.headers.get("x-task-id"), r.text


def success(code, body):
    return code == 200 and '"error"' not in body


def stored_success(st, tid):
    rec = st.get_task(tid)
    terms = [e for e in rec["events"] if e["type"] in ("task.done", "task.error")]
    assert len(terms) == 1, (rec["events"], rec["state"])
    ok = rec["state"] == "SUCCEEDED" if terms[0]["type"] == "task.done" else rec["state"] in ("FAILED", "CANCELLED")
    assert ok, (terms[0]["type"], rec["state"])
    return terms[0]["type"] == "task.done"


@pytest.fixture
def hook():
    yield
    engine.race_hook = None


@pytest.mark.parametrize("code", ["TIMEOUT", "CANCELLED", "SLOW_CONSUMER"])
async def test_decide_once_local_path_after_device_commit(serve_app, tmp_path, hook, code):
    st = SQLiteStore(str(tmp_path / "g.db"))
    lmbp = new(st)
    fired = []

    def h(t, point):
        if point == "device-terminal-committed" and not fired:
            fired.append(1)
            t.fail_local(code, "injected " + code)
    engine.race_hook = h
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        c1, tid, b1 = await chat(base, "k-" + code)
        assert fired
        await asyncio.sleep(0.15)
        assert success(c1, b1) == stored_success(st, tid), f"caller {c1} {b1} vs storage"
        lmbp.engine.tasks.pop(tid, None)  # drop the hub: replay from storage
        c2, _, b2 = await chat(base, "k-" + code)
        assert success(c2, b2) == success(c1, b1), f"replay {c2} {b2} vs caller {b1}"
        await ws.close()
        task.cancel()
    st.close()


async def test_local_decides_first_late_device_frames_dropped(serve_app, hook):
    st = MemoryStore()
    lmbp = new(st)
    fired = []

    def h(t, point):
        if point == "device-frame" and not fired:
            fired.append(1)
            t.fail_local("TIMEOUT", "injected timeout")
    engine.race_hook = h
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        c1, tid, b1 = await chat(base, "k-local-first", "a b c d")
        assert fired and not success(c1, b1) and "TIMEOUT" in b1, b1
        await asyncio.sleep(0.2)
        assert stored_success(st, tid) is False
        assert st.get_task(tid)["events"][-1]["type"] == "task.error"
        await ws.close()
        task.cancel()


async def test_idempotency_and_task_atomic(serve_app, tmp_path):
    st = SQLiteStore(str(tmp_path / "g.db"))
    armed = [True]
    for m in ("put_task", "create_task"):
        orig = getattr(st, m, None)
        if orig is None:
            continue

        def wrap(*a, _orig=orig, _m=m, **kw):
            if armed[0] and a and isinstance(a[0], dict) and a[0].get("state") == "QUEUED":
                armed[0] = False
                raise RuntimeError("injected crash while creating the task")
            return _orig(*a, **kw)
        setattr(st, m, wrap)
    lmbp = new(st)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        c1, _, b1 = await chat(base, "k-atomic")
        assert c1 == 500, b1
        rec = st.get_idempotency(T, "u1", "k-atomic")
        assert rec is None or st.get_task(rec["task_id"]) is not None, f"key stored without its task: {rec}"
        c2, _, b2 = await chat(base, "k-atomic")
        assert success(c2, b2), f"retry after the failed create: {c2} {b2}"
        await ws.close()
        task.cancel()
    st.close()
