"""Review9 P1-1 (port of Node late-frames.test.mjs): the gateway ends a task
locally (the caller goes away) while the device is still running. The
device's late frames, including its terminal frame, must be ACKed so its
reliable buffer and connection flow credit come back; they must not be
answered with unknown_task only. The decided outcome (CANCELLED) stays."""
import asyncio
import json

import httpx

from lmbp_server import LMBPServer, MemoryStore, TenantConfig
from lmbp_server import protocol as L
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
T = "acme"


async def until(cond, what, t=5.0):
    end = asyncio.get_running_loop().time() + t
    while not cond():
        assert asyncio.get_running_loop().time() < end, "timed out: " + (what() if callable(what) else what)
        await asyncio.sleep(0.01)


async def test_local_cancel_late_frames_acked(serve_app):
    store = MemoryStore()
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=store, log=lambda *a: None)
    runs = {}

    def manual(run, ws, listeners):
        tid = run["task_id"]
        st = runs[tid] = {"acked": 0, "cancels": [], "sent": 0}

        def send(typ, data):
            st["sent"] += 1
            return ws.send(json.dumps({"v": L.VERSION, "type": typ, "task_id": tid, "seq": st["sent"], "data": data}))

        async def late():
            await asyncio.sleep(0.05)  # the device only notices a bit later
            await send("task.delta", {"text": "late 1"})
            await send("task.delta", {"text": "late 2"})
            await send("task.error", {"code": "CANCELLED", "message": "cancelled", "retryable": False})

        def on(e):
            if e.get("task_id") != tid:
                return
            if e["type"] == "task.ack":
                st["acked"] = max(st["acked"], e["data"]["seq"])
            if e["type"] == "task.cancel":
                st["cancels"].append(e["data"]["reason"])
                if len(st["cancels"]) == 1:
                    asyncio.ensure_future(late())
        listeners.append(on)

        async def first():
            await send("task.delta", {"text": "hello "})
            await send("task.delta", {"text": "world"})
        asyncio.ensure_future(first())

    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1", manual=manual)
        try:
            n = 5
            hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}
            body = {"model": "m1", "stream": True, "messages": [{"role": "user", "content": "go"}]}
            for _ in range(n):
                async with httpx.AsyncClient(base_url=base, headers=hs, timeout=10) as h:
                    async with h.stream("POST", "/v1/chat/completions", json=body) as r:
                        assert r.status_code == 200
                        async for line in r.aiter_lines():
                            if "hello" in line:
                                break  # caller gone: the gateway ends the task locally
            await until(lambda: len(runs) == n and all(r["sent"] == 5 and r["acked"] == 5 for r in runs.values()),
                        lambda: "device frames ACKed: " + json.dumps(runs))
            for tid, r in runs.items():
                assert "unknown_task" not in r["cancels"], f"task {tid} late frames got unknown_task: {r['cancels']}"
            ds = next(iter(lmbp.engine.devs.values()))
            assert len(ds.reclaimed) == 0, "late-frame records left behind"
            for tid in runs:
                rec = store.get_task(tid)
                assert rec, f"task {tid} not stored"
                assert rec["state"] == "CANCELLED", f"task {tid} state {rec['state']}"
        finally:
            await ws.close()
            task.cancel()
