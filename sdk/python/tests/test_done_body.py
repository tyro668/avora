"""audit3 P2-6: a device terminal frame is validated (envelope + body against
task.done.json / task.error.json) BEFORE its seq is accepted, persisted or
ACKed. Was: task.done {} / null / wrong types were stored as SUCCEEDED,
ACKed, and the caller got a 200."""
import asyncio
import json

import httpx

from lmbp_server import LMBPServer, MemoryStore, TenantConfig
from lmbp_server import protocol as L
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
CASES = [
    ("task.done", {}), ("task.done", None), ("task.done", {"finish_reason": 5}),
    ("task.done", {"finish_reason": "stop", "usage": "lots"}), ("task.done", []),
    ("task.error", {}), ("task.error", {"code": 7, "message": "x"}),
]


async def test_invalid_terminal_body_not_accepted(serve_app):
    store = MemoryStore()
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig("acme", KEY, {"display_name": "Acme"})], store=store, log=lambda *a: None)
    st = {"bad": None, "last": "", "acks": {}}

    def manual(run, ws, listeners):
        tid = st["last"] = run["task_id"]
        typ, data = st["bad"]

        def on(e):
            if e.get("task_id") == tid and e["type"] == "task.ack":
                st["acks"][tid] = max(st["acks"].get(tid, 0), e["data"]["seq"])
        listeners.append(on)

        async def go():
            await ws.send(json.dumps({"v": L.VERSION, "type": "task.delta", "task_id": tid, "seq": 1, "data": {"text": "almost"}}))
            await ws.send(json.dumps({"v": L.VERSION, "type": typ, "task_id": tid, "seq": 2, "data": data}))
        asyncio.ensure_future(go())

    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, "acme", "u1", manual=manual)
        try:
            hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}
            for c in CASES:
                st["bad"], st["last"] = c, ""
                label = f"{c[0]} {json.dumps(c[1])}"
                async with httpx.AsyncClient(base_url=base, headers=hs, timeout=10) as h:
                    r = await h.post("/v1/chat/completions", json={"model": "m1", "messages": [{"role": "user", "content": "hi"}]})
                assert r.status_code != 200, f"{label}: answered 200 {r.text}"
                tid = st["last"]
                assert tid, f"{label}: never dispatched"
                await asyncio.sleep(0.1)
                t = store.get_task(tid)
                assert t["state"] != "SUCCEEDED", f"{label}: stored as SUCCEEDED"
                assert st["acks"].get(tid, 0) < 2, f"{label}: invalid terminal frame was ACKed"
                assert t["events"][-1]["type"] == "task.error", f"{label}: last event {t['events'][-1]}"
        finally:
            await ws.close()
            task.cancel()
