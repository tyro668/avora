"""audit3 P1 (port of Node outbox-forget.test.mjs): a chunked request waits
for connection credit, the device drops, the task ends (caller gone) inside
the resume window, the device resumes. Ending the task must not let its
queued blob.chunk sends re-create outbox state that holds connection credit
no resume returns; in strict FIFO that stuck send blocks every later task."""
import asyncio
import base64
import json
import os

import httpx

from lmbp_server import LMBPServer, MemoryStore, TenantConfig
from lmbp_server import protocol as L
from simdevice import connect, finish_pairing, start_pairing
from conftest import issuer

KEY = "k" * 40
T = "acme"
WIN = L.MAX_FRAME_BYTES  # smallest legal windows: one blob chunk at a time


async def until(cond, what, t=5.0):
    end = asyncio.get_running_loop().time() + t
    while not cond():
        assert asyncio.get_running_loop().time() < end, "timed out: " + (what() if callable(what) else what)
        await asyncio.sleep(0.01)


def body():
    img = "data:image/png;base64," + base64.b64encode(os.urandom(300 * 1024)).decode()
    return {"model": "m1", "stream": True, "messages": [{"role": "user", "content": [
        {"type": "text", "text": "look"}, {"type": "image_url", "image_url": {"url": img}}]}]}


async def test_cancel_while_chunks_wait_then_resume_no_credit_leak(serve_app):
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=MemoryStore(), log=lambda *a: None)
    state = {"answer": False, "token": ""}

    def manual(run, ws, listeners):
        tid = run["task_id"]

        def on(e):
            if e.get("task_id") != tid or not state["answer"] or e["type"] not in ("task.run", "blob.chunk"):
                return
            msgs = [{"v": L.VERSION, "type": "task.ack", "task_id": tid, "data": {"seq": e["seq"]}}]
            if e["type"] == "blob.chunk" and e["data"].get("last"):
                msgs += [{"v": L.VERSION, "type": "task.delta", "task_id": tid, "seq": 1, "data": {"text": "seen"}},
                         {"v": L.VERSION, "type": "task.done", "task_id": tid, "seq": 2,
                          "data": {"finish_reason": "stop", "usage": {"prompt_tokens": 1, "completion_tokens": 1}}}]

            async def go():
                for m in msgs:
                    await ws.send(json.dumps(m))
            asyncio.ensure_future(go())
        listeners.append(on)
        if state["answer"]:
            on({"task_id": tid, "type": "task.run", "seq": 1, "data": {}})

    patch = {"capabilities": ["tools", "flow", "resume", "multimodal"], "flow": {"task_window": WIN, "conn_window": WIN},
             "model_capabilities": {"m1": ["tools", "vision"]}}

    def welcome(w):
        state["token"] = w["data"]["resume_token"]
    hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}
    async with serve_app(lmbp.asgi()) as base:
        key, a = await start_pairing(base, T)
        lmbp.pairing.approve(T, "u1", a["user_code"])
        tok = await finish_pairing(base, key, a)
        ws, task = await connect(base, key, tok, manual=manual, hello_patch=patch, on_welcome=welcome)
        ws2 = task2 = None
        try:
            await until(lambda: lmbp.engine.devs, "device online")
            ds = next(iter(lmbp.engine.devs.values()))
            async with httpx.AsyncClient(base_url=base, headers=hs, timeout=10) as h:
                req = asyncio.ensure_future(h.post("/v1/chat/completions", json=body()))
                await until(lambda: len(ds.out.waiters) == 1, "a blob.chunk send waiting for credit")
                tid = next(iter(ds.tasks))
                await ws.close()
                task.cancel()
                await until(lambda: ds.ws is None, "gateway noticed the disconnect")
                req.cancel()  # the caller goes away inside the resume window
                await until(lambda: tid not in ds.tasks, "task ended")
                for _ in range(5):
                    await asyncio.sleep(0)
                assert tid not in ds.out.tasks, "ended task re-created its outbox entry"
                assert ds.out.conn_used == 0, f"connection credit still held by the ended task: {ds.out.conn_used}"
                assert not ds.out.waiters, "ended task still queued for credit"
                state["answer"] = True
                patch2 = {**patch, "resume": {"token": state["token"], "tasks": []}}
                ws2, task2 = await connect(base, key, tok, manual=manual, hello_patch=patch2, on_welcome=welcome)
                try:
                    r = await asyncio.wait_for(h.post("/v1/chat/completions", json=body()), 5)
                except asyncio.TimeoutError:
                    raise AssertionError(f"new chunked task blocked (conn_used {ds.out.conn_used}, waiters {len(ds.out.waiters)})")
                assert r.status_code == 200 and "seen" in r.text, r.text
        finally:
            for w, t in ((ws, task), (ws2, task2)):
                if w is not None:
                    await w.close()
                    t.cancel()
