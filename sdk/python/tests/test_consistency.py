"""SDK consistency review (2026-10, main@52f48ae): behaviours that diverged
from the Go reference gateway, driven through the real ASGI/HTTP surface.

P2-1 retention: finished tasks and their Idempotency-Key records are purged
     (default 7 days); a replay after the purge runs again.
P2-2 a model the named online device does not declare is 404, not 503.
P3-1 every JSON response carries Cache-Control: no-store.
"""
import asyncio
import time

import httpx
import pytest

from lmbp_server import LMBPServer, MemoryStore, SQLiteStore, TenantConfig
from lmbp_server.engine import RETENTION_DEFAULT, retention_every
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
T = "acme"
HS = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
async def test_retention_purges_task_and_idempotency(serve_app, tmp_path, kind):
    store = MemoryStore() if kind == "memory" else SQLiteStore(str(tmp_path / "x.db"))
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=store, log=lambda *a: None, retention=60)
    runs = []
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1", on_run=lambda r: runs.append(r["task_id"]))
        try:
            body = {"model": f"{dev}/m1", "messages": [{"role": "user", "content": "keep me"}]}
            hdr = {**HS, "Idempotency-Key": "ret-1"}
            async with httpx.AsyncClient(base_url=base, headers=hdr, timeout=10) as h:
                a = (await h.post("/v1/chat/completions", json=body)).json()
                b = (await h.post("/v1/chat/completions", json=body)).json()
                assert len(runs) == 1, "the immediate replay re-attached"
                assert a["id"] == b["id"]
                tid = runs[0]
                assert lmbp.engine.purge(time.time()) == 0, "nothing is older than the retention yet"
                assert store.get_idempotency(T, "u1", "ret-1") is not None
                assert lmbp.engine.purge(time.time() + 61) == 1, "the finished task is purged after the retention"
                assert store.get_task(tid) is None, "task survived the purge"
                assert store.get_idempotency(T, "u1", "ret-1") is None, "idempotency record survived its task"
                c = await h.post("/v1/chat/completions", json=body)
                assert c.status_code == 200
                assert len(runs) == 2 and runs[1] != tid, "the replay after the purge did not run again"
        finally:
            await ws.close()
            task.cancel()
            lmbp.close()


async def test_retention_defaults_and_timer(serve_app):
    assert RETENTION_DEFAULT == 7 * 24 * 3600
    assert retention_every(RETENTION_DEFAULT) == 3600 and retention_every(2) == 1
    off = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY)], log=lambda *a: None, retention=-1)
    off.engine.ensure_retention()
    assert off.engine.retention_task is None, "negative retention still schedules purges"
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], log=lambda *a: None, retention=1.5)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1")
        try:
            async with httpx.AsyncClient(base_url=base, headers={**HS, "Idempotency-Key": "ret-timer"}, timeout=10) as h:
                r = await h.post("/v1/chat/completions", json={"model": f"{dev}/m1", "messages": [{"role": "user", "content": "t"}]})
                assert r.status_code == 200
            await asyncio.sleep(3.5)
            assert lmbp.store.get_idempotency(T, "u1", "ret-timer") is None, "timer did not purge"
        finally:
            await ws.close()
            task.cancel()
            lmbp.close()


async def test_undeclared_model_is_404_offline_is_503(serve_app):
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], log=lambda *a: None)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1")
        async with httpx.AsyncClient(base_url=base, headers=HS, timeout=10) as h:
            r = await h.post("/v1/chat/completions", json={"model": f"{dev}/nope", "messages": [{"role": "user", "content": "x"}]})
            assert r.status_code == 404 and r.json()["error"]["code"] == "MODEL_NOT_FOUND", r.text
            r = await h.post("/v1/messages", headers={"Anthropic-Version": "2023-06-01"},
                             json={"model": f"{dev}/nope", "max_tokens": 5, "messages": [{"role": "user", "content": "x"}]})
            assert r.status_code == 404 and r.json()["error"]["type"] == "not_found_error", r.text
            await ws.close()
            task.cancel()
            for _ in range(100):
                if not lmbp.engine.online(dev):
                    break
                await asyncio.sleep(0.02)
            for ds in list(lmbp.engine.devs.values()):
                ds.drop("DEVICE_OFFLINE", "test")
            lmbp.engine.devs.clear()
            r = await h.post("/v1/chat/completions", json={"model": f"{dev}/nope", "messages": [{"role": "user", "content": "x"}]})
            assert r.status_code == 503 and r.json()["error"]["code"] == "DEVICE_OFFLINE", r.text


async def test_json_responses_are_no_store(serve_app):
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], log=lambda *a: None)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1")
        try:
            async with httpx.AsyncClient(base_url=base, timeout=10) as h:
                got = {
                    "models": (await h.get("/v1/models", headers=HS)).headers.get("cache-control"),
                    "devices": (await h.get("/lmbp/v1/tenant/devices", headers=HS)).headers.get("cache-control"),
                    "chat": (await h.post("/v1/chat/completions", headers=HS, json={"model": f"{dev}/m1", "messages": [{"role": "user", "content": "x"}]})).headers.get("cache-control"),
                    "error": (await h.post("/v1/chat/completions", headers=HS, json={"model": f"{dev}/m1", "messages": []})).headers.get("cache-control"),
                    "unauth": (await h.get("/v1/models")).headers.get("cache-control"),
                    "healthz": (await h.get("/healthz")).headers.get("cache-control"),
                }
                assert all(v == "no-store" for v in got.values()), got
                assert (await h.get("/.well-known/jwks.json")).headers.get("cache-control") == "public, max-age=300"
        finally:
            await ws.close()
            task.cancel()
