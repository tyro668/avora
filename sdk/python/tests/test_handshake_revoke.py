"""Review7 #2: a revoke while the gateway awaits the hello must not be undone
by the hello's E2EE metadata write (memory and SQLite stores)."""
import pytest

from lmbp_server import LMBPServer, MemoryStore, SQLiteStore, TenantConfig
from simdevice import start_pairing, finish_pairing, connect
from conftest import issuer

KEY = "k" * 40
T = "acme"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
async def test_revoke_during_handshake_cannot_resurrect(serve_app, tmp_path, kind):
    st = MemoryStore() if kind == "memory" else SQLiteStore(str(tmp_path / "g.db"))
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=st, log=lambda *a: None)
    async with serve_app(lmbp.asgi()) as base:
        key, a = await start_pairing(base, T)
        ok = lmbp.pairing.approve(T, "u1", a["user_code"])
        tok = await finish_pairing(base, key, a)

        async def revoke():
            assert lmbp.pairing.revoke_device(T, "u1", ok.device_id) is True

        with pytest.raises(AssertionError) as e:
            await connect(base, key, tok, e2ee=True, before_hello=revoke)
        assert "UNAUTHENTICATED" in str(e.value) or "revoked" in str(e.value)
        assert st.get_device(ok.device_id)["status"] == "revoked"


async def test_e2ee_replay_after_restart_stays_sealed(serve_app, tmp_path):
    """Review7 #6: an E2EE task replayed (idempotency) after a restart keeps its frames sealed."""
    import httpx
    from lmbp_server import seal_e2ee_request
    from simdevice import pair_and_connect
    st = SQLiteStore(str(tmp_path / "g.db"))
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=st, log=lambda *a: None)
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1", e2ee=True)
        dev = lmbp.pairing.list_devices(T, "u1")[0]
        sealed = seal_e2ee_request(dev, dev.jkt, {"model": "m1", "messages": [{"role": "user", "content": "secret"}]})
        hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1", "Idempotency-Key": "e2r-1"}
        async with httpx.AsyncClient(base_url=base, headers=hs, timeout=30) as h:
            r1 = await h.post("/v1/chat/completions", json={"model": "m1", "lmbp_e2ee": sealed.jwe})
            assert r1.status_code == 200 and r1.json().get("lmbp_e2ee"), r1.text
            lmbp.engine.tasks.clear()  # restart: only storage is left
            r2 = await h.post("/v1/chat/completions", json={"model": "m1", "lmbp_e2ee": sealed.jwe})
        assert r2.status_code == 200
        assert r2.json().get("lmbp_e2ee") == r1.json()["lmbp_e2ee"], r2.text
        await ws.close()
        task.cancel()


async def test_queued_disconnect_records_cancelled(serve_app):
    """Review7 #15: an HTTP caller that disconnects while its task is queued
    leaves an explicit CANCELLED terminal (never a QUEUED orphan); a replay
    with the same key reports exactly that."""
    import asyncio
    import httpx
    from simdevice import pair_and_connect
    st = MemoryStore()
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=st, log=lambda *a: None)
    async with serve_app(lmbp.asgi()) as base:
        ws, dtask, _ = await pair_and_connect(lmbp, base, T, "u1", max_concurrency=1, delay=2.0)
        model = lmbp.pairing.list_devices(T, "u1")[0].device_id + "/m1"
        body = {"model": model, "messages": [{"role": "user", "content": "hi"}]}
        hs = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}
        async with httpx.AsyncClient(base_url=base, headers=hs, timeout=30) as h:
            hog = asyncio.ensure_future(h.post("/v1/chat/completions", json=body))
            await asyncio.sleep(0.3)
            with pytest.raises(httpx.TimeoutException):
                await h.post("/v1/chat/completions", json=body, headers={"Idempotency-Key": "q-gone"}, timeout=0.5)
            rec = None
            for _ in range(100):
                rec = st.get_idempotency(T, "u1", "q-gone")
                if rec and st.get_task(rec["task_id"])["state"] != "QUEUED":
                    break
                await asyncio.sleep(0.05)
            assert rec is not None
            assert st.get_task(rec["task_id"])["state"] == "CANCELLED", st.get_task(rec["task_id"])
            await hog
            r = await h.post("/v1/chat/completions", json=body, headers={"Idempotency-Key": "q-gone"})
            assert "CANCELLED" in r.text and "DEVICE_BUSY" not in r.text, r.text
        await ws.close()
        dtask.cancel()
