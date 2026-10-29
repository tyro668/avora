"""Regression tests for the 2026-10-29 protocol review (P1/P2 hardening):
pairing abuse limits, untrusted device names, pending pairings never listed,
per-user failure counting, issuer configuration, revocation of an in-flight
task, the tool_calls index range and the per-task output budget."""
import asyncio
import json
import secrets
import time

import httpx
import pytest

from lmbp_server import LMBPServer, PairingError, TenantConfig, seal_e2ee_request
from lmbp_server import e2ee as E
from lmbp_server import protocol as L
from simdevice import pair_and_connect, proof, start_pairing
from conftest import issuer

KEY = "k" * 40
T = "acme"
HS = {"Authorization": "Bearer " + KEY, "Content-Type": "application/json"}


def new(**kw):
    kw.setdefault("issuer", issuer())
    return LMBPServer(tenants=[TenantConfig(T, KEY)], log=lambda *a: None, **kw)


async def authorize(base, local_address=None, **fields):
    transport = httpx.AsyncHTTPTransport(local_address=local_address) if local_address else None
    async with httpx.AsyncClient(transport=transport) as c:
        r = await c.post(base + "/lmbp/v1/device/authorize", data={"tenant": T, "public_key": L.b64(secrets.token_bytes(32)), **fields})
    return r.status_code, r.json()


async def tenant(base, user, method, path, body=None):
    async with httpx.AsyncClient(base_url=base, headers={**HS, "X-End-User": user}, timeout=30) as h:
        r = await h.request(method, path, json=body)
    return r.status_code, r.json()


async def poll(base, key, a):
    async with httpx.AsyncClient() as c:
        r = await c.post(base + "/lmbp/v1/token", data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": a["device_code"],
                                                   "proof": proof(key, "", L.PROOF_TOKEN, a["device_code"])})
    return r.json().get("error")


# P1-3: pending pairings are never listed; device names are sanitized.
async def test_pending_pairings_not_listed_and_names_sanitized(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        await start_pairing(base, T, "alice-laptop")
        for user in ("alice", "bob"):
            st, r = await tenant(base, user, "GET", "/lmbp/v1/tenant/devices")
            assert st == 200 and "pending_pairings" not in r and "alice-laptop" not in json.dumps(r), f"{user} sees pending pairings: {r}"
        for name in ("Office PC\u202egpj.exe", "a\nb", "x\u200by", "\u0085"):
            st, _ = await authorize(base, device_name=name)
            assert st == 400, f"device_name {name!r} accepted"
        assert (await authorize(base, device_name="张三的 MacBook 😀"))[0] == 200


# P2-1: tenant must exist; authorize is rate limited per client and per tenant.
async def test_authorize_unknown_tenant_is_invalid_client(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        st, r = await authorize(base, tenant="no-such-tenant")
        assert (st, r.get("error")) == (400, "invalid_client")


async def test_authorize_rate_limited_per_client(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        codes = {}
        for _ in range(70):
            st, _ = await authorize(base)
            codes[st] = codes.get(st, 0) + 1
        assert codes.get(200, 0) <= 60 and codes.get(429), f"70 authorizations from one address: {codes}"


async def test_authorize_pending_cap_per_tenant(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        codes = {}
        for i in range(1100):
            st, _ = await authorize(base, local_address=f"127.0.{1 + i // 50}.{1 + i % 50}")
            codes[st] = codes.get(st, 0) + 1
        assert codes.get(200, 0) <= 1000 and codes.get(429), f"1100 pending pairings: {codes}"


# P2-2: a device that ignores slow_down loses its device_code.
async def test_device_code_polling_capped(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        key, a = await start_pairing(base, T)
        errs = []
        for _ in range(30):
            errs.append(await poll(base, key, a))
            if errs[-1] == "expired_token":
                break
        assert errs[-1] == "expired_token" and errs.count("slow_down") == 10, errs
        before = len(lmbp.engine.jtis)
        for _ in range(20):
            await poll(base, key, a)
        assert len(lmbp.engine.jtis) == before, "polls of an expired code grew the jti store"


# P2-3/P2-4: approval is single use; failures count per end user.
async def test_approval_single_use_concurrent(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        _, a = await start_pairing(base, T)
        rs = await asyncio.gather(*(tenant(base, f"u{i}", "POST", "/lmbp/v1/tenant/devices/approvals", {"user_code": a["user_code"]}) for i in range(8)))
        assert [st for st, _ in rs].count(200) == 1, [st for st, _ in rs]


async def test_failures_counted_per_end_user(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        seq = [(await tenant(base, "mallory", "POST", "/lmbp/v1/tenant/devices/approvals", {"user_code": "BBBB-BBBB"}))[0] for _ in range(11)]
        assert seq == [404] * 10 + [429], seq
        assert (await tenant(base, "alice", "POST", "/lmbp/v1/tenant/devices/approvals", {"user_code": "BBBB-BBBB"}))[0] == 404, "another user was locked out"
        with pytest.raises(PairingError) as e:
            for _ in range(11):
                lmbp.pairing.lookup(T, "eve", "CCCC-CCCC")
        assert e.value.code == "RATE_LIMITED"


# P2-5: jti store with heap eviction (no O(n) scan per call).
def test_jti_store_fast_and_evicts():
    lmbp = LMBPServer(tenants=[TenantConfig(T, KEY)], issuer="http://127.0.0.1:1", log=lambda *a: None)
    g = lmbp.engine
    until = time.time() + 60
    for i in range(200_000):
        g.use_jti(f"j{i}", until)
    t0 = time.perf_counter()
    for i in range(1000):
        g.use_jti(f"k{i}", until)
    per = (time.perf_counter() - t0) / 1000 * 1000  # ms per call
    assert per < 0.2, f"use_jti took {per:.3f} ms per call at 200k entries"
    assert g.use_jti("j1", until) is False


# P2-6: the issuer is configuration, never derived from Host.
async def test_issuer_required_never_from_host(serve_app):
    with pytest.raises((TypeError, ValueError)):
        LMBPServer(tenants=[TenantConfig(T, KEY)], log=lambda *a: None)
    with pytest.raises(ValueError):
        LMBPServer(tenants=[TenantConfig(T, KEY)], issuer="", log=lambda *a: None)
    lmbp = new(issuer="https://gw.example.com")
    async with serve_app(lmbp.asgi(), port=None) as base:
        async with httpx.AsyncClient() as c:
            r = await c.get(base + "/.well-known/lmbp", headers={"Host": "evil.example"})
        assert r.json()["issuer"] == "https://gw.example.com"


# P2-8: revoking a device while its task runs is OUTCOME_UNKNOWN (502), not 401.
async def test_revoke_inflight_is_outcome_unknown(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        seen = asyncio.Event()
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1", manual=lambda run, w, ls: seen.set())
        try:
            call = asyncio.ensure_future(tenant(base, "u1", "POST", "/v1/chat/completions", {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}))
            await asyncio.wait_for(seen.wait(), 5)
            assert (await tenant(base, "u1", "POST", f"/lmbp/v1/tenant/devices/{dev}/revoke"))[0] == 200
            st, r = await call
            assert (st, r["error"]["code"]) == (502, "OUTCOME_UNKNOWN"), r
        finally:
            await ws.close()
            task.cancel()


async def manual_task(lmbp, base, drive, e2ee=False):
    cancelled = asyncio.get_running_loop().create_future()

    def on_run(run, w, listeners):
        def watch(e):
            if e["type"] == "task.cancel" and e.get("task_id") == run["task_id"] and not cancelled.done():
                cancelled.set_result(e["data"]["reason"])
        listeners.append(watch)
        asyncio.ensure_future(drive(run, w))
    ws, task, dev = await pair_and_connect(lmbp, base, T, "u1", e2ee=e2ee, manual=on_run)
    return ws, task, cancelled


def frame(run, seq, typ, data):
    return json.dumps({"v": L.VERSION, "type": typ, "task_id": run["task_id"], "seq": seq, "data": data})


# P1-1: a tool_calls index outside 0..127 fails the task.
async def test_tool_call_index_out_of_range(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        async def drive(run, w):
            await w.send(frame(run, 1, "task.delta", {"tool_calls": [{"index": 128, "id": "c", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}))
        ws, task, cancelled = await manual_task(lmbp, base, drive)
        try:
            st, r = await tenant(base, "u1", "POST", "/v1/chat/completions", {"model": "m1", "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}],
                                                                              "messages": [{"role": "user", "content": "x"}]})
            assert await asyncio.wait_for(cancelled, 3) == "protocol_error"
            assert (st, r["error"]["code"]) == (502, "INTERNAL"), r
        finally:
            await ws.close()
            task.cancel()


# P1-2: the per-task output budget (64 MiB) applies to cleartext and sealed deltas.
@pytest.mark.parametrize("e2ee", [False, True])
async def test_task_output_budget(serve_app, e2ee):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        chunk = "a" * (150 << 10)
        key = secrets.token_bytes(32)

        async def drive(run, w):
            for seq in range(1, L.MAX_TASK_OUTPUT_BYTES // len(chunk) + 9):
                data = {"e2ee": E.seal_chunk(key, "rid_x", "task.delta", seq, json.dumps({"text": chunk}).encode())} if e2ee else {"text": chunk}
                try:
                    await w.send(frame(run, seq, "task.delta", data))
                except Exception:  # noqa: BLE001 - connection closed
                    return
        ws, task, cancelled = await manual_task(lmbp, base, drive, e2ee=e2ee)
        try:
            body = {"model": "m1", "messages": [{"role": "user", "content": "flood"}]}
            if e2ee:
                dev = lmbp.pairing.list_devices(T, "u1")[0]
                body = {"model": "m1", "lmbp_e2ee": seal_e2ee_request(dev, dev.jkt, body).jwe}
            st, r = await tenant(base, "u1", "POST", "/v1/chat/completions", body)
            assert await asyncio.wait_for(cancelled, 10) == "protocol_error"
            assert (st, r["error"]["code"]) == (502, "INTERNAL"), str(r)[:300]
        finally:
            await ws.close()
            task.cancel()
