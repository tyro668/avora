import httpx
import pytest
from fastapi import FastAPI

from lmbp_server import LMBPAPIError, LMBPMiddleware, LMBPServer, PairingError, SQLiteStore, TenantConfig, anthropic
from simdevice import pair_and_connect, start_pairing
from conftest import issuer

KEY = "k" * 40
T = "acme"


def new(**kw):
    kw.setdefault("issuer", issuer())
    return LMBPServer(tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], log=lambda *a: None, **kw)


def test_anthropic_translation():
    o = anthropic.to_openai({"model": "m", "max_tokens": 10, "system": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}],
                             "tools": [{"name": "f", "input_schema": {"type": "object"}}], "tool_choice": {"type": "any"},
                             "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"},
                                                                       {"type": "image", "source": {"type": "url", "url": "https://x/y.png"}}]},
                                          {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "f", "input": {"a": 1}}]},
                                          {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "r"}]}]})
    assert o["messages"][0] == {"role": "system", "content": "a\n\nb"}
    assert o["messages"][1]["content"][1] == {"type": "image_url", "image_url": {"url": "https://x/y.png"}}
    assert o["messages"][2] == {"role": "assistant", "content": None, "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "f", "arguments": '{"a":1}'}}]}
    assert o["messages"][3] == {"role": "tool", "tool_call_id": "t1", "content": "r"}
    assert o["tool_choice"] == "required"
    with pytest.raises(ValueError, match="max_tokens"):
        anthropic.to_openai({"model": "m", "messages": [{"role": "user", "content": "x"}]})
    assert anthropic.error_type(429) == "rate_limit_error"


async def test_pairing_api(serve_app):
    lmbp = new(issuer="https://gw.example.com")
    async with serve_app(lmbp.asgi()) as base:
        info = lmbp.pairing.create(T)
        assert info.link == "lmbp://pair?v=2&gateway=https%3A%2F%2Fgw.example.com&tenant=acme"
        assert info.qr_svg.startswith("<svg")
        _, a = await start_pairing(base, T, "my-laptop")
        pend = lmbp.pairing.lookup(T, "u1", a["user_code"].lower().replace("-", ""))
        assert pend.device_name == "my-laptop" and pend.status == "pending"
        with pytest.raises(PairingError):
            lmbp.pairing.approve(T, "u1", "BBBB-BBBB")
        ok = lmbp.pairing.approve(T, "u1", a["user_code"], jkt=pend.jkt)
        assert ok.status == "approved"
        with pytest.raises(PairingError, match="already used"):
            lmbp.pairing.approve(T, "u1", a["user_code"])
        ds = lmbp.pairing.list_devices(T, "u1")
        assert [d.device_id for d in ds] == [ok.device_id]
        assert lmbp.pairing.list_devices(T, "other") == []
        assert lmbp.pairing.revoke_device(T, "u2", ok.device_id) is False
        assert lmbp.pairing.revoke_device(T, "u1", ok.device_id) is True
        assert lmbp.pairing.list_devices(T, "u1")[0].status == "revoked"
        _, a2 = await start_pairing(base, T)
        assert lmbp.pairing.deny(T, "u1", a2["user_code"]).status == "denied"
        assert lmbp.keys.jwks()["keys"][0]["kid"] == lmbp.keys.kid()


async def test_in_process_client(serve_app):
    lmbp = new()
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1")
        c = lmbp.client(T, "u1")
        assert (await c.models())[0]["id"] == f"{dev}/m1"
        r = await c.chat.completions.create(model="m1", messages=[{"role": "user", "content": "hello"}])
        assert r["choices"][0]["message"]["content"] == "echo: hello"
        txt = "".join([(ch["choices"][0]["delta"].get("content") or "") async for ch in c.chat.completions.stream(model="m1", messages=[{"role": "user", "content": "s"}]) if ch["choices"]])
        assert txt == "echo: s"
        m = await c.messages.create(model="m1", max_tokens=16, system="sys", messages=[{"role": "user", "content": "hi"}])
        assert m["content"][0]["text"] == "echo: hi" and m["usage"]["output_tokens"] == 4
        tools = [{"name": "get_weather", "input_schema": {"type": "object"}}]
        tu = await c.messages.create(model="m1", max_tokens=16, tools=tools, messages=[{"role": "user", "content": "w?"}])
        assert tu["stop_reason"] == "tool_use" and tu["content"][0] == {"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "Paris"}}
        names, out = [], ""
        async for e in c.messages.stream(model="m1", max_tokens=16, tools=tools, messages=[
                {"role": "user", "content": "w?"}, {"role": "assistant", "content": tu["content"]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "sunny"}]}]):
            names.append(e["type"])
            if e["type"] == "content_block_delta":
                out += e["delta"]["text"]
        assert out == "echo: tool said sunny"
        assert names[0] == "message_start" and names[-2:] == ["message_delta", "message_stop"]
        with pytest.raises(LMBPAPIError) as ei:
            await c.messages.create(model="nope", max_tokens=1, messages=[{"role": "user", "content": "x"}])
        assert ei.value.status == 404 and ei.value.code == "MODEL_NOT_FOUND"
        await ws.close()
        task.cancel()


async def test_fastapi_middleware(serve_app):
    lmbp = new()
    app = FastAPI()

    @app.get("/app/hello")
    async def hello():
        return {"hi": True}
    app.add_middleware(LMBPMiddleware, server=lmbp)
    async with serve_app(app) as base:
        async with httpx.AsyncClient(base_url=base) as h:
            assert (await h.get("/app/hello")).json() == {"hi": True}
            assert (await h.get("/healthz")).json() == {"status": "ok"}
            r = await h.post("/v1/messages", headers={"x-api-key": "bad"}, json={})
            assert r.status_code == 401 and r.json()["error"]["type"] == "authentication_error"
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1")
        async with httpx.AsyncClient(base_url=base, headers={"Authorization": "Bearer " + KEY, "X-End-User": "u1"}) as h:
            r = await h.post("/v1/chat/completions", json={"model": "m1", "messages": [{"role": "user", "content": "fa"}]})
            assert r.json()["choices"][0]["message"]["content"] == "echo: fa"
        await ws.close()
        task.cancel()


async def test_sqlite_persistence(serve_app, tmp_path):
    db = str(tmp_path / "gw.db")
    lmbp = new(store=SQLiteStore(db))
    kid = lmbp.keys.kid()
    async with serve_app(lmbp.asgi()) as base:
        ws, task, dev = await pair_and_connect(lmbp, base, T, "u1")
        r = await lmbp.client(T, "u1").chat.completions.create(model="m1", messages=[{"role": "user", "content": "persist me"}])
        await ws.close()
        task.cancel()
    lmbp.store.close()
    lmbp = new(store=SQLiteStore(db))
    assert lmbp.keys.kid() == kid
    assert [d.device_id for d in lmbp.pairing.list_devices(T, "u1")] == [dev]
    async with serve_app(lmbp.asgi()) as base:
        async with httpx.AsyncClient(base_url=base, headers={"Authorization": "Bearer " + KEY, "X-End-User": "u1"}) as h:
            ev = await h.get(f"/lmbp/v1/tenant/tasks/{r['id'].removeprefix('chatcmpl-')}/events")
            assert ev.status_code == 200 and "persist me" in ev.text
