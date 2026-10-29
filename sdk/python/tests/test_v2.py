"""LMBP 2.0 (spec §4.1, §7.1, §7.4, §11, §18.2): version identifiers, 1.x
refusal, hello/models.update schema validation without clamping, code-point
lengths and printable-ASCII headers. Each case failed on the 1.0 engine."""
import asyncio
import json

import httpx
import pytest
import websockets

from lmbp_server import LMBPServer, MemoryStore, PairingError, TenantConfig
from lmbp_server import protocol as L
from simdevice import connect, finish_pairing, proof, start_pairing
from conftest import issuer

KEY = "k" * 40
T = "acme"
H = {"Authorization": "Bearer " + KEY, "X-End-User": "u1"}


def server():
    return LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], store=MemoryStore(), log=lambda *a: None)


async def paired(lmbp, base):
    key, a = await start_pairing(base, T)
    lmbp.pairing.approve(T, "u1", a["user_code"])
    return key, await finish_pairing(base, key, a)


async def test_metadata_advertises_2_0_and_profiles(serve_app):
    lmbp = server()
    async with serve_app(lmbp.asgi()) as base, httpx.AsyncClient() as c:
        m = (await c.get(base + "/.well-known/lmbp")).json()
        assert m["protocol_versions"] == ["2.0"]
        assert "core" in m["profiles"] and len(m["profiles"]) == 7
        assert (L.VERSION, L.SUBPROTOCOL) == (2, "lmbp")


async def test_1x_peers_are_refused(serve_app):
    lmbp = server()
    async with serve_app(lmbp.asgi()) as base:
        key, tok = await paired(lmbp, base)
        with pytest.raises(websockets.exceptions.InvalidStatus) as e:
            await websockets.connect(base.replace("http", "ws", 1) + "/lmbp/v1/connect", subprotocols=["lmbp.2"],
                                     additional_headers={"Authorization": "Bearer " + tok["access_token"]})
        assert e.value.response.status_code == 400
        with pytest.raises(AssertionError) as e:
            await connect(base, key, tok, env_patch={"v": 1})
        assert "VERSION_UNSUPPORTED" in str(e.value)


@pytest.mark.parametrize("patch", [{"max_concurrency": 0}, {"max_concurrency": 17}, {"max_concurrency": None},
                                   {"max_concurrency": "2"}, {"model_names": {"m1": "😀" * 129}}])
async def test_hello_out_of_range_is_rejected_not_clamped(serve_app, patch):
    lmbp = server()
    async with serve_app(lmbp.asgi()) as base:
        key, tok = await paired(lmbp, base)
        with pytest.raises(AssertionError) as e:
            await connect(base, key, tok, hello_patch=patch)
        assert "BAD_REQUEST" in str(e.value)
        ws, task = await connect(base, key, tok, max_concurrency=16, hello_patch={"model_names": {"m1": "😀" * 128}})
        await ws.close()
        task.cancel()


async def test_models_update_rejected_whole(serve_app):
    lmbp = server()
    async with serve_app(lmbp.asgi()) as base, httpx.AsyncClient() as c:
        key, tok = await paired(lmbp, base)
        ws = await websockets.connect(base.replace("http", "ws", 1) + "/lmbp/v1/connect", subprotocols=[L.SUBPROTOCOL],
                                      additional_headers={"Authorization": "Bearer " + tok["access_token"]})
        await ws.send(json.dumps({"v": 2, "type": "hello", "id": "h1", "data": {
            "device_id": tok["device_id"], "client": "t", "models": ["m1"], "max_concurrency": 2,
            "proof": proof(key, tok["device_id"], L.PROOF_HELLO, tok["access_token"])}}))
        assert json.loads(await ws.recv())["data"]["max_concurrency"] == 2
        await ws.send(json.dumps({"v": 2, "type": "models.update", "id": "mu1", "data": {"models": ["m1", "zzz"], "max_concurrency": 99}}))
        e = json.loads(await asyncio.wait_for(ws.recv(), 5))
        assert e["type"] == "error" and e["data"]["code"] == "BAD_REQUEST", e
        ids = [m["id"] for m in (await c.get(base + "/v1/models", headers=H)).json()["data"]]
        assert not any(i.endswith("/zzz") for i in ids), ids
        devs = (await c.get(base + "/lmbp/v1/tenant/devices", headers=H)).json()["devices"]
        assert devs[0]["max_concurrency"] == 2, devs
        await ws.close()


async def test_lengths_in_code_points_and_ascii_headers(serve_app):
    lmbp = server()
    async with serve_app(lmbp.asgi()) as base, httpx.AsyncClient() as c:
        def auth(name):
            return c.post(base + "/lmbp/v1/device/authorize", data={"tenant": T, "public_key": L.b64(bytes([7]) * 32), "device_name": name})
        assert (await auth("😀" * 100)).status_code == 200
        assert (await auth("设" * 101)).status_code == 400
        assert (await c.get(base + "/v1/models", headers={**H, "X-End-User": "张三".encode()})).status_code == 400
        assert (await c.get(base + "/v1/models", headers={**H, "X-End-User": "a" * 129})).status_code == 400
        assert (await c.get(base + "/v1/models", headers={**H, "X-End-User": "a" * 128})).status_code == 200
        chat = {"model": "m1", "messages": [{"role": "user", "content": "hi"}]}
        assert (await c.post(base + "/v1/chat/completions", json=chat, headers={**H, "Idempotency-Key": "k" * 256})).status_code == 400
        assert (await c.post(base + "/v1/chat/completions", json=chat, headers={**H, "Idempotency-Key": "键".encode()})).status_code == 400
        with pytest.raises(PairingError):
            lmbp.pairing.approve(T, "张三", "BCDF-GHJK")
