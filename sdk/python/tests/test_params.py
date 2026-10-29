"""Third audit #2: request parameters are validated against the protocol
before anything is signed. spec/testvectors/params.json is shared by Go,
Node, Python and the conformance tool (Z8)."""
import json
from pathlib import Path

import httpx

from lmbp_server import LMBPServer, TenantConfig
from simdevice import pair_and_connect
from conftest import issuer

KEY = "k" * 40
T = "acme"
ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / "spec/testvectors/params.json").read_text())


def body(c, model):
    m = {**V["base"][c["endpoint"]], "model": model}
    m.update(c["set"])
    for k in c.get("remove", []):
        m.pop(k, None)
    return m


def err_param(b):
    e = (b or {}).get("error") or {}
    return (e.get("code"), e.get("param")) if e.get("code") else (e.get("lmbp_code"), e.get("lmbp_param"))


async def test_param_vectors(serve_app):
    assert len(V["cases"]) >= 80
    lmbp = LMBPServer(issuer=issuer(), tenants=[TenantConfig(T, KEY, {"display_name": "Acme"})], log=lambda *a: None)
    runs = {}
    failures = []
    async with serve_app(lmbp.asgi()) as base:
        ws, task, _ = await pair_and_connect(lmbp, base, T, "u1", on_run=lambda r: runs.__setitem__(r["task_id"], r))
        async with httpx.AsyncClient(base_url=base, headers={"Authorization": "Bearer " + KEY, "X-End-User": "u1"}, timeout=30) as h:
            for c in V["cases"]:
                name = f"{c['endpoint']}/{c['name']}"
                before = len(runs)
                path = "/v1/chat/completions" if c["endpoint"] == "chat" else "/v1/messages"
                r = await h.post(path, content=json.dumps(body(c, "m1")), headers={"Content-Type": "application/json"})
                if r.status_code != c["status"]:
                    failures.append(f"{name}: status {r.status_code}, want {c['status']}: {r.text[:160]}")
                    continue
                if c["status"] != 200:
                    try:
                        j = r.json()
                    except ValueError:
                        j = None
                    code, param = err_param(j)
                    if (code, param) != (c["code"], c["param"]):
                        failures.append(f"{name}: code {code} param {param}, want {c['code']} {c['param']}: {r.text[:160]}")
                    if len(runs) != before:
                        failures.append(f"{name}: rejected request reached the device")
                    continue
                run = runs.get(r.headers.get("x-task-id"))
                if run is None:
                    failures.append(f"{name}: no task.run")
                    continue
                for k, want in (c.get("run") or {}).items():
                    if run.get(k, "<absent>") != want:
                        failures.append(f"{name}: task.run {k} = {json.dumps(run.get(k))}, want {json.dumps(want)}")
                for k in c.get("run_absent", []):
                    if k in run:
                        failures.append(f"{name}: task.run has {k}")
        await ws.close()
        task.cancel()
    assert not failures, f"{len(failures)} of {len(V['cases'])} vectors failed:\n" + "\n".join(failures)


def test_bundled_schemas_match_spec():
    from importlib import resources
    for n in ("defs.json", "task.run.payload.json"):
        bundled = (resources.files("lmbp_server") / "schemas" / n).read_text("utf-8")
        assert bundled == (ROOT / "spec/schemas" / n).read_text("utf-8"), f"{n} is stale: copy spec/schemas/{n} to src/lmbp_server/schemas/"


def test_schema_validator_fails_closed():
    import pytest
    from lmbp_server.jsonschema import SchemaSet
    with pytest.raises(ValueError, match="unsupported keyword format"):
        SchemaSet([{"$id": "https://x/a.json", "type": "string", "format": "email"}])


def test_task_run_schema_backstop():
    import pytest
    from lmbp_server.params import ParamError, validate_task_run
    base = {"task_id": "task_1", "iat": 1, "exp": 2, "nonce": "n" * 20, "device_id": "dev_1", "model": "m", "messages": [{"role": "user", "content": "hi"}]}
    validate_task_run(base)
    for param, mut in {"temperature": {"temperature": 3}, "max_tokens": {"max_tokens": -1}, "top_p": {"top_p": 1.5},
                       "stop": {"stop": ["a", "b", "c", "d", "e"]}, "messages": {"messages": [{"role": "robot"}]}, "nonce": {"nonce": "short"}}.items():
        with pytest.raises(ParamError) as ei:
            validate_task_run({**base, **mut})
        assert ei.value.param == param, (param, str(ei.value))
    with pytest.raises(ParamError):
        validate_task_run({k: v for k, v in base.items() if k != "messages"})
