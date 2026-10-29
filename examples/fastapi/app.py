"""FastAPI SaaS example: the lmbp-server SDK mounted next to your own routes.

What the business code does (and nothing else):
  1. pairing   GET /app/pair → link + QR; POST /app/pair/approve {user_code}; devices list/revoke
  2. LLM calls the official ``openai`` / ``anthropic`` clients with base_url pointed at this
               server, or the SDK's in-process client.
Everything protocol-related (/lmbp/v1/*, /.well-known/*, /v1/*) is served by LMBPMiddleware.

    TENANT_API_KEY=$(openssl rand -hex 24) uvicorn app:app --port 8000
"""
from __future__ import annotations

import json
import os

import anthropic
import openai
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from lmbp_server import LMBPMiddleware, LMBPServer, PairingError, SQLiteStore, TenantConfig

PORT = int(os.environ.get("PORT", "8000"))
TENANT = os.environ.get("TENANT_ID", "acme")
API_KEY = os.environ["TENANT_API_KEY"]  # >= 32 chars; server-side secret
PROFILE = (json.load(open(os.environ["TENANT_PROFILE_FILE"]))[TENANT] if os.environ.get("TENANT_PROFILE_FILE")
           else {"display_name": "Acme Chat (FastAPI)", "requested_scopes": ["lmbp.chat", "lmbp.tools", "lmbp.vision"]})

# The gateway's public origin (iss of every token): configuration, never the request's Host header.
ISSUER = os.environ.get("LMBP_ISSUER") or f"http://127.0.0.1:{PORT}"
lmbp = LMBPServer([TenantConfig(TENANT, API_KEY, PROFILE)], issuer=ISSUER,
                 store=SQLiteStore(os.environ["LMBP_DB"]) if os.environ.get("LMBP_DB") else None,
                 # finished tasks + idempotency records: 7 days unless set (negative disables)
                 retention=float(os.environ.get("LMBP_RETENTION_SECONDS") or 0))

app = FastAPI(title="Acme Chat")
app.add_middleware(LMBPMiddleware, server=lmbp)  # protocol endpoints + /v1/chat/completions, /v1/models, /v1/messages


def user(x_demo_user: str | None) -> str:  # your own login decides who the end user is
    return x_demo_user or "demo-user"


# ---- 1. pairing ----
@app.get("/app/pair")
def pair():
    info = lmbp.pairing.create(TENANT)
    return {"link": info.link, "qr_svg": info.qr_svg}


class Approve(BaseModel):
    user_code: str


@app.post("/app/pair/approve")
def approve(body: Approve, x_demo_user: str | None = Header(None)):
    try:
        return lmbp.pairing.approve(TENANT, user(x_demo_user), body.user_code)
    except PairingError as e:
        raise HTTPException(404 if e.code == "NOT_FOUND" else 400, str(e))


@app.get("/app/devices")
def devices(x_demo_user: str | None = Header(None)):
    return lmbp.pairing.list_devices(TENANT, user(x_demo_user))


@app.post("/app/devices/{device}/revoke")
def revoke(device: str, x_demo_user: str | None = Header(None)):
    return {"revoked": lmbp.pairing.revoke_device(TENANT, user(x_demo_user), device)}


# ---- 2. LLM calls with the official clients, unchanged ----
oa = openai.AsyncOpenAI(base_url=f"http://127.0.0.1:{PORT}/v1", api_key=API_KEY)
claude = anthropic.AsyncAnthropic(base_url=f"http://127.0.0.1:{PORT}", api_key=API_KEY)


class Ask(BaseModel):
    model: str
    prompt: str


@app.post("/app/ask")
async def ask(body: Ask, x_demo_user: str | None = Header(None)):
    r = await oa.chat.completions.create(model=body.model, messages=[{"role": "user", "content": body.prompt}],
                                         extra_headers={"X-End-User": user(x_demo_user)})
    return {"answer": r.choices[0].message.content}


@app.post("/app/ask/claude")
async def ask_claude(body: Ask, x_demo_user: str | None = Header(None)):
    m = await claude.messages.create(model=body.model, max_tokens=512, messages=[{"role": "user", "content": body.prompt}],
                                     extra_headers={"X-End-User": user(x_demo_user)})
    return {"answer": "".join(b.text for b in m.content if b.type == "text")}


@app.post("/app/ask/inprocess")  # ...or without an HTTP hop
async def ask_inprocess(body: Ask, x_demo_user: str | None = Header(None)):
    m = await lmbp.client(TENANT, user(x_demo_user)).messages.create(model=body.model, max_tokens=512,
                                                                     messages=[{"role": "user", "content": body.prompt}])
    return {"answer": "".join(b["text"] for b in m["content"] if b["type"] == "text")}
