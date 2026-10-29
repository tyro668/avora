"""lmbp-server: let your SaaS use models that run on your users' own machines.

Business code does two things only:

1. **pairing**: show a pair link / QR code, then approve the user code the
   user reads off the desktop app (``server.pairing``);
2. **LLM calls**: standard OpenAI (``/v1/chat/completions``, ``/v1/models``)
   or Anthropic (``/v1/messages``) requests, over HTTP with the official
   client libraries or with ``server.client(tenant, user)``.

The WebSocket session, JOSE, resume, flow control and E2EE pass-through stay
inside the SDK.
"""
from __future__ import annotations

import datetime
import secrets
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote

from . import anthropic
from . import protocol as _L
from .asgi import LMBPASGI, LMBPMiddleware
from .client import IncompleteStreamError, InProcessClient, LMBPAPIError, LMBPStream
from .types import ChatRequest, MessagesRequest
from .e2ee import E2EEReader, E2EESealed, decode_e2ee_delta, seal_e2ee_request
from .engine import Gateway
from .store import MemoryStore, SQLiteStore, Store, StoreConflict, StoreNotFound

__all__ = ["LMBPStream", "IncompleteStreamError", "E2EESealed", "E2EEReader", "seal_e2ee_request", "decode_e2ee_delta", "LMBPServer", "TenantConfig", "PairingInfo", "PendingPairing", "ApproveResult", "DeviceInfo", "PairingError",
           "Store", "StoreConflict", "StoreNotFound", "MemoryStore", "SQLiteStore", "InProcessClient", "LMBPAPIError", "LMBPMiddleware", "anthropic", "Gateway", "ChatRequest", "MessagesRequest"]
__version__ = "0.1.0"


@dataclass
class TenantConfig:
    id: str
    api_key: str  # >= 32 chars; server-side only
    profile: dict = field(default_factory=dict)  # display_name, logo_uri, homepage_uri, policy_uri, tos_uri, pairing_uri, requested_models, requested_scopes


@dataclass
class PairingInfo:
    link: str
    qr_svg: str


@dataclass
class PendingPairing:
    user_code: str
    device_name: str
    jkt: str
    status: str
    expires_at: datetime.datetime


@dataclass
class ApproveResult:
    status: str  # approved | denied
    device_id: str
    device_name: str
    jkt: str


@dataclass
class DeviceInfo:
    device_id: str
    name: str
    status: str
    created_at: datetime.datetime
    jkt: str
    online: bool
    models: list[str]
    model_capabilities: dict[str, list[str]]
    public_key: bytes = b""  # Ed25519 identity key (check against your pinned jkt)
    e2ee_key: str = ""       # device-signed X25519 key statement, for seal_e2ee_request
    model_names: dict = field(default_factory=dict)  # optional display name per model id


class PairingError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code  # BAD_REQUEST | NOT_FOUND | FORBIDDEN | RATE_LIMITED


class _Keys:
    def __init__(self, g: Gateway):
        self._g = g

    def kid(self) -> str:
        """Key id (RFC 7638 thumbprint) of the gateway signing key."""
        return self._g.kid

    def public_jwk(self) -> dict:
        return _L.public_jwk(self._g.pub)

    def jwks(self) -> dict:
        return {"keys": [_L.public_jwk(self._g.pub)]}


class _Pairing:
    def __init__(self, s: "LMBPServer"):
        self._s = s

    def link(self, tenant: str) -> str:
        """§19.4 deep link for the desktop app, on the configured issuer."""
        iss = self._s.engine.cfg["issuer"]
        return f"lmbp://pair?v={_L.PAIR_LINK_VERSION}&gateway={quote(iss, safe='')}&tenant={quote(tenant, safe='')}"

    def create(self, tenant: str) -> PairingInfo:
        """Pair link plus its QR code as SVG (needs the ``segno`` package)."""
        link = self.link(tenant)
        import io

        import segno
        buf = io.BytesIO()
        segno.make(link, error="m").save(buf, kind="svg", scale=4, border=2, xmldecl=False)
        return PairingInfo(link=link, qr_svg=buf.getvalue().decode())

    def lookup(self, tenant: str, end_user: str, user_code: str) -> Optional[PendingPairing]:
        """Pending pairing for the user code end_user typed (shown on their desktop), to show the device
        before approving. ``device_name`` is untrusted text chosen by the device: render it as plain text.
        A code that is not pending returns None and counts as a failed attempt of end_user
        (PairingError RATE_LIMITED after 10 a minute)."""
        self._s._check_caller(tenant, end_user)
        d, e = self._s.engine.pair_lookup(tenant, end_user, user_code)
        if e and e[0] == 429:
            raise PairingError(e[2], "RATE_LIMITED")
        if d is None:
            return None
        return PendingPairing(d["user_code"], d["name"], _L.thumbprint(d["pub"]), d["status"],
                              datetime.datetime.fromtimestamp(d["expires"], datetime.timezone.utc))

    def approve(self, tenant: str, end_user: str, user_code: str, jkt: Optional[str] = None) -> ApproveResult:
        """Approve the code for end_user; the desktop app finishes pairing on its next poll."""
        return self._s._decide(tenant, end_user, user_code, False, jkt)

    def deny(self, tenant: str, end_user: str, user_code: str) -> ApproveResult:
        return self._s._decide(tenant, end_user, user_code, True, None)

    def list_devices(self, tenant: str, end_user: str) -> list[DeviceInfo]:
        out = []
        for d in self._s.store.list_devices(tenant, end_user):
            s = self._s.engine.online(d["id"])
            out.append(DeviceInfo(d["id"], d["name"], d["status"], d["created"], _L.thumbprint(d["pub"]), s is not None,
                                  list(s.models) if s else [], dict(s.model_caps) if s else {},
                                  bytes(d["pub"]), d.get("e2ee_key") or "",
                                  dict(s.model_names) if s else {}))
        return out

    def revoke_device(self, tenant: str, end_user: str, device_id: str) -> bool:
        """Revoke a device: its session ends at once and refresh is refused."""
        return self._s.engine.revoke_device(tenant, end_user, device_id)


class LMBPServer:
    """The gateway. Mount ``server.asgi()`` (or ``LMBPMiddleware``) in your ASGI app."""

    def __init__(self, tenants: list[TenantConfig | dict], issuer: str, store: Optional[Store] = None,
                 signing_seed: Optional[bytes] = None, max_concurrency: int = 16, chat_ui_dir: str = "",
                 log: Optional[Callable[..., None]] = None, retention: float = 0, **tuning: Any):
        """``issuer`` (required): the gateway's public origin, e.g. ``https://gw.example.com``;
        never derived from the Host header (§18.1).
        ``retention``: seconds finished tasks and their Idempotency-Key records
        are kept (default 7 days; negative disables purging). Spec §14.4 (errata E6)."""
        self.store: Store = store if store is not None else MemoryStore()
        self.engine = Gateway(issuer=issuer, seed=signing_seed, max_conc=max_concurrency, web_dir=chat_ui_dir,
                              log=log, store=self.store, retention=retention, **tuning)
        for t in tenants:
            t = t if isinstance(t, TenantConfig) else TenantConfig(**t)
            self.engine.register_tenant(t.id, t.api_key, t.profile)
        self.keys = _Keys(self.engine)
        self.pairing = _Pairing(self)

    def close(self) -> None:
        """Stops the retention loop (the store stays open; close it yourself)."""
        self.engine.stop_retention()

    def asgi(self, app: Any = None) -> LMBPASGI:
        """ASGI app; with ``app``, unknown paths fall through to it."""
        return LMBPASGI(self.engine, app)

    def client(self, tenant: str, end_user: str) -> InProcessClient:
        """Typed client calling the gateway in-process as end_user of tenant."""
        return InProcessClient(self, tenant, end_user)

    def _check_caller(self, tenant, end_user):
        if tenant not in self.engine.tenants:
            raise PairingError("unknown tenant", "BAD_REQUEST")
        if not _L.valid_header(end_user, 128):
            raise PairingError("end_user must be 1-128 printable ASCII characters (it travels as X-End-User)", "BAD_REQUEST")

    def _decide(self, tenant, end_user, user_code, deny, jkt):
        self._check_caller(tenant, end_user)
        d, e = self.engine.pair_decide(tenant, end_user, user_code, deny, jkt)
        if e:
            raise PairingError(e[2], {429: "RATE_LIMITED", 404: "NOT_FOUND", 403: "FORBIDDEN", 409: "FORBIDDEN"}.get(e[0], "BAD_REQUEST"))
        return ApproveResult(d["status"], d["device_id"], d["name"], _L.thumbprint(d["pub"]))

    def run(self, host: str = "127.0.0.1", port: int = 8080, app: Any = None) -> None:
        """Standalone server (needs uvicorn)."""
        import uvicorn
        uvicorn.run(self.asgi(app), host=host, port=port, log_level="warning", ws_max_size=_L.MAX_FRAME_BYTES, ws_ping_interval=20)

    @staticmethod
    def generate_signing_seed() -> bytes:
        return secrets.token_bytes(32)

    @staticmethod
    def generate_tenant_key() -> str:
        return "lmbp_" + secrets.token_urlsafe(24)
