"""Framework-neutral HTTP/WebSocket primitives used by the engine.

The engine was written against a small aiohttp-like surface (Request,
Response, StreamResponse, WebSocketResponse). This module implements that
surface over ASGI (see asgi.py) so the SDK runs under any ASGI server and
mounts into FastAPI / Starlette, with no aiohttp dependency.
"""
from __future__ import annotations

import asyncio
import enum
import json
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional
from urllib.parse import parse_qsl

Send = Callable[[dict], Awaitable[None]]
Receive = Callable[[], Awaitable[dict]]


class CIMultiDict(dict):
    """Case-insensitive header map (single value per name)."""

    def __init__(self, items: Iterable[tuple[str, str]] | Mapping[str, str] = ()):
        super().__init__()
        for k, v in (items.items() if isinstance(items, Mapping) else items):
            self[k] = v

    def __setitem__(self, k: str, v: str) -> None:
        super().__setitem__(k.lower(), v)

    def __getitem__(self, k: str) -> str:
        return super().__getitem__(k.lower())

    def __contains__(self, k: object) -> bool:
        return isinstance(k, str) and super().__contains__(k.lower())

    def get(self, k: str, default: Any = None) -> Any:  # type: ignore[override]
        return super().get(k.lower(), default)

    def pop(self, k: str, *default: Any) -> Any:  # type: ignore[override]
        return super().pop(k.lower(), *default)


class Request:
    """One HTTP request or WebSocket handshake."""

    def __init__(self, scope: dict, receive: Receive, send: Send, body: Optional[bytes] = None):
        self.scope, self._receive, self._send = scope, receive, send
        self.method: str = scope.get("method", "GET") if scope["type"] == "http" else "GET"
        self.path: str = scope.get("path", "/")
        self.headers = CIMultiDict((k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", []))
        self.query = dict(parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True))
        self.match_info: dict[str, str] = {}
        self.secure = scope.get("scheme") in ("https", "wss")
        self.host = self.headers.get("Host") or ("%s:%d" % tuple(scope["server"]) if scope.get("server") else "localhost")
        self.peer = (scope.get("client") or ("", 0))[0] or ""  # TCP peer; forwarding headers are not trusted
        self.is_websocket = scope["type"] == "websocket"
        self.anthropic = False
        self._body = body
        self.started = False  # response start sent

    async def read(self, limit: int) -> Optional[bytes]:
        """Read the whole body; None if it exceeds limit."""
        if self._body is not None:
            return None if len(self._body) > limit else self._body
        data = bytearray()
        while True:
            m = await self._receive()
            if m["type"] == "http.disconnect":
                raise asyncio.CancelledError("client disconnected")
            data += m.get("body", b"")
            if len(data) > limit:
                self._body = b""  # drained enough; caller will 413
                return None
            if not m.get("more_body"):
                break
        self._body = bytes(data)
        return self._body


class Response:
    def __init__(self, status: int = 200, body: bytes = b"", content_type: Optional[str] = None,
                 headers: Optional[Mapping[str, str]] = None):
        self.status, self.body = status, body
        self.headers = CIMultiDict(headers or {})
        if content_type and "Content-Type" not in self.headers:
            self.headers["Content-Type"] = content_type
        self.headers.setdefault("content-type", "application/octet-stream")

    async def send_to(self, req: Request) -> None:
        hs = [(k.encode("latin-1"), str(v).encode("latin-1")) for k, v in self.headers.items()]
        hs.append((b"content-length", str(len(self.body)).encode()))
        await req._send({"type": "http.response.start", "status": self.status, "headers": hs})
        await req._send({"type": "http.response.body", "body": self.body})
        req.started = True

    def json(self) -> Any:
        return json.loads(self.body)


class StreamResponse:
    def __init__(self, status: int = 200, headers: Optional[Mapping[str, str]] = None):
        self.status = status
        self.headers = CIMultiDict(headers or {})
        self._req: Optional[Request] = None
        self.prepared = False

    async def prepare(self, req: Request) -> None:
        self._req = req
        hs = [(k.encode("latin-1"), str(v).encode("latin-1")) for k, v in self.headers.items()]
        await req._send({"type": "http.response.start", "status": self.status, "headers": hs})
        req.started = True
        self.prepared = True

    async def write(self, data: bytes) -> None:
        assert self._req is not None
        try:
            await self._req._send({"type": "http.response.body", "body": data, "more_body": True})
        except Exception as e:  # server-specific "client gone" errors
            raise ConnectionError(str(e)) from e

    async def write_eof(self) -> None:
        if self._req is not None:
            try:
                await self._req._send({"type": "http.response.body", "body": b"", "more_body": False})
            except Exception:
                pass


class WSMsgType(enum.IntEnum):
    TEXT = 1
    BINARY = 2
    PING = 9
    PONG = 10
    CLOSE = 8
    CLOSING = 256
    CLOSED = 257
    ERROR = 258


class WSMessage:
    __slots__ = ("type", "data")

    def __init__(self, type: WSMsgType, data: Any = None):
        self.type, self.data = type, data


class WebSocketResponse:
    """Server side of an ASGI WebSocket (subset of aiohttp's API)."""

    def __init__(self, protocols: Iterable[str] = (), max_msg_size: int = 4 << 20, **_: Any):
        self.protocols, self.max_msg_size = tuple(protocols), max_msg_size
        self._req: Optional[Request] = None
        self.closed = False
        self._send_lock = asyncio.Lock()

    async def prepare(self, req: Request) -> None:
        self._req = req
        m = await req._receive()
        if m["type"] != "websocket.connect":
            self.closed = True
            raise ConnectionError("websocket handshake aborted")
        offered = [p.strip() for p in req.headers.get("Sec-WebSocket-Protocol", "").split(",")]
        sub = next((p for p in self.protocols if p in offered), None)
        await req._send({"type": "websocket.accept", "subprotocol": sub})
        req.started = True

    async def receive(self, timeout: Optional[float] = None) -> WSMessage:
        assert self._req is not None
        if self.closed:
            return WSMessage(WSMsgType.CLOSED)
        m = await asyncio.wait_for(self._req._receive(), timeout)
        if m["type"] == "websocket.disconnect":
            self.closed = True
            return WSMessage(WSMsgType.CLOSE, m.get("code"))
        if m.get("text") is not None:
            # the limit is in UTF-8 bytes, as on the wire (audit finding 6)
            if len(m["text"].encode()) > self.max_msg_size:
                await self.close(code=1009, message=b"message too big")
                return WSMessage(WSMsgType.ERROR)
            return WSMessage(WSMsgType.TEXT, m["text"])
        b = m.get("bytes") or b""
        if len(b) > self.max_msg_size:
            await self.close(code=1009, message=b"message too big")
            return WSMessage(WSMsgType.ERROR)
        return WSMessage(WSMsgType.BINARY, b)

    async def send_str(self, s: str) -> None:
        if self.closed or self._req is None:
            raise ConnectionError("websocket closed")
        async with self._send_lock:
            try:
                await self._req._send({"type": "websocket.send", "text": s})
            except Exception as e:
                self.closed = True
                raise ConnectionError(str(e)) from e

    async def ping(self) -> None:
        """ASGI has no ping message; servers ping on their own (uvicorn ws_ping_interval)."""

    async def close(self, code: int = 1000, message: bytes = b"") -> None:
        if self.closed or self._req is None:
            self.closed = True
            return
        self.closed = True
        try:
            await self._req._send({"type": "websocket.close", "code": code, "reason": message.decode(errors="replace")})
        except Exception:
            pass


class web:  # noqa: N801 - mimics the aiohttp `web` namespace used by the engine
    Response = Response
    StreamResponse = StreamResponse
    WebSocketResponse = WebSocketResponse
