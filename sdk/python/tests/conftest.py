import asyncio
import contextlib
import socket

import pytest
import uvicorn


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_last_port = None


def issuer():
    """A loopback issuer for a gateway under test; the next serve() listens on its port
    (the issuer is configuration and must be known before the server starts)."""
    global _last_port
    _last_port = free_port()
    return f"http://127.0.0.1:{_last_port}"


@contextlib.asynccontextmanager
async def serve(app, port=None):
    port = port or _last_port or free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", ws="websockets", lifespan="off"))
    task = asyncio.ensure_future(srv.serve())
    while not srv.started:
        await asyncio.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        await task


@pytest.fixture
def serve_app():
    return serve
