"""LMBP primitives: base64url, EdDSA JWS/JWT, proofs, thumbprints, origins and
the reliable flow-controlled delivery state machines (LMBP spec §8, §15)."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = 2
SUBPROTOCOL = "lmbp"
PROTOCOL_VERSIONS = ["2.0"]
PAIR_LINK_VERSION = "2"
# Conformance profiles (spec §13.1); metadata.profiles lists those this gateway meets.
PROFILES = ["core", "reliable", "tools", "multimodal", "e2ee", "openai", "anthropic"]
MIN_CONCURRENCY, MAX_CONCURRENCY = 1, 16
VERSION_REQUIRED = "LMBP 2.0 required: WebSocket subprotocol lmbp and envelope v 2 (LMBP 1.x is not supported)"


def char_len(s: str) -> int:
    """Unicode code points, the unit of every string limit (spec §4.1)."""
    return len(s)


MAX_TOOL_CALL_INDEX = 127  # largest task.delta tool_calls[].index (spec §16.1)
MAX_TASK_OUTPUT_BYTES = 64 << 20  # encoded task.delta bytes per task, cleartext or sealed (spec §10)
MAX_DEVICE_NAME_CHARS = 100  # spec §6.2
# Characters that can disguise text (spec §6.2): C0/C1 controls, U+00AD,
# U+061C, U+180E, zero-width and directional marks, separators and embedding
# controls, invisible operators, BOM, interlinear annotation controls.
_DEVICE_NAME_FORBIDDEN = re.compile("[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]")


def valid_device_name(s) -> bool:
    """The spec §6.2 rule for the untrusted, device-reported name."""
    if not isinstance(s, str) or char_len(s) > MAX_DEVICE_NAME_CHARS or _DEVICE_NAME_FORBIDDEN.search(s):
        return False
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates
        return False
    return True


def valid_header(s, max_len: int) -> bool:
    """1..max_len printable ASCII (0x20-0x7E): X-End-User, Idempotency-Key (spec §4.1)."""
    return isinstance(s, str) and 1 <= len(s) <= max_len and all(0x20 <= ord(c) <= 0x7E for c in s)
CAPABILITIES = ["session.token", "models.update", "resume", "flow", "tools", "multimodal", "e2ee"]
SCOPES = ["lmbp.chat", "lmbp.tools", "lmbp.vision", "lmbp.audio"]
TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Normative limits (spec §10). Frame sizes are UTF-8 bytes of the encoded frame.
MAX_FRAME_BYTES = 256 << 10
MAX_MESSAGES = 200
BLOB_CHUNK_BYTES = 96 << 10
MAX_BLOB_BYTES = 20 << 20
MAX_TASK_BLOB_BYTES = 32 << 20
INLINE_DATA_URI_BYTES = 16 << 10
BLOB_SCHEME = "lmbp-blob:"
TYP_ACCESS, TYP_ASSERTION, TYP_PROOF = "at+jwt", "JWT", "lmbp-proof+jwt"
TYP_TASK, TYP_METADATA, TYP_E2EE_KEY = "lmbp-task+jws", "lmbp-metadata+jwt", "lmbp-e2ee-key+jwt"
PROOF_TOKEN, PROOF_HELLO, PROOF_SESSION_TOKEN = "lmbp:token", "lmbp:hello", "lmbp:session.token"

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def dumps(v) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def random_id(prefix: str = "") -> str:
    return prefix + secrets.token_hex(16)


def now() -> int:
    return int(time.time())


def is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def ath(cred: str) -> str:
    return b64(sha256(cred.encode()))


def thumbprint(pub: bytes) -> str:
    return b64(sha256(('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % b64(pub)).encode()))


def x25519_thumbprint(pub: bytes) -> str:
    return b64(sha256(('{"crv":"X25519","kty":"OKP","x":"%s"}' % b64(pub)).encode()))


def public_jwk(pub: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64(pub), "kid": thumbprint(pub), "alg": "EdDSA", "use": "sig"}


def token_audience(iss: str, tenant: str) -> str:
    return f"{iss}/tenants/{tenant}"


def assertion_audience(iss: str) -> str:
    return f"{iss}/lmbp/v1/token"


class SigningKey:
    def __init__(self, seed: bytes):
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        self.pub = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.kid = thumbprint(self.pub)


def sign_jws(key: SigningKey, typ: str, kid: str, payload) -> str:
    h = {"alg": "EdDSA", "typ": typ}
    if kid:
        h["kid"] = kid
    body = payload if isinstance(payload, (bytes, str)) else dumps(payload)
    if isinstance(body, str):
        body = body.encode()
    inp = b64(dumps(h).encode()) + "." + b64(body)
    return inp + "." + b64(key.priv.sign(inp.encode()))


def verify_jws(pub: bytes, jws: str, typ: str) -> bytes:
    """Strict compact EdDSA JWS (spec §5.2): the protected header is exactly
    {alg: "EdDSA", typ, kid?}; any other member (crit, b64, jku, ...) is
    rejected; kid, when present, is the verifying key's RFC 7638 thumbprint.
    The payload MUST be a JSON object."""
    if not isinstance(jws, str):
        raise ValueError("malformed JWS")
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWS")
    try:
        h = json.loads(unb64(parts[0]))
    except ValueError:
        raise ValueError("bad JWS header") from None
    if not isinstance(h, dict):
        raise ValueError("bad JWS header")
    for k in h:
        if k not in ("alg", "typ", "kid"):
            raise ValueError(f"forbidden JWS header {k}")
    if h.get("alg") != "EdDSA":
        raise ValueError("JWS alg must be EdDSA")
    if h.get("typ") != typ:
        raise ValueError(f"JWS typ must be {typ}")
    if "kid" in h and (not isinstance(h["kid"], str) or len(pub) != 32 or h["kid"] != thumbprint(pub)):
        raise ValueError("JWS kid does not match the verifying key")
    sig = unb64(parts[2])
    if len(pub) != 32 or len(sig) != 64:
        raise ValueError("bad JWS signature")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, (parts[0] + "." + parts[1]).encode())
    except InvalidSignature:
        raise ValueError("bad JWS signature") from None
    p = unb64(parts[1])
    try:
        c = json.loads(p)
    except ValueError:
        raise ValueError("bad JWS payload") from None
    if not isinstance(c, dict):
        raise ValueError("JWS payload must be a JSON object")
    return p


def is_numeric_date(v) -> bool:
    """A NumericDate is a JSON integer 0..2^53-1 (bool and float rejected)."""
    return is_int(v) and 0 <= v <= 2**53 - 1


def require_claims(c: dict, ints=(), strs=(), opt=()) -> None:
    for k in ints:
        if not is_numeric_date(c.get(k)):
            raise ValueError(f"claim {k} must be a non-negative integer")
    for k in strs:
        if not isinstance(c.get(k), str) or c[k] == "":
            raise ValueError(f"claim {k} must be a non-empty string")
    for k in opt:
        if not isinstance(c.get(k), str):
            raise ValueError(f"claim {k} must be a string")


def _time_range(c: dict) -> None:
    require_claims(c, ints=("iat", "exp"))
    if c["exp"] < c["iat"]:
        raise ValueError("exp before iat")


def verify_jwt(pub: bytes, tok: str, typ: str, aud: str, t: int | None = None) -> dict:
    t = now() if t is None else t
    c = json.loads(verify_jws(pub, tok, typ))
    require_claims(c, strs=("iss", "sub", "aud", "jti"))
    _time_range(c)
    if c["aud"] != aud:
        raise ValueError("wrong audience")
    if t > c["exp"] + 30 or t + 30 < c["iat"]:
        raise ValueError("token expired")
    return c


def unverified_claims(tok) -> dict:
    parts = str(tok or "").split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    c = json.loads(unb64(parts[1]))
    if not isinstance(c, dict):
        raise ValueError("bad claims")
    return c


def verify_proof(pub: bytes, proof, device_id: str, aud: str, credential: str, t: int | None = None) -> dict:
    t = now() if t is None else t
    c = json.loads(verify_jws(pub, proof, TYP_PROOF))
    require_claims(c, ints=("iat",), strs=("aud", "jti", "ath"), opt=("iss",))
    if (c["aud"] != aud or c["iss"] != device_id or not c.get("jti")
            or c.get("ath") != ath(credential)):
        raise ValueError("proof claims invalid")
    if not is_int(c.get("iat")) or abs(t - c["iat"]) > 60:
        raise ValueError("proof iat outside allowed skew")
    return c


def verify_e2ee_key(device_pub: bytes, device_id: str, stmt: str, t: int | None = None) -> None:
    t = now() if t is None else t
    c = json.loads(verify_jws(device_pub, stmt, TYP_E2EE_KEY))
    require_claims(c, strs=("iss", "sub"))
    _time_range(c)
    k = c.get("jwk")
    if c.get("sub") != device_id or c.get("iss") != device_id or not isinstance(k, dict) or k.get("kty") != "OKP" or k.get("crv") != "X25519":
        raise ValueError("bad e2ee key statement")
    if t > c["exp"] or t + 60 < c["iat"]:
        raise ValueError("e2ee key statement expired")
    x = unb64(k.get("x", ""))
    if len(x) != 32 or k.get("kid") != x25519_thumbprint(x):
        raise ValueError("bad e2ee key")


def is_loopback_host(h: str) -> bool:
    h = h.strip("[]").lower()
    return h in ("localhost", "::1") or re.match(r"^127\.\d+\.\d+\.\d+$", h) is not None


def origin(raw: str) -> str:
    """Normalize scheme://host[:port]; http only for loopback hosts (§18.1)."""
    s = str(raw).strip().rstrip("/")
    u = urlsplit(s)
    if not u.netloc or "@" in u.netloc or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError(f"not an origin: {raw!r}")
    scheme = u.scheme.lower()
    host = (u.hostname or "").lower()
    if scheme == "http" and not is_loopback_host(host):
        raise ValueError(f"issuer {raw!r} must use https")
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme in {raw!r}")
    if ":" in host:
        host = f"[{host}]"
    port = u.port
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        host += f":{port}"
    return f"{scheme}://{host}"


def can_send(flow, task_used: int, conn_used: int, n: int) -> bool:
    if not flow:
        return True
    return ((task_used + n <= flow["task_window"] or task_used == 0)
            and (conn_used + n <= flow["conn_window"] or conn_used == 0))


class OutboxClosed(Exception):
    pass


class TaskForgotten(OutboxClosed):
    """The task ended (Outbox.forget): it never re-enters the send queue."""


MAX_FORGOTTEN = 4096


class Outbox:
    """Sending half: send() completes once the frame fits the peer's windows;
    unacknowledged frames are retransmitted on resume. write() must be
    synchronous and order-preserving (it enqueues onto the socket writer)."""

    def __init__(self):
        self.flow = None
        self.conn_used = 0
        self.tasks: dict[str, dict] = {}
        self.waiters: list[dict] = []
        self.write = None
        self.closed = False
        # tasks dropped with forget() (bounded, insertion ordered): their
        # sends fail instead of re-creating state no retransmit list covers
        self.forgotten: dict[str, None] = {}

    def set_flow(self, f):
        self.flow = f
        self._wake()

    def attach(self, write):
        self.write = write
        for t in self.tasks.values():
            t["written"] = -1

    def _task(self, tid):
        t = self.tasks.get(tid)
        if t is None:
            t = self.tasks[tid] = {"next": 0, "unacked": [], "used": 0, "written": 0}
        return t

    def _fits(self, tid, n):
        return can_send(self.flow, self._task(tid)["used"], self.conn_used, n)

    def _wake(self):
        """Admit queued sends in strict FIFO order. Admission and credit
        reservation are one synchronous step: the seq is assigned, the frame
        built, recorded unacked and charged to both windows before the waiter
        is released, so concurrent senders cannot jointly overshoot a window
        (audit finding 2)."""
        while self.waiters:
            w = self.waiters[0]
            if self.closed:
                self.waiters.pop(0)
                if not w["fut"].done():
                    w["fut"].set_exception(OutboxClosed())
                continue
            if w["task"] in self.forgotten:
                self.waiters.pop(0)
                if not w["fut"].done():
                    w["fut"].set_exception(TaskForgotten())
                continue
            t = self._task(w["task"])
            seq = t["next"] + 1
            raw = w["mk"](seq)
            n = len(raw.encode())
            if not self._fits(w["task"], n):
                return
            self.waiters.pop(0)
            t["next"] = seq
            t["unacked"].append((seq, raw, n))
            t["used"] += n
            self.conn_used += n
            if not w["fut"].done():
                w["fut"].set_result(seq)

    def _flush(self, tid):
        while True:
            t = self.tasks.get(tid)
            if t is None or self.write is None or t["written"] < 0:
                return
            f = next((f for f in t["unacked"] if f[0] > t["written"]), None)
            if f is None:
                return
            t["written"] = f[0]
            try:
                self.write(f[1])
            except Exception:
                return

    async def send(self, tid: str, build) -> int:
        def mk(seq):
            e = {"v": VERSION, **build(seq), "task_id": tid, "seq": seq}
            return dumps(e)
        if self.closed:
            raise OutboxClosed()
        if tid in self.forgotten:
            raise TaskForgotten()
        w = {"task": tid, "mk": mk, "fut": asyncio.get_running_loop().create_future()}
        self.waiters.append(w)
        self._wake()  # commits w synchronously when it is first and fits
        try:
            seq = await w["fut"]
        except asyncio.CancelledError:
            if w in self.waiters:  # not yet admitted: withdraw
                self.waiters.remove(w)
                self._wake()
            raise  # if already admitted, the committed frame still goes out
        self._flush(tid)
        return seq

    def ack(self, tid, seq):
        t = self.tasks.get(tid)
        if t is None:
            return
        while t["unacked"] and t["unacked"][0][0] <= seq:
            _, _, n = t["unacked"].pop(0)
            t["used"] -= n
            self.conn_used -= n
        self._wake()

    def retransmit(self, tid, peer_recv):
        self.ack(tid, peer_recv)
        t = self.tasks.get(tid)
        if t is not None:
            t["written"] = peer_recv
        self._flush(tid)

    def forget(self, tid):
        """Drop a terminal task for good, atomically: release its credit and
        fail every send of it still queued for credit BEFORE waking the
        others, so it can never re-create its entry and re-consume
        connection credit that no resume returns (audit3 P1)."""
        t = self.tasks.pop(tid, None)
        if t is not None:
            self.conn_used -= t["used"]
        if tid not in self.forgotten:
            self.forgotten[tid] = None
            if len(self.forgotten) > MAX_FORGOTTEN:
                del self.forgotten[next(iter(self.forgotten))]
        kept = []
        for w in self.waiters:
            if w["task"] == tid:
                if not w["fut"].done():
                    w["fut"].set_exception(TaskForgotten())
            else:
                kept.append(w)
        self.waiters = kept
        self._wake()

    def close(self):
        self.closed = True
        self._wake()


ACCEPTED, DUPLICATE, GAP, OVERFLOW = range(4)


class Inbound:
    """Receiving half: detects duplicates/gaps and enforces our windows."""

    def __init__(self, flow):
        self.flow = flow
        self.conn_used = 0
        self.tasks: dict[str, dict] = {}

    def accept(self, tid, seq, size):
        t = self.tasks.setdefault(tid, {"recv": 0, "sizes": [], "used": 0})
        if seq <= t["recv"]:
            return DUPLICATE
        if seq != t["recv"] + 1:
            return GAP
        f = self.flow
        if f and ((t["used"] + size > f["task_window"] and t["used"] > 0) or (self.conn_used + size > f["conn_window"] and self.conn_used > 0)):
            return OVERFLOW
        t["recv"] = seq
        t["sizes"].append((seq, size))
        t["used"] += size
        self.conn_used += size
        return ACCEPTED

    def acked(self, tid, seq):
        t = self.tasks.get(tid)
        if t is None:
            return
        while t["sizes"] and t["sizes"][0][0] <= seq:
            _, n = t["sizes"].pop(0)
            t["used"] -= n
            self.conn_used -= n

    def recv(self, tid):
        t = self.tasks.get(tid)
        return t["recv"] if t else 0

    def reset_windows(self):
        self.conn_used = 0
        for t in self.tasks.values():
            t["used"], t["sizes"] = 0, []

    def forget(self, tid):
        t = self.tasks.pop(tid, None)
        if t is not None:
            self.conn_used -= t["used"]


def task_run_frame_size(jws: str, task_id: str) -> int:
    """Encoded size in bytes of the task.run frame carrying jws (worst-case seq)."""
    return len(dumps({"v": VERSION, "type": "task.run", "task_id": task_id, "seq": 2**53, "jws": jws}).encode())
