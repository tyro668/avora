"""LMBP gateway engine (Python), the core of the lmbp-server SDK.

Behaviourally equivalent to the Go reference gateway (internal/lmbp/gateway):
RFC 8628 pairing, EdDSA tokens bound to issuer/tenant audiences, gateway
metadata + signed_metadata, RFC 7523 refresh, the lmbp WebSocket tunnel
(seq/ack/resume, credit flow control, tools, multimodal blobs, E2EE relay),
the OpenAI-compatible API and the Anthropic Messages API (§6.7). Durable
state goes through a Store (store.py); live sessions are in-process.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import datetime
import heapq
import hmac
import json
import os
import re
import secrets
import sys
import time
from urllib.parse import parse_qsl

from . import anthropic as A
from . import protocol as L
from ._http import Request, WSMsgType, web
from .store import MemoryStore, Store, StoreConflict, StoreNotFound
from .params import ParamError, announce_problem, device_data_problem, param_error_body, validate_anthropic_params, validate_chat_params, validate_task_run

PROBLEM_BASE = "https://avora.dev/problems/"
USER_CODE_CHARS = "BCDFGHJKLMNPQRSTVWXZ"
STATUS_OF = {
    "BAD_REQUEST": 400, "CAPABILITY_UNSUPPORTED": 400, "PAYLOAD_TOO_LARGE": 413, "IDEMPOTENCY_KEY_REUSED": 422,
    "MODEL_NOT_FOUND": 404, "DEVICE_OFFLINE": 503, "DEVICE_BUSY": 429, "TIMEOUT": 504, "CANCELLED": 499,
    "RATE_LIMITED": 429, "UNAUTHENTICATED": 401, "FORBIDDEN": 403, "CONSENT_DENIED": 403,
}
DEFAULT_FLOW = {"task_window": 1 << 20, "conn_window": 4 << 20}
RETENTION_DEFAULT = 7 * 24 * 3600  # seconds (spec §14.4, errata E6)


def retention_every(ret):
    """How often the retention pass runs: half the period, between 1 s and 1 h."""
    return min(3600.0, max(1.0, ret / 2))


def err_status(code):
    return STATUS_OF.get(code, 502)


TERMINAL_STATES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})


def state_of(ev):
    if ev["type"] == "task.done":
        return "SUCCEEDED"
    return "CANCELLED" if (ev.get("data") or {}).get("code") == "CANCELLED" else "FAILED"


MAX_RECLAIMED = 1024  # late-frame reclaim records per device session (same bound as Node/Go)


def is_terminal(t):
    return t in ("task.done", "task.error")


def error_body(code, message, retryable=False):
    return {"code": code, "message": message, "retryable": retryable}


def envelope(typ, id=None, task_id=None, data=None):
    e = {"v": L.VERSION, "type": typ}
    if id:
        e["id"] = id
    if task_id:
        e["task_id"] = task_id
    if data is not None:
        e["data"] = data
    return e


def json_resp(status, body, headers=None, ctype="application/json"):
    # §6.1: every JSON response is no-store unless the route set its own policy (JWKS/metadata).
    h = {"Cache-Control": "no-store", **(headers or {})}
    return web.Response(status=status, body=L.dumps(body).encode(), content_type=ctype, headers=h)


def problem_body(status, code, detail):
    return {"type": PROBLEM_BASE + code.lower().replace("_", "-"), "title": code, "status": status, "detail": detail, "code": code}


def problem(status, code, detail):
    return json_resp(status, problem_body(status, code, detail), {"Cache-Control": "no-store"}, "application/problem+json")


def api_error(status, code, message):
    return json_resp(status, {"error": {"message": message, "type": "lmbp_error", "code": code}})


def oauth_error(status, error, headers=None):
    return json_resp(status, {"error": error}, {"Cache-Control": "no-store", **(headers or {})})


class HTTPDone(Exception):
    """Carries an early error response out of helper functions."""

    def __init__(self, resp):
        self.resp = resp


def user_code():
    s = "".join(secrets.choice(USER_CODE_CHARS) for _ in range(8))
    return s[:4] + "-" + s[4:]


def norm_code(s):
    s = str(s or "").strip().replace("-", "").replace(" ", "").upper()
    return s[:4] + "-" + s[4:] if len(s) == 8 else ""


def intersect(a, b):
    out = []
    for x in a:
        if x in b and x not in out:
            out.append(x)
    return out


def valid_flow(f):
    return (isinstance(f, dict) and L.is_int(f.get("task_window")) and L.is_int(f.get("conn_window"))
            and f["task_window"] >= L.MAX_FRAME_BYTES and f["task_window"] <= f["conn_window"] <= 2**31)


def norm_message(m):
    o = {"role": m["role"], "content": m.get("content", "")}
    for k in ("name", "tool_calls", "tool_call_id"):
        if m.get(k) not in (None, ""):
            o[k] = m[k]
    return o


_STD_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def strict_b64(s):
    if not _STD_B64.match(s) or len(s) % 4:
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def extract_blobs(msgs):
    """Move large inline binaries (data: URIs, input_audio) into blobs (§16.3)."""
    blobs, total, vision, audio = [], 0, False, False

    def add(data, mt):
        nonlocal total
        total += len(data)
        if len(data) > L.MAX_BLOB_BYTES or total > L.MAX_TASK_BLOB_BYTES:
            return None
        bid = L.random_id("blob_")
        blobs.append({"ref": {"id": bid, "size": len(data), "sha256": L.b64(L.sha256(data)), "media_type": mt}, "data": data})
        return L.BLOB_SCHEME + bid

    for m in msgs:
        if not isinstance(m.get("content"), list):
            continue
        for p in m["content"]:
            typ = p.get("type") if isinstance(p, dict) else None
            if typ == "text":
                continue
            if typ == "image_url":
                vision = True
                u = (p.get("image_url") or {}).get("url")
                if not isinstance(u, str):
                    return None, "BAD_REQUEST", "image_url part without url"
                if u.startswith("https://"):
                    continue
                if not u.startswith("data:"):
                    return None, "BAD_REQUEST", "image_url must be https:// or a data: URI"
                comma = u.find(",")
                meta = u[5:comma] if comma >= 0 else ""
                if comma < 0 or not meta.endswith(";base64") or not meta.startswith("image/"):
                    return None, "BAD_REQUEST", "image data URI must be data:image/*;base64,"
                if len(u) <= L.INLINE_DATA_URI_BYTES:
                    continue
                raw = strict_b64(u[comma + 1:])
                if raw is None:
                    return None, "BAD_REQUEST", "invalid base64 in image data URI"
                ref = add(raw, meta[:-7])
                if ref is None:
                    return None, "PAYLOAD_TOO_LARGE", "image exceeds size limits"
                p["image_url"]["url"] = ref
            elif typ == "input_audio":
                audio = True
                a = p.get("input_audio")
                if not isinstance(a, dict) or not isinstance(a.get("data"), str) or a.get("format") not in ("wav", "mp3"):
                    return None, "BAD_REQUEST", "input_audio needs data and format wav|mp3"
                if len(a["data"]) <= L.INLINE_DATA_URI_BYTES:
                    continue
                raw = strict_b64(a["data"])
                if raw is None:
                    return None, "BAD_REQUEST", "invalid base64 in input_audio"
                ref = add(raw, "audio/" + a["format"])
                if ref is None:
                    return None, "PAYLOAD_TOO_LARGE", "audio exceeds size limits"
                a["data"] = ref
            else:
                return None, "BAD_REQUEST", f"unsupported content part {typ}"
    return (blobs, vision, audio), "", ""


async def read_body(req, limit):
    return await req.read(limit)


async def params(req, limit):
    """OAuth request as form-urlencoded (normative) or JSON (accepted)."""
    b = await read_body(req, limit)
    if b is None:
        return None
    if req.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
        out = {}
        for k, v in parse_qsl(b.decode(errors="replace"), keep_blank_values=True):
            if k in out:
                return None
            out[k] = v
        return out
    try:
        m = json.loads(b)
    except ValueError:
        return None
    if not isinstance(m, dict):
        return None
    return {k: v for k, v in m.items() if isinstance(v, str)}


class DState:
    """One device's protocol state; outlives a socket for the resume window."""

    def __init__(self, g, dev):
        self.g = g
        self.device_id, self.tenant, self.owner = dev["id"], dev["tenant"], dev["owner"]
        self.out = L.Outbox()
        self.inb = None
        self.ws = None
        self.q = None
        self.gen = 0
        self.models, self.model_caps, self.caps = [], {}, []
        self.model_names = {}
        self.max_conc, self.token_exp, self.issuer, self.resume_token = 1, 0, "", ""
        self.tasks: dict[str, Task] = {}
        self.slots = 0
        self.slot_wait: list[asyncio.Future] = []
        self.reclaimed: dict[str, int] = {}  # locally ended task id -> highest seq ACKed (bounded, oldest first)
        self.dropped = False

    def connected(self):
        return self.ws is not None and not self.dropped

    def control(self, e):
        if self.q is None:
            return False
        self.q.put_nowait(L.dumps(e))
        return True

    def send_err(self, id, code, msg):
        self.control(envelope("error", id=id, data=error_body(code, msg)))

    async def acquire(self, timeout):
        if self.slots < self.max_conc and not self.slot_wait:
            self.slots += 1
            return True
        fut = asyncio.get_running_loop().create_future()
        self.slot_wait.append(fut)
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            if fut in self.slot_wait:
                self.slot_wait.remove(fut)
            elif fut.done() and not fut.cancelled():
                self.release()  # granted concurrently: give it back
            if isinstance(e, asyncio.CancelledError):
                raise
            return False

    def reclaim(self, tid, acked):
        """Remember a locally ended task so its late frames (including its
        terminal frame) are ACKed and the device's reliable buffer and flow
        credit come back. Bounded; the oldest record is dropped first."""
        self.reclaimed.pop(tid, None)
        self.reclaimed[tid] = acked
        while len(self.reclaimed) > MAX_RECLAIMED:
            del self.reclaimed[next(iter(self.reclaimed))]

    def release(self):
        self.slots -= 1
        self.wake_slots()

    def wake_slots(self):
        while self.slot_wait and self.slots < self.max_conc:
            self.slots += 1
            f = self.slot_wait.pop(0)
            if not f.done():
                f.set_result(True)

    def drop(self, code, msg):
        self.dropped = True
        for f in self.slot_wait:
            if not f.done():
                f.set_result(True)
        self.slot_wait = []
        self.out.close()
        for t in list(self.tasks.values()):
            t.fail_offline(code, msg)
        if self.ws is not None:
            asyncio.ensure_future(self.ws.close())


#: Test-only: race_hook(task, point) is called at named points of the terminal
#: paths so races can be reproduced deterministically (None in production).
race_hook = None


def _hook(t, point):
    if race_hook is not None:
        race_hook(t, point)


class Task:
    """Gateway-side hub of one task: buffers device frames, fans them out to
    (re-)attached HTTP subscribers and paces task.ack (§8)."""

    def __init__(self, g, ds, id, tenant, owner, req_model, e2ee, idempotent, done=False, events=None):
        self.g, self.ds, self.id, self.tenant, self.owner = g, ds, id, tenant, owner
        self.req_model, self.e2ee, self.idempotent = req_model, e2ee, idempotent
        self.created = L.now()
        self.sent_run = False
        self.events = list(events or [])
        self.waiters: list[asyncio.Future] = []
        self.done = done
        self.subs: dict[int, int] = {}
        self.next_sub = 0
        self.acked = 0
        self.persisted = 0  # highest device seq durably stored; never ACK beyond it
        self.ack_at = time.monotonic()
        self.grace = None
        self.slot = False
        self.dispatcher = None
        self.timers = []
        if ds is not None:
            g.tasks[id] = self
            ds.tasks[id] = self
            self.timers.append(asyncio.get_running_loop().call_later(g.cfg["task_timeout"], self._timeout))
            self.watch = asyncio.ensure_future(self._watchdog())

    @classmethod
    def finished(cls, g, rec, req_model):
        t = cls(g, None, rec["id"], rec["tenant"], rec["owner"], req_model, bool(rec.get("e2ee")), False, done=True, events=list(rec["events"]))
        t.replayed = True
        # Recovery decides from a consistent terminal state: the last event is
        # terminal AND the stored state agrees (finish_task writes both
        # atomically). Otherwise (no terminal event, or a legacy row whose event
        # and state disagree) the outcome is OUTCOME_UNKNOWN: a synthetic event
        # that is only served, never stored, at the next unused seq.
        last = t.events[-1] if t.events else None
        last_seq = last["seq"] if last else 0
        consistent = bool(last) and is_terminal(last["type"]) and (
            rec.get("state") == "SUCCEEDED" if last["type"] == "task.done" else rec.get("state") in ("FAILED", "CANCELLED"))
        if not consistent:
            if last and is_terminal(last["type"]):
                g.log(f"lmbp: task {rec['id']}: stored terminal {last['type']} disagrees with state {rec.get('state')}; reporting OUTCOME_UNKNOWN")
                t.events.pop()
            t.events.append({"seq": last_seq + 1, "type": "task.error", "data": error_body("OUTCOME_UNKNOWN", "task outcome unknown")})
        return t

    def _timeout(self):
        if self.cancel("timeout"):
            self.fail_local("TIMEOUT", "task timed out")

    async def _watchdog(self):
        while not self.done:
            await asyncio.sleep(1)
            stalled = self.subs and self.recv_seq() > self.acked and time.monotonic() - self.ack_at > self.g.cfg["slow_consumer"]
            if stalled and self.cancel("slow_consumer"):
                self.fail_local("SLOW_CONSUMER", "client did not consume the stream in time")

    def recv_seq(self):
        return self.ds.inb.recv(self.id) if self.ds is not None and self.ds.inb is not None else 0

    def broadcast(self):
        ws, self.waiters = self.waiters, []
        for f in ws:
            if not f.done():
                f.set_result(None)

    def record(self, ev):
        """Publish a gateway-local terminal event. It is stored atomically with
        the terminal state; if that fails nothing is stored and a later
        re-attach reports OUTCOME_UNKNOWN (an error, never a success). There is
        nothing to ACK. Commit first, then publish."""
        if not getattr(self, "replayed", False):
            try:
                self.g.store.finish_task(self.id, ev, state_of(ev))
            except StoreNotFound:
                pass  # the task row was never created (storage error at creation)
            except Exception as e:  # noqa: BLE001 - any store failure
                self.g.log(f"lmbp: task {self.id}: persisting local event failed: {e}")
        self.events.append(ev)
        self.broadcast()

    def decide(self):
        """Claim the single terminal decision (see Go gtask.decide): exactly one
        terminal path (device done/error, timeout, cancel, slow consumer, local
        error) wins and alone commits and then publishes its outcome."""
        if self.done or getattr(self, "decided", False):
            return False
        self.decided = True
        return True

    def on_device_frame(self, inp):
        """Device frames are persisted (and, for the terminal frame, the task
        state) before they are published or ACKed: an ACK lets the device drop
        the frame from its resume buffer, so it may only cover frames the
        gateway can still serve after a restart."""
        _hook(self, "device-frame")
        if self.done or getattr(self, "decided", False):
            return self.maybe_ack()
        self.seen = max(getattr(self, "seen", 0), inp["seq"])
        data = inp.get("data") if isinstance(inp.get("data"), dict) else {}
        if inp["type"] == "task.delta" and not self.e2ee and data.get("e2ee"):
            data = {k: v for k, v in data.items() if k != "e2ee"}
        if inp["type"] == "task.delta":
            why = self.check_delta(data)
            if why:
                self.g.log(f"lmbp: task {self.id}: {why}")
                self.cancel("protocol_error")
                self.fail_local("INTERNAL", "device sent an invalid delta: " + why)
                return None
        ev = {"seq": inp["seq"], "type": inp["type"], "data": data}
        state = ""
        if is_terminal(inp["type"]):
            # Terminal event + terminal state in one transaction: on failure
            # neither is stored, so the local INTERNAL error can take this seq.
            state = state_of(ev)
            if not self.decide():  # another terminal path already decided
                return self.maybe_ack()
            try:
                self.g.store.finish_task(self.id, ev, state)
            except Exception as e:  # noqa: BLE001
                self.g.log(f"lmbp: task {self.id}: persisting terminal event and state for seq {inp['seq']} failed: {e} (not acknowledged)")
                self.store_failed = True  # never ACK frames that were not persisted
                self.send_cancel("internal_error")
                return self.commit_local("INTERNAL", "gateway could not persist task output")
            _hook(self, "device-terminal-committed")
        else:
            try:
                self.g.store.append_event(self.id, ev)
            except Exception as e:  # noqa: BLE001
                return self.persist_failed(inp["seq"], "event", e)
        if self.done or (getattr(self, "decided", False) and not state):
            return  # decided elsewhere meanwhile
        self.events.append(ev)
        self.persisted = inp["seq"]
        self.broadcast()
        if state:
            return self.finish(state, True, write_state=False)
        self.maybe_ack()

    def persist_failed(self, seq, what, e):
        self.store_failed = True  # never ACK frames that were not persisted
        self.g.log(f"lmbp: task {self.id}: persisting {what} for seq {seq} failed: {e} (not acknowledged)")
        self.cancel("internal_error")
        self.fail_local("INTERNAL", "gateway could not persist task output")

    def maybe_ack(self):
        if self.ds is None:
            return
        target = min(self.recv_seq(), self.persisted)
        if not self.done:
            for d in self.subs.values():
                target = min(target, d)
        if target <= self.acked:
            return
        self.acked, self.ack_at = target, time.monotonic()
        if self.ds.inb is not None:
            self.ds.inb.acked(self.id, target)
        self.ds.control(envelope("task.ack", task_id=self.id, data={"seq": target}))

    def cancel(self, reason):
        if self.done or getattr(self, "decided", False):
            return False
        self.send_cancel(reason)
        return True

    def send_cancel(self, reason):
        if self.ds is not None and self.sent_run:
            self.ds.control(envelope("task.cancel", task_id=self.id, data={"reason": reason}))

    def fail_local(self, code, msg, retryable=False):
        """Returns whether this call decided the terminal outcome."""
        if not self.decide():
            return False
        self.commit_local(code, msg, retryable)
        return True

    def commit_local(self, code, msg, retryable=False):
        """The caller holds the decision. The seq follows every device seq seen."""
        _hook(self, "local-terminal-decided")
        seq = max(self.events[-1]["seq"] if self.events else 0, getattr(self, "seen", 0)) + 1
        self.record({"seq": seq, "type": "task.error", "data": error_body(code, msg, retryable)})
        self.finish("CANCELLED" if code == "CANCELLED" else "FAILED", False, write_state=False)

    def fail_offline(self, code, msg):
        """End a task whose device session is gone, whatever ended it
        (disconnect, revocation, replacement): once task.run was sent the
        device may have run it, so OUTCOME_UNKNOWN (§7.5); before that
        DEVICE_OFFLINE (retryable)."""
        if self.sent_run:
            if code != "OUTCOME_UNKNOWN":
                msg += "; outcome unknown"
            code = "OUTCOME_UNKNOWN"
        else:
            code = "DEVICE_OFFLINE"
        self.fail_local(code, msg, code == "DEVICE_OFFLINE")

    def check_delta(self, data):
        """Validate a device delta before it is stored or aggregated: the
        tool-call index range (§16.1) and the task's output budget (§10),
        which counts every encoded delta body, cleartext or sealed."""
        if not self.e2ee:
            for c in data.get("tool_calls") or []:
                if isinstance(c, dict) and "index" in c:
                    i = c["index"]
                    if not L.is_int(i) or i < 0 or i > L.MAX_TOOL_CALL_INDEX:
                        return f"tool call index {i} out of range [0,{L.MAX_TOOL_CALL_INDEX}]"
        self.out_bytes = getattr(self, "out_bytes", 0) + len(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode())
        if self.out_bytes > L.MAX_TASK_OUTPUT_BYTES:
            return "task output exceeds the per-task limit"
        return ""

    def finish(self, state, from_device, write_state=True):
        if self.done:
            return
        self.done = True
        self.finished_at = time.time()
        slot, self.slot = self.slot, False
        for h in self.timers + ([self.grace] if self.grace else []):
            h.cancel()
        self.broadcast()
        ds = self.ds
        if ds is not None:
            if from_device:
                self.maybe_ack()
            elif not getattr(self, "store_failed", False):
                # Ended here while the device may still be sending: ACK what
                # arrived so far and remember the task (bounded) so later
                # frames, including its terminal frame, are ACKed too. Same
                # rule as the Node and Go gateways. Never after a failed write:
                # unpersisted frames are not ACKed.
                late = self.recv_seq()
                if late > self.acked:
                    self.acked = late
                    ds.control(envelope("task.ack", task_id=self.id, data={"seq": late}))
                if not getattr(self, "dev_terminal", False):
                    ds.reclaim(self.id, late)
            ds.tasks.pop(self.id, None)
            ds.out.forget(self.id)
            if ds.inb is not None:
                ds.inb.forget(self.id)
            if slot:
                ds.release()
        if self.dispatcher is not None and not self.dispatcher.done():
            self.dispatcher.cancel()

        def gc():
            if self.g.tasks.get(self.id) is self:
                del self.g.tasks[self.id]
        asyncio.get_running_loop().call_later(self.g.cfg["attach_grace"] + 600, gc)

    def attach(self, after):
        self.next_sub += 1
        self.subs[self.next_sub] = after
        if self.grace:
            self.grace.cancel()
            self.grace = None
        return self.next_sub

    def detach(self, sid):
        self.subs.pop(sid, None)
        left = not self.subs and not self.done
        if left and self.idempotent:
            def expire():
                if not self.subs and self.cancel("client_disconnected"):
                    self.fail_local("CANCELLED", "client did not re-attach")
            self.grace = asyncio.get_running_loop().call_later(self.g.cfg["attach_grace"], expire)
        if left and not self.idempotent:
            if self.cancel("client_disconnected"):
                self.fail_local("CANCELLED", "client disconnected")
            return
        self.maybe_ack()

    async def stream(self, after, keepalive, fn):
        """Deliver events with seq > after until the terminal one. Cancellation
        (client disconnect) propagates; the subscriber is detached either way."""
        sid = self.attach(after)
        try:
            while True:
                batch = [e for e in self.events if e["seq"] > after]
                # finished and nothing after the cursor (Last-Event-ID >= terminal seq): end
                if not batch and self.events and is_terminal(self.events[-1]["type"]):
                    return
                for e in batch:
                    await fn(e)
                    after = e["seq"]
                    if sid in self.subs:
                        self.subs[sid] = after
                    if is_terminal(e["type"]):
                        return
                self.maybe_ack()
                if batch:
                    continue
                fut = asyncio.get_running_loop().create_future()
                self.waiters.append(fut)
                try:
                    await asyncio.wait_for(fut, 15)
                except asyncio.TimeoutError:
                    if keepalive is not None:
                        await keepalive()
        finally:
            self.detach(sid)


# Pairing abuse limits (spec §6.2-§6.4, §10).
AUTHORIZE_PER_MINUTE = 60
MAX_PENDING_PER_TENANT = 1000
MAX_SLOW_DOWNS = 10
FAILURES_PER_MINUTE = 10
INITIAL_INTERVAL = 2


class JtiCache:
    """Remembers proof/assertion jtis until they expire. Expired entries
    leave from the top of a min-heap ordered by expiry (O(log n) per call),
    never by scanning the whole set."""

    def __init__(self):
        self.seen: dict[str, float] = {}
        self.heap: list[tuple[float, str]] = []

    def __len__(self):
        return len(self.seen)

    def _evict(self, now):
        h = self.heap
        while h and h[0][0] < now:
            at, j = heapq.heappop(h)
            if self.seen.get(j) == at:
                del self.seen[j]

    def has(self, j):
        self._evict(time.time())
        return j in self.seen

    def use(self, j, until):
        """Records j until `until` (epoch seconds); False if already recorded."""
        self._evict(time.time())
        if j in self.seen:
            return False
        self.seen[j] = until
        heapq.heappush(self.heap, (until, j))
        return True


class WindowCounter:
    """Counts events per key in fixed one-minute windows (the whole map is
    dropped when the window rolls over)."""

    def __init__(self):
        self.start, self.n = 0.0, {}

    def allow(self, key, limit):
        now = time.time()
        if now - self.start >= 60:
            self.start, self.n = now, {}
        c = self.n.get(key, 0)
        if c >= limit:
            return False
        self.n[key] = c + 1
        return True


class Gateway:
    def __init__(self, issuer="", seed=None, max_conc=16, log=None, web_dir="", store: Store | None = None, **tuning):
        # §18.1: the issuer is configuration, never derived from a request's Host.
        if not issuer:
            raise ValueError("lmbp: issuer is required (the gateway's public origin, e.g. https://gw.example.com)")
        self.cfg = {"issuer": L.origin(issuer), "code_ttl": 600, "token_ttl": 900, "max_conc": max_conc,
                    "ping_interval": 20, "resume_window": 30, "task_timeout": 600, "slow_consumer": 60, "attach_grace": 30, "queue_timeout": 15,
                    "flow": dict(DEFAULT_FLOW)}
        self.cfg.update(tuning)
        self.log = log or (lambda *a: print(*a, file=sys.stderr, flush=True))
        self.web_dir = web_dir
        self.store = store if store is not None else MemoryStore()
        if not seed:
            seed = self.store.get_secret("gateway_signing_seed")
            if not seed:
                seed = secrets.token_bytes(32)
                self.store.put_secret("gateway_signing_seed", seed)
        self.key = L.SigningKey(seed)
        self.pub, self.kid = self.key.pub, self.key.kid
        self.tenants = {}
        self.devs: dict[str, DState] = {}
        self.tasks: dict[str, Task] = {}
        self.jtis = JtiCache()
        self.fails: dict[tuple[str, str], list[float]] = {}  # (tenant, end user) -> failure times (last minute)
        self.pending: dict[str, dict[str, float]] = {}  # tenant -> device_code hash -> expiry
        self.auth_rate = WindowCounter()
        # Retention (spec §14.4, errata E6): 7 days by default; 0/None keeps the default, negative disables.
        if not self.cfg.get("retention"):
            self.cfg["retention"] = RETENTION_DEFAULT
        self.retention_task = None
        self.recover_orphans()

    def recover_orphans(self):
        """Store OUTCOME_UNKNOWN for tasks a previous process left without a
        terminal state (crash while QUEUED/RUNNING): this gateway owns no task
        yet, so all of them are orphans. The persisted terminal event and
        state make replays agree and let retention purge the prompt and
        output; without it they bypassed retention forever (audit3 P2-5)."""
        fn = getattr(self.store, "unfinished_tasks", None)
        if not callable(fn):
            return
        try:
            ids = fn()
        except Exception as e:  # noqa: BLE001
            self.log("lmbp: listing unfinished tasks:", e)
            return
        for tid in ids:
            try:
                rec = self.store.get_task(tid)
                if rec is None:
                    continue
                seq = max((e["seq"] for e in rec.get("events") or []), default=0) + 1
                self.store.finish_task(tid, {"seq": seq, "type": "task.error",
                                             "data": error_body("OUTCOME_UNKNOWN", "gateway restarted; task outcome unknown")}, "FAILED")
            except Exception as e:  # noqa: BLE001
                self.log(f"lmbp: orphaned task {tid}:", e)
        if ids:
            self.log(f"lmbp: {len(ids)} orphaned task(s) from a previous run recorded as OUTCOME_UNKNOWN")

    def ensure_retention(self):
        """Starts the purge loop on the running event loop (first request or connection)."""
        if self.retention_task is not None or self.cfg["retention"] < 0:
            return
        if not callable(getattr(self.store, "purge", None)):
            self.retention_task = False
            self.log("lmbp: store has no purge(); retention is disabled")
            return
        self.retention_task = asyncio.get_running_loop().create_task(self._retention_loop())

    async def _retention_loop(self):
        while True:
            await asyncio.sleep(retention_every(self.cfg["retention"]))
            self.purge()

    def stop_retention(self):
        if self.retention_task:
            self.retention_task.cancel()
        self.retention_task = None

    def purge(self, now=None):
        """One retention pass; returns the number of tasks removed from the store."""
        cutoff = (time.time() if now is None else now) - self.cfg["retention"]
        try:
            n = self.store.purge(cutoff)
        except Exception as e:  # noqa: BLE001 - a failed pass is retried next time
            self.log("retention purge:", e)
            return 0
        for i in [i for i, t in self.tasks.items() if getattr(t, "finished_at", None) and t.finished_at < cutoff]:
            del self.tasks[i]
        if n:
            self.log(f"retention purge: removed {n} tasks")
        return n

    def register_tenant(self, id, api_key, profile=None):
        profile = profile or {}
        if not L.TENANT_ID_RE.match(id):
            raise ValueError("invalid tenant id " + id)
        if not api_key or len(api_key) < 32:
            raise ValueError("tenant API key must be at least 32 characters")
        for s in profile.get("requested_scopes") or []:
            if s not in L.SCOPES:
                raise ValueError("unknown scope " + s)
        self.tenants[id] = {"id": id, "name": profile.get("display_name") or id, "key_hash": L.sha_hex(api_key), "profile": profile}

    ROUTES = [
        (re.compile(r"^/\.well-known/lmbp$"), "metadata"),
        (re.compile(r"^/lmbp/v1/device/authorize$"), "authorize"),
        (re.compile(r"^/lmbp/v1/token$"), "token"),
        (re.compile(r"^/lmbp/v1/connect$"), "connect"),
        (re.compile(r"^/lmbp/v1/tenant/devices/approvals$"), "approve"),
        (re.compile(r"^/lmbp/v1/tenant/devices$"), "list_devices"),
        (re.compile(r"^/lmbp/v1/tenant/devices/(?P<id>[^/]+)/revoke$"), "revoke"),
        (re.compile(r"^/lmbp/v1/tenant/tasks/(?P<id>[^/]+)/events$"), "task_events"),
        (re.compile(r"^/v1/models$"), "models"),
        (re.compile(r"^/v1/chat/completions$"), "chat"),
        (re.compile(r"^/v1/messages$"), "messages"),
    ]

    def handles(self, path: str) -> bool:
        """Whether path belongs to the gateway (frameworks fall through otherwise)."""
        return (path in ("/healthz", "/.well-known/jwks.json") or (bool(self.web_dir) and path in WEB_FILES)
                or any(rx.match(path) for rx, _ in self.ROUTES))

    async def route(self, req: Request):
        """Dispatch one request; returns a Response, or None once streamed."""
        self.ensure_retention()
        p = req.path
        if p == "/healthz":
            return json_resp(200, {"status": "ok"})
        if p == "/.well-known/jwks.json":
            return json_resp(200, {"keys": [L.public_jwk(self.pub)]}, {"Cache-Control": "public, max-age=300"})
        if self.web_dir and p in WEB_FILES and req.method in ("GET", "HEAD"):
            return await self.serve_web(req)
        for rx, name in self.ROUTES:
            m = rx.match(p)
            if m:
                req.match_info = {k: __import__("urllib.parse").parse.unquote(v) for k, v in m.groupdict().items()}
                if name in ("list_devices", "task_events", "models") and req.method != "GET":
                    break
                return await getattr(self, name)(req)
        return self.err_for(req)(404, "BAD_REQUEST", "not found")

    @staticmethod
    async def _static(resp):
        return resp

    async def serve_web(self, req):
        """Shared mock SaaS chat page (mock/web): static files only, no secrets."""
        name, ctype = WEB_FILES[req.path]
        try:
            with open(os.path.join(self.web_dir, name), "rb") as f:
                body = f.read()
        except OSError:
            return json_resp(404, {"error": "chat UI not installed"})
        return web.Response(body=body, headers={"Content-Type": ctype, "Content-Security-Policy": WEB_CSP,
                                                "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                                                "Cache-Control": "no-cache"})

    def issuer(self, req):  # noqa: ARG002 - never derived from the request (§18.1)
        return self.cfg["issuer"]

    def use_jti(self, j, until):
        return self.jtis.use(j, until)

    def verify_access(self, tok, iss):
        uc = L.unverified_claims(tok)
        c = L.verify_jwt(self.pub, tok, L.TYP_ACCESS, L.token_audience(iss, uc.get("tenant", "")))
        if c.get("iss") != iss:
            raise ValueError("token issuer mismatch")
        return c

    def online(self, id):
        ds = self.devs.get(id)
        return ds if ds is not None and ds.connected() else None

    @staticmethod
    def err_for(req):
        if getattr(req, "anthropic", False):
            return lambda st, code, msg: json_resp(st, A.error_body(st, code, msg))
        return api_error if req.path.startswith("/v1/") else problem

    def tenant_auth(self, req):
        err = self.err_for(req)
        ip = req.scope.get("lmbp.in_process_tenant") if hasattr(req, "scope") else None
        if ip is not None:
            user = req.headers.get("X-End-User", "")
            if not L.valid_header(user, 128):
                raise HTTPDone(err(400, "BAD_REQUEST", "end user must be 1-128 printable ASCII characters"))
            return ip, user
        a = req.headers.get("Authorization", "")
        if not a and req.headers.get("X-Api-Key"):
            a = "Bearer " + req.headers["X-Api-Key"]
        if not a.startswith("Bearer "):
            raise HTTPDone(err(401, "UNAUTHENTICATED", "tenant API key required"))
        h = L.sha_hex(a[7:])
        t = next((t for t in self.tenants.values() if hmac.compare_digest(t["key_hash"], h)), None)
        if t is None:
            raise HTTPDone(err(401, "UNAUTHENTICATED", "invalid tenant API key"))
        user = req.headers.get("X-End-User", "")
        if not L.valid_header(user, 128):
            raise HTTPDone(err(400, "BAD_REQUEST", "X-End-User must be 1-128 printable ASCII characters"))
        return t, user

    # ---------- §18 metadata ----------
    def build_metadata(self, iss, t):
        m = {"issuer": iss, "jwks_uri": iss + "/.well-known/jwks.json", "device_authorization_endpoint": iss + "/lmbp/v1/device/authorize",
             "token_endpoint": iss + "/lmbp/v1/token", "connect_endpoint": "ws" + iss[4:] + "/lmbp/v1/connect",
             "chat_completions_endpoint": iss + "/v1/chat/completions", "protocol_versions": L.PROTOCOL_VERSIONS, "profiles": L.PROFILES,
             "capabilities": L.CAPABILITIES, "scopes_supported": L.SCOPES}
        if t is None:
            return m
        p = t["profile"]
        saas = {"name": p.get("display_name") or t["name"]}
        for k in ("logo_uri", "homepage_uri", "policy_uri", "tos_uri", "pairing_uri"):
            if p.get(k):
                saas[k] = p[k]
        m.update(tenant=t["id"], audience=L.token_audience(iss, t["id"]), saas=saas)
        if p.get("requested_models"):
            m["requested_models"] = p["requested_models"]
        iat = L.now()
        m.update(requested_scopes=p.get("requested_scopes") or ["lmbp.chat"], iat=iat, exp=iat + 3600)
        m["signed_metadata"] = L.sign_jws(self.key, L.TYP_METADATA, self.kid, m)
        return m

    async def metadata(self, req):
        if req.method != "GET":
            return problem(405, "BAD_REQUEST", "GET required")
        t = None
        tid = req.query.get("tenant", "")
        if tid:
            t = self.tenants.get(tid) if L.TENANT_ID_RE.match(tid) else None
            if t is None:
                return problem(404, "BAD_REQUEST", "unknown tenant")
        return json_resp(200, self.build_metadata(self.issuer(req), t), {"Cache-Control": "public, max-age=300"})

    # ---------- RFC 8628 pairing ----------
    async def authorize(self, req):
        if req.method != "POST":
            return oauth_error(405, "invalid_request")
        # §6.2: limited per client address (the TCP peer) before anything is parsed or stored.
        if not self.auth_rate.allow(getattr(req, "peer", ""), AUTHORIZE_PER_MINUTE):
            return oauth_error(429, "slow_down", {"Retry-After": "60"})
        ps = await params(req, 4096)
        if not ps or not ps.get("tenant") or ("device_name" in ps and not L.valid_device_name(ps["device_name"])):
            return oauth_error(400, "invalid_request")
        try:
            pub = L.unb64(ps.get("public_key", ""))
        except ValueError:
            return oauth_error(400, "invalid_request")
        if len(pub) != 32:
            return oauth_error(400, "invalid_request")
        if not L.TENANT_ID_RE.match(ps["tenant"]) or ps["tenant"] not in self.tenants:
            return oauth_error(400, "invalid_client")
        dc = L.random_id("dc_")
        d = {"code_hash": L.sha_hex(dc), "user_code": user_code(), "tenant": ps["tenant"], "pub": pub, "name": ps.get("device_name", ""),
             "status": "pending", "expires": time.time() + self.cfg["code_ttl"], "interval": INITIAL_INTERVAL, "last_poll": 0.0, "device_id": "", "owner": ""}
        if not self.reserve_pending(d["tenant"], d["code_hash"], d["expires"]):
            return oauth_error(429, "slow_down", {"Retry-After": "60"})
        try:
            self.store.put_device_auth(d)
        except Exception:
            self.release_pending(d["tenant"], d["code_hash"])
            raise
        return json_resp(200, {"device_code": dc, "user_code": d["user_code"], "expires_in": self.cfg["code_ttl"], "interval": d["interval"]},
                         {"Cache-Control": "no-store"})

    def reserve_pending(self, tenant, h, expires):
        """Count a new pending pairing against its tenant's cap (expired entries are dropped first)."""
        now = time.time()
        m = self.pending.setdefault(tenant, {})
        for k in [k for k, at in m.items() if now > at]:
            del m[k]
        if len(m) >= MAX_PENDING_PER_TENANT:
            return False
        m[h] = expires
        return True

    def release_pending(self, tenant, h):
        m = self.pending.get(tenant)
        if m is not None:
            m.pop(h, None)
            if not m:
                del self.pending[tenant]

    # Failures are counted per end user of a tenant (§6.4). Decisions run
    # synchronously on the event loop (no await between the check, the
    # decision and the record), so they are atomic: a code is decided once.
    def allow_attempt(self, tenant, user):
        cut = time.time() - 60
        keep = [t for t in self.fails.get((tenant, user), []) if t > cut]
        if keep:
            self.fails[(tenant, user)] = keep
        else:
            self.fails.pop((tenant, user), None)
        return len(keep) < FAILURES_PER_MINUTE

    def record_failure(self, tenant, user):
        self.fails.setdefault((tenant, user), []).append(time.time())

    def pair_lookup(self, tenant, owner, user_code):
        """The pending pairing for a code the end user typed (to show the
        device before deciding). A code that is not pending counts as a
        failure of that user, like a failed decision. Returns (d, None) or
        (None, (status, code, message))."""
        if not self.allow_attempt(tenant, owner):
            return None, (429, "RATE_LIMITED", "too many failed codes; wait a minute")
        code = norm_code(user_code)
        d = self.store.device_auth_by_user_code(tenant, code) if code else None
        if d is None or d["status"] != "pending" or time.time() > d["expires"]:
            self.record_failure(tenant, owner)
            return None, (404, "BAD_REQUEST", "code invalid, expired or already used")
        return d, None

    async def approve(self, req):
        err = self.err_for(req)
        if req.method != "POST":
            return err(405, "BAD_REQUEST", "POST required")
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        raw = await read_body(req, 4096)
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return err(400, "BAD_REQUEST", "invalid JSON")
        d, e = self.pair_decide(t["id"], user, body.get("user_code"), body.get("deny") is True, body.get("jkt"))
        if e:
            return err(*e)
        return json_resp(200, {"status": d["status"], "device_id": d["device_id"], "device_name": d["name"], "jkt": L.thumbprint(d["pub"])})

    def pair_decide(self, tenant, owner, user_code, deny, jkt):
        """The one business-layer entry for approving/denying a user code (HTTP
        handler and in-process SDK API alike): enforces the per-tenant
        failed-code lockout and counts every failure. Returns (d, None) or
        (None, (status, code, message))."""
        if not self.allow_attempt(tenant, owner):
            return None, (429, "RATE_LIMITED", "too many failed codes; wait a minute")

        def fail(*e):
            self.record_failure(tenant, owner)
            return None, e
        code = norm_code(user_code)
        d = self.store.device_auth_by_user_code(tenant, code) if code else None
        if d is not None and d["status"] == "denied" and time.time() <= d["expires"]:
            # §19: the pairing was declined; a later approval cannot override it.
            return fail(403, "CONSENT_DENIED", "pairing consent was denied for this code")
        if d is None or d["status"] != "pending" or time.time() > d["expires"]:
            return fail(404, "BAD_REQUEST", "code invalid, expired or already used")
        if jkt and jkt != L.thumbprint(d["pub"]):
            return fail(409, "FORBIDDEN", "device key thumbprint does not match the pairing request")
        return self.decide(d, tenant, owner, deny), None

    def decide(self, d, tenant, owner, deny):
        """Approve (binding the device to owner) or deny a pending pairing."""
        if deny:
            d["status"] = "denied"
        else:
            d.update(status="approved", owner=owner, device_id=L.random_id("dev_"))
            self.store.put_device({"id": d["device_id"], "tenant": tenant, "owner": owner, "name": d["name"], "pub": d["pub"],
                                   "status": "active", "created": datetime.datetime.now(datetime.timezone.utc), "e2ee_key": ""})
        self.store.put_device_auth(d)
        self.release_pending(tenant, d["code_hash"])
        return d

    def issue(self, dev, iss):
        iat = L.now()
        c = {"iss": iss, "sub": dev["id"], "aud": L.token_audience(iss, dev["tenant"]), "tenant": dev["tenant"], "iat": iat,
             "exp": iat + self.cfg["token_ttl"], "jti": L.random_id("jti_"), "cnf": {"jkt": L.thumbprint(dev["pub"])}}
        return {"access_token": L.sign_jws(self.key, L.TYP_ACCESS, self.kid, c), "token_type": "Bearer", "expires_in": self.cfg["token_ttl"],
                "device_id": dev["id"], "gateway_key": L.public_jwk(self.pub), "issuer": iss}

    async def token(self, req):
        if req.method != "POST":
            return oauth_error(405, "invalid_request")
        ps = await params(req, 8192)
        if ps is None:
            return oauth_error(400, "invalid_request")
        iss = self.issuer(req)
        gt = ps.get("grant_type")
        if gt == "urn:ietf:params:oauth:grant-type:device_code":
            d = self.store.get_device_auth(L.sha_hex(ps.get("device_code", "")))
            if d is None:
                return oauth_error(400, "invalid_grant")
            try:
                pc = L.verify_proof(d["pub"], ps.get("proof"), "", L.PROOF_TOKEN, ps["device_code"])
                if self.jtis.has(pc["jti"]):
                    raise ValueError("replay")
            except (ValueError, TypeError, KeyError):
                return oauth_error(400, "invalid_grant")
            # A code that can no longer yield a token answers without remembering the proof's jti.
            if time.time() > d["expires"]:
                return oauth_error(400, "expired_token")
            if d["status"] == "denied":
                return oauth_error(400, "access_denied")
            if d["status"] == "consumed":
                return oauth_error(400, "invalid_grant")
            if not self.use_jti(pc["jti"], time.time() + 180):
                return oauth_error(400, "invalid_grant")
            if d["status"] == "pending":
                t = time.time()
                slow = t - d["last_poll"] < d["interval"] - 0.2
                d["last_poll"] = t
                if slow:
                    d["interval"] += 5
                # §6.3: a device that keeps ignoring slow_down loses its code.
                dead = (d["interval"] - INITIAL_INTERVAL) // 5 > MAX_SLOW_DOWNS
                if dead:
                    d["expires"] = t
                    self.release_pending(d["tenant"], d["code_hash"])
                self.store.put_device_auth(d)
                return oauth_error(400, "expired_token" if dead else "slow_down" if slow else "authorization_pending")
            dev = self.store.get_device(d["device_id"])
            if dev is None:
                return oauth_error(500, "server_error")
            d["status"] = "consumed"
            self.store.put_device_auth(d)
            return json_resp(200, self.issue(dev, iss))
        if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            try:
                a = ps.get("assertion", "")
                dev = self.store.get_device(L.unverified_claims(a).get("sub"))
                if dev is None or dev["status"] != "active":
                    raise ValueError("device")
                c = L.verify_jwt(dev["pub"], a, L.TYP_ASSERTION, L.assertion_audience(iss))
                if c.get("iss") != dev["id"] or c["exp"] - c["iat"] > 300 or not c.get("jti") or not self.use_jti(c["jti"], c["exp"] + 60):
                    raise ValueError("claims")
                return json_resp(200, self.issue(dev, iss))
            except (ValueError, TypeError, KeyError):
                return oauth_error(400, "invalid_grant")
        return oauth_error(400, "unsupported_grant_type")

    # ---------- tenant device management ----------
    def own_devices(self, tenant, owner):
        return self.store.list_devices(tenant, owner)

    async def list_devices(self, req):
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        out = []
        for d in self.own_devices(t["id"], user):
            item = {"device_id": d["id"], "name": d["name"], "status": d["status"], "created_at": d["created"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "online": False, "models": [], "public_key": L.public_jwk(d["pub"]), "jkt": L.thumbprint(d["pub"])}
            if d["e2ee_key"]:
                item["e2ee_key"] = d["e2ee_key"]
            s = self.online(d["id"])
            if s is not None:
                item.update(online=True, models=list(s.models), model_capabilities=dict(s.model_caps), capabilities=list(s.caps), max_concurrency=s.max_conc)
                if s.model_names:
                    item["model_names"] = dict(s.model_names)
            out.append(item)
        # Pending pairings are never listed (§6.4, §12.6): approval needs the code shown on the device.
        return json_resp(200, {"devices": out})

    async def revoke(self, req):
        err = self.err_for(req)
        if req.method != "POST":
            return err(404, "BAD_REQUEST", "not found")
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        id = req.match_info["id"]
        if not self.revoke_device(t["id"], user, id):
            return err(404, "FORBIDDEN", "device not found")
        return json_resp(200, {"device_id": id, "status": "revoked"})

    def revoke_device(self, tenant, owner, id):
        d = self.store.get_device(id)
        if d is None or d["tenant"] != tenant or d["owner"] != owner:
            return False
        d["status"] = "revoked"
        self.store.put_device(d)
        self.drop_device(id, "DEVICE_OFFLINE", "device revoked")  # in-flight tasks: OUTCOME_UNKNOWN (§7.5)
        return True

    def drop_device(self, id, code, msg):
        ds = self.devs.pop(id, None)
        if ds is not None:
            ds.drop(code, msg)

    # ---------- WebSocket tunnel ----------
    async def connect(self, req):
        protos = [p.strip() for p in req.headers.get("Sec-WebSocket-Protocol", "").split(",")]
        if req.headers.get("Upgrade", "").lower() != "websocket" or L.SUBPROTOCOL not in protos:
            return problem(400, "VERSION_UNSUPPORTED", L.VERSION_REQUIRED)
        if req.headers.get("Origin"):
            return problem(403, "FORBIDDEN", "browser origins are not allowed")
        tok = req.headers.get("Authorization", "").removeprefix("Bearer ")
        iss = self.issuer(req)
        try:
            claims = self.verify_access(tok, iss)
        except (ValueError, TypeError, KeyError) as e:
            return problem(401, "UNAUTHENTICATED", str(e))
        dev = self.store.get_device(claims.get("sub"))
        if (dev is None or dev["status"] != "active" or dev["tenant"] != claims.get("tenant")
                or (claims.get("cnf") or {}).get("jkt") != L.thumbprint(dev["pub"])):
            return problem(403, "FORBIDDEN", "device revoked or token not bound to device key")
        ws = web.WebSocketResponse(protocols=(L.SUBPROTOCOL,), max_msg_size=L.MAX_FRAME_BYTES, autoping=True, compress=False)
        await ws.prepare(req)
        try:
            msg = await ws.receive(timeout=15)
        except asyncio.TimeoutError:
            await ws.close()
            return ws
        env = None
        if msg.type == WSMsgType.TEXT:
            try:
                env = json.loads(msg.data)
            except ValueError:
                env = None
        hello = env.get("data") if isinstance(env, dict) else None
        if not isinstance(env, dict) or env.get("type") != "hello" or not isinstance(hello, dict):
            await ws.close()
            return ws

        async def early(code, m):
            await ws.send_str(L.dumps(envelope("error", id=env.get("id"), data=error_body(code, m))))
            await ws.close()
            return ws
        if env.get("v") != L.VERSION:
            return await early("VERSION_UNSUPPORTED", L.VERSION_REQUIRED)
        # §7.4 order: v, schema (BAD_REQUEST), device/proof (UNAUTHENTICATED), extension semantics.
        schema_bad = announce_problem(hello, True)
        if schema_bad:
            return await early("BAD_REQUEST", schema_bad)
        try:
            if hello.get("device_id") != dev["id"]:
                raise ValueError("device")
            pc = L.verify_proof(dev["pub"], hello.get("proof"), dev["id"], L.PROOF_HELLO, tok)
            if not self.use_jti(pc["jti"], time.time() + 180):
                raise ValueError("replay")
        except (ValueError, TypeError, KeyError):
            return await early("UNAUTHENTICATED", "invalid key proof")
        caps = intersect(hello.get("capabilities") or [], L.CAPABILITIES)
        if hello.get("flow") is not None and "flow" in caps and not valid_flow(hello["flow"]):
            return await early("BAD_REQUEST", f"flow windows must be >= max_frame_bytes ({L.MAX_FRAME_BYTES}) and conn_window >= task_window")
        # The device may have been revoked while we awaited the hello: the
        # upgrade-time snapshot is stale. Re-check before activating (no await
        # until the session is registered, so no revoke can slip in).
        cur = self.store.get_device(dev["id"])
        if cur is None or cur.get("status") != "active":
            return await early("UNAUTHENTICATED", "device revoked")
        dev = cur
        if hello.get("e2ee_key") and "e2ee" in caps:
            try:
                L.verify_e2ee_key(dev["pub"], dev["id"], hello["e2ee_key"])
            except (ValueError, TypeError, KeyError):
                return await early("BAD_REQUEST", "invalid e2ee key statement")
            if not self.save_e2ee_key(dev["id"], hello["e2ee_key"]):
                return await early("UNAUTHENTICATED", "device revoked")
            dev["e2ee_key"] = hello["e2ee_key"]
        else:
            caps = [c for c in caps if c != "e2ee"]
        conc = min(hello["max_concurrency"], self.cfg["max_conc"])  # validated 1..16; may lower, never raise
        await self.run_session(ws, dev, claims, iss, env, hello, caps, conc)
        return ws

    def save_e2ee_key(self, device_id, key):
        """Field-only, status-conditional E2EE key update; False when the
        device is gone or revoked (a revoked record is never rewritten)."""
        f = getattr(self.store, "set_device_e2ee_key", None)
        if f is not None:
            return bool(f(device_id, key))
        cur = self.store.get_device(device_id)  # synchronous: atomic in-process
        if cur is None or cur.get("status") != "active":
            return False
        cur["e2ee_key"] = key
        self.store.put_device(cur)
        return True

    async def run_session(self, ws, dev, claims, iss, env, hello, caps, conc):
        old = self.devs.get(dev["id"])
        res = hello.get("resume") if isinstance(hello.get("resume"), dict) else None
        resumed = bool(old and res and "resume" in caps and res.get("token") and res.get("token") == old.resume_token)
        if old is not None and not resumed:
            self.devs.pop(dev["id"], None)
            old.drop("OUTCOME_UNKNOWN", "device reconnected without resuming")
        ds = old if resumed else DState(self, dev)
        if not resumed:
            self.devs[dev["id"]] = ds
        prev_ws, prev_q = ds.ws, ds.q
        ds.gen += 1
        gen = ds.gen
        q: asyncio.Queue = asyncio.Queue()
        ds.ws, ds.q = ws, q
        ds.models = hello.get("models") if isinstance(hello.get("models"), list) else []
        ds.model_caps = hello.get("model_capabilities") if isinstance(hello.get("model_capabilities"), dict) else {}
        ds.model_names = clean_names(hello.get("model_names"), ds.models)
        ds.caps, ds.max_conc, ds.token_exp, ds.issuer, ds.resume_token = caps, conc, claims["exp"], iss, L.random_id("rt_")
        if ds.inb is None:
            ds.inb = L.Inbound(self.cfg["flow"] if "flow" in caps else None)
        else:
            ds.inb.reset_windows()  # the device retransmits everything we did not ack
        resume_tasks, device_recv, lost = [], {}, []
        if resumed:
            for rt in res.get("tasks") or []:
                if isinstance(rt, dict):
                    device_recv[rt.get("task_id")] = rt.get("recv_seq") if L.is_int(rt.get("recv_seq")) else 0
            for id, t in ds.tasks.items():
                if id not in device_recv and t.sent_run:
                    lost.append(t)  # device no longer has it: never re-executed
                    continue
                resume_tasks.append({"task_id": id, "recv_seq": ds.inb.recv(id)})
        if prev_q is not None:
            prev_q.put_nowait(None)
        if prev_ws is not None and prev_ws is not ws:
            asyncio.ensure_future(prev_ws.close())
        for t in lost:
            t.fail_offline("OUTCOME_UNKNOWN", "device resumed without this task; outcome unknown")
        if "flow" in caps:
            f = hello.get("flow")
            ds.out.set_flow({"task_window": f["task_window"], "conn_window": f["conn_window"]} if valid_flow(f) else dict(DEFAULT_FLOW))
        else:
            ds.out.set_flow(None)
        welcome = {"session_id": L.random_id("sess_"), "heartbeat_seconds": max(1, self.cfg["ping_interval"]), "max_frame_bytes": L.MAX_FRAME_BYTES,
                   "token_expires_at": claims["exp"], "capabilities": caps, "max_concurrency": conc}
        if "flow" in caps:
            welcome["flow"] = self.cfg["flow"]
        if "resume" in caps:
            welcome["resume_token"], welcome["resume_window_seconds"] = ds.resume_token, self.cfg["resume_window"]
            if res is not None:
                welcome["resume"] = {"resumed": resumed, "tasks": resume_tasks}
        ds.control(envelope("welcome", id=env.get("id"), data=welcome))

        async def writer():
            # Single writer per socket: frames go out in exactly the enqueued order.
            while True:
                raw = await q.get()
                if raw is None or ws.closed:
                    return
                try:
                    await ws.send_str(raw)
                except (ConnectionError, RuntimeError):
                    return
        wtask = asyncio.ensure_future(writer())
        ds.out.attach(q.put_nowait)
        if resumed:
            for rt in resume_tasks:
                ds.out.retransmit(rt["task_id"], device_recv.get(rt["task_id"], 0))
            self.log(f"device {dev['id']} resumed {len(resume_tasks)} task(s)")
        else:
            self.log(f"device {dev['id']} (tenant {dev['tenant']}) online, models={ds.models} caps={caps} conc={conc}")

        async def pinger():
            while True:
                await asyncio.sleep(self.cfg["ping_interval"])
                if L.now() > ds.token_exp + 30:
                    await ws.close()
                    return
                try:
                    await ws.ping()
                except (ConnectionError, RuntimeError):
                    return
        ptask = asyncio.ensure_future(pinger())
        try:
            while True:
                try:
                    msg = await ws.receive(timeout=60)
                except asyncio.TimeoutError:
                    break
                if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                    break
                if msg.type != WSMsgType.TEXT:
                    await ws.close(code=1003, message=b"text frames only")
                    break
                try:
                    inp = json.loads(msg.data)
                except ValueError:
                    inp = None
                if not isinstance(inp, dict) or inp.get("v") != L.VERSION:
                    ds.send_err(inp.get("id") if isinstance(inp, dict) else None, "BAD_REQUEST", "malformed frame")
                    continue
                typ = inp.get("type")
                if typ in ("task.delta", "task.done", "task.error"):
                    if not self.on_device_data(ds, inp, len(msg.data.encode())):
                        break
                elif typ == "task.ack":
                    seq = (inp.get("data") or {}).get("seq")
                    if L.is_int(seq):
                        ds.out.ack(inp.get("task_id"), seq)
                elif typ == "session.token":
                    if not self.refresh_session(ds, dev, inp):
                        ds.send_err(inp.get("id"), "UNAUTHENTICATED", "session token rejected")
                        break
                elif typ == "models.update":
                    mu_bad = announce_problem(inp.get("data"), False)
                    if mu_bad:
                        ds.send_err(inp.get("id"), "BAD_REQUEST", mu_bad)  # rejected whole: nothing applied
                    else:
                        self.models_update(ds, dev, inp.get("data"))
                elif typ == "ping":
                    ds.control(envelope("pong", id=inp.get("id")))
                elif typ == "pong":
                    pass
                else:
                    ds.send_err(inp.get("id"), "BAD_REQUEST", f"unknown message type {typ}")
        finally:
            ptask.cancel()
            if ds.gen == gen:
                ds.out.attach(None)
                ds.ws, ds.q = None, None
                q.put_nowait(None)
                try:
                    await asyncio.wait_for(wtask, 5)  # flush queued frames (e.g. the error) before closing
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
                if not ws.closed:
                    await ws.close()
                if "resume" not in ds.caps or ds.dropped:
                    self.drop_device(dev["id"], "DEVICE_OFFLINE", "device disconnected")
                else:
                    def expire():
                        if ds.gen == gen and ds.ws is None:
                            if self.devs.get(dev["id"]) is ds:
                                del self.devs[dev["id"]]
                            ds.drop("DEVICE_OFFLINE", "device did not resume in time")
                    asyncio.get_running_loop().call_later(self.cfg["resume_window"], expire)

    def models_update(self, ds, dev, mu):
        if not (isinstance(mu, dict) and isinstance(mu.get("models"), list) and len(mu["models"]) <= 500):
            return
        ds.models = mu["models"]
        ds.model_caps = mu.get("model_capabilities") or {}
        ds.model_names = clean_names(mu.get("model_names"), ds.models)
        if mu.get("max_concurrency") is not None:
            ds.max_conc = min(mu["max_concurrency"], self.cfg["max_conc"])
            ds.wake_slots()
        if mu.get("e2ee_key") and "e2ee" in ds.caps:
            try:
                L.verify_e2ee_key(dev["pub"], dev["id"], mu["e2ee_key"])
                if self.save_e2ee_key(dev["id"], mu["e2ee_key"]):
                    dev["e2ee_key"] = mu["e2ee_key"]
            except (ValueError, TypeError, KeyError):
                pass

    def on_device_data(self, ds, inp, size):
        tid = inp.get("task_id")
        # Envelope + body validated BEFORE the seq is accepted, persisted or
        # ACKed: an invalid terminal frame (task.done {}) never becomes
        # SUCCEEDED. The task fails as a protocol error (audit3 P2-6).
        bad = device_data_problem(inp)
        if bad:
            tt = ds.tasks.get(tid) if isinstance(tid, str) else None
            self.log(f"lmbp: device {ds.device_id} task {tid}: {bad}")
            if tt is not None:
                tt.cancel("protocol_error")
                tt.fail_local("INTERNAL", "device sent an invalid frame: " + bad)
            else:
                ds.send_err(inp.get("id"), "BAD_REQUEST", bad)
            return True
        t = ds.tasks.get(tid)
        seq = inp.get("seq") if L.is_int(inp.get("seq")) else 0
        if t is None:
            acked = ds.reclaimed.get(tid)
            if acked is not None:
                # Ended here (cancel, timeout, slow consumer, ...) while the
                # device was still running: ACK its late frames so its
                # reliable buffer and flow credit come back. The decided
                # outcome is not touched.
                if seq > acked:
                    ds.reclaimed[tid] = seq
                if is_terminal(inp.get("type")):
                    ds.reclaimed.pop(tid, None)
                if seq > acked:
                    ds.control(envelope("task.ack", task_id=tid, data={"seq": seq}))
                return True
            ds.control(envelope("task.cancel", task_id=tid, data={"reason": "unknown_task"}))
            return True
        v = ds.inb.accept(tid, seq, size)
        if v == L.ACCEPTED and is_terminal(inp.get("type")):
            t.dev_terminal = True
        if v == L.DUPLICATE:
            t.maybe_ack()  # the device may have missed our ack
            return True
        if v == L.GAP:
            t.cancel("protocol_error")
            t.fail_local("INTERNAL", "sequence gap from device")
            return True
        if v == L.OVERFLOW:
            ds.send_err("", "FLOW_CONTROL", "flow-control window exceeded")
            t.fail_local("FLOW_CONTROL", "device exceeded the flow-control window")
            return False
        inp["seq"] = seq
        t.on_device_frame(inp)
        return True

    def refresh_session(self, ds, dev, inp):
        st = inp.get("data") if isinstance(inp.get("data"), dict) else {}
        try:
            c = self.verify_access(st.get("access_token"), ds.issuer)
            if (c.get("sub") != dev["id"] or (c.get("cnf") or {}).get("jkt") != L.thumbprint(dev["pub"])
                    or (self.store.get_device(dev["id"]) or {}).get("status") != "active"):
                return False
            pc = L.verify_proof(dev["pub"], st.get("proof"), dev["id"], L.PROOF_SESSION_TOKEN, st["access_token"])
            if not self.use_jti(pc["jti"], time.time() + 180):
                return False
        except (ValueError, TypeError, KeyError, AttributeError):
            return False
        ds.token_exp = c["exp"]
        ds.control(envelope("session.token", id=inp.get("id"), data={"token_expires_at": c["exp"]}))
        return True

    # ---------- OpenAI-compatible surface ----------
    async def models(self, req):
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        data = []
        for d in self.own_devices(t["id"], user):
            s = self.online(d["id"])
            if s is None or d["status"] != "active":
                continue
            for m in s.models:
                item = {"id": f"{d['id']}/{m}", "object": "model", "owned_by": d["name"], "capabilities": s.model_caps.get(m) or []}
                if s.model_names.get(m):
                    item["display_name"] = s.model_names[m]
                data.append(item)
        if req.headers.get("Anthropic-Version"):
            return json_resp(200, A.models_list(data))
        return json_resp(200, {"object": "list", "data": data})

    def resolve(self, tenant, user, model):
        ds = self.own_devices(tenant, user)
        want, bare, dev_id = model, True, ""
        i = model.find("/")
        if i > 0 and model.startswith("dev_"):
            dev_id, want, bare = model[:i], model[i + 1:], False
        known = up = False
        for d in ds:
            if d["status"] != "active" or (not bare and d["id"] != dev_id):
                continue
            known = known or not bare
            s = self.online(d["id"])
            if s is not None:
                if want in s.models:
                    return s, want, "", 0
                up = True
        # §6.6: a named device that is online but lacks the model is 404; only an offline one is 503.
        if known:
            return (None, "", "MODEL_NOT_FOUND", 404) if up else (None, "", "DEVICE_OFFLINE", 503)
        if ds and bare and not any(self.online(d["id"]) for d in ds):
            return None, "", "DEVICE_OFFLINE", 503
        return None, "", "MODEL_NOT_FOUND", 404

    async def messages(self, req):
        """Anthropic Messages endpoint: translate, then run chat."""
        req.anthropic = True
        err = self.err_for(req)
        if req.method != "POST":
            return err(405, "BAD_REQUEST", "POST required")
        try:
            self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        body = await read_body(req, 48 << 20)
        if body is None:
            return err(413, "PAYLOAD_TOO_LARGE", "request body too large")
        try:
            r = json.loads(body)
        except ValueError:
            r = None
        if not isinstance(r, dict):
            return err(400, "BAD_REQUEST", "invalid JSON body")
        try:
            validate_anthropic_params(r)
        except ParamError as e:
            return json_resp(400, param_error_body(e, True))
        try:
            out = A.to_openai(r)
        except ValueError as e:
            return err(400, "BAD_REQUEST", str(e))
        return await self.chat(req, A.canonical_json(out).encode())

    async def chat(self, req, pre_body=None):
        err = self.err_for(req)
        if req.method != "POST":
            return err(405, "BAD_REQUEST", "POST required")
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        body = pre_body if pre_body is not None else await read_body(req, 48 << 20)
        if body is None:
            return err(413, "PAYLOAD_TOO_LARGE", "request body too large")
        try:
            r = json.loads(body)
        except ValueError:
            r = None
        if not isinstance(r, dict):
            return err(400, "BAD_REQUEST", "invalid JSON body")
        # Every parameter is validated before anything is stored, queued or
        # signed (third audit #2; spec/testvectors/params.json).
        try:
            params = validate_chat_params(r)
        except ParamError as e:
            return json_resp(400, param_error_body(e, bool(getattr(req, "anthropic", False))))
        idem_key = req.headers.get("Idempotency-Key", "")
        if idem_key and not L.valid_header(idem_key, 255):
            return err(400, "BAD_REQUEST", "Idempotency-Key must be 1-255 printable ASCII characters")
        body_hash = L.sha256(body).hex()
        rec = self.store.get_idempotency(t["id"], user, idem_key) if idem_key else None
        if rec is not None and (rec.get("tenant") != t["id"] or rec.get("owner") != user):
            return err(500, "INTERNAL", "idempotency store returned a foreign record")
        if rec is not None:
            if rec["body_hash"] != body_hash:
                return err(422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body")
            return await self.reattach(req, t["id"], user, rec["task_id"], r["model"], bool(r.get("stream")))
        msgs = r.get("messages") if isinstance(r.get("messages"), list) else []
        tools = r.get("tools") if isinstance(r.get("tools"), list) else []
        has_tc = r.get("tool_choice") is not None
        if r.get("lmbp_e2ee"):
            if msgs or tools:
                return err(400, "BAD_REQUEST", "lmbp_e2ee requests must not carry cleartext messages or tools")
        else:
            if not msgs or len(msgs) > L.MAX_MESSAGES:
                return err(400, "BAD_REQUEST", f"1-{L.MAX_MESSAGES} messages required")
            for m in msgs:
                if not isinstance(m, dict) or m.get("role") not in ("system", "user", "assistant", "tool", "developer"):
                    return err(400, "BAD_REQUEST", f"unsupported role {m.get('role') if isinstance(m, dict) else None}")
                if m["role"] == "tool" and not m.get("tool_call_id"):
                    return err(400, "BAD_REQUEST", "tool messages need tool_call_id")
        ds, model, code, status = self.resolve(t["id"], user, r["model"])
        if ds is None:
            return err(status, code, {"DEVICE_OFFLINE": "your device is offline", "MODEL_NOT_FOUND": "model not found on your devices"}[code])
        run = {"task_id": "", "iat": 0, "device_id": ds.device_id, "model": model}
        blobs = []
        mcaps = ds.model_caps.get(model) or []
        if r.get("lmbp_e2ee"):
            if "e2ee" not in ds.caps:
                return err(400, "CAPABILITY_UNSUPPORTED", "device does not support end-to-end encryption")
            jwe = str(r["lmbp_e2ee"])
            if jwe.count(".") != 4 or len(jwe.encode()) > L.MAX_TASK_BLOB_BYTES:
                return err(400, "BAD_REQUEST", "lmbp_e2ee must be a compact JWE")
            bid = L.random_id("blob_")
            data = jwe.encode()
            blobs = [{"ref": {"id": bid, "size": len(data), "sha256": L.b64(L.sha256(data)), "media_type": "application/jose"}, "data": data}]
            run["e2ee"] = {"blob": bid}
        else:
            ex, code, msg = extract_blobs(msgs)
            if code:
                return err(err_status(code), code, msg)
            blobs, vision, audio = ex
            if tools or has_tc:
                if "tools" not in ds.caps or "tools" not in mcaps:
                    return err(400, "CAPABILITY_UNSUPPORTED", f"model {model} does not support tools")
                for tl in tools:
                    if not isinstance(tl, dict) or tl.get("type") != "function" or not (tl.get("function") or {}).get("name"):
                        return err(400, "BAD_REQUEST", "tools must be type function with a name")
            if (vision or audio) and "multimodal" not in ds.caps:
                return err(400, "CAPABILITY_UNSUPPORTED", "device does not support multimodal input")
            if vision and "vision" not in mcaps:
                return err(400, "CAPABILITY_UNSUPPORTED", f"model {model} does not accept images")
            if audio and "audio" not in mcaps:
                return err(400, "CAPABILITY_UNSUPPORTED", f"model {model} does not accept audio")
            run["messages"] = [norm_message(m) for m in msgs]
            if tools:
                run["tools"] = tools
            if has_tc:
                run["tool_choice"] = r["tool_choice"]
        if params["max_tokens"]:
            run["max_tokens"] = params["max_tokens"]
        for k in ("temperature", "top_p", "stop"):
            if params[k] is not None:
                run[k] = params[k]
        # Per-model parameter support (spec §16.4; see Go gateway.chat): a model
        # that declares it ("params") gets every other parameter rejected; on
        # /v1/messages the mandatory max_tokens is dropped instead.
        anthropic = bool(getattr(req, "anthropic", False))
        mc = ds.model_caps.get(model, [])
        if "params" in mc:
            if run.get("max_tokens") and anthropic and "max_tokens" not in mc:
                del run["max_tokens"]
            for flag in ("temperature", "top_p", "stop", "max_tokens"):
                if flag in run and flag not in mc:
                    name = "stop_sequences" if anthropic and flag == "stop" else flag
                    return err(400, "CAPABILITY_UNSUPPORTED", f"model {model} does not support the {name} parameter")
        if blobs:
            run["blobs"] = [b["ref"] for b in blobs]

        task_id = L.random_id("task_")
        # limits stage 2/3 (spec §10): the signed task.run frame MUST fit max_frame_bytes
        iat0 = L.now()
        payload = {**run, "task_id": task_id, "iat": iat0, "exp": iat0 + 60, "nonce": L.random_id("n_")}
        trial = L.sign_jws(self.key, L.TYP_TASK, self.kid, payload)
        size = L.task_run_frame_size(trial, task_id)
        if size > L.MAX_FRAME_BYTES:
            return err(413, "PAYLOAD_TOO_LARGE", f"request too large: the signed task.run frame would be {size} bytes, over max_frame_bytes {L.MAX_FRAME_BYTES}; send large content as images/attachments")
        # The payload that will be signed MUST satisfy the published schema.
        try:
            validate_task_run(payload)
        except ParamError as e:
            return json_resp(400, param_error_body(e, bool(getattr(req, "anthropic", False))))
        # Idempotency record, task row and the in-memory hub are created in one
        # step with no await in between, so from the moment the record exists a
        # duplicate re-attaches to this live, pending task. Every way out of the
        # queue below ends the task with a recorded terminal event, so a replay
        # sees the same outcome instead of OUTCOME_UNKNOWN.
        try:
            # One atomic write: a key never exists without its task.
            idem = {"tenant": t["id"], "owner": user, "key": idem_key, "rec": {"tenant": t["id"], "owner": user, "task_id": task_id, "body_hash": body_hash}} if idem_key else None
            self.store.create_task({"id": task_id, "tenant": t["id"], "owner": user, "device": ds.device_id, "model": model, "state": "QUEUED", "events": [],
                                    "e2ee": "e2ee" in run}, idem)
        except StoreConflict:
            won = self.store.get_idempotency(t["id"], user, idem_key) if idem_key else None
            if won is not None and won.get("body_hash") == body_hash:  # a concurrent request took the key first
                return await self.reattach(req, t["id"], user, won["task_id"], r["model"], bool(r.get("stream")))
            if idem_key:
                return err(422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body")
            return err(500, "INTERNAL", "storage error")
        except Exception as e:  # noqa: BLE001
            self.log(f"lmbp: task {task_id}: storage error: {e}")
            return err(500, "INTERNAL", "storage error")
        task = Task(self, ds, task_id, t["id"], user, r["model"], "e2ee" in run, bool(idem_key))
        try:
            got = await ds.acquire(self.cfg["queue_timeout"])  # fair FIFO wait for a negotiated concurrency slot
        except asyncio.CancelledError:
            # Review7 #15: the HTTP caller went away while queued (aiohttp
            # cancels the handler): record an explicit terminal so the task
            # never stays QUEUED and a replay sees CANCELLED.
            task.fail_local("CANCELLED", "client disconnected while queued", False)
            raise
        if not got or not ds.connected() or task.done:
            if got:
                ds.release()
            hdr = {"X-Task-Id": task_id}
            resp = None
            # Review7 #10: only a decided local outcome is reported as such;
            # otherwise the caller gets the recorded winner.
            if task.done:
                pass
            elif not ds.connected():
                if task.fail_local("DEVICE_OFFLINE", "device disconnected", True):
                    resp = err(503, "DEVICE_OFFLINE", "device disconnected")
            elif task.fail_local("DEVICE_BUSY", "device is at max concurrency", True):
                resp = err(429, "DEVICE_BUSY", "device is at max concurrency")
                hdr["Retry-After"] = "2"
            if resp is None:
                return await self.serve(req, task, 0, bool(r.get("stream")), hdr)
            resp.headers.update(hdr)
            return resp
        task.slot = True
        self.set_task_state(task_id, "RUNNING")
        iat = L.now()
        run["task_id"], run["iat"] = task_id, iat
        run["exp"], run["nonce"] = iat + 60, L.random_id("n_")
        jws = L.sign_jws(self.key, L.TYP_TASK, self.kid, run)
        task.dispatcher = asyncio.ensure_future(self.dispatch(task, jws, blobs))
        return await self.serve(req, task, 0, bool(r.get("stream")), {"X-Task-Id": task_id})

    def set_task_state(self, id, state):
        """Non-terminal states only (terminal states are written with their
        event by store.finish_task); never overwrites a terminal state."""
        rec = self.store.get_task(id)
        if rec is not None and rec.get("state") not in TERMINAL_STATES:
            self.store.put_task({**rec, "state": state})

    async def dispatch(self, t, jws, blobs):
        """task.run, then the blob chunks, through the flow-controlled outbox."""
        t.sent_run = True
        try:
            await t.ds.out.send(t.id, lambda seq: {"type": "task.run", "jws": jws})
        except (L.OutboxClosed, asyncio.CancelledError):
            t.sent_run = False
            t.fail_offline("DEVICE_OFFLINE", "device disconnected")
            return
        for b in blobs:
            data, off = b["data"], 0
            while True:
                end = min(off + L.BLOB_CHUNK_BYTES, len(data))
                c = {"blob_id": b["ref"]["id"], "offset": off, "data": L.b64(data[off:end])}
                if end == len(data):
                    c["last"] = True
                try:
                    await t.ds.out.send(t.id, lambda seq, c=c: {"type": "blob.chunk", "data": c})
                except (L.OutboxClosed, asyncio.CancelledError):
                    return
                if end == len(data):
                    break
                off = end

    async def reattach(self, req, tenant, owner, task_id, req_model, stream):
        """Serve an existing task again (a live, possibly still queued task from
        memory first); every replay re-verifies tenant and owner."""
        t = self.tasks.get(task_id)
        if t is not None and (t.tenant != tenant or t.owner != owner):
            return self.err_for(req)(404, "BAD_REQUEST", "task no longer available")
        if t is None:
            rec = self.store.get_task(task_id)
            if rec is None or rec["tenant"] != tenant or rec["owner"] != owner:
                return self.err_for(req)(404, "BAD_REQUEST", "task no longer available")
            t = Task.finished(self, rec, req_model)
        try:
            after = int(req.headers.get("Last-Event-ID", "0") or 0)
        except ValueError:
            after = 0
        return await self.serve(req, t, after, stream, {"X-Task-Id": task_id})

    async def task_events(self, req):
        try:
            t, user = self.tenant_auth(req)
        except HTTPDone as e:
            return e.resp
        id = req.match_info["id"]
        rec = self.store.get_task(id)
        if rec is None or rec["tenant"] != t["id"] or rec["owner"] != user:
            return problem(404, "BAD_REQUEST", "task not found")
        return await self.reattach(req, t["id"], user, id, f"{rec['device']}/{rec['model']}", True)

    async def serve(self, req, t, after, stream, headers):
        """Render a task's events as an OpenAI response (SSE or aggregated JSON)."""
        if getattr(req, "anthropic", False):
            return await A.serve(req, t, after, stream, headers, json_resp, err_status)
        def chunk(delta, finish, usage=None, extra=None):
            m = {"id": "chatcmpl-" + t.id, "object": "chat.completion.chunk", "created": t.created, "model": t.req_model,
                 "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            if usage:
                m["usage"] = usage
            m.update(extra or {})
            return L.dumps(m)

        def sealed(e):
            s = (e.get("data") or {}).get("e2ee")
            return {"lmbp_e2ee": {"seq": e["seq"], "type": e["type"], "data": s}} if isinstance(s, str) and s else None

        if stream:
            resp = web.StreamResponse(status=200, headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no", **headers})
            await resp.prepare(req)
            if after == 0:
                await resp.write(f"id: 0\ndata: {chunk({'role': 'assistant', 'content': ''}, None)}\n\n".encode())

            async def keepalive():
                await resp.write(b": keep-alive\n\n")

            wrote = []

            async def emit(e):
                wrote.append(True)
                d, tail = e.get("data") or {}, ""
                if e["type"] == "task.delta":
                    if t.e2ee:
                        b = chunk({}, None, None, sealed(e))
                    else:
                        delta = {}
                        if d.get("text"):
                            delta["content"] = d["text"]
                        if d.get("tool_calls"):
                            delta["tool_calls"] = d["tool_calls"]
                        b = chunk(delta, None)
                elif e["type"] == "task.done":
                    b, tail = chunk({}, d.get("finish_reason") or "stop", d.get("usage"), sealed(e) if t.e2ee else None), "data: [DONE]\n\n"
                else:
                    b = L.dumps({"error": {"message": d.get("message"), "type": "lmbp_error", "code": d.get("code"), "retryable": bool(d.get("retryable"))}})
                await resp.write(f"id: {e['seq']}\ndata: {b}\n\n{tail}".encode())
            try:
                await t.stream(after, keepalive, emit)
            except (ConnectionError, RuntimeError):
                return resp
            if not wrote:
                # Last-Event-ID at or beyond the terminal event: nothing left, but
                # end with the terminator so clients can tell completion from truncation.
                await resp.write(b"data: [DONE]\n\n")
            await resp.write_eof()
            return resp

        text, calls, sealed_frames = [], [], []
        state = {"done": None, "fail": None}

        async def collect(e):
            d = e.get("data") or {}
            if e["type"] == "task.delta":
                if t.e2ee:
                    s = sealed(e)
                    if s:
                        sealed_frames.append(s["lmbp_e2ee"])
                    return
                text.append(d.get("text") or "")
                for c in d.get("tool_calls") or []:
                    idx = c.get("index") if L.is_int(c.get("index")) else 0
                    while len(calls) <= idx:
                        calls.append({"type": "function", "function": {"name": "", "arguments": ""}})
                    if c.get("id"):
                        calls[idx]["id"] = c["id"]
                    fn = c.get("function") or {}
                    calls[idx]["function"]["name"] += fn.get("name") or ""
                    calls[idx]["function"]["arguments"] += fn.get("arguments") or ""
            elif e["type"] == "task.done":
                state["done"] = d
                if t.e2ee:
                    s = sealed(e)
                    if s:
                        sealed_frames.append(s["lmbp_e2ee"])
            else:
                state["fail"] = d
        await t.stream(after, None, collect)
        if state["fail"] is not None:
            f = state["fail"]
            resp = api_error(err_status(f.get("code")), f.get("code"), f.get("message"))
            resp.headers.update(headers)  # X-Task-Id on task failures too (as Go/Node)
            return resp
        done = state["done"]
        finish = done.get("finish_reason") or "stop"
        txt = "".join(text)
        msg = {"role": "assistant", "content": txt}
        if calls:
            msg["tool_calls"] = [({"id": c["id"]} if c.get("id") else {}) | {"type": "function", "function": c["function"]} for c in calls]
            if not txt:
                msg["content"] = None
        out = {"id": "chatcmpl-" + t.id, "object": "chat.completion", "created": t.created, "model": t.req_model,
               "choices": [{"index": 0, "message": msg, "finish_reason": finish}]}
        if t.e2ee:
            out["choices"] = [{"index": 0, "message": {"role": "assistant", "content": None}, "finish_reason": finish}]
            out["lmbp_e2ee"] = sealed_frames
        if done.get("usage"):
            out["usage"] = done["usage"]
        return json_resp(200, out, headers)


# Same paths and CSP as mock/web/web.go.
WEB_FILES = {
    "/": ("chat.html", "text/html; charset=utf-8"), "/chat": ("chat.html", "text/html; charset=utf-8"),
    "/chat/": ("chat.html", "text/html; charset=utf-8"), "/chat/chat.js": ("chat.js", "text/javascript; charset=utf-8"),
    "/chat/qrcode.js": ("qrcode.js", "text/javascript; charset=utf-8"),
}
WEB_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def clean_names(names, models):
    """Optional display names (model_names), kept only for advertised models."""
    if not isinstance(names, dict) or not isinstance(models, list):
        return {}
    out = {}
    for m in models:
        n = names.get(m) if isinstance(m, str) else None
        if isinstance(n, str) and n.strip():
            out[m] = n.strip()  # length bounded by the schema (1-128 code points)
    return out
