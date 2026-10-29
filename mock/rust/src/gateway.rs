//! LMBP gateway engine (Rust port of the Node SDK engine, sdk/node/src/engine/gateway.js,
//! via the Java mock): RFC 8628 pairing, EdDSA tokens bound to issuer/tenant audiences,
//! metadata + signed_metadata, RFC 7523 refresh, the lmbp WebSocket tunnel (seq/ack/resume,
//! credit flow control, tools, multimodal blobs, E2EE relay), the OpenAI-compatible API
//! and the Anthropic Messages API. State is in memory.
//!
//! Concurrency: the Node engine is single-threaded; this port keeps those semantics with one
//! gateway lock held by every handler, timer and socket reader. Blocking waits release it
//! (Condvar), socket writes run unlocked.
use crate::anthropic;
use crate::http::{self, Abort, Req, Res, WsEvent, WsIo};
use crate::json::{self, get, truthy, Obj};
use crate::lmbp::{self, Flow, Inbound, Outbox};
use crate::obj;
use crate::params;
use crate::store::{Device, DeviceAuth, Event, Idempotency, Store, StoreErr, TaskRecord};
use ed25519_dalek::SigningKey;
use parking_lot::{Condvar, Mutex, MutexGuard};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub type Guard = MutexGuard<'static, St>;

pub const PROBLEM_BASE: &str = "https://avora.dev/problems/";
const USER_CODE_CHARS: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const ROLES: [&str; 5] = ["system", "user", "assistant", "tool", "developer"];
const WEB_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub fn err_status(code: &str) -> u16 {
    match code {
        "BAD_REQUEST" | "CAPABILITY_UNSUPPORTED" => 400,
        "PAYLOAD_TOO_LARGE" => 413,
        "IDEMPOTENCY_KEY_REUSED" => 422,
        "MODEL_NOT_FOUND" => 404,
        "DEVICE_OFFLINE" => 503,
        "DEVICE_BUSY" | "RATE_LIMITED" => 429,
        "TIMEOUT" => 504,
        "CANCELLED" => 499,
        "UNAUTHENTICATED" => 401,
        "FORBIDDEN" | "CONSENT_DENIED" => 403,
        _ => 502,
    }
}

pub fn is_terminal(t: &str) -> bool {
    t == "task.done" || t == "task.error"
}

fn state_of(ev: &Event) -> &'static str {
    if ev.ty == "task.done" {
        "SUCCEEDED"
    } else if get(&ev.data, "code").as_str() == Some("CANCELLED") {
        "CANCELLED"
    } else {
        "FAILED"
    }
}

pub fn error_body(code: &str, message: &str, retryable: bool) -> Value {
    obj! {"code" => code, "message" => message, "retryable" => retryable}
}

pub struct Config {
    pub issuer: String,
    pub code_ttl: i64,
    pub token_ttl: i64,
    pub max_conc: i64,
    pub ping_interval: u64,
    pub resume_window: u64,
    pub task_timeout: u64,
    pub slow_consumer: i64,
    pub attach_grace: u64,
    pub queue_timeout: u64,
    pub flow: Flow,
    pub web_dir: String,
    /// Retention of finished tasks and their idempotency records, ms (default 7 days; negative disables).
    pub retention: i64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            issuer: String::new(),
            code_ttl: 600,
            token_ttl: 900,
            max_conc: 16,
            ping_interval: 20_000,
            resume_window: 30_000,
            task_timeout: 600_000,
            slow_consumer: 60_000,
            attach_grace: 30_000,
            queue_timeout: 15_000,
            flow: Flow { task_window: 1 << 20, conn_window: 4 << 20 },
            web_dir: String::new(),
            retention: 7 * 24 * 3_600_000,
        }
    }
}

pub struct Tenant {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub profile: Value,
}

type TimerFn = Box<dyn FnMut(&mut Guard) + Send>;

struct Timer {
    at: Instant,
    every: Option<Duration>,
    f: Option<TimerFn>,
}

pub struct DState {
    pub device_id: String,
    pub out: Outbox,
    pub inb: Option<Inbound>,
    pub ws: Option<u64>,
    pub gen: u64,
    pub models: Vec<Value>,
    pub model_caps: Obj,
    pub model_names: Obj,
    pub caps: Vec<String>,
    pub max_conc: i64,
    pub token_exp: i64,
    pub issuer: String,
    pub resume_token: String,
    pub tasks: Vec<(String, u64)>,
    /// Tasks ended here (cancel, timeout, ...) whose device may still send frames:
    /// those late frames are ACKed so the device gets its flow credit back (spec §15.5).
    pub reclaimed: VecDeque<(String, i64)>,
    pub slots: i64,
    slot_wait: VecDeque<u64>,
    slot_ok: HashSet<u64>,
    pub dropped: bool,
    pub last_seen: i64,
}

impl DState {
    fn has_cap(&self, c: &str) -> bool {
        self.caps.iter().any(|x| x == c)
    }
}

pub struct Task {
    pub ds: Option<u64>,
    pub id: String,
    pub tenant: String,
    pub owner: String,
    pub req_model: String,
    pub e2ee: bool,
    pub idempotent: bool,
    pub created: i64,
    pub sent_run: bool,
    pub done: bool,
    pub decided: bool,
    pub replayed: bool,
    pub slot: bool,
    pub abort: Abort,
    pub events: Vec<Event>,
    subs: Vec<(u64, i64)>,
    next_sub: u64,
    acked: i64,
    persisted: i64,
    seen: i64,
    out_bytes: usize,
    ack_at: i64,
    grace: Option<u64>,
    timeout: Option<u64>,
    watch: Option<u64>,
}

enum Phase {
    Hello { dev: Device, tok: String, claims: Obj, iss: String, timer: u64 },
    Session { ds: u64, gen: u64, dev_id: String, ping: u64 },
    Done,
}

struct WsState {
    io: WsIo,
    close_fired: bool,
    phase: Phase,
}

pub struct St {
    pub cfg: Config,
    pub store: Store,
    key: SigningKey,
    pub_: Vec<u8>,
    pub kid: String,
    tenants: Vec<Tenant>,
    devs: HashMap<String, u64>,
    dstates: HashMap<u64, DState>,
    tasks: HashMap<String, u64>,
    tobj: HashMap<u64, Task>,
    jtis: JtiCache,
    fails: HashMap<String, Vec<i64>>,                // tenant \0 end user -> failure times (last minute)
    pending: HashMap<String, HashMap<String, i64>>, // tenant -> device_code hash -> expiry
    auth_rate: WindowCounter,
    wss: HashMap<u64, WsState>,
    timers: HashMap<u64, Timer>,
    theap: BinaryHeap<Reverse<(Instant, u64)>>,
    next: u64,
}

/// Pairing abuse limits (spec §6.2-§6.4, §10).
const AUTHORIZE_PER_MINUTE: u32 = 60;
const MAX_PENDING_PER_TENANT: usize = 1000;
const MAX_SLOW_DOWNS: i64 = 10;
const FAILURES_PER_MINUTE: usize = 10;
const INITIAL_INTERVAL: i64 = 2;

/// Remembers proof/assertion jtis until they expire. Expired entries leave from the top of a
/// min-heap ordered by expiry (O(log n) per call), never by scanning the whole set.
#[derive(Default)]
pub struct JtiCache {
    seen: HashMap<String, i64>,
    heap: BinaryHeap<Reverse<(i64, String)>>,
}

impl JtiCache {
    fn evict(&mut self, now: i64) {
        while let Some(Reverse((at, _))) = self.heap.peek() {
            if *at >= now {
                break;
            }
            let Reverse((at, j)) = self.heap.pop().unwrap();
            if self.seen.get(&j) == Some(&at) {
                self.seen.remove(&j);
            }
        }
    }
    pub fn has(&mut self, j: &str) -> bool {
        self.evict(lmbp::now_ms());
        self.seen.contains_key(j)
    }
    pub fn use_jti(&mut self, j: &str, until_ms: i64) -> bool {
        self.evict(lmbp::now_ms());
        if self.seen.contains_key(j) {
            return false;
        }
        self.seen.insert(j.to_string(), until_ms);
        self.heap.push(Reverse((until_ms, j.to_string())));
        true
    }
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

/// Counts events per key in fixed one-minute windows (the whole map is dropped when the window rolls).
#[derive(Default)]
struct WindowCounter {
    start: i64,
    n: HashMap<String, u32>,
}

impl WindowCounter {
    fn allow(&mut self, key: &str, limit: u32) -> bool {
        let now = lmbp::now_ms();
        if now - self.start >= 60_000 {
            self.start = now;
            self.n.clear();
        }
        let c = self.n.entry(key.to_string()).or_insert(0);
        if *c >= limit {
            return false;
        }
        *c += 1;
        true
    }
}

static GW: OnceLock<Mutex<St>> = OnceLock::new();
static CV: Condvar = Condvar::new();
static TCV: Condvar = Condvar::new();

pub fn lock() -> Guard {
    GW.get().expect("gateway").lock()
}

pub fn wake_all() {
    CV.notify_all();
}

fn wait(g: &mut Guard, ms: i64) {
    CV.wait_for(g, Duration::from_millis(ms.max(1) as u64));
}

pub fn log(s: &str) {
    eprintln!("{}", s);
}

/// init creates the global gateway; returns the key id.
pub fn init(mut cfg: Config, seed: Option<[u8; 32]>) -> lmbp::R<String> {
    // §18.1: the issuer is configuration, never derived from a request's Host.
    if cfg.issuer.is_empty() {
        return Err("issuer is required (the gateway's public origin, e.g. https://gw.example.com)".into());
    }
    cfg.issuer = lmbp::origin(&cfg.issuer)?;
    let seed = seed.unwrap_or_else(|| lmbp::random_bytes(32).try_into().unwrap());
    let key = SigningKey::from_bytes(&seed);
    let pub_ = key.verifying_key().to_bytes().to_vec();
    let kid = lmbp::thumbprint(&pub_);
    let st = St {
        cfg,
        store: Store::default(),
        key,
        pub_,
        kid: kid.clone(),
        tenants: vec![],
        devs: HashMap::new(),
        dstates: HashMap::new(),
        tasks: HashMap::new(),
        tobj: HashMap::new(),
        jtis: JtiCache::default(),
        fails: HashMap::new(),
        pending: HashMap::new(),
        auth_rate: WindowCounter::default(),
        wss: HashMap::new(),
        timers: HashMap::new(),
        theap: BinaryHeap::new(),
        next: 0,
    };
    if GW.set(Mutex::new(st)).is_err() {
        return Err("gateway already initialized".into());
    }
    std::thread::Builder::new().name("lmbp-timer".into()).spawn(timer_loop).unwrap();
    let mut g = lock();
    let ret = g.cfg.retention;
    if ret >= 0 {
        // every half the retention period, between 1 s and 1 h (as in every SDK)
        g.every((ret / 2).clamp(1000, 3_600_000) as u64, move |g| {
            let n = g.store.purge(lmbp::now_ms() - ret);
            if n > 0 {
                log(&format!("retention purge: removed {} tasks", n));
            }
        });
    }
    drop(g);
    Ok(kid)
}

// ---------- timers ----------
fn timer_loop() {
    let mut g = lock();
    loop {
        let now = Instant::now();
        let Some(Reverse((at, id))) = g.theap.peek().copied() else {
            TCV.wait_for(&mut g, Duration::from_secs(1));
            continue;
        };
        if at > now {
            TCV.wait_until(&mut g, at);
            continue;
        }
        g.theap.pop();
        let Some(t) = g.timers.get_mut(&id) else { continue };
        if t.at != at {
            continue;
        }
        let every = t.every;
        let Some(mut f) = t.f.take() else { continue };
        f(&mut g);
        if let Some(t) = g.timers.get_mut(&id) {
            match every {
                Some(e) => {
                    let next = at + e;
                    t.at = next;
                    t.f = Some(f);
                    g.theap.push(Reverse((next, id)));
                }
                None => {
                    g.timers.remove(&id);
                }
            }
        }
    }
}

impl St {
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
    fn later(&mut self, ms: u64, f: impl FnMut(&mut Guard) + Send + 'static) -> u64 {
        self.add_timer(ms, None, Box::new(f))
    }
    fn every(&mut self, ms: u64, f: impl FnMut(&mut Guard) + Send + 'static) -> u64 {
        self.add_timer(ms, Some(Duration::from_millis(ms)), Box::new(f))
    }
    fn add_timer(&mut self, ms: u64, every: Option<Duration>, f: TimerFn) -> u64 {
        let id = self.id();
        let at = Instant::now() + Duration::from_millis(ms);
        self.timers.insert(id, Timer { at, every, f: Some(f) });
        self.theap.push(Reverse((at, id)));
        TCV.notify_all();
        id
    }
    fn cancel(&mut self, t: Option<u64>) {
        if let Some(id) = t {
            self.timers.remove(&id);
        }
    }

    // ---------- tenants ----------
    pub fn register_tenant(&mut self, id: &str, api_key: &str, profile: Value) -> lmbp::R<()> {
        if !lmbp::tenant_id_ok(id) {
            return Err(format!("invalid tenant id {}", id));
        }
        if api_key.chars().count() < 32 {
            return Err("tenant API key must be at least 32 characters".into());
        }
        if let Some(rs) = get(&profile, "requested_scopes").as_array() {
            for s in rs {
                if !s.as_str().map(|x| lmbp::SCOPES.contains(&x)).unwrap_or(false) {
                    return Err(format!("unknown scope {}", json::js_string(s)));
                }
            }
        }
        let name = match get(&profile, "display_name").as_str() {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => id.to_string(),
        };
        self.tenants.retain(|t| t.id != id);
        self.tenants.push(Tenant { id: id.into(), name, key_hash: lmbp::sha_hex(api_key), profile });
        Ok(())
    }

    fn tenant(&self, id: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|t| t.id == id)
    }

    fn issuer(&self, _req: &Req) -> String {
        self.cfg.issuer.clone()
    }

    fn use_jti(&mut self, j: &str, until_ms: i64) -> bool {
        self.jtis.use_jti(j, until_ms)
    }

    fn verify_access(&self, tok: &Value, iss: &str) -> lmbp::R<Obj> {
        let uc = lmbp::unverified_claims(tok)?;
        let tenant = json::js_string(uc.get("tenant").unwrap_or(&Value::Null));
        let c = lmbp::verify_jwt(&self.pub_, tok, lmbp::TYP_ACCESS, &lmbp::token_audience(iss, &tenant), lmbp::now())?;
        if c.get("iss").and_then(|v| v.as_str()) != Some(iss) {
            return Err("token issuer mismatch".into());
        }
        Ok(c)
    }

    fn online(&self, id: &str) -> Option<u64> {
        let h = *self.devs.get(id)?;
        let ds = self.dstates.get(&h)?;
        if ds.ws.is_some() && !ds.dropped { Some(h) } else { None }
    }

    fn ds(&mut self, h: u64) -> &mut DState {
        self.dstates.get_mut(&h).expect("dstate")
    }

    fn sign(&self, typ: &str, payload: &Value) -> String {
        lmbp::sign_jws(&self.key, typ, &self.kid, payload)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Problem,
    Api,
    Anthropic,
}

pub fn send_err(g: &mut Guard, res: &mut Res, mode: Mode, status: u16, code: &str, msg: &str) {
    match mode {
        Mode::Problem => problem(g, res, status, code, msg),
        Mode::Api => api_error(g, res, status, code, msg),
        Mode::Anthropic => json_res(g, res, status, &anthropic::error_body(status, code, msg)),
    }
}

// ---------- HTTP routing ----------
pub fn handle(req: &Req, res: &mut Res) {
    let mut g = lock();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| route(&mut g, req, res)));
    if let Err(e) = r {
        log(&format!("handler error: {:?}", e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))));
        if !res.headers_sent {
            problem(&mut g, res, 500, "INTERNAL", "internal error");
        }
    }
    res.end(&mut g, None);
}

fn web_file(p: &str) -> Option<(&'static str, &'static str)> {
    match p {
        "/" | "/chat" | "/chat/" => Some(("chat.html", "text/html; charset=utf-8")),
        "/chat/chat.js" => Some(("chat.js", "text/javascript; charset=utf-8")),
        "/chat/qrcode.js" => Some(("qrcode.js", "text/javascript; charset=utf-8")),
        _ => None,
    }
}

fn seg_match<'a>(p: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let mid = p.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if mid.is_empty() || mid.contains('/') { None } else { Some(mid) }
}

fn route(g: &mut Guard, req: &Req, res: &mut Res) {
    let p = req.path.as_str();
    let mode = if p.starts_with("/v1/") { Mode::Api } else { Mode::Problem };
    if p == "/healthz" {
        return json_res(g, res, 200, &obj! {"status" => "ok"});
    }
    if !g.cfg.web_dir.is_empty() && (req.method == "GET" || req.method == "HEAD") {
        if let Some(f) = web_file(p) {
            return serve_web(g, res, f);
        }
    }
    if p == "/.well-known/jwks.json" {
        res.set_header("Cache-Control", "public, max-age=300");
        let k = lmbp::public_jwk(&g.pub_);
        return json_res(g, res, 200, &obj! {"keys" => vec![k]});
    }
    match p {
        "/.well-known/lmbp" => return metadata(g, req, res),
        "/lmbp/v1/device/authorize" => return authorize(g, req, res),
        "/lmbp/v1/token" => return token(g, req, res),
        "/lmbp/v1/connect" => return problem(g, res, 400, "VERSION_UNSUPPORTED", lmbp::VERSION_REQUIRED),
        "/lmbp/v1/tenant/devices/approvals" => return approve(g, req, res, mode),
        "/lmbp/v1/tenant/devices" => return list_devices(g, req, res, mode),
        "/v1/models" => return models(g, req, res, mode),
        "/v1/chat/completions" => return chat(g, req, res, mode, None, false),
        "/v1/messages" => return messages(g, req, res),
        _ => {}
    }
    if let Some(id) = seg_match(p, "/lmbp/v1/tenant/devices/", "/revoke") {
        return revoke(g, req, res, mode, &http::dec(id));
    }
    if let Some(id) = seg_match(p, "/lmbp/v1/tenant/tasks/", "/events") {
        if req.method == "GET" {
            return task_events(g, req, res, mode, id);
        }
    }
    send_err(g, res, mode, 404, "BAD_REQUEST", "not found");
}

fn serve_web(g: &mut Guard, res: &mut Res, f: (&str, &str)) {
    let path = std::path::Path::new(&g.cfg.web_dir).join(f.0);
    let Ok(b) = std::fs::read(path) else {
        return json_res(g, res, 404, &obj! {"error" => "chat UI not installed"});
    };
    res.set_header("Content-Type", f.1);
    res.set_header("Content-Security-Policy", WEB_CSP);
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Referrer-Policy", "no-referrer");
    res.set_header("Cache-Control", "no-cache");
    res.send(g, 200, f.1, &b);
}

struct Auth {
    tenant: String,
    user: String,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn tenant_auth(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode) -> Option<Auth> {
    let mut a = req.header("authorization").to_string();
    if a.is_empty() && !req.header("x-api-key").is_empty() {
        a = format!("Bearer {}", req.header("x-api-key"));
    }
    let Some(k) = a.strip_prefix("Bearer ") else {
        send_err(g, res, mode, 401, "UNAUTHENTICATED", "tenant API key required");
        return None;
    };
    let h = lmbp::sha_hex(k);
    let mut found = None;
    for t in &g.tenants {
        if ct_eq(t.key_hash.as_bytes(), h.as_bytes()) {
            found = Some(t.id.clone());
        }
    }
    let Some(tenant) = found else {
        send_err(g, res, mode, 401, "UNAUTHENTICATED", "invalid tenant API key");
        return None;
    };
    let user = req.headers.get("x-end-user").cloned().unwrap_or_default();
    if !lmbp::valid_header(&user, 128) {
        send_err(g, res, mode, 400, "BAD_REQUEST", "X-End-User must be 1-128 printable ASCII characters");
        return None;
    }
    Some(Auth { tenant, user })
}

// ---------- §18 metadata ----------
fn build_metadata(g: &Guard, iss: &str, t: Option<&Tenant>) -> Value {
    let ws = format!("ws{}", &iss[4..]);
    let mut m = obj! {"issuer" => iss, "jwks_uri" => format!("{}/.well-known/jwks.json", iss),
        "device_authorization_endpoint" => format!("{}/lmbp/v1/device/authorize", iss),
        "token_endpoint" => format!("{}/lmbp/v1/token", iss), "connect_endpoint" => format!("{}/lmbp/v1/connect", ws),
        "chat_completions_endpoint" => format!("{}/v1/chat/completions", iss),
        "protocol_versions" => lmbp::PROTOCOL_VERSIONS.to_vec(), "profiles" => lmbp::PROFILES.to_vec(), "capabilities" => lmbp::CAPABILITIES.to_vec(), "scopes_supported" => lmbp::SCOPES.to_vec()};
    let Some(t) = t else { return m };
    let p = &t.profile;
    let name = match get(p, "display_name").as_str() {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => t.name.clone(),
    };
    let mut saas = obj! {"name" => name};
    for k in ["logo_uri", "homepage_uri", "policy_uri", "tos_uri", "pairing_uri"] {
        if truthy(get(p, k)) {
            saas.as_object_mut().unwrap().insert(k.into(), get(p, k).clone());
        }
    }
    let iat = lmbp::now();
    let mo = m.as_object_mut().unwrap();
    mo.insert("tenant".into(), t.id.clone().into());
    mo.insert("audience".into(), lmbp::token_audience(iss, &t.id).into());
    mo.insert("saas".into(), saas);
    if let Some(rm) = get(p, "requested_models").as_array() {
        if !rm.is_empty() {
            mo.insert("requested_models".into(), Value::Array(rm.clone()));
        }
    }
    let rs = match get(p, "requested_scopes").as_array() {
        Some(rs) if !rs.is_empty() => Value::Array(rs.clone()),
        _ => obj_list(vec!["lmbp.chat".into()]),
    };
    mo.insert("requested_scopes".into(), rs);
    mo.insert("iat".into(), iat.into());
    mo.insert("exp".into(), (iat + 3600).into());
    let signed = g.sign(lmbp::TYP_METADATA, &m);
    m.as_object_mut().unwrap().insert("signed_metadata".into(), signed.into());
    m
}

fn obj_list(v: Vec<Value>) -> Value {
    Value::Array(v)
}

fn metadata(g: &mut Guard, req: &Req, res: &mut Res) {
    if req.method != "GET" {
        return problem(g, res, 405, "BAD_REQUEST", "GET required");
    }
    let iss = g.issuer(req);
    let mut tid = None;
    if let Some(id) = req.query_param("tenant") {
        if !id.is_empty() {
            if !lmbp::tenant_id_ok(&id) || g.tenant(&id).is_none() {
                return problem(g, res, 404, "BAD_REQUEST", "unknown tenant");
            }
            tid = Some(id);
        }
    }
    res.set_header("Cache-Control", "public, max-age=300");
    let m = build_metadata(g, &iss, tid.as_deref().and_then(|id| g.tenant(id)));
    json_res(g, res, 200, &m);
}

// ---------- RFC 8628 pairing ----------
fn authorize(g: &mut Guard, req: &Req, res: &mut Res) {
    if req.method != "POST" {
        return oauth_error(g, res, 405, "invalid_request");
    }
    // §6.2: limited per client address (the TCP peer) before anything is parsed or stored.
    if !g.auth_rate.allow(&req.peer, AUTHORIZE_PER_MINUTE) {
        res.set_header("Retry-After", "60");
        return oauth_error(g, res, 429, "slow_down");
    }
    let ps = match form_params(req, 4096) {
        Some(ps) if ps.get("tenant").map(|t| !t.is_empty()).unwrap_or(false)
            && ps.get("device_name").map(|n| lmbp::valid_device_name(n)).unwrap_or(true) => ps,
        _ => return oauth_error(g, res, 400, "invalid_request"),
    };
    let pub_ = match lmbp::unb64(ps.get("public_key").map(|s| s.as_str()).unwrap_or("")) {
        Ok(p) if p.len() == 32 => p,
        _ => return oauth_error(g, res, 400, "invalid_request"),
    };
    if g.tenant(&ps["tenant"]).is_none() {
        return oauth_error(g, res, 400, "invalid_client");
    }
    let dc = lmbp::random_id("dc_");
    let d = DeviceAuth {
        code_hash: lmbp::sha_hex(&dc),
        user_code: user_code(),
        tenant: ps["tenant"].clone(),
        pub_,
        name: ps.get("device_name").cloned().unwrap_or_default(),
        status: "pending".into(),
        expires: lmbp::now_ms() + g.cfg.code_ttl * 1000,
        interval: INITIAL_INTERVAL,
        ..Default::default()
    };
    let uc = d.user_code.clone();
    if !reserve_pending(g, &d.tenant, &d.code_hash, d.expires) {
        res.set_header("Retry-After", "60");
        return oauth_error(g, res, 429, "slow_down");
    }
    g.store.put_device_auth(d);
    res.set_header("Cache-Control", "no-store");
    let ttl = g.cfg.code_ttl;
    json_res(g, res, 200, &obj! {"device_code" => dc, "user_code" => uc, "expires_in" => ttl, "interval" => INITIAL_INTERVAL});
}

/// Counts a new pending pairing against its tenant's cap (expired entries are dropped first).
fn reserve_pending(g: &mut Guard, tenant: &str, hash: &str, expires: i64) -> bool {
    let now = lmbp::now_ms();
    let m = g.pending.entry(tenant.to_string()).or_default();
    m.retain(|_, at| now <= *at);
    if m.len() >= MAX_PENDING_PER_TENANT {
        return false;
    }
    m.insert(hash.to_string(), expires);
    true
}

fn release_pending(g: &mut Guard, tenant: &str, hash: &str) {
    if let Some(m) = g.pending.get_mut(tenant) {
        m.remove(hash);
        if m.is_empty() {
            g.pending.remove(tenant);
        }
    }
}

// Failures are counted per end user of a tenant (§6.4). Callers hold the gateway lock, so the
// check, the decision and the record are one atomic step: a code is decided once.
fn allow_attempt(g: &mut Guard, tenant: &str, user: &str) -> bool {
    let key = format!("{}\0{}", tenant, user);
    let cut = lmbp::now_ms() - 60_000;
    let keep: Vec<i64> = g.fails.get(&key).map(|v| v.iter().copied().filter(|t| *t > cut).collect()).unwrap_or_default();
    let n = keep.len();
    if keep.is_empty() {
        g.fails.remove(&key);
    } else {
        g.fails.insert(key, keep);
    }
    n < FAILURES_PER_MINUTE
}

fn record_failure(g: &mut Guard, tenant: &str, user: &str) {
    g.fails.entry(format!("{}\0{}", tenant, user)).or_default().push(lmbp::now_ms());
}

fn approve(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode) {
    if req.method != "POST" {
        return send_err(g, res, mode, 405, "BAD_REQUEST", "POST required");
    }
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    let body = req.body.as_ref().filter(|b| b.len() <= 4096).and_then(|b| serde_json::from_slice::<Value>(b).ok());
    let Some(body) = body.filter(|b| b.is_object()) else {
        return send_err(g, res, mode, 400, "BAD_REQUEST", "invalid JSON");
    };
    let uc = match get(&body, "user_code") {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v => json::stringify(v),
    };
    let jkt = get(&body, "jkt");
    let jkt = if truthy(jkt) { Some(json::js_string(jkt)) } else { None };
    match pair_decide(g, &a.tenant, &a.user, &uc, get(&body, "deny") == &Value::Bool(true), jkt.as_deref()) {
        Err((s, c, m)) => send_err(g, res, mode, s, c, m),
        Ok(d) => {
            let jkt = lmbp::thumbprint(&d.pub_);
            json_res(g, res, 200, &obj! {"status" => d.status, "device_id" => d.device_id, "device_name" => d.name, "jkt" => jkt})
        }
    }
}

type PairErr = (u16, &'static str, &'static str);

/// The one entry for approving/denying a user code; enforces the per-user failed-code lockout.
pub fn pair_decide(g: &mut Guard, tenant: &str, owner: &str, user_code: &str, deny: bool, jkt: Option<&str>) -> Result<DeviceAuth, PairErr> {
    if !allow_attempt(g, tenant, owner) {
        return Err((429, "RATE_LIMITED", "too many failed codes; wait a minute"));
    }
    let code = norm_code(user_code);
    let d = if code.is_empty() { None } else { g.store.device_auth_by_user_code(tenant, &code) };
    let now = lmbp::now_ms();
    let fail = |g: &mut Guard, e: PairErr| {
        record_failure(g, tenant, owner);
        Err(e)
    };
    // §19: a declined pairing cannot be overridden by a later approval.
    if let Some(d) = &d {
        if d.status == "denied" && now <= d.expires {
            return fail(g, (403, "CONSENT_DENIED", "pairing consent was denied for this code"));
        }
    }
    let Some(mut d) = d.filter(|d| d.status == "pending" && now <= d.expires) else {
        return fail(g, (404, "BAD_REQUEST", "code invalid, expired or already used"));
    };
    if let Some(j) = jkt {
        if j != lmbp::thumbprint(&d.pub_) {
            return fail(g, (409, "FORBIDDEN", "device key thumbprint does not match the pairing request"));
        }
    }
    if deny {
        d.status = "denied".into();
    } else {
        d.status = "approved".into();
        d.owner = owner.into();
        d.device_id = lmbp::random_id("dev_");
        g.store.put_device(Device {
            id: d.device_id.clone(),
            tenant: tenant.into(),
            owner: owner.into(),
            name: d.name.clone(),
            pub_: d.pub_.clone(),
            status: "active".into(),
            e2ee_key: String::new(),
            created: lmbp::now(),
        });
    }
    g.store.put_device_auth(d.clone());
    release_pending(g, tenant, &d.code_hash);
    Ok(d)
}

fn issue(g: &Guard, dev: &Device, iss: &str) -> Value {
    let iat = lmbp::now();
    let ttl = g.cfg.token_ttl;
    let c = obj! {"iss" => iss, "sub" => dev.id.clone(), "aud" => lmbp::token_audience(iss, &dev.tenant), "tenant" => dev.tenant.clone(),
        "iat" => iat, "exp" => iat + ttl, "jti" => lmbp::random_id("jti_"), "cnf" => obj!{"jkt" => lmbp::thumbprint(&dev.pub_)}};
    obj! {"access_token" => g.sign(lmbp::TYP_ACCESS, &c), "token_type" => "Bearer", "expires_in" => ttl,
        "device_id" => dev.id.clone(), "gateway_key" => lmbp::public_jwk(&g.pub_), "issuer" => iss}
}

fn token(g: &mut Guard, req: &Req, res: &mut Res) {
    if req.method != "POST" {
        return oauth_error(g, res, 405, "invalid_request");
    }
    let Some(ps) = form_params(req, 8192) else { return oauth_error(g, res, 400, "invalid_request") };
    let iss = g.issuer(req);
    let pv = |k: &str| ps.get(k).map(|s| Value::String(s.clone())).unwrap_or(Value::Null);
    let gt = ps.get("grant_type").map(|s| s.as_str()).unwrap_or("");
    if gt == "urn:ietf:params:oauth:grant-type:device_code" {
        let dcode = ps.get("device_code").cloned().unwrap_or_default();
        let Some(mut d) = g.store.get_device_auth(&lmbp::sha_hex(&dcode)) else { return oauth_error(g, res, 400, "invalid_grant") };
        let jti = match lmbp::verify_proof(&d.pub_, &pv("proof"), "", lmbp::PROOF_TOKEN, &dcode, lmbp::now()) {
            Ok(pc) => json::js_string(pc.get("jti").unwrap_or(&Value::Null)),
            Err(_) => return oauth_error(g, res, 400, "invalid_grant"),
        };
        if g.jtis.has(&jti) {
            return oauth_error(g, res, 400, "invalid_grant");
        }
        // A code that can no longer yield a token answers without remembering the proof's jti.
        let now = lmbp::now_ms();
        if now > d.expires {
            return oauth_error(g, res, 400, "expired_token");
        }
        match d.status.as_str() {
            "denied" => return oauth_error(g, res, 400, "access_denied"),
            "consumed" => return oauth_error(g, res, 400, "invalid_grant"),
            _ => {}
        }
        if !g.use_jti(&jti, now + 180_000) {
            return oauth_error(g, res, 400, "invalid_grant");
        }
        if d.status == "pending" {
            let slow = now - d.last_poll < d.interval * 1000 - 200;
            d.last_poll = now;
            if slow {
                d.interval += 5;
            }
            // §6.3: a device that keeps ignoring slow_down loses its code.
            let dead = (d.interval - INITIAL_INTERVAL) / 5 > MAX_SLOW_DOWNS;
            if dead {
                d.expires = now;
                let (t, h) = (d.tenant.clone(), d.code_hash.clone());
                release_pending(g, &t, &h);
            }
            g.store.put_device_auth(d);
            return oauth_error(g, res, 400, if dead { "expired_token" } else if slow { "slow_down" } else { "authorization_pending" });
        }
        let Some(dev) = g.store.get_device(&d.device_id) else { return oauth_error(g, res, 500, "server_error") };
        d.status = "consumed".into();
        g.store.put_device_auth(d);
        let body = issue(g, &dev, &iss);
        return json_res(g, res, 200, &body);
    }
    if gt == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
        let r = (|| -> lmbp::R<Device> {
            let a = pv("assertion");
            let uc = lmbp::unverified_claims(&a)?;
            let dev = uc.get("sub").and_then(|s| s.as_str()).and_then(|s| g.store.get_device(s)).filter(|d| d.status == "active").ok_or("device")?;
            let c = lmbp::verify_jwt(&dev.pub_, &a, lmbp::TYP_ASSERTION, &lmbp::assertion_audience(&iss), lmbp::now())?;
            let exp = json::int(&c["exp"]);
            let iat = json::int(&c["iat"]);
            let jti = c.get("jti").cloned().unwrap_or(Value::Null);
            if c.get("iss").and_then(|v| v.as_str()) != Some(dev.id.as_str()) || exp - iat > 300 || !truthy(&jti) || !g.use_jti(&json::js_string(&jti), (exp + 60) * 1000) {
                return Err("claims".into());
            }
            Ok(dev)
        })();
        return match r {
            Ok(dev) => {
                let body = issue(g, &dev, &iss);
                json_res(g, res, 200, &body)
            }
            Err(_) => oauth_error(g, res, 400, "invalid_grant"),
        };
    }
    oauth_error(g, res, 400, "unsupported_grant_type")
}

// ---------- tenant device management ----------
fn iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

fn list_devices(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode) {
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    let mut out = vec![];
    for d in g.store.list_devices(&a.tenant, Some(&a.user)) {
        let mut item = obj! {"device_id" => d.id.clone(), "name" => d.name.clone(), "status" => d.status.clone(),
            "created_at" => iso8601(d.created), "online" => false, "models" => Value::Array(vec![]),
            "public_key" => lmbp::public_jwk(&d.pub_), "jkt" => lmbp::thumbprint(&d.pub_)};
        let io = item.as_object_mut().unwrap();
        if !d.e2ee_key.is_empty() {
            io.insert("e2ee_key".into(), d.e2ee_key.clone().into());
        }
        if let Some(h) = g.online(&d.id) {
            let s = &g.dstates[&h];
            io.insert("online".into(), true.into());
            io.insert("models".into(), Value::Array(s.models.clone()));
            io.insert("model_capabilities".into(), Value::Object(s.model_caps.clone()));
            if !s.model_names.is_empty() {
                io.insert("model_names".into(), Value::Object(s.model_names.clone()));
            }
            io.insert("capabilities".into(), s.caps.clone().into());
            io.insert("max_concurrency".into(), s.max_conc.into());
        }
        out.push(item);
    }
    // Pending pairings are never listed (§6.4, §12.6): approval needs the code shown on the device.
    json_res(g, res, 200, &obj! {"devices" => out});
}

fn revoke(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode, id: &str) {
    if req.method != "POST" {
        return send_err(g, res, mode, 404, "BAD_REQUEST", "not found");
    }
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    if !revoke_device(g, &a.tenant, &a.user, id) {
        return send_err(g, res, mode, 404, "FORBIDDEN", "device not found");
    }
    json_res(g, res, 200, &obj! {"device_id" => id, "status" => "revoked"});
}

pub fn revoke_device(g: &mut Guard, tenant: &str, owner: &str, id: &str) -> bool {
    let Some(mut d) = g.store.get_device(id).filter(|d| d.tenant == tenant && d.owner == owner) else { return false };
    d.status = "revoked".into();
    g.store.put_device(d);
    drop_device(g, id, "DEVICE_OFFLINE", "device revoked"); // in-flight tasks: OUTCOME_UNKNOWN (§7.5)
    true
}

fn drop_device(g: &mut Guard, id: &str, code: &str, msg: &str) {
    if let Some(h) = g.devs.remove(id) {
        ds_drop(g, h, code, msg);
    }
}

// ---------- WebSocket tunnel ----------
fn envelope(ty: &str, id: Option<&str>, task_id: Option<&str>, data: Option<Value>) -> Value {
    let mut e = obj! {"v" => lmbp::VERSION, "type" => ty};
    let m = e.as_object_mut().unwrap();
    if let Some(id) = id.filter(|s| !s.is_empty()) {
        m.insert("id".into(), id.into());
    }
    if let Some(t) = task_id.filter(|s| !s.is_empty()) {
        m.insert("task_id".into(), t.into());
    }
    if let Some(d) = data {
        m.insert("data".into(), d);
    }
    e
}

fn id_of(env: &Value) -> Option<String> {
    get(env, "id").as_str().map(|s| s.to_string())
}

fn is_version(v: &Value) -> bool {
    v.as_f64() == Some(lmbp::VERSION as f64)
}

/// JavaScript `x | 0`.
fn to_int32(v: &Value) -> i64 {
    match v.as_f64() {
        Some(d) if d.is_finite() => (d.trunc() as i64 as i32) as i64,
        _ => 0,
    }
}

fn valid_flow(f: &Value) -> bool {
    if !f.is_object() {
        return false;
    }
    let (tw, cw) = (get(f, "task_window"), get(f, "conn_window"));
    if !json::is_safe_int(tw) || !json::is_safe_int(cw) {
        return false;
    }
    let (t, c) = (tw.as_f64().unwrap(), cw.as_f64().unwrap());
    t >= lmbp::MAX_FRAME_BYTES as f64 && c >= t && c <= 2147483648.0
}

fn reject_resp(status: u16, code: &str, msg: &str) -> Vec<u8> {
    let b = json::stringify(&problem_body(status, code, msg));
    format!("HTTP/1.1 {} {}\r\nContent-Type: application/problem+json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, http::reason(status), b.len(), b).into_bytes()
}

pub fn upgrade(req: &Req, mut inp: std::io::BufReader<TcpStream>, mut out: TcpStream) {
    let mut g = lock();
    let tok = req.header("authorization").strip_prefix("Bearer ").unwrap_or(req.header("authorization")).to_string();
    let iss = g.issuer(req);
    let protos: Vec<&str> = req.header("sec-websocket-protocol").split(',').map(|s| s.trim()).collect();
    let mut reject: Option<(u16, &str, String)> = None;
    let mut claims = Obj::new();
    let mut dev = None;
    if req.path != "/lmbp/v1/connect" {
        reject = Some((404, "BAD_REQUEST", "not found".into()));
    } else if !protos.contains(&lmbp::SUBPROTOCOL) {
        reject = Some((400, "VERSION_UNSUPPORTED", lmbp::VERSION_REQUIRED.into()));
    } else if !req.header("origin").is_empty() {
        reject = Some((403, "FORBIDDEN", "browser origins are not allowed".into()));
    } else {
        match g.verify_access(&Value::String(tok.clone()), &iss) {
            Err(e) => reject = Some((401, "UNAUTHENTICATED", e)),
            Ok(c) => {
                let d = c.get("sub").and_then(|s| s.as_str()).and_then(|s| g.store.get_device(s));
                let ok = d.as_ref().map(|d| {
                    d.status == "active" && Some(d.tenant.as_str()) == c.get("tenant").and_then(|t| t.as_str())
                        && Some(lmbp::thumbprint(&d.pub_).as_str()) == get(c.get("cnf").unwrap_or(&Value::Null), "jkt").as_str()
                });
                if ok != Some(true) {
                    reject = Some((403, "FORBIDDEN", "device revoked or token not bound to device key".into()));
                }
                claims = c;
                dev = d;
            }
        }
    }
    if reject.is_none() && (req.header("sec-websocket-key").is_empty() || req.header("sec-websocket-version") != "13") {
        reject = Some((400, "BAD_REQUEST", "bad WebSocket handshake".into()));
    }
    if let Some((s, c, m)) = reject {
        let b = reject_resp(s, c, &m);
        MutexGuard::unlocked(&mut g, || {
            let _ = out.write_all(&b);
            let _ = out.flush();
        });
        return;
    }
    let resp = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        http::accept_key(req.header("sec-websocket-key")), lmbp::SUBPROTOCOL);
    if out.write_all(resp.as_bytes()).and_then(|_| out.flush()).is_err() {
        return;
    }
    let io = WsIo::new(out);
    let wsid = g.id();
    let io2 = io.clone();
    let timer = g.later(15_000, move |_g| io2.terminate());
    g.wss.insert(wsid, WsState { io: io.clone(), close_fired: false, phase: Phase::Hello { dev: dev.unwrap(), tok, claims, iss, timer } });
    drop(g);
    http::ws_run(&mut inp, &io, lmbp::MAX_FRAME_BYTES, |ev| {
        let mut g = lock();
        on_ws_event(&mut g, wsid, ev);
    });
    let mut g = lock();
    on_ws_close(&mut g, wsid);
}

fn ws_io(g: &Guard, wsid: u64) -> Option<WsIo> {
    g.wss.get(&wsid).map(|w| w.io.clone())
}

fn on_ws_event(g: &mut Guard, wsid: u64, ev: WsEvent) {
    let Some(w) = g.wss.get_mut(&wsid) else { return };
    match &w.phase {
        Phase::Done => {}
        Phase::Hello { .. } => {
            if let WsEvent::Message(raw, binary, _) = ev {
                let Phase::Hello { dev, tok, claims, iss, timer } = std::mem::replace(&mut w.phase, Phase::Done) else { unreachable!() };
                g.cancel(Some(timer));
                on_hello(g, wsid, dev, &tok, claims, &iss, &raw, binary);
            }
        }
        Phase::Session { ds, dev_id, .. } => {
            let (dsh, dev_id) = (*ds, dev_id.clone());
            match ev {
                WsEvent::Pong => {
                    if let Some(d) = g.dstates.get_mut(&dsh) {
                        d.last_seen = lmbp::now_ms();
                    }
                }
                WsEvent::Message(raw, binary, size) => on_session_message(g, wsid, dsh, &dev_id, &raw, binary, size),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn on_hello(g: &mut Guard, wsid: u64, mut dev: Device, tok: &str, claims: Obj, iss: &str, raw: &str, binary: bool) {
    let io = ws_io(g, wsid).unwrap();
    let env = json::parse(raw).unwrap_or(Value::Null);
    let hello = get(&env, "data").clone();
    if binary || get(&env, "type").as_str() != Some("hello") || !hello.is_object() {
        io.close(1000, "");
        return;
    }
    let env_id = id_of(&env);
    let early = |code: &str, msg: &str| {
        io.send(&json::stringify(&envelope("error", env_id.as_deref(), None, Some(error_body(code, msg, false)))));
        io.close(1000, "");
    };
    if !is_version(get(&env, "v")) {
        return early("VERSION_UNSUPPORTED", lmbp::VERSION_REQUIRED);
    }
    // §7.4 order: v, schema (BAD_REQUEST), device/proof (UNAUTHENTICATED), extension semantics.
    if let Some(bad) = params::announce_problem(&hello, true) {
        return early("BAD_REQUEST", &bad);
    }
    let proof_ok = get(&hello, "device_id").as_str() == Some(dev.id.as_str())
        && match lmbp::verify_proof(&dev.pub_, get(&hello, "proof"), &dev.id, lmbp::PROOF_HELLO, tok, lmbp::now()) {
            Ok(pc) => g.use_jti(&json::js_string(pc.get("jti").unwrap_or(&Value::Null)), lmbp::now_ms() + 180_000),
            Err(_) => false,
        };
    if !proof_ok {
        return early("UNAUTHENTICATED", "invalid key proof");
    }
    let mut caps: Vec<String> = vec![];
    if let Some(hc) = get(&hello, "capabilities").as_array() {
        for c in hc {
            if let Some(s) = c.as_str() {
                if lmbp::CAPABILITIES.contains(&s) && !caps.iter().any(|x| x == s) {
                    caps.push(s.into());
                }
            }
        }
    }
    let has = |caps: &Vec<String>, c: &str| caps.iter().any(|x| x == c);
    if !get(&hello, "flow").is_null() && has(&caps, "flow") && !valid_flow(get(&hello, "flow")) {
        return early("BAD_REQUEST", &format!("flow windows must be >= max_frame_bytes ({}) and conn_window >= task_window", lmbp::MAX_FRAME_BYTES));
    }
    if truthy(get(&hello, "e2ee_key")) && has(&caps, "e2ee") {
        if lmbp::verify_e2ee_key(&dev.pub_, &dev.id, get(&hello, "e2ee_key"), lmbp::now()).is_err() {
            return early("BAD_REQUEST", "invalid e2ee key statement");
        }
        dev.e2ee_key = get(&hello, "e2ee_key").as_str().unwrap_or("").into();
        g.store.put_device(dev.clone());
    } else {
        caps.retain(|c| c != "e2ee");
    }
    let conc = get(&hello, "max_concurrency").as_i64().unwrap_or(1).min(g.cfg.max_conc); // validated 1..16; may lower, never raise
    attach_session(g, wsid, dev, claims, iss, env_id, &hello, caps, conc);
}

#[allow(clippy::too_many_arguments)]
fn attach_session(g: &mut Guard, wsid: u64, dev: Device, claims: Obj, iss: &str, env_id: Option<String>, hello: &Value, caps: Vec<String>, conc: i64) {
    let io = ws_io(g, wsid).unwrap();
    let old = g.devs.get(&dev.id).copied();
    let resume = get(hello, "resume").clone();
    let has = |c: &str| caps.iter().any(|x| x == c);
    let resumed = match old {
        Some(h) => resume.is_object() && has("resume") && truthy(get(&resume, "token")) && get(&resume, "token").as_str() == Some(g.dstates[&h].resume_token.as_str()),
        None => false,
    };
    if let (Some(h), false) = (old, resumed) {
        g.devs.remove(&dev.id);
        ds_drop(g, h, "OUTCOME_UNKNOWN", "device reconnected without resuming");
    }
    let dsh = if resumed {
        old.unwrap()
    } else {
        let h = g.id();
        g.dstates.insert(h, DState {
            device_id: dev.id.clone(),
            out: Outbox::default(),
            inb: None,
            ws: None,
            gen: 0,
            models: vec![],
            model_caps: Obj::new(),
            model_names: Obj::new(),
            caps: vec![],
            max_conc: 1,
            token_exp: 0,
            issuer: String::new(),
            resume_token: String::new(),
            tasks: vec![],
            reclaimed: VecDeque::new(),
            slots: 0,
            slot_wait: VecDeque::new(),
            slot_ok: HashSet::new(),
            dropped: false,
            last_seen: lmbp::now_ms(),
        });
        g.devs.insert(dev.id.clone(), h);
        h
    };
    let flow_cfg = g.cfg.flow;
    let ds = g.ds(dsh);
    let prev = ds.ws;
    ds.gen += 1;
    let gen = ds.gen;
    ds.ws = Some(wsid);
    ds.models = get(hello, "models").as_array().cloned().unwrap_or_default();
    ds.model_caps = get(hello, "model_capabilities").as_object().cloned().unwrap_or_default();
    ds.model_names = clean_names(get(hello, "model_names"), &ds.models);
    ds.caps = caps.clone();
    ds.max_conc = conc;
    ds.token_exp = json::int(claims.get("exp").unwrap_or(&Value::Null));
    ds.issuer = iss.into();
    ds.resume_token = lmbp::random_id("rt_");
    match ds.inb.as_mut() {
        None => ds.inb = Some(Inbound::new(if has("flow") { Some(flow_cfg) } else { None })),
        Some(i) => i.reset_windows(),
    }
    let mut resume_tasks = vec![];
    let mut device_recv: HashMap<String, i64> = HashMap::new();
    let mut lost = vec![];
    if resumed {
        if let Some(rts) = get(&resume, "tasks").as_array() {
            for rt in rts {
                device_recv.insert(json::js_string(get(rt, "task_id")), to_int32(get(rt, "recv_seq")));
            }
        }
        let list = g.dstates[&dsh].tasks.clone();
        for (tid, tk) in list {
            let sent = g.tobj.get(&tk).map(|t| t.sent_run).unwrap_or(false);
            if !device_recv.contains_key(&tid) && sent {
                lost.push(tk);
                continue;
            }
            let r = g.dstates[&dsh].inb.as_ref().unwrap().recv(&tid);
            resume_tasks.push(obj! {"task_id" => tid, "recv_seq" => r});
        }
    }
    if let Some(p) = prev.filter(|p| *p != wsid) {
        if let Some(pio) = ws_io(g, p) {
            pio.terminate();
        }
    }
    for tk in lost {
        task_fail_offline(g, tk, "OUTCOME_UNKNOWN", "device resumed without this task; outcome unknown");
    }
    let hf = get(hello, "flow");
    let f = if has("flow") {
        Some(if valid_flow(hf) { Flow { task_window: json::int(get(hf, "task_window")), conn_window: json::int(get(hf, "conn_window")) } } else { Flow { task_window: 1 << 20, conn_window: 4 << 20 } })
    } else {
        None
    };
    g.ds(dsh).out.set_flow(f);
    wake_all();
    let token_exp = g.dstates[&dsh].token_exp;
    let rtok = g.dstates[&dsh].resume_token.clone();
    let mut welcome = obj! {"session_id" => lmbp::random_id("sess_"), "heartbeat_seconds" => (g.cfg.ping_interval / 1000).max(1),
        "max_frame_bytes" => lmbp::MAX_FRAME_BYTES, "token_expires_at" => token_exp, "capabilities" => caps.clone(), "max_concurrency" => conc};
    let wm = welcome.as_object_mut().unwrap();
    if has("flow") {
        wm.insert("flow".into(), obj! {"task_window" => flow_cfg.task_window, "conn_window" => flow_cfg.conn_window});
    }
    if has("resume") {
        wm.insert("resume_token".into(), rtok.into());
        wm.insert("resume_window_seconds".into(), (g.cfg.resume_window / 1000).into());
        if resume.is_object() {
            wm.insert("resume".into(), obj! {"resumed" => resumed, "tasks" => resume_tasks.clone()});
        }
    }
    control(g, dsh, &envelope("welcome", env_id.as_deref(), None, Some(welcome)));
    let wio = io.clone();
    g.ds(dsh).out.attach(Some(Arc::new(move |raw: &str| wio.send(raw))));
    if resumed {
        for rt in &resume_tasks {
            let id = rt["task_id"].as_str().unwrap().to_string();
            let r = device_recv.get(&id).copied().unwrap_or(0);
            g.ds(dsh).out.retransmit(&id, r);
        }
        wake_all();
        log(&format!("device {} resumed {} task(s)", dev.id, resume_tasks.len()));
    } else {
        let ms: Vec<String> = g.dstates[&dsh].models.iter().map(json::js_string).collect();
        log(&format!("device {} (tenant {}) online, models=[{}] caps=[{}] conc={}", dev.id, dev.tenant, ms.join(", "), caps.join(", "), conc));
    }
    let pio = io.clone();
    let pi = g.cfg.ping_interval;
    let ping = g.every(pi, move |g| {
        let Some(ds) = g.dstates.get(&dsh) else { return };
        if lmbp::now() > ds.token_exp + 30 || lmbp::now_ms() - ds.last_seen > 60_000 {
            pio.terminate();
            return;
        }
        pio.ping();
    });
    g.ds(dsh).last_seen = lmbp::now_ms();
    if let Some(w) = g.wss.get_mut(&wsid) {
        w.phase = Phase::Session { ds: dsh, gen, dev_id: dev.id.clone(), ping };
    }
}

fn on_ws_close(g: &mut Guard, wsid: u64) {
    let Some(mut w) = g.wss.remove(&wsid) else { return };
    if w.close_fired {
        return;
    }
    w.close_fired = true;
    match std::mem::replace(&mut w.phase, Phase::Done) {
        Phase::Hello { timer, .. } => g.cancel(Some(timer)),
        Phase::Done => {}
        Phase::Session { ds: dsh, gen, dev_id, ping } => {
            g.cancel(Some(ping));
            let ds = g.ds(dsh);
            if ds.gen != gen {
                return; // replaced by a newer connection
            }
            ds.out.attach(None);
            ds.ws = None;
            if !ds.has_cap("resume") || ds.dropped {
                if g.devs.get(&dev_id) == Some(&dsh) || !g.devs.contains_key(&dev_id) {
                    drop_device(g, &dev_id, "DEVICE_OFFLINE", "device disconnected");
                }
                return;
            }
            let rw = g.cfg.resume_window;
            g.later(rw, move |g| {
                let ds = g.ds(dsh);
                if ds.gen == gen && ds.ws.is_none() {
                    if g.devs.get(&dev_id) == Some(&dsh) {
                        g.devs.remove(&dev_id);
                    }
                    ds_drop(g, dsh, "DEVICE_OFFLINE", "device did not resume in time");
                }
            });
        }
    }
}

fn on_session_message(g: &mut Guard, wsid: u64, dsh: u64, dev_id: &str, raw: &str, binary: bool, size: usize) {
    let io = ws_io(g, wsid).unwrap();
    g.ds(dsh).last_seen = lmbp::now_ms();
    if binary {
        io.close(1003, "text frames only");
        return;
    }
    let inp = json::parse(raw).unwrap_or(Value::Null);
    if !inp.is_object() || !is_version(get(&inp, "v")) {
        return send_ds_err(g, dsh, id_of(&inp).as_deref(), "BAD_REQUEST", "malformed frame");
    }
    let ty = json::js_string(get(&inp, "type"));
    match ty.as_str() {
        "task.delta" | "task.done" | "task.error" => {
            if !on_device_data(g, dsh, &inp, size as i64) {
                io.close(1000, "");
            }
        }
        "task.ack" => {
            let seq = get(get(&inp, "data"), "seq");
            if json::is_int(seq) {
                let tid = json::js_string(get(&inp, "task_id"));
                let s = json::int(seq);
                g.ds(dsh).out.ack(&tid, s);
                wake_all();
            }
        }
        "session.token" => {
            if !refresh_session(g, dsh, dev_id, &inp) {
                send_ds_err(g, dsh, id_of(&inp).as_deref(), "UNAUTHENTICATED", "session token rejected");
                io.close(1000, "");
            }
        }
        "models.update" => {
            let mu = get(&inp, "data");
            if let Some(bad) = params::announce_problem(mu, false) {
                send_ds_err(g, dsh, id_of(&inp).as_deref(), "BAD_REQUEST", &bad); // rejected whole: nothing applied
            } else if let Some(ml) = get(mu, "models").as_array() {
                let max_c = g.cfg.max_conc;
                let ds = g.ds(dsh);
                ds.models = ml.clone();
                ds.model_caps = get(mu, "model_capabilities").as_object().cloned().unwrap_or_default();
                ds.model_names = clean_names(get(mu, "model_names"), &ml);
                if let Some(mx) = get(mu, "max_concurrency").as_i64() {
                    ds.max_conc = mx.min(max_c);
                    wake_slots(g, dsh);
                }
                let e2ee_cap = g.dstates[&dsh].has_cap("e2ee");
                if truthy(get(mu, "e2ee_key")) && e2ee_cap {
                    if let Some(mut dev) = g.store.get_device(dev_id) {
                        if lmbp::verify_e2ee_key(&dev.pub_, &dev.id, get(mu, "e2ee_key"), lmbp::now()).is_ok() {
                            dev.e2ee_key = get(mu, "e2ee_key").as_str().unwrap_or("").into();
                            g.store.put_device(dev);
                        }
                    }
                }
            }
        }
        "ping" => {
            control(g, dsh, &envelope("pong", id_of(&inp).as_deref(), None, None));
        }
        "pong" => {}
        _ => send_ds_err(g, dsh, id_of(&inp).as_deref(), "BAD_REQUEST", &format!("unknown message type {}", ty)),
    }
}

fn on_device_data(g: &mut Guard, dsh: u64, inp: &Value, size: i64) -> bool {
    let tid = json::js_string(get(inp, "task_id"));
    let tk = g.dstates[&dsh].tasks.iter().find(|t| t.0 == tid).map(|t| t.1);
    // envelope + body validated before the seq is accepted, persisted or
    // ACKed: an invalid terminal frame (task.done {}) never becomes SUCCEEDED
    if let Some(bad) = params::device_data_problem(inp) {
        eprintln!("lmbp: device task {}: {}", tid, bad);
        match tk {
            Some(tk) => {
                task_cancel(g, tk, "protocol_error");
                task_fail_local(g, tk, "INTERNAL", &format!("device sent an invalid frame: {}", bad), false);
            }
            None => send_ds_err(g, dsh, id_of(inp).as_deref(), "BAD_REQUEST", &bad),
        }
        return true;
    }
    let seq = get(inp, "seq").as_f64().map(|f| f as i64).unwrap_or(0);
    let Some(tk) = tk else {
        let d = g.ds(dsh);
        if let Some(i) = d.reclaimed.iter().position(|r| r.0 == tid) {
            let acked = d.reclaimed[i].1;
            if seq > acked {
                d.reclaimed[i].1 = seq;
            }
            let ty = json::js_string(get(inp, "type"));
            if ty == "task.done" || ty == "task.error" {
                d.reclaimed.remove(i);
            }
            if seq > acked {
                control(g, dsh, &envelope("task.ack", None, Some(&tid), Some(obj! {"seq" => seq})));
            }
            return true;
        }
        control(g, dsh, &envelope("task.cancel", None, Some(&tid), Some(obj! {"reason" => "unknown_task"})));
        return true;
    };
    match g.ds(dsh).inb.as_mut().unwrap().accept(&tid, seq, size) {
        lmbp::DUPLICATE => {
            task_maybe_ack(g, tk);
            return true;
        }
        lmbp::GAP => {
            task_cancel(g, tk, "protocol_error");
            task_fail_local(g, tk, "INTERNAL", "sequence gap from device", false);
            return true;
        }
        lmbp::OVERFLOW => {
            send_ds_err(g, dsh, Some(""), "FLOW_CONTROL", "flow-control window exceeded");
            task_fail_local(g, tk, "FLOW_CONTROL", "device exceeded the flow-control window", false);
            return false;
        }
        _ => {}
    }
    task_on_device_frame(g, tk, inp, seq);
    true
}

fn refresh_session(g: &mut Guard, dsh: u64, dev_id: &str, inp: &Value) -> bool {
    let st = get(inp, "data").clone();
    let iss = g.dstates[&dsh].issuer.clone();
    let Ok(c) = g.verify_access(get(&st, "access_token"), &iss) else { return false };
    let Some(dev) = g.store.get_device(dev_id) else { return false };
    if c.get("sub").and_then(|s| s.as_str()) != Some(dev_id) || get(c.get("cnf").unwrap_or(&Value::Null), "jkt").as_str() != Some(lmbp::thumbprint(&dev.pub_).as_str()) || dev.status != "active" {
        return false;
    }
    let at = json::js_string(get(&st, "access_token"));
    let Ok(pc) = lmbp::verify_proof(&dev.pub_, get(&st, "proof"), dev_id, lmbp::PROOF_SESSION_TOKEN, &at, lmbp::now()) else { return false };
    if !g.use_jti(&json::js_string(pc.get("jti").unwrap_or(&Value::Null)), lmbp::now_ms() + 180_000) {
        return false;
    }
    let exp = json::int(c.get("exp").unwrap_or(&Value::Null));
    g.ds(dsh).token_exp = exp;
    control(g, dsh, &envelope("session.token", id_of(inp).as_deref(), None, Some(obj! {"token_expires_at" => exp})));
    true
}

// ---------- DState ops ----------
fn control(g: &mut Guard, dsh: u64, e: &Value) -> bool {
    let Some(ws) = g.dstates.get(&dsh).and_then(|d| d.ws) else { return false };
    match ws_io(g, ws) {
        Some(io) if io.is_open() => io.send(&json::stringify(e)),
        _ => false,
    }
}

fn send_ds_err(g: &mut Guard, dsh: u64, id: Option<&str>, code: &str, msg: &str) {
    control(g, dsh, &envelope("error", id, None, Some(error_body(code, msg, false))));
}

fn ds_connected(g: &Guard, dsh: u64) -> bool {
    g.dstates.get(&dsh).map(|d| d.ws.is_some() && !d.dropped).unwrap_or(false)
}

fn acquire(g: &mut Guard, dsh: u64, timeout_ms: i64, signal: &Abort) -> bool {
    let ds = g.ds(dsh);
    if ds.slots < ds.max_conc && ds.slot_wait.is_empty() {
        ds.slots += 1;
        return true;
    }
    let w = g.id();
    g.ds(dsh).slot_wait.push_back(w);
    let deadline = lmbp::now_ms() + timeout_ms;
    loop {
        if g.ds(dsh).slot_ok.remove(&w) {
            return true;
        }
        let left = deadline - lmbp::now_ms();
        if left <= 0 || signal.load(Ordering::SeqCst) {
            g.ds(dsh).slot_wait.retain(|x| *x != w);
            return false;
        }
        wait(g, left.min(1000));
    }
}

fn release(g: &mut Guard, dsh: u64) {
    g.ds(dsh).slots -= 1;
    wake_slots(g, dsh);
}

fn wake_slots(g: &mut Guard, dsh: u64) {
    let ds = g.ds(dsh);
    while !ds.slot_wait.is_empty() && ds.slots < ds.max_conc {
        ds.slots += 1;
        let w = ds.slot_wait.pop_front().unwrap();
        ds.slot_ok.insert(w);
    }
    wake_all();
}

fn ds_drop(g: &mut Guard, dsh: u64, code: &str, msg: &str) {
    let ds = g.ds(dsh);
    ds.dropped = true;
    let w = ds.ws;
    for x in std::mem::take(&mut ds.slot_wait) {
        ds.slot_ok.insert(x);
    }
    ds.out.close();
    let tasks: Vec<u64> = ds.tasks.iter().map(|t| t.1).collect();
    for tk in tasks {
        task_fail_offline(g, tk, code, msg);
    }
    if let Some(io) = w.and_then(|w| ws_io(g, w)) {
        io.close(1000, "");
    }
    wake_all();
}

/// Blocking send through the outbox; returns the assigned seq.
fn out_send(g: &mut Guard, dsh: u64, task_id: &str, build: Value, abort: &Abort) -> lmbp::R<i64> {
    if g.ds(dsh).out.closed {
        return Err("outbox closed".into());
    }
    let tid = task_id.to_string();
    let mk = Box::new(move |seq: i64| {
        let mut m = obj! {"v" => lmbp::VERSION};
        let mo = m.as_object_mut().unwrap();
        for (k, v) in build.as_object().unwrap() {
            mo.insert(k.clone(), v.clone());
        }
        mo.insert("task_id".into(), tid.clone().into());
        mo.insert("seq".into(), seq.into());
        json::stringify(&m)
    });
    let w = g.ds(dsh).out.enqueue(task_id, mk);
    loop {
        if let Some(r) = g.ds(dsh).out.results.remove(&w) {
            let seq = r?;
            g.ds(dsh).out.flush(task_id);
            return Ok(seq);
        }
        if abort.load(Ordering::SeqCst) {
            g.ds(dsh).out.cancel(w);
            if let Some(r) = g.ds(dsh).out.results.remove(&w) {
                let _ = r; // admitted concurrently; drop it like a cancelled send
            }
            return Err("aborted".into());
        }
        wait(g, 1000);
    }
}

// ---------- OpenAI-compatible surface ----------
fn models(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode) {
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    let mut data = vec![];
    for d in g.store.list_devices(&a.tenant, Some(&a.user)) {
        let Some(h) = g.online(&d.id) else { continue };
        if d.status != "active" {
            continue;
        }
        let s = &g.dstates[&h];
        for m in &s.models {
            let c = s.model_caps.get(&json::js_string(m)).cloned().unwrap_or(Value::Null);
            let mut item = obj! {"id" => format!("{}/{}", d.id, json::js_string(m)), "object" => "model", "owned_by" => d.name.clone(),
                "capabilities" => if truthy(&c) { c } else { Value::Array(vec![]) }};
            if let (Some(n), Some(o)) = (s.model_names.get(&json::js_string(m)).cloned(), item.as_object_mut()) {
                o.insert("display_name".into(), n);
            }
            data.push(item);
        }
    }
    if !req.header("anthropic-version").is_empty() {
        return json_res(g, res, 200, &anthropic::models_list(&data));
    }
    json_res(g, res, 200, &obj! {"object" => "list", "data" => data});
}

fn resolve(g: &Guard, tenant: &str, user: &str, model: &str) -> Result<(u64, String), (&'static str, u16)> {
    let list = g.store.list_devices(tenant, Some(user));
    let (mut want, mut dev_id, mut bare) = (model.to_string(), String::new(), true);
    if let Some(i) = model.find('/') {
        if i > 0 && model.starts_with("dev_") {
            dev_id = model[..i].into();
            want = model[i + 1..].into();
            bare = false;
        }
    }
    let (mut known, mut up) = (false, false);
    for d in &list {
        if d.status != "active" || (!bare && d.id != dev_id) {
            continue;
        }
        known = known || !bare;
        if let Some(h) = g.online(&d.id) {
            if g.dstates[&h].models.iter().any(|m| m.as_str() == Some(want.as_str())) {
                return Ok((h, want));
            }
            up = true;
        }
    }
    // §6.6: a named device that is online but lacks the model is 404; only an offline one is 503.
    if known {
        return Err(if up { ("MODEL_NOT_FOUND", 404) } else { ("DEVICE_OFFLINE", 503) });
    }
    let any_online = list.iter().any(|d| g.online(&d.id).is_some());
    if !list.is_empty() && bare && !any_online {
        return Err(("DEVICE_OFFLINE", 503));
    }
    Err(("MODEL_NOT_FOUND", 404))
}

/// Anthropic Messages endpoint: validate, translate, then run chat.
fn messages(g: &mut Guard, req: &Req, res: &mut Res) {
    let mode = Mode::Anthropic;
    if req.method != "POST" {
        return send_err(g, res, mode, 405, "BAD_REQUEST", "POST required");
    }
    if tenant_auth(g, req, res, mode).is_none() {
        return;
    }
    let Some(body) = &req.body else { return send_err(g, res, mode, 413, "PAYLOAD_TOO_LARGE", "request body too large") };
    let Some(r) = serde_json::from_slice::<Value>(body).ok().and_then(|v| v.as_object().cloned()) else {
        return send_err(g, res, mode, 400, "BAD_REQUEST", "invalid JSON body");
    };
    if let Err(e) = params::validate_anthropic_params(&r) {
        return json_res(g, res, 400, &params::param_error_body(&e, true));
    }
    let out = match anthropic::to_openai(&r) {
        Ok(o) => o,
        Err(e) => return send_err(g, res, mode, 400, "BAD_REQUEST", &e),
    };
    let b = json::stringify(&out).into_bytes();
    chat(g, req, res, mode, Some(b), true)
}

pub struct Blob {
    pub r: Value,
    pub data: Vec<u8>,
}

fn chat(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode, pre_body: Option<Vec<u8>>, anthropic: bool) {
    if req.method != "POST" {
        return send_err(g, res, mode, 405, "BAD_REQUEST", "POST required");
    }
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    let Some(body) = pre_body.or_else(|| req.body.clone()) else {
        return send_err(g, res, mode, 413, "PAYLOAD_TOO_LARGE", "request body too large");
    };
    let Some(r) = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v.as_object().cloned()) else {
        return send_err(g, res, mode, 400, "BAD_REQUEST", "invalid JSON body");
    };
    // Every parameter is validated before anything is stored, queued or signed.
    let params = match params::validate_chat_params(&r) {
        Ok(p) => p,
        Err(e) => return json_res(g, res, 400, &params::param_error_body(&e, anthropic)),
    };
    let idem_key = req.header("idempotency-key").to_string();
    if !idem_key.is_empty() && !lmbp::valid_header(&idem_key, 255) {
        return send_err(g, res, mode, 400, "BAD_REQUEST", "Idempotency-Key must be 1-255 printable ASCII characters");
    }
    let body_hash = lmbp::hex(&lmbp::sha256(&body));
    let (tenant, user) = (a.tenant.clone(), a.user.clone());
    let req_model = r["model"].as_str().unwrap().to_string();
    let stream = r.get("stream") == Some(&Value::Bool(true));
    let prior = if idem_key.is_empty() { None } else { g.store.get_idempotency(&tenant, &user, &idem_key) };
    if let Some(p) = prior {
        if p.tenant != tenant || p.owner != user {
            return send_err(g, res, mode, 500, "INTERNAL", "idempotency store returned a foreign record");
        }
        if p.body_hash != body_hash {
            return send_err(g, res, mode, 422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body");
        }
        return reattach(g, req, res, mode, &tenant, &user, &p.task_id, &req_model, stream, anthropic);
    }
    let mut msgs = r.get("messages").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let tools = r.get("tools").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let has_tool_choice = r.get("tool_choice").map(|v| !v.is_null()).unwrap_or(false);
    let e2ee = truthy(r.get("lmbp_e2ee").unwrap_or(&Value::Null));
    if e2ee {
        if !msgs.is_empty() || !tools.is_empty() {
            return send_err(g, res, mode, 400, "BAD_REQUEST", "lmbp_e2ee requests must not carry cleartext messages or tools");
        }
    } else {
        if msgs.is_empty() || msgs.len() > lmbp::MAX_MESSAGES {
            return send_err(g, res, mode, 400, "BAD_REQUEST", &format!("1-{} messages required", lmbp::MAX_MESSAGES));
        }
        for m in &msgs {
            let role = get(m, "role");
            let Some(rs) = role.as_str().filter(|r| ROLES.contains(r)) else {
                return send_err(g, res, mode, 400, "BAD_REQUEST", &format!("unsupported role {}", json::js_string(role)));
            };
            if rs == "tool" && !truthy(get(m, "tool_call_id")) {
                return send_err(g, res, mode, 400, "BAD_REQUEST", "tool messages need tool_call_id");
            }
        }
    }
    let (dsh, model) = match resolve(g, &tenant, &user, &req_model) {
        Ok(x) => x,
        Err((code, status)) => {
            return send_err(g, res, mode, status, code, if code == "DEVICE_OFFLINE" { "your device is offline" } else { "model not found on your devices" });
        }
    };
    let dev_id = g.dstates[&dsh].device_id.clone();
    let mut run = obj! {"task_id" => "", "iat" => 0, "device_id" => dev_id.clone(), "model" => model.clone()};
    let rm = run.as_object_mut().unwrap();
    let mut blobs: Vec<Blob> = vec![];
    let mc: Vec<String> = g.dstates[&dsh].model_caps.get(&model).and_then(|v| v.as_array()).map(|a| a.iter().map(json::js_string).collect()).unwrap_or_default();
    let mch = |c: &str| mc.iter().any(|x| x == c);
    let caps = g.dstates[&dsh].caps.clone();
    let has = |c: &str| caps.iter().any(|x| x == c);
    if e2ee {
        if !has("e2ee") {
            return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", "device does not support end-to-end encryption");
        }
        let jwe = match &r["lmbp_e2ee"] {
            Value::String(s) => s.clone(),
            v => json::stringify(v),
        };
        if jwe.split('.').count() != 5 || jwe.len() > lmbp::MAX_TASK_BLOB_BYTES {
            return send_err(g, res, mode, 400, "BAD_REQUEST", "lmbp_e2ee must be a compact JWE");
        }
        let id = lmbp::random_id("blob_");
        let data = jwe.into_bytes();
        blobs.push(Blob { r: obj! {"id" => id.clone(), "size" => data.len(), "sha256" => lmbp::b64(&lmbp::sha256(&data)), "media_type" => "application/jose"}, data });
        rm.insert("e2ee".into(), obj! {"blob" => id});
    } else {
        let ex = match extract_blobs(&mut msgs) {
            Ok(x) => x,
            Err((code, msg)) => return send_err(g, res, mode, err_status(code), code, &msg),
        };
        blobs = ex.blobs;
        if !tools.is_empty() || has_tool_choice {
            if !has("tools") || !mch("tools") {
                return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", &format!("model {} does not support tools", model));
            }
            for tl in &tools {
                if get(tl, "type").as_str() != Some("function") || !truthy(get(get(tl, "function"), "name")) {
                    return send_err(g, res, mode, 400, "BAD_REQUEST", "tools must be type function with a name");
                }
            }
        }
        if (ex.vision || ex.audio) && !has("multimodal") {
            return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", "device does not support multimodal input");
        }
        if ex.vision && !mch("vision") {
            return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", &format!("model {} does not accept images", model));
        }
        if ex.audio && !mch("audio") {
            return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", &format!("model {} does not accept audio", model));
        }
        let nm: Vec<Value> = msgs.iter().map(norm_message).collect();
        rm.insert("messages".into(), Value::Array(nm));
        if !tools.is_empty() {
            rm.insert("tools".into(), Value::Array(tools.clone()));
        }
        if has_tool_choice {
            rm.insert("tool_choice".into(), r["tool_choice"].clone());
        }
    }
    if params.max_tokens != 0 {
        rm.insert("max_tokens".into(), params.max_tokens.into());
    }
    if let Some(t) = &params.temperature {
        rm.insert("temperature".into(), t.clone());
    }
    if let Some(t) = &params.top_p {
        rm.insert("top_p".into(), t.clone());
    }
    if let Some(s) = &params.stop {
        rm.insert("stop".into(), Value::Array(s.clone()));
    }
    // Per-model parameter support (spec §16.4): a model that declares "params" gets every
    // other parameter rejected; on /v1/messages the mandatory max_tokens is dropped instead.
    if mch("params") {
        if rm.contains_key("max_tokens") && anthropic && !mch("max_tokens") {
            rm.remove("max_tokens");
        }
        for flag in ["temperature", "top_p", "stop", "max_tokens"] {
            if rm.contains_key(flag) && !mch(flag) {
                let name = if anthropic && flag == "stop" { "stop_sequences" } else { flag };
                return send_err(g, res, mode, 400, "CAPABILITY_UNSUPPORTED", &format!("model {} does not support the {} parameter", model, name));
            }
        }
    }
    if !blobs.is_empty() {
        rm.insert("blobs".into(), Value::Array(blobs.iter().map(|b| b.r.clone()).collect()));
    }
    let task_id = lmbp::random_id("task_");
    {
        // limits (spec §10): the signed task.run frame MUST fit max_frame_bytes and satisfy the schema
        let iat = lmbp::now();
        let mut payload = run.clone();
        let pm = payload.as_object_mut().unwrap();
        pm.insert("task_id".into(), task_id.clone().into());
        pm.insert("iat".into(), iat.into());
        pm.insert("exp".into(), (iat + 60).into());
        pm.insert("nonce".into(), lmbp::random_id("n_").into());
        let trial = g.sign(lmbp::TYP_TASK, &payload);
        let size = lmbp::task_run_frame_size(&trial, &task_id);
        if size > lmbp::MAX_FRAME_BYTES {
            return send_err(g, res, mode, 413, "PAYLOAD_TOO_LARGE", &format!(
                "request too large: the signed task.run frame would be {} bytes, over max_frame_bytes {}; send large content as images/attachments", size, lmbp::MAX_FRAME_BYTES));
        }
        if let Err(e) = params::validate_task_run(&payload) {
            return json_res(g, res, 400, &params::param_error_body(&e, anthropic));
        }
    }
    let rec = TaskRecord { id: task_id.clone(), tenant: tenant.clone(), owner: user.clone(), device: dev_id, model: model.clone(), state: "QUEUED".into(), events: vec![], finished: 0 };
    let ik = if idem_key.is_empty() { None } else { Some(idem_key.as_str()) };
    let irec = ik.map(|_| Idempotency { tenant: tenant.clone(), owner: user.clone(), task_id: task_id.clone(), body_hash: body_hash.clone() });
    if g.store.create_task(rec, ik, irec).is_err() {
        // one atomic write: a key never exists without its task
        if let Some(k) = ik {
            if let Some(won) = g.store.get_idempotency(&tenant, &user, k).filter(|w| w.body_hash == body_hash) {
                return reattach(g, req, res, mode, &tenant, &user, &won.task_id, &req_model, stream, anthropic);
            }
            return send_err(g, res, mode, 422, "IDEMPOTENCY_KEY_REUSED", "Idempotency-Key was used with a different request body");
        }
        return send_err(g, res, mode, 500, "INTERNAL", "storage error");
    }
    let has_e2ee = run.get("e2ee").is_some();
    let tk = task_new(g, Some(dsh), &task_id, &tenant, &user, &req_model, has_e2ee, !idem_key.is_empty());
    let abort = req.abort.clone();
    let qt = g.cfg.queue_timeout as i64;
    let got = acquire(g, dsh, qt, &abort);
    let tdone = g.tobj[&tk].done;
    if !got || !ds_connected(g, dsh) || tdone {
        if got {
            release(g, dsh);
        }
        res.set_header("X-Task-Id", &task_id);
        if !ds_connected(g, dsh) {
            task_fail_local(g, tk, "DEVICE_OFFLINE", "device disconnected", true);
            return send_err(g, res, mode, 503, "DEVICE_OFFLINE", "device disconnected");
        }
        if g.tobj[&tk].done {
            return serve(g, res, tk, 0, stream, &abort, anthropic);
        }
        task_fail_local(g, tk, "DEVICE_BUSY", "device is at max concurrency", true);
        if abort.load(Ordering::SeqCst) {
            return;
        }
        res.set_header("Retry-After", "2");
        return send_err(g, res, mode, 429, "DEVICE_BUSY", "device is at max concurrency");
    }
    g.tobj.get_mut(&tk).unwrap().slot = true;
    set_task_state(g, &task_id, "RUNNING");
    let iat = lmbp::now();
    let mut signed = run;
    let sm = signed.as_object_mut().unwrap();
    sm.insert("task_id".into(), task_id.clone().into());
    sm.insert("iat".into(), iat.into());
    sm.insert("exp".into(), (iat + 60).into());
    sm.insert("nonce".into(), lmbp::random_id("n_").into());
    let jws = g.sign(lmbp::TYP_TASK, &signed);
    g.tobj.get_mut(&tk).unwrap().sent_run = true;
    std::thread::spawn(move || {
        let mut g = lock();
        dispatch(&mut g, tk, jws, blobs);
    });
    res.set_header("X-Task-Id", &task_id);
    serve(g, res, tk, 0, stream, &abort, anthropic)
}

/// Non-terminal states only; terminal states are written with their terminal event.
fn set_task_state(g: &mut Guard, id: &str, state: &str) {
    if let Some(rec) = g.store.get_task(id) {
        if !crate::store::TERMINAL.contains(&rec.state.as_str()) {
            g.store.set_state(id, state);
        }
    }
}

fn dispatch(g: &mut Guard, tk: u64, jws: String, blobs: Vec<Blob>) {
    let Some(t) = g.tobj.get_mut(&tk) else { return };
    t.sent_run = true;
    let (dsh, id, abort) = (t.ds.unwrap(), t.id.clone(), t.abort.clone());
    if out_send(g, dsh, &id, obj! {"type" => "task.run", "jws" => jws}, &abort).is_err() {
        if let Some(t) = g.tobj.get_mut(&tk) {
            t.sent_run = false;
        }
        task_fail_offline(g, tk, "DEVICE_OFFLINE", "device disconnected");
        return;
    }
    for b in &blobs {
        let mut off = 0;
        loop {
            let end = (off + lmbp::BLOB_CHUNK_BYTES).min(b.data.len());
            let mut data = obj! {"blob_id" => b.r["id"].clone(), "offset" => off, "data" => lmbp::b64(&b.data[off..end])};
            if end == b.data.len() {
                data.as_object_mut().unwrap().insert("last".into(), true.into());
            }
            if out_send(g, dsh, &id, obj! {"type" => "blob.chunk", "data" => data}, &abort).is_err() {
                return;
            }
            if end == b.data.len() {
                break;
            }
            off += lmbp::BLOB_CHUNK_BYTES;
        }
    }
}

/// Every replay re-verifies the task's tenant and owner; a live task is served from memory first.
#[allow(clippy::too_many_arguments)]
fn reattach(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode, tenant: &str, owner: &str, task_id: &str, req_model: &str, stream: bool, anthropic: bool) {
    let live = g.tasks.get(task_id).copied().filter(|tk| g.tobj.contains_key(tk));
    let tk = match live {
        Some(tk) => {
            let t = &g.tobj[&tk];
            if t.tenant != tenant || t.owner != owner {
                return send_err(g, res, mode, 404, "BAD_REQUEST", "task no longer available");
            }
            tk
        }
        None => {
            let ok = g.store.get_task(task_id).map(|r| r.tenant == tenant && r.owner == owner).unwrap_or(false);
            if !ok {
                return send_err(g, res, mode, 404, "BAD_REQUEST", "task no longer available");
            }
            task_finished(g, task_id, req_model)
        }
    };
    let after = parse_leading_int(req.header("last-event-id"));
    res.set_header("X-Task-Id", task_id);
    serve(g, res, tk, after, stream, &req.abort, anthropic);
}

/// parseInt(s, 10) || 0.
fn parse_leading_int(s: &str) -> i64 {
    let t = s.trim_start();
    let (sign, rest) = match t.as_bytes().first() {
        Some(b'-') => (-1, &t[1..]),
        Some(b'+') => (1, &t[1..]),
        _ => (1, t),
    };
    let d: String = rest.chars().take_while(|c| c.is_ascii_digit()).take(15).collect();
    d.parse::<i64>().map(|n| n * sign).unwrap_or(0)
}

fn task_events(g: &mut Guard, req: &Req, res: &mut Res, mode: Mode, id: &str) {
    let Some(a) = tenant_auth(g, req, res, mode) else { return };
    let rec = g.store.get_task(id).filter(|r| r.tenant == a.tenant && r.owner == a.user).map(|r| format!("{}/{}", r.device, r.model));
    let Some(m) = rec else { return send_err(g, res, mode, 404, "BAD_REQUEST", "task not found") };
    reattach(g, req, res, mode, &a.tenant, &a.user, id, &m, true, false);
}

pub const SSE_HEADERS: [(&str, &str); 3] = [("Content-Type", "text/event-stream"), ("Cache-Control", "no-cache"), ("X-Accel-Buffering", "no")];

pub struct TInfo {
    pub id: String,
    pub created: i64,
    pub req_model: String,
    pub e2ee: bool,
}

pub fn tinfo(g: &Guard, tk: u64) -> TInfo {
    let t = &g.tobj[&tk];
    TInfo { id: t.id.clone(), created: t.created, req_model: t.req_model.clone(), e2ee: t.e2ee }
}

fn serve(g: &mut Guard, res: &mut Res, tk: u64, after: i64, stream: bool, signal: &Abort, anthropic: bool) {
    serve_inner(g, res, tk, after, stream, signal, anthropic);
    // A replayed task lives only for this response.
    if g.tobj.get(&tk).map(|t| t.replayed).unwrap_or(false) {
        g.tobj.remove(&tk);
    }
}

fn serve_inner(g: &mut Guard, res: &mut Res, tk: u64, after: i64, stream: bool, signal: &Abort, anthropic: bool) {
    if anthropic {
        return anthropic::serve(g, res, tk, after, stream, signal);
    }
    let t = tinfo(g, tk);
    if stream {
        res.write_head(g, 200, &SSE_HEADERS);
        if after == 0 {
            let c = chunk(&t, obj! {"role" => "assistant", "content" => ""}, Value::Null, &Value::Null, None);
            res.write(g, &format!("id: 0\ndata: {}\n\n", c));
        }
        let mut wrote = false;
        let ok = task_stream(g, tk, after, signal, true, &mut |g, se| {
            let e = match se {
                SE::Keepalive => return res.write(g, ": keep-alive\n\n"),
                SE::Ev(e) => e,
            };
            wrote = true;
            let mut tail = "";
            let b = if e.ty == "task.delta" {
                if t.e2ee {
                    chunk(&t, obj! {}, Value::Null, &Value::Null, sealed(&e))
                } else {
                    let mut delta = obj! {};
                    let dm = delta.as_object_mut().unwrap();
                    if truthy(get(&e.data, "text")) {
                        dm.insert("content".into(), e.data["text"].clone());
                    }
                    if let Some(tc) = get(&e.data, "tool_calls").as_array().filter(|a| !a.is_empty()) {
                        dm.insert("tool_calls".into(), Value::Array(tc.clone()));
                    }
                    chunk(&t, delta, Value::Null, &Value::Null, None)
                }
            } else if e.ty == "task.done" {
                let fr = get(&e.data, "finish_reason");
                tail = "data: [DONE]\n\n";
                chunk(&t, obj! {}, if truthy(fr) { fr.clone() } else { "stop".into() }, get(&e.data, "usage"), if t.e2ee { sealed(&e) } else { None })
            } else {
                let eb = &e.data;
                json::stringify(&obj! {"error" => obj!{"message" => get(eb, "message").clone(), "type" => "lmbp_error", "code" => get(eb, "code").clone(), "retryable" => truthy(get(eb, "retryable"))}})
            };
            res.write(g, &format!("id: {}\ndata: {}\n\n{}", e.seq, b, tail))
        });
        // Last-Event-ID at or beyond the terminal event: end with the terminator.
        if ok && !wrote {
            res.write(g, "data: [DONE]\n\n");
        }
        res.end(g, None);
        return;
    }
    let mut text = String::new();
    let mut calls: Vec<Value> = vec![];
    let mut sealed_frames = vec![];
    let mut done: Option<Value> = None;
    let mut fail: Option<Value> = None;
    let ok = task_stream(g, tk, after, signal, false, &mut |_g, se| {
        let SE::Ev(e) = se else { return true };
        if e.ty == "task.delta" {
            if t.e2ee {
                if let Some(s) = sealed(&e) {
                    sealed_frames.push(s["lmbp_e2ee"].clone());
                }
                return true;
            }
            let tx = get(&e.data, "text");
            if truthy(tx) {
                text.push_str(&json::js_string(tx));
            }
            merge_calls(&mut calls, get(&e.data, "tool_calls"));
        } else if e.ty == "task.done" {
            done = Some(e.data.clone());
            if t.e2ee {
                if let Some(s) = sealed(&e) {
                    sealed_frames.push(s["lmbp_e2ee"].clone());
                }
            }
        } else {
            fail = Some(e.data.clone());
        }
        true
    });
    if !ok {
        return;
    }
    if let Some(f) = fail {
        let code = json::js_string(get(&f, "code"));
        let msg = get(&f, "message").as_str().unwrap_or("").to_string();
        return api_error_v(g, res, err_status(&code), &code, get(&f, "message").as_str().map(|_| Value::String(msg)).unwrap_or(Value::Null));
    }
    let done = done.unwrap_or(Value::Null);
    let fr = get(&done, "finish_reason");
    let finish = if truthy(fr) { fr.clone() } else { "stop".into() };
    let mut msg = obj! {"role" => "assistant", "content" => text.clone()};
    if !calls.is_empty() {
        let tcs: Vec<Value> = calls.iter().map(|c| {
            let mut o = obj! {};
            let om = o.as_object_mut().unwrap();
            if !get(c, "id").is_null() {
                om.insert("id".into(), c["id"].clone());
            }
            om.insert("type".into(), "function".into());
            om.insert("function".into(), c["function"].clone());
            o
        }).collect();
        let mm = msg.as_object_mut().unwrap();
        mm.insert("tool_calls".into(), Value::Array(tcs));
        if text.is_empty() {
            mm.insert("content".into(), Value::Null);
        }
    }
    let mut out = obj! {"id" => format!("chatcmpl-{}", t.id), "object" => "chat.completion", "created" => t.created, "model" => t.req_model.clone(),
        "choices" => vec![obj!{"index" => 0, "message" => msg, "finish_reason" => finish.clone()}]};
    let om = out.as_object_mut().unwrap();
    if t.e2ee {
        om.insert("choices".into(), Value::Array(vec![obj! {"index" => 0, "message" => obj!{"role" => "assistant", "content" => Value::Null}, "finish_reason" => finish}]));
        om.insert("lmbp_e2ee".into(), Value::Array(sealed_frames));
    }
    let usage = get(&done, "usage");
    if truthy(usage) {
        om.insert("usage".into(), usage.clone());
    }
    json_res(g, res, 200, &out);
}

/// Accumulate OpenAI tool_call deltas by index.
pub fn merge_calls(calls: &mut Vec<Value>, deltas: &Value) {
    let Some(ds) = deltas.as_array() else { return };
    for c in ds {
        let ix = get(c, "index");
        let mut idx = if json::is_int(ix) { json::int(ix) } else { 0 };
        if !(0..=1024).contains(&idx) {
            idx = 0;
        }
        while calls.len() as i64 <= idx {
            calls.push(obj! {"type" => "function", "function" => obj!{"name" => "", "arguments" => ""}});
        }
        let call = calls[idx as usize].as_object_mut().unwrap();
        if truthy(get(c, "id")) {
            call.insert("id".into(), c["id"].clone());
        }
        let fnv = get(c, "function");
        let (nm, ar) = (get(fnv, "name"), get(fnv, "arguments"));
        let f = call.get_mut("function").unwrap().as_object_mut().unwrap();
        let n0 = f["name"].as_str().unwrap_or("").to_string();
        let a0 = f["arguments"].as_str().unwrap_or("").to_string();
        f.insert("name".into(), format!("{}{}", n0, if truthy(nm) { json::js_string(nm) } else { String::new() }).into());
        f.insert("arguments".into(), format!("{}{}", a0, if truthy(ar) { json::js_string(ar) } else { String::new() }).into());
    }
}

fn sealed(e: &Event) -> Option<Value> {
    match get(&e.data, "e2ee") {
        Value::String(s) if !s.is_empty() => Some(obj! {"lmbp_e2ee" => obj!{"seq" => e.seq, "type" => e.ty.clone(), "data" => s.clone()}}),
        _ => None,
    }
}

fn chunk(t: &TInfo, delta: Value, finish: Value, usage: &Value, extra: Option<Value>) -> String {
    let mut m = obj! {"id" => format!("chatcmpl-{}", t.id), "object" => "chat.completion.chunk", "created" => t.created, "model" => t.req_model.clone(),
        "choices" => vec![obj!{"index" => 0, "delta" => delta, "finish_reason" => finish}]};
    let mm = m.as_object_mut().unwrap();
    if truthy(usage) {
        mm.insert("usage".into(), usage.clone());
    }
    if let Some(Value::Object(x)) = extra {
        for (k, v) in x {
            mm.insert(k, v);
        }
    }
    json::stringify(&m)
}

// ---------- helpers ----------
pub fn json_res(g: &mut Guard, res: &mut Res, status: u16, body: &Value) {
    let b = json::stringify(body);
    let ct = res.get_header("Content-Type").unwrap_or("application/json").to_string();
    // §6.1: every JSON response is no-store unless the route set its own policy (JWKS/metadata).
    if res.get_header("Cache-Control").is_none() {
        res.set_header("Cache-Control", "no-store");
    }
    res.send(g, status, &ct, b.as_bytes());
}

pub fn problem_body(status: u16, code: &str, detail: &str) -> Value {
    obj! {"type" => format!("{}{}", PROBLEM_BASE, code.to_lowercase().replace('_', "-")), "title" => code, "status" => status, "detail" => detail, "code" => code}
}

pub fn problem(g: &mut Guard, res: &mut Res, status: u16, code: &str, detail: &str) {
    res.set_header("Content-Type", "application/problem+json");
    res.set_header("Cache-Control", "no-store");
    json_res(g, res, status, &problem_body(status, code, detail));
}

fn api_error(g: &mut Guard, res: &mut Res, status: u16, code: &str, message: &str) {
    api_error_v(g, res, status, code, Value::String(message.into()))
}

fn api_error_v(g: &mut Guard, res: &mut Res, status: u16, code: &str, message: Value) {
    json_res(g, res, status, &obj! {"error" => obj!{"message" => message, "type" => "lmbp_error", "code" => code}});
}

fn oauth_error(g: &mut Guard, res: &mut Res, status: u16, error: &str) {
    res.set_header("Cache-Control", "no-store");
    json_res(g, res, status, &obj! {"error" => error});
}

/// OAuth request as form-urlencoded (normative) or JSON (accepted).
fn form_params(req: &Req, max: usize) -> Option<HashMap<String, String>> {
    let b = req.body.as_ref().filter(|b| b.len() <= max)?;
    let s = String::from_utf8_lossy(b);
    let mut out = HashMap::new();
    if req.header("content-type").starts_with("application/x-www-form-urlencoded") {
        for kv in s.split('&') {
            if kv.is_empty() {
                continue;
            }
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let (k, v) = (http::dec(k), http::dec(v));
            if out.contains_key(&k) {
                return None;
            }
            out.insert(k, v);
        }
        return Some(out);
    }
    let m = json::parse(&s)?;
    for (k, v) in m.as_object()? {
        if let Some(v) = v.as_str() {
            out.insert(k.clone(), v.into());
        }
    }
    Some(out)
}

fn user_code() -> String {
    let s: String = (0..8).map(|_| USER_CODE_CHARS[lmbp::random_below(USER_CODE_CHARS.len() as u32) as usize] as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

pub fn norm_code(s: &str) -> String {
    let s: String = s.trim().replace(['-', ' '], "").to_uppercase();
    if s.chars().count() == 8 && s.is_ascii() { format!("{}-{}", &s[..4], &s[4..]) } else { String::new() }
}

fn norm_message(m: &Value) -> Value {
    let content = if json::has(m, "content") { m["content"].clone() } else { "".into() };
    let mut o = obj! {"role" => get(m, "role").clone(), "content" => content};
    for k in ["name", "tool_calls", "tool_call_id"] {
        let v = get(m, k);
        if !v.is_null() && v.as_str() != Some("") {
            o.as_object_mut().unwrap().insert(k.into(), v.clone());
        }
    }
    o
}

struct Extracted {
    blobs: Vec<Blob>,
    vision: bool,
    audio: bool,
}

/// extract_blobs moves large inline binaries (data: URIs, input_audio) into blobs (§16.3).
fn extract_blobs(msgs: &mut [Value]) -> Result<Extracted, (&'static str, String)> {
    let mut x = Extracted { blobs: vec![], vision: false, audio: false };
    let mut total = 0usize;
    let mut add = |x: &mut Extracted, data: Vec<u8>, mt: String| -> Option<String> {
        total += data.len();
        if data.len() > lmbp::MAX_BLOB_BYTES || total > lmbp::MAX_TASK_BLOB_BYTES {
            return None;
        }
        let id = lmbp::random_id("blob_");
        x.blobs.push(Blob { r: obj! {"id" => id.clone(), "size" => data.len(), "sha256" => lmbp::b64(&lmbp::sha256(&data)), "media_type" => mt}, data });
        Some(format!("{}{}", lmbp::BLOB_SCHEME, id))
    };
    for m in msgs.iter_mut() {
        let Some(parts) = m.get_mut("content").and_then(|c| c.as_array_mut()) else { continue };
        for p in parts.iter_mut() {
            let ty = get(p, "type").clone();
            match ty.as_str().unwrap_or("") {
                "text" => {}
                "image_url" => {
                    x.vision = true;
                    let Some(iu) = p.get_mut("image_url").and_then(|v| v.as_object_mut()) else { return Err(("BAD_REQUEST", "image_url part without url".to_string())) };
                    let Some(u) = iu.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()) else { return Err(("BAD_REQUEST", "image_url part without url".to_string())) };
                    if u.starts_with("https://") {
                        continue;
                    }
                    if !u.starts_with("data:") {
                        return Err(("BAD_REQUEST", "image_url must be https:// or a data: URI".to_string()));
                    }
                    let comma = u.find(',');
                    let meta = comma.map(|c| &u[5..c]).unwrap_or("");
                    if comma.is_none() || !meta.ends_with(";base64") || !meta.starts_with("image/") {
                        return Err(("BAD_REQUEST", "image data URI must be data:image/*;base64,".to_string()));
                    }
                    if u.encode_utf16().count() <= lmbp::INLINE_DATA_URI_BYTES {
                        continue;
                    }
                    let Some(raw) = lmbp::std_b64_strict(&u[comma.unwrap() + 1..]) else { return Err(("BAD_REQUEST", "invalid base64 in image data URI".to_string())) };
                    let Some(r) = add(&mut x, raw, meta[..meta.len() - 7].to_string()) else { return Err(("PAYLOAD_TOO_LARGE", "image exceeds size limits".to_string())) };
                    iu.insert("url".into(), r.into());
                }
                "input_audio" => {
                    x.audio = true;
                    let bad = Err(("BAD_REQUEST", "input_audio needs data and format wav|mp3".to_string()));
                    let Some(a) = p.get_mut("input_audio").and_then(|v| v.as_object_mut()) else { return bad };
                    let fmt = a.get("format").and_then(|f| f.as_str()).unwrap_or("").to_string();
                    let Some(data) = a.get("data").and_then(|d| d.as_str()).map(|s| s.to_string()) else { return bad };
                    if fmt != "wav" && fmt != "mp3" {
                        return bad;
                    }
                    if data.encode_utf16().count() <= lmbp::INLINE_DATA_URI_BYTES {
                        continue;
                    }
                    let Some(raw) = lmbp::std_b64_strict(&data) else { return Err(("BAD_REQUEST", "invalid base64 in input_audio".to_string())) };
                    let Some(r) = add(&mut x, raw, format!("audio/{}", fmt)) else { return Err(("PAYLOAD_TOO_LARGE", "audio exceeds size limits".to_string())) };
                    a.insert("data".into(), r.into());
                }
                _ => {
                    let d = if ty.is_null() && !json::has(p, "type") { "undefined".to_string() } else { json::js_string(&ty) };
                    return Err(("BAD_REQUEST", format!("unsupported content part {}", d)));
                }
            }
        }
    }
    Ok(x)
}

// =====================================================================
// Task: gateway-side hub of one task; buffers device frames, fans them out to
// (re-)attached HTTP subscribers and paces task.ack (§8).

#[allow(clippy::too_many_arguments)]
fn task_new(g: &mut Guard, ds: Option<u64>, id: &str, tenant: &str, owner: &str, req_model: &str, e2ee: bool, idempotent: bool) -> u64 {
    let tk = g.id();
    g.tobj.insert(tk, Task {
        ds,
        id: id.into(),
        tenant: tenant.into(),
        owner: owner.into(),
        req_model: req_model.into(),
        e2ee,
        idempotent,
        created: lmbp::now(),
        sent_run: false,
        done: false,
        decided: false,
        replayed: false,
        slot: false,
        abort: Arc::new(AtomicBool::new(false)),
        events: vec![],
        subs: vec![],
        next_sub: 0,
        acked: 0,
        persisted: 0,
        seen: 0,
        out_bytes: 0,
        ack_at: lmbp::now_ms(),
        grace: None,
        timeout: None,
        watch: None,
    });
    let Some(dsh) = ds else { return tk };
    g.tasks.insert(id.into(), tk);
    g.ds(dsh).tasks.push((id.into(), tk));
    let tt = g.cfg.task_timeout;
    let timeout = g.later(tt, move |g| {
        if task_cancel(g, tk, "timeout") {
            task_fail_local(g, tk, "TIMEOUT", "task timed out", false);
        }
    });
    let slow = g.cfg.slow_consumer;
    let watch = g.every(1000, move |g| {
        let Some(t) = g.tobj.get(&tk) else { return };
        let stalled = !t.subs.is_empty() && task_recv_seq(g, tk) > t.acked && lmbp::now_ms() - t.ack_at > slow;
        if stalled && task_cancel(g, tk, "slow_consumer") {
            task_fail_local(g, tk, "SLOW_CONSUMER", "client did not consume the stream in time", false);
        }
    });
    let t = g.tobj.get_mut(&tk).unwrap();
    t.timeout = Some(timeout);
    t.watch = Some(watch);
    tk
}

/// A finished task rebuilt from the store; an inconsistent or missing terminal yields
/// OUTCOME_UNKNOWN (served, never stored).
fn task_finished(g: &mut Guard, task_id: &str, req_model: &str) -> u64 {
    let rec = g.store.get_task(task_id).unwrap();
    let (id, tenant, owner, state) = (rec.id.clone(), rec.tenant.clone(), rec.owner.clone(), rec.state.clone());
    let mut events = rec.events.clone();
    let tk = task_new(g, None, &id, &tenant, &owner, req_model, false, false);
    let last = events.last().cloned();
    let last_seq = last.as_ref().map(|e| e.seq).unwrap_or(0);
    let consistent = last.as_ref().map(|l| is_terminal(&l.ty) && if l.ty == "task.done" { state == "SUCCEEDED" } else { state == "FAILED" || state == "CANCELLED" }).unwrap_or(false);
    if !consistent {
        if let Some(l) = last.as_ref().filter(|l| is_terminal(&l.ty)) {
            log(&format!("lmbp: task {}: stored terminal {} disagrees with state {}; reporting OUTCOME_UNKNOWN", id, l.ty, state));
            events.pop();
        }
        events.push(Event { seq: last_seq + 1, ty: "task.error".into(), data: error_body("OUTCOME_UNKNOWN", "task outcome unknown", false) });
    }
    let t = g.tobj.get_mut(&tk).unwrap();
    t.replayed = true;
    t.done = true;
    t.events = events;
    tk
}

fn task_recv_seq(g: &Guard, tk: u64) -> i64 {
    let Some(t) = g.tobj.get(&tk) else { return 0 };
    t.ds.and_then(|d| g.dstates.get(&d)).and_then(|d| d.inb.as_ref()).map(|i| i.recv(&t.id)).unwrap_or(0)
}

/// Commit first, then publish: nothing is visible before it is decided and stored.
fn task_record(g: &mut Guard, tk: u64, ev: Event) {
    let t = &g.tobj[&tk];
    if !t.replayed {
        let id = t.id.clone();
        match g.store.finish_task(&id, ev.clone(), state_of(&ev)) {
            Ok(()) | Err(StoreErr::NotFound(_)) => {}
            Err(e) => log(&format!("lmbp: task {}: persisting local event failed: {}", id, e.msg())),
        }
    }
    g.tobj.get_mut(&tk).unwrap().events.push(ev);
    wake_all();
}

/// Claims the single terminal decision: exactly one terminal path wins.
fn task_decide(g: &mut Guard, tk: u64) -> bool {
    let Some(t) = g.tobj.get_mut(&tk) else { return false };
    if t.done || t.decided {
        return false;
    }
    t.decided = true;
    true
}

fn task_on_device_frame(g: &mut Guard, tk: u64, inp: &Value, seq: i64) {
    let t = g.tobj.get_mut(&tk).unwrap();
    if t.done || t.decided {
        return task_maybe_ack(g, tk);
    }
    if seq > t.seen {
        t.seen = seq;
    }
    let mut data = get(inp, "data").clone();
    if !data.is_object() {
        data = obj! {};
    }
    let ty = inp["type"].as_str().unwrap().to_string();
    if ty == "task.delta" && !t.e2ee && truthy(get(&data, "e2ee")) {
        data.as_object_mut().unwrap().remove("e2ee");
    }
    if ty == "task.delta" {
        if let Some(why) = check_delta(t, &data) {
            log(&format!("lmbp: task {}: {}", t.id, why));
            task_cancel(g, tk, "protocol_error");
            task_fail_local(g, tk, "INTERNAL", &format!("device sent an invalid delta: {}", why), false);
            return;
        }
    }
    let id = t.id.clone();
    let ev = Event { seq, ty: ty.clone(), data };
    let mut state = "";
    if is_terminal(&ty) {
        state = state_of(&ev);
        if !task_decide(g, tk) {
            return task_maybe_ack(g, tk);
        }
        if let Err(e) = g.store.finish_task(&id, ev.clone(), state) {
            log(&format!("lmbp: task {}: persisting terminal event and state for seq {} failed: {} (not acknowledged)", id, seq, e.msg()));
            task_send_cancel(g, tk, "internal_error");
            task_commit_local(g, tk, "INTERNAL", "gateway could not persist task output", false);
            return;
        }
    } else if let Err(e) = g.store.append_event(&id, ev.clone()) {
        log(&format!("lmbp: task {}: persisting event for seq {} failed: {} (not acknowledged)", id, seq, e.msg()));
        task_cancel(g, tk, "internal_error");
        task_fail_local(g, tk, "INTERNAL", "gateway could not persist task output", false);
        return;
    }
    let t = g.tobj.get_mut(&tk).unwrap();
    if t.done || (t.decided && state.is_empty()) {
        return;
    }
    t.events.push(ev);
    t.persisted = seq;
    wake_all();
    if !state.is_empty() {
        return task_finish(g, tk, state, true);
    }
    task_maybe_ack(g, tk);
}

fn task_maybe_ack(g: &mut Guard, tk: u64) {
    let Some(t) = g.tobj.get(&tk) else { return };
    let Some(dsh) = t.ds else { return };
    let mut target = task_recv_seq(g, tk).min(t.persisted);
    if !t.done {
        for (_, d) in &t.subs {
            target = target.min(*d);
        }
    }
    if target <= t.acked {
        return;
    }
    let id = t.id.clone();
    let t = g.tobj.get_mut(&tk).unwrap();
    t.acked = target;
    t.ack_at = lmbp::now_ms();
    if let Some(i) = g.ds(dsh).inb.as_mut() {
        i.acked(&id, target);
    }
    control(g, dsh, &envelope("task.ack", None, Some(&id), Some(obj! {"seq" => target})));
}

fn task_cancel(g: &mut Guard, tk: u64, reason: &str) -> bool {
    match g.tobj.get(&tk) {
        Some(t) if !t.done && !t.decided => {}
        _ => return false,
    }
    task_send_cancel(g, tk, reason);
    true
}

fn task_send_cancel(g: &mut Guard, tk: u64, reason: &str) {
    let t = &g.tobj[&tk];
    if let (Some(dsh), true) = (t.ds, t.sent_run) {
        let id = t.id.clone();
        control(g, dsh, &envelope("task.cancel", None, Some(&id), Some(obj! {"reason" => reason})));
    }
}

fn task_fail_local(g: &mut Guard, tk: u64, code: &str, msg: &str, retryable: bool) {
    if !task_decide(g, tk) {
        return;
    }
    task_commit_local(g, tk, code, msg, retryable);
}

/// The caller holds the decision. The seq follows every device seq seen.
fn task_commit_local(g: &mut Guard, tk: u64, code: &str, msg: &str, retryable: bool) {
    let t = &g.tobj[&tk];
    let last = t.events.last().map(|e| e.seq).unwrap_or(0);
    let seq = last.max(t.seen) + 1;
    task_record(g, tk, Event { seq, ty: "task.error".into(), data: error_body(code, msg, retryable) });
    task_finish(g, tk, if code == "CANCELLED" { "CANCELLED" } else { "FAILED" }, false);
}

/// Ends a task whose device session is gone, whatever ended it (disconnect, revocation,
/// replacement): once task.run was sent the device may have run it, so OUTCOME_UNKNOWN (§7.5);
/// before that DEVICE_OFFLINE (retryable).
fn task_fail_offline(g: &mut Guard, tk: u64, code: &str, msg: &str) {
    let Some(t) = g.tobj.get(&tk) else { return };
    if t.sent_run {
        let msg = if code == "OUTCOME_UNKNOWN" { msg.to_string() } else { format!("{}; outcome unknown", msg) };
        return task_fail_local(g, tk, "OUTCOME_UNKNOWN", &msg, false);
    }
    task_fail_local(g, tk, "DEVICE_OFFLINE", msg, true);
}

/// Validates a device delta before it is stored or aggregated: the tool-call index range
/// (§16.1) and the task's output budget (§10), which counts every encoded delta body, cleartext
/// or sealed.
fn check_delta(t: &mut Task, data: &Value) -> Option<String> {
    if !t.e2ee {
        if let Some(calls) = get(data, "tool_calls").as_array() {
            for c in calls {
                let Some(ix) = c.as_object().and_then(|m| m.get("index")) else { continue };
                if !json::is_int(ix) || json::int(ix) < 0 || json::int(ix) > lmbp::MAX_TOOL_CALL_INDEX {
                    return Some(format!("tool call index {} out of range [0,{}]", json::stringify(ix), lmbp::MAX_TOOL_CALL_INDEX));
                }
            }
        }
    }
    t.out_bytes += json::stringify(data).len();
    if t.out_bytes > lmbp::MAX_TASK_OUTPUT_BYTES {
        return Some("task output exceeds the per-task limit".into());
    }
    None
}

fn task_finish(g: &mut Guard, tk: u64, _state: &str, from_device: bool) {
    let t = g.tobj.get_mut(&tk).unwrap();
    if t.done {
        return;
    }
    t.done = true;
    let had_slot = t.slot;
    t.slot = false;
    let timers = [t.grace.take(), t.timeout.take(), t.watch.take()];
    let (ds, id) = (t.ds, t.id.clone());
    for x in timers {
        g.cancel(x);
    }
    wake_all();
    if let Some(dsh) = ds {
        if from_device {
            task_maybe_ack(g, tk);
        } else {
            let late = task_recv_seq(g, tk);
            if late > g.tobj[&tk].acked {
                g.tobj.get_mut(&tk).unwrap().acked = late;
                control(g, dsh, &envelope("task.ack", None, Some(&id), Some(obj! {"seq" => late})));
            }
            let d = g.ds(dsh);
            d.reclaimed.retain(|r| r.0 != id);
            d.reclaimed.push_back((id.clone(), late));
            while d.reclaimed.len() > 1024 {
                d.reclaimed.pop_front();
            }
        }
        let d = g.ds(dsh);
        d.tasks.retain(|x| x.1 != tk);
        d.out.forget(&id);
        if let Some(i) = d.inb.as_mut() {
            i.forget(&id);
        }
        if had_slot {
            release(g, dsh);
        }
    }
    g.tobj[&tk].abort.store(true, Ordering::SeqCst);
    wake_all();
    let grace = g.cfg.attach_grace + 600_000;
    g.later(grace, move |g| {
        if g.tasks.get(&id) == Some(&tk) {
            g.tasks.remove(&id);
            if g.tobj.get(&tk).map(|t| t.subs.is_empty()).unwrap_or(true) {
                g.tobj.remove(&tk);
            }
        }
    });
}

fn task_attach(g: &mut Guard, tk: u64, after: i64) -> u64 {
    let t = g.tobj.get_mut(&tk).unwrap();
    t.next_sub += 1;
    let sid = t.next_sub;
    t.subs.push((sid, after));
    let gr = t.grace.take();
    g.cancel(gr);
    sid
}

fn task_detach(g: &mut Guard, tk: u64, sid: u64) {
    let Some(t) = g.tobj.get_mut(&tk) else { return };
    t.subs.retain(|s| s.0 != sid);
    let left = t.subs.is_empty() && !t.done;
    if left && t.idempotent {
        let ag = g.cfg.attach_grace;
        let gr = g.later(ag, move |g| {
            let empty = g.tobj.get(&tk).map(|t| t.subs.is_empty()).unwrap_or(false);
            if empty && task_cancel(g, tk, "client_disconnected") {
                task_fail_local(g, tk, "CANCELLED", "client did not re-attach", false);
            }
        });
        g.tobj.get_mut(&tk).unwrap().grace = Some(gr);
    }
    if left && !g.tobj[&tk].idempotent {
        if task_cancel(g, tk, "client_disconnected") {
            task_fail_local(g, tk, "CANCELLED", "client disconnected", false);
        }
        return;
    }
    task_maybe_ack(g, tk);
}

pub enum SE {
    Ev(Event),
    Keepalive,
}

/// Deliver events with seq > after until the terminal one; false if aborted.
/// f returns false when the client is gone.
pub fn task_stream(g: &mut Guard, tk: u64, mut after: i64, signal: &Abort, keepalive: bool, f: &mut dyn FnMut(&mut Guard, SE) -> bool) -> bool {
    let sub = task_attach(g, tk, after);
    let r = (|| {
        let mut last_activity = lmbp::now_ms();
        loop {
            if signal.load(Ordering::SeqCst) {
                return false;
            }
            let Some(t) = g.tobj.get(&tk) else { return false };
            let batch: Vec<Event> = t.events.iter().filter(|e| e.seq > after).cloned().collect();
            // finished and nothing after the cursor (Last-Event-ID >= terminal seq): end
            if batch.is_empty() && t.events.last().map(|e| is_terminal(&e.ty)).unwrap_or(false) {
                return true;
            }
            let n = batch.len();
            for e in batch {
                let (seq, term) = (e.seq, is_terminal(&e.ty));
                // a slow reader holds the cursor (and the ack) until the write drains
                if !f(g, SE::Ev(e)) || signal.load(Ordering::SeqCst) {
                    return false;
                }
                after = seq;
                if let Some(t) = g.tobj.get_mut(&tk) {
                    if let Some(s) = t.subs.iter_mut().find(|s| s.0 == sub) {
                        s.1 = after;
                    }
                }
                if term {
                    return true;
                }
            }
            task_maybe_ack(g, tk);
            if n > 0 {
                last_activity = lmbp::now_ms();
                continue;
            }
            let w = 15_000 - (lmbp::now_ms() - last_activity);
            if w <= 0 {
                if keepalive {
                    f(g, SE::Keepalive);
                }
                last_activity = lmbp::now_ms();
                continue;
            }
            wait(g, w.min(1000));
        }
    })();
    task_detach(g, tk, sub);
    r
}

/// Optional display names (model_names), kept only for advertised models.
fn clean_names(names: &Value, models: &[Value]) -> Obj {
    let mut out = Obj::new();
    let Some(m) = names.as_object() else { return out };
    for id in models {
        let Some(k) = id.as_str() else { continue };
        if let Some(n) = m.get(k).and_then(|v| v.as_str()) {
            let t = n.trim();
            if !t.is_empty() {
                out.insert(k.to_string(), Value::String(t.to_string())); // length bounded by the schema (1-128 code points)
            }
        }
    }
    out
}
