//! LMBP primitives: base64url, EdDSA JWS/JWT, proofs, thumbprints, origins
//! (spec §5, §18) and the flow-controlled delivery state (§8, §15).
use crate::json::{self, get, Obj};
use crate::obj;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: i64 = 2;
pub const SUBPROTOCOL: &str = "lmbp";
pub const PROTOCOL_VERSIONS: [&str; 1] = ["2.0"];
/// Conformance profiles (spec §13.1); metadata.profiles lists those this gateway meets.
pub const PROFILES: [&str; 7] = ["core", "reliable", "tools", "multimodal", "e2ee", "openai", "anthropic"];
pub const VERSION_REQUIRED: &str = "LMBP 2.0 required: WebSocket subprotocol lmbp and envelope v 2 (LMBP 1.x is not supported)";

/// Unicode code points, the unit of every string limit (spec §4.1).
pub fn char_len(s: &str) -> usize {
    s.chars().count()
}

/// Largest task.delta tool_calls[].index (spec §16.1).
pub const MAX_TOOL_CALL_INDEX: i64 = 127;
/// Encoded task.delta bytes one task may send, cleartext or sealed (spec §10).
pub const MAX_TASK_OUTPUT_BYTES: usize = 64 << 20;
/// device_name: at most 100 code points (spec §6.2).
pub const MAX_DEVICE_NAME_CHARS: usize = 100;

/// The spec §6.2 rule for the untrusted, device-reported name: at most 100 code points and none
/// of the characters that can disguise text (C0/C1 controls, U+00AD, U+061C, U+180E,
/// U+200B-U+200F, U+2028-U+202E, U+2060-U+206F, U+FEFF, U+FFF9-U+FFFB).
pub fn valid_device_name(s: &str) -> bool {
    char_len(s) <= MAX_DEVICE_NAME_CHARS
        && !s.chars().any(|c| {
            let r = c as u32;
            r <= 0x1F
                || (0x7F..=0x9F).contains(&r)
                || r == 0xAD
                || r == 0x61C
                || r == 0x180E
                || (0x200B..=0x200F).contains(&r)
                || (0x2028..=0x202E).contains(&r)
                || (0x2060..=0x206F).contains(&r)
                || r == 0xFEFF
                || (0xFFF9..=0xFFFB).contains(&r)
        })
}

/// 1..max printable ASCII (0x20-0x7E): X-End-User and Idempotency-Key (spec §4.1).
pub fn valid_header(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}
pub const CAPABILITIES: [&str; 7] = ["session.token", "models.update", "resume", "flow", "tools", "multimodal", "e2ee"];
pub const SCOPES: [&str; 4] = ["lmbp.chat", "lmbp.tools", "lmbp.vision", "lmbp.audio"];
pub const MAX_FRAME_BYTES: usize = 256 << 10;
pub const MAX_MESSAGES: usize = 200;
pub const BLOB_CHUNK_BYTES: usize = 96 << 10;
pub const MAX_BLOB_BYTES: usize = 20 << 20;
pub const MAX_TASK_BLOB_BYTES: usize = 32 << 20;
pub const INLINE_DATA_URI_BYTES: usize = 16 << 10;
pub const BLOB_SCHEME: &str = "lmbp-blob:";
pub const TYP_ACCESS: &str = "at+jwt";
pub const TYP_ASSERTION: &str = "JWT";
pub const TYP_PROOF: &str = "lmbp-proof+jwt";
pub const TYP_TASK: &str = "lmbp-task+jws";
pub const TYP_METADATA: &str = "lmbp-metadata+jwt";
pub const TYP_E2EE_KEY: &str = "lmbp-e2ee-key+jwt";
pub const PROOF_TOKEN: &str = "lmbp:token";
pub const PROOF_HELLO: &str = "lmbp:hello";
pub const PROOF_SESSION_TOKEN: &str = "lmbp:session.token";

pub type R<T> = Result<T, String>;

pub fn tenant_id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> R<Vec<u8>> {
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') || s.len() % 4 == 1 {
        return Err("bad base64url".into());
    }
    // Node's decoder ignores non-zero trailing bits; accept them too.
    base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false).with_decode_allow_trailing_bits(true).with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone))
        .decode(s).map_err(|_| "bad base64url".to_string())
}

pub fn std_b64_strict(s: &str) -> Option<Vec<u8>> {
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || s.len() % 4 != 0 || !body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') {
        return None;
    }
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true))
        .decode(s).ok().or_else(|| STANDARD.decode(s).ok())
}

pub fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn sha_hex(s: &str) -> String {
    hex(&sha256(s.as_bytes()))
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("rng");
    b
}

pub fn random_id(prefix: &str) -> String {
    format!("{}{}", prefix, hex(&random_bytes(16)))
}

pub fn random_below(n: u32) -> u32 {
    loop {
        let b = random_bytes(4);
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let lim = u32::MAX - (u32::MAX % n);
        if v < lim {
            return v % n;
        }
    }
}

pub fn ath(cred: &str) -> String {
    b64(&sha256(cred.as_bytes()))
}

pub fn thumbprint(pub_: &[u8]) -> String {
    b64(&sha256(format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", b64(pub_)).as_bytes()))
}

pub fn x25519_thumbprint(pub_: &[u8]) -> String {
    b64(&sha256(format!("{{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", b64(pub_)).as_bytes()))
}

pub fn public_jwk(pub_: &[u8]) -> Value {
    obj! {"kty" => "OKP", "crv" => "Ed25519", "x" => b64(pub_), "kid" => thumbprint(pub_), "alg" => "EdDSA", "use" => "sig"}
}

pub fn token_audience(iss: &str, tenant: &str) -> String {
    format!("{}/tenants/{}", iss, tenant)
}

pub fn assertion_audience(iss: &str) -> String {
    format!("{}/lmbp/v1/token", iss)
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn sign_jws(key: &SigningKey, typ: &str, kid: &str, payload: &Value) -> String {
    let mut h = obj! {"alg" => "EdDSA", "typ" => typ};
    if !kid.is_empty() {
        h.as_object_mut().unwrap().insert("kid".into(), Value::from(kid));
    }
    let input = format!("{}.{}", b64(json::stringify(&h).as_bytes()), b64(json::stringify(payload).as_bytes()));
    let sig = key.sign(input.as_bytes());
    format!("{}.{}", input, b64(&sig.to_bytes()))
}

/// Strict compact EdDSA JWS (§5.2); returns the payload object.
pub fn verify_jws(pub_: &[u8], jws: &Value, typ: &str) -> R<Obj> {
    let jws = jws.as_str().ok_or("malformed JWS")?;
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed JWS".into());
    }
    let h = unb64(parts[0]).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).ok_or("bad JWS header")?;
    let hm = h.as_object().ok_or("bad JWS header")?;
    for k in hm.keys() {
        if k != "alg" && k != "typ" && k != "kid" {
            return Err(format!("forbidden JWS header {}", k));
        }
    }
    if hm.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err("JWS alg must be EdDSA".into());
    }
    if hm.get("typ").and_then(|v| v.as_str()) != Some(typ) {
        return Err(format!("JWS typ must be {}", typ));
    }
    if let Some(kid) = hm.get("kid") {
        if kid.as_str().is_none() || pub_.len() != 32 || kid.as_str() != Some(thumbprint(pub_).as_str()) {
            return Err("JWS kid does not match the verifying key".into());
        }
    }
    let sig = unb64(parts[2])?;
    let ok = pub_.len() == 32 && sig.len() == 64 && {
        let pk: [u8; 32] = pub_.try_into().unwrap();
        let sb: [u8; 64] = sig[..].try_into().unwrap();
        match VerifyingKey::from_bytes(&pk) {
            Ok(vk) => vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &Signature::from_bytes(&sb)).is_ok(),
            Err(_) => false,
        }
    };
    if !ok {
        return Err("bad JWS signature".into());
    }
    let p = unb64(parts[1]).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).ok_or("bad JWS payload")?;
    match p {
        Value::Object(m) => Ok(m),
        _ => Err("JWS payload must be a JSON object".into()),
    }
}

fn is_numeric_date(v: &Value) -> bool {
    json::is_safe_int(v) && v.as_f64().unwrap_or(-1.0) >= 0.0
}

fn require_claims(c: &Obj, ints: &[&str], strs: &[&str], opt: &[&str]) -> R<()> {
    for k in ints {
        if !is_numeric_date(c.get(*k).unwrap_or(&json::NULL)) {
            return Err(format!("claim {} must be a non-negative integer", k));
        }
    }
    for k in strs {
        match c.get(*k).and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => {}
            _ => return Err(format!("claim {} must be a non-empty string", k)),
        }
    }
    for k in opt {
        if c.get(*k).and_then(|v| v.as_str()).is_none() {
            return Err(format!("claim {} must be a string", k));
        }
    }
    Ok(())
}

fn ci(c: &Obj, k: &str) -> i64 {
    json::int(c.get(k).unwrap_or(&json::NULL))
}

fn cs<'a>(c: &'a Obj, k: &str) -> &'a str {
    c.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

fn time_range(c: &Obj) -> R<()> {
    require_claims(c, &["iat", "exp"], &[], &[])?;
    if ci(c, "exp") < ci(c, "iat") {
        return Err("exp before iat".into());
    }
    Ok(())
}

pub fn verify_jwt(pub_: &[u8], tok: &Value, typ: &str, aud: &str, t: i64) -> R<Obj> {
    let c = verify_jws(pub_, tok, typ)?;
    require_claims(&c, &[], &["iss", "sub", "aud", "jti"], &[])?;
    time_range(&c)?;
    if cs(&c, "aud") != aud {
        return Err("wrong audience".into());
    }
    if t > ci(&c, "exp") + 30 || t + 30 < ci(&c, "iat") {
        return Err("token expired".into());
    }
    Ok(c)
}

pub fn unverified_claims(tok: &Value) -> R<Obj> {
    let s = match tok {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => json::js_string(o),
    };
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed token".into());
    }
    match serde_json::from_slice::<Value>(&unb64(parts[1])?) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err("bad claims".into()),
    }
}

pub fn verify_proof(pub_: &[u8], proof: &Value, device_id: &str, aud: &str, credential: &str, t: i64) -> R<Obj> {
    let c = verify_jws(pub_, proof, TYP_PROOF)?;
    require_claims(&c, &["iat"], &["aud", "jti", "ath"], &["iss"])?;
    if cs(&c, "aud") != aud || cs(&c, "iss") != device_id || cs(&c, "jti").is_empty() || cs(&c, "ath") != ath(credential) {
        return Err("proof claims invalid".into());
    }
    if (t - ci(&c, "iat")).abs() > 60 {
        return Err("proof iat outside allowed skew".into());
    }
    Ok(c)
}

pub fn verify_e2ee_key(device_pub: &[u8], device_id: &str, stmt: &Value, t: i64) -> R<()> {
    let c = verify_jws(device_pub, stmt, TYP_E2EE_KEY)?;
    require_claims(&c, &[], &["iss", "sub"], &[])?;
    time_range(&c)?;
    let k = c.get("jwk").cloned().unwrap_or(Value::Null);
    if cs(&c, "sub") != device_id || cs(&c, "iss") != device_id || !k.is_object() || get(&k, "kty").as_str() != Some("OKP") || get(&k, "crv").as_str() != Some("X25519") {
        return Err("bad e2ee key statement".into());
    }
    if t > ci(&c, "exp") || t + 60 < ci(&c, "iat") {
        return Err("e2ee key statement expired".into());
    }
    let x = unb64(get(&k, "x").as_str().ok_or("bad e2ee key")?)?;
    if x.len() != 32 || get(&k, "kid").as_str() != Some(x25519_thumbprint(&x).as_str()) {
        return Err("bad e2ee key".into());
    }
    Ok(())
}

pub fn is_loopback_host(h: &str) -> bool {
    let h = h.trim_start_matches('[').trim_end_matches(']').to_lowercase();
    if h == "localhost" || h == "::1" {
        return true;
    }
    let p: Vec<&str> = h.split('.').collect();
    p.len() == 4 && p[0] == "127" && p.iter().all(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
}

/// origin normalizes scheme://host[:port]; http only for loopback (§18.1).
pub fn origin(raw: &str) -> R<String> {
    let s = raw.trim().trim_end_matches('/');
    let bad = || format!("not an origin: {}", raw);
    let (scheme, rest) = s.split_once("://").ok_or_else(bad)?;
    let scheme = scheme.to_lowercase();
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(bad());
    }
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported scheme in {}", raw));
    }
    let (host, port) = if rest.starts_with('[') {
        let end = rest.find(']').ok_or_else(bad)?;
        let after = &rest[end + 1..];
        let port = if after.is_empty() { None } else { Some(after.strip_prefix(':').ok_or_else(bad)?) };
        (&rest[..=end], port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    let mut port_s = String::new();
    if let Some(p) = port {
        if !p.is_empty() {
            let n: u32 = p.parse().map_err(|_| bad())?;
            if n > 65535 {
                return Err(bad());
            }
            if !((scheme == "http" && n == 80) || (scheme == "https" && n == 443)) {
                port_s = format!(":{}", n);
            }
        }
    }
    if scheme == "http" && !is_loopback_host(host) {
        return Err(format!("issuer {} must use https", raw));
    }
    Ok(format!("{}://{}{}", scheme, host.to_lowercase(), port_s))
}

/// Encoded size of the task.run frame carrying jws (worst-case seq).
pub fn task_run_frame_size(jws: &str, task_id: &str) -> usize {
    json::stringify(&obj! {"v" => VERSION, "type" => "task.run", "task_id" => task_id, "seq" => 9007199254740992u64, "jws" => jws}).len()
}

// ---------- flow control (§15) ----------
#[derive(Clone, Copy, Debug)]
pub struct Flow {
    pub task_window: i64,
    pub conn_window: i64,
}

pub fn can_send(f: Option<Flow>, task_used: i64, conn_used: i64, n: i64) -> bool {
    match f {
        None => true,
        Some(f) => (task_used + n <= f.task_window || task_used == 0) && (conn_used + n <= f.conn_window || conn_used == 0),
    }
}

#[derive(Default)]
pub struct OTask {
    pub next_seq: i64,
    pub unacked: VecDeque<(i64, String, i64)>,
    pub used: i64,
    pub written: i64,
}

pub struct OWaiter {
    pub id: u64,
    pub task: String,
    pub mk: Box<dyn Fn(i64) -> String + Send>,
}

pub type Writer = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Outbox: sending half; methods run under the gateway lock. Admission and
/// credit reservation are one step (audit finding 2).
#[derive(Default)]
pub struct Outbox {
    pub flow: Option<Flow>,
    pub conn_used: i64,
    pub tasks: HashMap<String, OTask>,
    pub waiters: VecDeque<OWaiter>,
    pub results: HashMap<u64, R<i64>>,
    pub write: Option<Writer>,
    pub closed: bool,
    next_id: u64,
    /// Tasks dropped with forget (bounded FIFO): their sends fail instead of
    /// re-creating state no retransmit list covers (audit3 P1).
    pub forgotten: std::collections::HashSet<String>,
    forgotten_fifo: VecDeque<String>,
}

const MAX_FORGOTTEN: usize = 4096;

impl Outbox {
    pub fn set_flow(&mut self, f: Option<Flow>) {
        self.flow = f;
        self.wake();
    }
    pub fn attach(&mut self, w: Option<Writer>) {
        self.write = w;
        for t in self.tasks.values_mut() {
            t.written = -1;
        }
    }
    pub fn enqueue(&mut self, task: &str, mk: Box<dyn Fn(i64) -> String + Send>) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        if self.forgotten.contains(task) {
            self.results.insert(id, Err("task forgotten".into()));
            return id;
        }
        self.waiters.push_back(OWaiter { id, task: task.to_string(), mk });
        self.wake();
        id
    }
    pub fn cancel(&mut self, id: u64) {
        self.waiters.retain(|w| w.id != id);
        self.wake();
    }
    /// Admit queued sends in strict FIFO order.
    pub fn wake(&mut self) {
        while let Some(w) = self.waiters.front() {
            if self.closed {
                let w = self.waiters.pop_front().unwrap();
                self.results.insert(w.id, Err("outbox closed".into()));
                continue;
            }
            if self.forgotten.contains(&w.task) {
                let w = self.waiters.pop_front().unwrap();
                self.results.insert(w.id, Err("task forgotten".into()));
                continue;
            }
            let t = self.tasks.entry(w.task.clone()).or_default();
            let seq = t.next_seq + 1;
            let raw = (w.mk)(seq);
            let n = raw.len() as i64;
            if !can_send(self.flow, t.used, self.conn_used, n) {
                break;
            }
            let w = self.waiters.pop_front().unwrap();
            let t = self.tasks.get_mut(&w.task).unwrap();
            t.next_seq = seq;
            t.unacked.push_back((seq, raw, n));
            t.used += n;
            self.conn_used += n;
            self.results.insert(w.id, Ok(seq));
        }
    }
    pub fn flush(&mut self, id: &str) {
        let Some(w) = self.write.clone() else { return };
        let Some(t) = self.tasks.get_mut(id) else { return };
        if t.written < 0 {
            return;
        }
        for (seq, raw, _) in t.unacked.iter() {
            if *seq > t.written {
                t.written = *seq;
                if !w(raw) {
                    return;
                }
            }
        }
    }
    pub fn ack(&mut self, id: &str, seq: i64) {
        if let Some(t) = self.tasks.get_mut(id) {
            while let Some(f) = t.unacked.front() {
                if f.0 > seq {
                    break;
                }
                let f = t.unacked.pop_front().unwrap();
                t.used -= f.2;
                self.conn_used -= f.2;
            }
            self.wake();
        }
    }
    pub fn retransmit(&mut self, id: &str, peer_recv: i64) {
        self.ack(id, peer_recv);
        if let Some(t) = self.tasks.get_mut(id) {
            t.written = peer_recv;
        }
        self.flush(id);
    }
    /// Drop a terminal task for good, atomically: release its credit and fail
    /// its queued sends BEFORE waking the others, so it never re-creates its
    /// entry and re-consumes connection credit no resume returns (audit3 P1).
    pub fn forget(&mut self, id: &str) {
        if let Some(t) = self.tasks.remove(id) {
            self.conn_used -= t.used;
        }
        if self.forgotten.insert(id.to_string()) {
            self.forgotten_fifo.push_back(id.to_string());
            if self.forgotten_fifo.len() > MAX_FORGOTTEN {
                if let Some(old) = self.forgotten_fifo.pop_front() {
                    self.forgotten.remove(&old);
                }
            }
        }
        let mut kept = VecDeque::new();
        while let Some(w) = self.waiters.pop_front() {
            if w.task == id {
                self.results.insert(w.id, Err("task forgotten".into()));
            } else {
                kept.push_back(w);
            }
        }
        self.waiters = kept;
        self.wake();
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.wake();
    }
}

pub const ACCEPTED: i32 = 0;
pub const DUPLICATE: i32 = 1;
pub const GAP: i32 = 2;
pub const OVERFLOW: i32 = 3;

#[derive(Default)]
pub struct ITask {
    recv: i64,
    sizes: VecDeque<(i64, i64)>,
    used: i64,
}

/// Inbound: receiving half; detects duplicates/gaps and enforces our windows.
pub struct Inbound {
    pub flow: Option<Flow>,
    conn_used: i64,
    tasks: HashMap<String, ITask>,
}

impl Inbound {
    pub fn new(flow: Option<Flow>) -> Self {
        Inbound { flow, conn_used: 0, tasks: HashMap::new() }
    }
    pub fn accept(&mut self, id: &str, seq: i64, size: i64) -> i32 {
        let t = self.tasks.entry(id.to_string()).or_default();
        if seq <= t.recv {
            return DUPLICATE;
        }
        if seq != t.recv + 1 {
            return GAP;
        }
        if let Some(f) = self.flow {
            if (t.used + size > f.task_window && t.used > 0) || (self.conn_used + size > f.conn_window && self.conn_used > 0) {
                return OVERFLOW;
            }
        }
        t.recv = seq;
        t.sizes.push_back((seq, size));
        t.used += size;
        self.conn_used += size;
        ACCEPTED
    }
    pub fn acked(&mut self, id: &str, seq: i64) {
        if let Some(t) = self.tasks.get_mut(id) {
            while let Some(f) = t.sizes.front() {
                if f.0 > seq {
                    break;
                }
                let (_, n) = t.sizes.pop_front().unwrap();
                t.used -= n;
                self.conn_used -= n;
            }
        }
    }
    pub fn recv(&self, id: &str) -> i64 {
        self.tasks.get(id).map(|t| t.recv).unwrap_or(0)
    }
    pub fn reset_windows(&mut self) {
        self.conn_used = 0;
        for t in self.tasks.values_mut() {
            t.used = 0;
            t.sizes.clear();
        }
    }
    pub fn forget(&mut self, id: &str) {
        if let Some(t) = self.tasks.remove(id) {
            self.conn_used -= t.used;
        }
    }
}
