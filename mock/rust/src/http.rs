//! A small HTTP/1.1 server (one thread per connection, one request per connection)
//! with RFC 6455 WebSocket support. Not a general-purpose server.
use crate::gateway::{self, Guard};
use base64::Engine;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

pub const MAX_BODY: usize = 48 << 20;
pub const MAX_HEADER_BYTES: usize = 64 << 10;

pub type Abort = Arc<AtomicBool>;

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>, // None if over MAX_BODY
    pub abort: Abort,
    /// TCP peer address (the per-client key of the authorize rate limit).
    pub peer: String,
}

pub fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let h = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(x) => {
                        out.push(x);
                        i += 2;
                    }
                    None => return s.to_string(),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

impl Req {
    pub fn header(&self, k: &str) -> &str {
        self.headers.get(k).map(|s| s.as_str()).unwrap_or("")
    }
    pub fn query_param(&self, k: &str) -> Option<String> {
        for kv in self.query.split('&') {
            if kv.is_empty() {
                continue;
            }
            let (a, b) = kv.split_once('=').unwrap_or((kv, ""));
            if dec(a) == k {
                return Some(dec(b));
            }
        }
        None
    }
}

/// Response writer; every socket write runs with the gateway lock released.
pub struct Res {
    out: TcpStream,
    pub head: bool,
    pub abort: Abort,
    pub headers: Vec<(String, String)>,
    pub headers_sent: bool,
    pub ended: bool,
}

impl Res {
    pub fn set_header(&mut self, k: &str, v: &str) {
        if let Some(h) = self.headers.iter_mut().find(|h| h.0 == k) {
            h.1 = v.to_string();
        } else {
            self.headers.push((k.to_string(), v.to_string()));
        }
    }
    pub fn get_header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|h| h.0 == k).map(|h| h.1.as_str())
    }
    pub fn write_head(&mut self, g: &mut Guard, status: u16, extra: &[(&str, &str)]) -> bool {
        if self.headers_sent {
            return false;
        }
        self.headers_sent = true;
        for (k, v) in extra {
            self.set_header(k, v);
        }
        let mut b = format!("HTTP/1.1 {} {}\r\n", status, reason(status));
        for (k, v) in &self.headers {
            b.push_str(&format!("{}: {}\r\n", k, v));
        }
        b.push_str("Connection: close\r\n\r\n");
        self.raw(g, b.as_bytes())
    }
    pub fn write(&mut self, g: &mut Guard, s: &str) -> bool {
        self.raw(g, s.as_bytes())
    }
    pub fn raw(&mut self, g: &mut Guard, b: &[u8]) -> bool {
        if self.ended || self.abort.load(Ordering::SeqCst) {
            return false;
        }
        let out = &mut self.out;
        let ok = parking_lot::MutexGuard::unlocked(g, || out.write_all(b).and_then(|_| out.flush()).is_ok());
        if !ok {
            self.abort.store(true, Ordering::SeqCst);
            gateway::wake_all();
        }
        ok
    }
    pub fn end(&mut self, g: &mut Guard, body: Option<&[u8]>) {
        if self.ended {
            return;
        }
        if let Some(b) = body {
            if !b.is_empty() {
                self.raw(g, b);
            }
        }
        self.ended = true;
    }
    pub fn send(&mut self, g: &mut Guard, status: u16, content_type: &str, body: &[u8]) {
        if self.get_header("Content-Type").is_none() {
            self.set_header("Content-Type", content_type);
        }
        self.set_header("Content-Length", &body.len().to_string());
        self.write_head(g, status, &[]);
        if !self.head {
            self.end(g, Some(body));
        } else {
            self.end(g, None);
        }
    }
}

pub fn reason(s: u16) -> &'static str {
    match s {
        101 => "Switching Protocols",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

pub fn serve(l: TcpListener) {
    for s in l.incoming() {
        if let Ok(s) = s {
            std::thread::spawn(move || conn(s));
        }
    }
}

fn read_line<R: Read>(r: &mut R, budget: &mut usize) -> Option<String> {
    let mut b = vec![];
    let mut c = [0u8; 1];
    loop {
        match r.read(&mut c) {
            Ok(1) => {}
            _ => {
                if b.is_empty() {
                    return None;
                }
                break;
            }
        }
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        if c[0] == b'\n' {
            break;
        }
        b.push(c[0]);
    }
    if b.last() == Some(&b'\r') {
        b.pop();
    }
    Some(b.iter().map(|&x| x as char).collect())
}

fn read_n<R: Read>(r: &mut R, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n.min(1 << 20));
    let _ = r.take(n as u64).read_to_end(&mut v);
    v
}

fn conn(s: TcpStream) {
    let _ = s.set_nodelay(true);
    let peer = s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let Ok(out) = s.try_clone() else { return };
    let mut inp = BufReader::new(s);
    let mut budget = MAX_HEADER_BYTES;
    let Some(line) = read_line(&mut inp, &mut budget) else { return };
    let rl: Vec<&str> = line.split(' ').collect();
    if rl.len() != 3 {
        return;
    }
    let target = rl[1].to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let mut req = Req { method: rl[0].to_string(), path, query, headers: BTreeMap::new(), body: Some(vec![]), abort: Arc::new(AtomicBool::new(false)), peer };
    loop {
        let Some(h) = read_line(&mut inp, &mut budget) else { break };
        if h.is_empty() {
            break;
        }
        let Some(c) = h.find(':') else { continue };
        if c == 0 {
            continue;
        }
        let k = h[..c].trim().to_lowercase();
        let v = h[c + 1..].trim().to_string();
        req.headers.entry(k).and_modify(|a| *a = format!("{}, {}", a, v)).or_insert(v);
    }
    if req.header("upgrade").eq_ignore_ascii_case("websocket") {
        gateway::upgrade(&req, inp, out);
        return;
    }
    req.body = read_body(&mut inp, &req);
    let abort = req.abort.clone();
    let mut res = Res { out: out.try_clone().unwrap(), head: req.method == "HEAD", abort: abort.clone(), headers: vec![], headers_sent: false, ended: false };
    // A long request (chat/messages/events) notices a client disconnect via EOF.
    let a2 = abort.clone();
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match inp.read(&mut buf) {
                Ok(0) | Err(_) => break,
                _ => {}
            }
        }
        if !d2.load(Ordering::SeqCst) {
            let _g = gateway::lock();
            a2.store(true, Ordering::SeqCst);
            gateway::wake_all();
        }
    });
    gateway::handle(&req, &mut res);
    done.store(true, Ordering::SeqCst);
    let _ = out.shutdown(Shutdown::Both);
}

fn read_body<R: Read>(r: &mut R, req: &Req) -> Option<Vec<u8>> {
    if req.header("transfer-encoding").to_lowercase().contains("chunked") {
        let mut b = vec![];
        let mut over = false;
        let mut budget = MAX_HEADER_BYTES;
        loop {
            let Some(l) = read_line(r, &mut budget) else { break };
            let n = usize::from_str_radix(l.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
            if n == 0 {
                while let Some(t) = read_line(r, &mut budget) {
                    if t.is_empty() {
                        break;
                    }
                }
                break;
            }
            let chunk = read_n(r, n);
            if b.len() + chunk.len() > MAX_BODY {
                over = true;
            } else {
                b.extend_from_slice(&chunk);
            }
            read_line(r, &mut budget);
        }
        return if over { None } else { Some(b) };
    }
    let cl = req.header("content-length");
    if cl.is_empty() {
        return Some(vec![]);
    }
    let Ok(n) = cl.parse::<u64>() else { return Some(vec![]) };
    if n as usize > MAX_BODY {
        // Drain (bounded) so the client sees our 413 instead of a reset.
        let _ = std::io::copy(&mut r.take(n.min(64 << 20)), &mut std::io::sink());
        return None;
    }
    Some(read_n(r, n as usize))
}

// ---------------- WebSocket (RFC 6455) ----------------
pub enum WMsg {
    Frame(Vec<u8>),
    Poison,
}

/// The sending side of one WebSocket; cheap to clone.
#[derive(Clone)]
pub struct WsIo {
    pub open: Arc<AtomicBool>,
    tx: mpsc::Sender<WMsg>,
    sock: Arc<TcpStream>,
}

pub fn frame(opcode: u8, p: &[u8]) -> Vec<u8> {
    let n = p.len();
    let mut b = Vec::with_capacity(n + 10);
    b.push(0x80 | opcode);
    if n < 126 {
        b.push(n as u8);
    } else if n < 65536 {
        b.push(126);
        b.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        b.push(127);
        b.extend_from_slice(&(n as u64).to_be_bytes());
    }
    b.extend_from_slice(p);
    b
}

impl WsIo {
    pub fn new(out: TcpStream) -> WsIo {
        let (tx, rx) = mpsc::channel::<WMsg>();
        let sock = Arc::new(out.try_clone().expect("clone"));
        let mut w = out;
        let s2 = sock.clone();
        std::thread::spawn(move || {
            let mut bw = std::io::BufWriter::new(&mut w);
            'outer: while let Ok(m) = rx.recv() {
                let mut cur = Some(m);
                while let Some(m) = cur.take() {
                    match m {
                        WMsg::Poison => break 'outer,
                        WMsg::Frame(f) => {
                            if bw.write_all(&f).is_err() {
                                break 'outer;
                            }
                        }
                    }
                    cur = rx.try_recv().ok();
                }
                if bw.flush().is_err() {
                    break;
                }
            }
            let _ = bw.flush();
            drop(bw);
            let _ = s2.shutdown(Shutdown::Both);
        });
        WsIo { open: Arc::new(AtomicBool::new(true)), tx, sock }
    }
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }
    pub fn send(&self, text: &str) -> bool {
        if !self.is_open() {
            return false;
        }
        self.tx.send(WMsg::Frame(frame(1, text.as_bytes()))).is_ok()
    }
    pub fn raw(&self, f: Vec<u8>) {
        if self.is_open() {
            let _ = self.tx.send(WMsg::Frame(f));
        }
    }
    pub fn ping(&self) {
        self.raw(frame(9, &[]));
    }
    pub fn close(&self, code: u16, reason: &str) {
        if !self.open.swap(false, Ordering::SeqCst) {
            return;
        }
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(reason.as_bytes());
        let _ = self.tx.send(WMsg::Frame(frame(8, &p)));
        let _ = self.tx.send(WMsg::Poison);
    }
    pub fn terminate(&self) {
        self.open.store(false, Ordering::SeqCst);
        let _ = self.tx.send(WMsg::Poison);
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

pub enum WsEvent {
    Message(String, bool, usize),
    Pong,
}

fn rd<R: Read>(r: &mut R) -> Option<u8> {
    let mut b = [0u8; 1];
    match r.read(&mut b) {
        Ok(1) => Some(b[0]),
        _ => None,
    }
}

/// Reader loop on the connection thread; events are handled under the gateway lock.
pub fn ws_run<R: Read>(inp: &mut R, io: &WsIo, max_payload: usize, mut on: impl FnMut(WsEvent)) {
    let mut msg: Option<Vec<u8>> = None;
    let mut msg_op = 0u8;
    loop {
        let (Some(b0), Some(b1)) = (rd(inp), rd(inp)) else { break };
        let fin = b0 & 0x80 != 0;
        let op = b0 & 0x0f;
        if b0 & 0x70 != 0 || b1 & 0x80 == 0 {
            proto_close(io, 1002, "protocol error");
            break;
        }
        let mut n = (b1 & 0x7f) as u64;
        if n == 126 {
            let (Some(a), Some(b)) = (rd(inp), rd(inp)) else { break };
            n = ((a as u64) << 8) | b as u64;
        } else if n == 127 {
            n = 0;
            for _ in 0..8 {
                let Some(a) = rd(inp) else { break };
                n = (n << 8) | a as u64;
            }
        }
        if n > max_payload as u64 || msg.as_ref().map(|m| m.len() as u64 + n > max_payload as u64).unwrap_or(false) {
            proto_close(io, 1009, "message too big");
            break;
        }
        let mask = read_n(inp, 4);
        let mut p = read_n(inp, n as usize);
        if p.len() as u64 != n || mask.len() != 4 {
            break;
        }
        for (i, x) in p.iter_mut().enumerate() {
            *x ^= mask[i & 3];
        }
        if op >= 8 {
            match op {
                8 => {
                    let _g = gateway::lock();
                    io.close(1000, "");
                    break;
                }
                9 => {
                    io.raw(frame(10, &p));
                    continue;
                }
                10 => {
                    on(WsEvent::Pong);
                    continue;
                }
                _ => {
                    proto_close(io, 1002, "bad opcode");
                    break;
                }
            }
        }
        if op == 0 {
            let Some(m) = msg.as_mut() else {
                proto_close(io, 1002, "unexpected continuation");
                break;
            };
            m.extend_from_slice(&p);
        } else {
            if msg.is_some() || (op != 1 && op != 2) {
                proto_close(io, 1002, "bad frame");
                break;
            }
            msg = Some(p);
            msg_op = op;
        }
        if fin {
            let data = msg.take().unwrap();
            let size = data.len();
            let text = String::from_utf8_lossy(&data).into_owned();
            if io.is_open() {
                on(WsEvent::Message(text, msg_op == 2, size));
            }
        }
    }
    io.open.store(false, Ordering::SeqCst);
    let _ = io.tx.send(WMsg::Poison);
    let _ = io.sock.shutdown(Shutdown::Both);
}

fn proto_close(io: &WsIo, code: u16, reason: &str) {
    let _g = gateway::lock();
    io.close(code, reason);
}

pub fn accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}
