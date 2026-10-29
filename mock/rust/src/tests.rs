//! Self-tests: shared JOSE vectors, JS-compatible JSON, origins, parameter
//! validation and the chat page (CSP headers, disabled mode) over real HTTP.
use crate::json;
use crate::lmbp;
use crate::{gateway, http, params};
use serde_json::Value;
use std::io::{Read, Write};

fn jose() -> Value {
    serde_json::from_str(include_str!("../../../spec/testvectors/jose.json")).unwrap()
}

fn check(f: &Value, v: &Value) -> lmbp::R<()> {
    let key = lmbp::unb64(f["keys"][v["verify_with_key"].as_str().unwrap()]["public_b64url"].as_str().unwrap()).unwrap();
    let now = json::int(&f["now"]);
    let c = &v["context"];
    let s = |k: &str| c[k].as_str().unwrap_or("").to_string();
    let compact = &v["compact"];
    match v["kind"].as_str().unwrap() {
        "proof" => lmbp::verify_proof(&key, compact, &s("iss"), &s("aud"), &s("credential"), now).map(|_| ()),
        "client_assertion" => lmbp::verify_jwt(&key, compact, lmbp::TYP_ASSERTION, &s("aud"), now).map(|_| ()),
        "access_token" => lmbp::verify_jwt(&key, compact, lmbp::TYP_ACCESS, &s("aud"), now).map(|_| ()),
        "e2ee_key" => lmbp::verify_e2ee_key(&key, &s("device_id"), compact, now),
        _ => unreachable!(),
    }
}

const KINDS: [&str; 4] = ["proof", "client_assertion", "access_token", "e2ee_key"];

#[test]
fn jose_vectors() {
    let f = jose();
    let mut bad = vec![];
    let mut n = 0;
    for v in f["valid"].as_array().unwrap() {
        if KINDS.contains(&v["kind"].as_str().unwrap()) {
            if let Err(e) = check(&f, v) {
                bad.push(format!("valid {} rejected: {}", v["name"], e));
            }
        }
    }
    for v in f["negative"].as_array().unwrap() {
        if KINDS.contains(&v["kind"].as_str().unwrap()) {
            n += 1;
            if check(&f, v).is_ok() {
                bad.push(format!("negative {} accepted ({})", v["name"], v["must_reject_because"]));
            }
        }
    }
    assert!(n > 50, "only {} negative vectors", n);
    assert!(bad.is_empty(), "{:#?}", bad);
}

#[test]
fn jwk_thumbprint_matches_vector() {
    let f = jose();
    let d = &f["keys"]["device"];
    let seed: [u8; 32] = lmbp::unb64(d["seed_b64url"].as_str().unwrap()).unwrap().try_into().unwrap();
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(lmbp::b64(&pk), d["public_b64url"].as_str().unwrap());
    assert_eq!(lmbp::thumbprint(&pk), d["jkt"].as_str().unwrap());
    assert_eq!(lmbp::public_jwk(&pk), d["jwk"]);
}

#[test]
fn sign_verify_round_trip() {
    let k = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pk = k.verifying_key().to_bytes();
    let kid = lmbp::thumbprint(&pk);
    let t = lmbp::now();
    let jws = lmbp::sign_jws(&k, lmbp::TYP_ACCESS, &kid, &crate::obj! {"iss" => "i", "sub" => "s", "aud" => "a", "jti" => "j", "iat" => t, "exp" => t + 60});
    assert!(lmbp::verify_jwt(&pk, &Value::String(jws.clone()), lmbp::TYP_ACCESS, "a", t).is_ok());
    assert!(lmbp::verify_jwt(&pk, &Value::String(jws.clone()), lmbp::TYP_ACCESS, "b", t).is_err());
    assert!(lmbp::verify_jwt(&pk, &Value::String(jws), lmbp::TYP_PROOF, "a", t).is_err());
}

#[test]
fn json_like_javascript() {
    let v: Value = serde_json::from_str(r#"{"b":1,"a":[1.0,0.5,-0.0,1e21,1e-7,"\u2028x"],"c":null}"#).unwrap();
    assert_eq!(json::stringify(&v), r#"{"b":1,"a":[1,0.5,0,1e+21,1e-7,"\u2028x"],"c":null}"#.replace("\\u2028", "\u{2028}"));
    assert!(json::truthy(&Value::from(0.5)) && !json::truthy(&Value::from(0)) && !json::truthy(&Value::from("")));
    assert_eq!(json::js_string(&Value::Null), "null");
}

#[test]
fn origins() {
    assert_eq!(lmbp::origin("HTTPS://GW.Example.com:443/").unwrap(), "https://gw.example.com");
    assert_eq!(lmbp::origin("http://127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
    assert_eq!(lmbp::origin("http://[::1]:80").unwrap(), "http://[::1]");
    assert!(lmbp::origin("http://gw.example.com").is_err());
    assert!(lmbp::origin("https://gw.example.com/path").is_err());
    assert!(lmbp::origin("https://u@gw.example.com").is_err());
}

#[test]
fn chat_params() {
    let m = |s: &str| serde_json::from_str::<Value>(s).unwrap().as_object().cloned().unwrap();
    let e = params::validate_chat_params(&m(r#"{"model":"x","messages":[{"role":"user","content":"hi"}],"temperature":3}"#)).err().unwrap();
    assert_eq!(e.param, "temperature");
    assert_eq!(e.message, "temperature: must be between 0 and 2, got 3");
    let p = params::validate_chat_params(&m(r#"{"model":"x","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":5,"stop":"x"}"#)).unwrap();
    assert_eq!(p.max_tokens, 5);
    assert_eq!(p.stop.unwrap().len(), 1);
    let e = params::validate_anthropic_params(&m(r#"{"model":"x","messages":[{"role":"user","content":"hi"}]}"#)).err().unwrap();
    assert_eq!(e.param, "max_tokens");
}

fn get(port: u16, path: &str) -> (u16, String) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", path, port).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split(' ').nth(1).unwrap().parse().unwrap();
    (status, out)
}

#[test]
fn chat_page_and_core_endpoints() {
    let web = concat!(env!("CARGO_MANIFEST_DIR"), "/../web").to_string();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    gateway::init(gateway::Config { web_dir: web, issuer: format!("http://127.0.0.1:{}", port), ..Default::default() }, Some([1u8; 32])).unwrap();
    std::thread::spawn(move || http::serve(l));
    for (path, ct) in [("/", "text/html"), ("/chat", "text/html"), ("/chat/chat.js", "text/javascript"), ("/chat/qrcode.js", "text/javascript")] {
        let (st, r) = get(port, path);
        assert_eq!(st, 200, "{}", path);
        assert!(r.contains(&format!("Content-Type: {}", ct)), "{}", path);
        assert!(r.contains("Content-Security-Policy: default-src 'self'; script-src 'self';"), "{}", path);
        assert!(r.contains("X-Content-Type-Options: nosniff"));
    }
    let (st, r) = get(port, "/.well-known/jwks.json");
    assert_eq!(st, 200);
    assert!(r.contains("\"kty\":\"OKP\""));
    let (st, r) = get(port, "/.well-known/lmbp");
    assert_eq!(st, 200);
    assert!(r.contains(&format!("\"connect_endpoint\":\"ws://127.0.0.1:{}/lmbp/v1/connect\"", port)));
    let (st, r) = get(port, "/lmbp/v1/connect");
    assert_eq!(st, 400);
    assert!(r.contains("application/problem+json") && r.contains("VERSION_UNSUPPORTED"));
    gateway::lock().cfg.web_dir = String::new();
    assert_eq!(get(port, "/chat").0, 404);
}

/// LMBP 2.0 (§4.1, §7.4): hello / models.update are schema-checked without
/// clamping, lengths count code points, the two headers are printable ASCII.
#[test]
fn lmbp2_announce_lengths_headers() {
    let hello = |conc: Value| serde_json::json!({"device_id": "d", "client": "c", "models": ["m1"], "max_concurrency": conc, "proof": "eyJh.eyJh.c2ln"});
    assert!(params::announce_problem(&hello(serde_json::json!(2)), true).is_none());
    for bad in [serde_json::json!(0), serde_json::json!(17), serde_json::json!("2")] {
        assert!(params::announce_problem(&hello(bad.clone()), true).is_some(), "{bad}");
    }
    let mut missing = hello(serde_json::json!(2));
    missing.as_object_mut().unwrap().remove("max_concurrency");
    assert!(params::announce_problem(&missing, true).is_some());
    let names = |n: usize| serde_json::json!({"models": ["m1"], "model_names": {"m1": "😀".repeat(n)}});
    assert!(params::announce_problem(&names(128), false).is_none());
    assert!(params::announce_problem(&names(129), false).is_some());
    assert!(params::announce_problem(&serde_json::json!({"models": ["m1"], "max_concurrency": 99}), false).is_some());
    assert_eq!(lmbp::char_len(&"😀".repeat(100)), 100);
    assert!(lmbp::valid_header(&"a".repeat(128), 128) && !lmbp::valid_header(&"a".repeat(129), 128));
    assert!(!lmbp::valid_header("张三", 128) && !lmbp::valid_header("", 128) && !lmbp::valid_header("a\tb", 128));
    assert_eq!((lmbp::VERSION, lmbp::SUBPROTOCOL), (2, "lmbp"));
}

// audit3 P1: forget fails the task's queued sends before waking the others,
// so a terminal task never re-creates its outbox entry or holds credit.
#[test]
fn outbox_forget_fails_queued_sends_first() {
    let mut o = lmbp::Outbox::default();
    let w = lmbp::MAX_FRAME_BYTES as i64;
    o.set_flow(Some(lmbp::Flow { task_window: w, conn_window: w }));
    let big = "x".repeat(130 << 10);
    let ids: Vec<u64> = (0..3)
        .map(|_| {
            let b = big.clone();
            o.enqueue("t1", Box::new(move |seq| format!("{{\"seq\":{seq},\"d\":\"{b}\"}}")))
        })
        .collect();
    assert!(o.results.contains_key(&ids[0]) && !o.results.contains_key(&ids[1]), "second chunk should wait for credit");
    o.forget("t1");
    assert!(!o.tasks.contains_key("t1"), "forgotten task re-created its outbox entry");
    assert_eq!(o.conn_used, 0);
    assert!(o.waiters.is_empty());
    assert!(matches!(o.results.get(&ids[1]), Some(Err(_))) && matches!(o.results.get(&ids[2]), Some(Err(_))));
    let again = o.enqueue("t1", Box::new(|seq| format!("{{\"seq\":{seq}}}")));
    assert!(matches!(o.results.get(&again), Some(Err(_))), "send after forget admitted");
}

/// Review 2026-10-29 (P2): the issuer is configuration; an empty one is refused.
#[test]
fn issuer_is_required() {
    let e = gateway::init(gateway::Config::default(), Some([2u8; 32])).err().expect("empty issuer accepted");
    assert!(e.contains("issuer is required"), "{}", e);
}

/// Review 2026-10-29 (P1-3): device_name is untrusted; text-disguising characters are refused.
#[test]
fn device_name_rule() {
    for bad in ["Office PC\u{202E}gpj.exe", "a\nb", "x\u{200B}y", "\u{85}", &"a".repeat(101)] {
        assert!(!lmbp::valid_device_name(bad), "{:?} accepted", bad);
    }
    assert!(lmbp::valid_device_name("张三的 MacBook 😀"));
}

/// Review 2026-10-29 (P2): the jti store evicts by expiry from a heap, never by a full scan.
#[test]
fn jti_cache_is_bounded_by_expiry() {
    let mut c = gateway::JtiCache::default();
    let until = lmbp::now_ms() + 60_000;
    for i in 0..200_000 {
        c.use_jti(&format!("j{}", i), until);
    }
    let t0 = std::time::Instant::now();
    for i in 0..1000 {
        c.use_jti(&format!("k{}", i), until);
    }
    let per = t0.elapsed().as_secs_f64() * 1000.0 / 1000.0;
    assert!(per < 0.2, "use_jti took {:.3} ms per call at 200k entries", per);
    assert!(!c.use_jti("j1", until), "replay accepted");
    c.use_jti("short", lmbp::now_ms() - 1);
    c.use_jti("trigger", until);
    assert!(!c.has("short"), "expired entry kept");
    assert_eq!(c.len(), 201_001);
}
