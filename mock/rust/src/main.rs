//! LMBP mock SaaS gateway (Rust): flags mirror mock/python/gateway.py and the Java mock.
//! In-memory state only.
mod anthropic;
mod gateway;
mod http;
mod json;
mod lmbp;
mod params;
mod schema;
mod store;
#[cfg(test)]
mod tests;

use serde_json::Value;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::exit;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.to_string())
}

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    exit(2)
}

const USAGE: &str = "usage: lmbp-mock-rust [--listen host:port] [--issuer origin] [--tenant ID:ENV]... [--tenant-profiles file]
                      [--signing-key-env ENV] [--max-concurrency N] [--retention-seconds N] [--web-dir dir] [--no-chat-ui]";

fn main() {
    let mut listen = env("LMBP_LISTEN", "127.0.0.1:8080");
    let mut issuer = env("LMBP_ISSUER", "");
    let mut profiles = env("LMBP_TENANT_PROFILES", "");
    let mut seed_env = "LMBP_SIGNING_SEED".to_string();
    let mut web_dir = env("LMBP_WEB_DIR", "");
    let mut no_chat = false;
    let mut max_conc: i64 = 16;
    let mut retention: i64 = 0; // ms; 0 keeps the default (7 days), negative disables
    let mut tenants = vec![];
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let (k, mut v) = match a.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (a.clone(), None),
        };
        if !matches!(k.as_str(), "--no-chat-ui" | "-h" | "--help") && v.is_none() {
            i += 1;
            if i >= args.len() {
                die(&format!("flag {} needs a value", k));
            }
            v = Some(args[i].clone());
        }
        let v = v.unwrap_or_default();
        match k.as_str() {
            "--listen" => listen = v,
            "--issuer" => issuer = v,
            "--tenant" => tenants.push(v),
            "--tenant-profiles" => profiles = v,
            "--signing-key-env" => seed_env = v,
            "--max-concurrency" => max_conc = v.parse().unwrap_or_else(|_| die("--max-concurrency must be an integer")),
            "--retention-seconds" => retention = (v.parse::<f64>().unwrap_or_else(|_| die("--retention-seconds must be a number")) * 1000.0) as i64,
            "--web-dir" => web_dir = v,
            "--no-chat-ui" => no_chat = true,
            "--db" => die(&format!("--db is not supported by the Rust mock (state is in memory; the signing key comes from {})", seed_env)),
            "-h" | "--help" => {
                println!("{}", USAGE);
                return;
            }
            _ => die(&format!("unknown flag {}", k)),
        }
        i += 1;
    }
    let seed = match std::env::var(&seed_env).ok().filter(|s| !s.is_empty()) {
        Some(h) => {
            let b = lmbp::unhex(h.trim()).unwrap_or_default();
            if b.len() != 32 {
                die(&format!("{} must hold 32 bytes of hex", seed_env));
            }
            Some(<[u8; 32]>::try_from(b).unwrap())
        }
        None => {
            eprintln!("warning: no signing key; using an ephemeral key (tokens do not survive restarts)");
            None
        }
    };
    if web_dir.is_empty() {
        let mut guess = PathBuf::from("mock/web");
        if !guess.is_dir() {
            guess = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("web");
        }
        web_dir = guess.to_string_lossy().into_owned();
    }
    let issuer = if issuer.is_empty() { loopback_issuer(&listen) } else { issuer };
    let mut cfg = gateway::Config { issuer, max_conc, web_dir: if no_chat { String::new() } else { web_dir }, ..Default::default() };
    if retention != 0 {
        cfg.retention = retention;
    }
    let kid = gateway::init(cfg, seed).unwrap_or_else(|e| die(&e));
    let mut g = gateway::lock();
    let mut n = 0;
    for spec in &tenants {
        let (id, env_name) = spec.split_once(':').unwrap_or((spec, ""));
        let key = std::env::var(env_name).unwrap_or_default();
        if key.is_empty() {
            die(&format!("tenant {}: env {} is empty", id, env_name));
        }
        g.register_tenant(id, &key, obj! {}).unwrap_or_else(|e| die(&e));
        n += 1;
    }
    if !profiles.is_empty() {
        let raw = std::fs::read_to_string(&profiles).unwrap_or_else(|e| die(&format!("{}: {}", profiles, e)));
        let m = serde_json::from_str::<Value>(&raw).ok().and_then(|v| v.as_object().cloned()).unwrap_or_else(|| die("tenant profiles must be a JSON object"));
        for (id, p) in m {
            let env_name = json::js_string(json::get(&p, "api_key_env"));
            let env_name = if json::has(&p, "api_key_env") { env_name } else { String::new() };
            let key = std::env::var(&env_name).unwrap_or_default();
            if key.is_empty() {
                die(&format!("tenant {}: api_key_env {} is empty", id, env_name));
            }
            g.register_tenant(&id, &key, p).unwrap_or_else(|e| die(&e));
            n += 1;
        }
    }
    if n == 0 {
        eprintln!("warning: no tenants registered (use --tenant id:ENV_VAR)");
    }
    let iss = g.cfg.issuer.clone();
    drop(g);
    let addr = if listen.starts_with(':') { format!("0.0.0.0{}", listen) } else { listen.clone() };
    let l = TcpListener::bind(&addr).unwrap_or_else(|e| die(&format!("listen {}: {}", listen, e)));
    eprintln!("lmbp rust mock gateway listening on {} issuer={} kid={}", listen, iss, kid);
    http::serve(l);
}

/// The default issuer for a loopback --listen address; any other address needs --issuer (spec §18.1).
fn loopback_issuer(listen: &str) -> String {
    let h = listen.rsplit_once(':').map(|(h, _)| h).unwrap_or(listen).trim_start_matches('[').trim_end_matches(']');
    if h == "localhost" || h == "::1" || h.starts_with("127.") {
        return format!("http://{}", listen);
    }
    die(&format!("--issuer (or LMBP_ISSUER) is required when listening on {}", listen))
}
