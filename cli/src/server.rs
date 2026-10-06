//! Local UI server: serves the embedded web tool and a small JSON API for local folders/repos.
//!
//! Security model: binds to 127.0.0.1 only; every /api call must carry the per-session random
//! token in the `X-Polinrider-Token` header (custom header ⇒ browsers preflight cross-origin
//! requests and we never send CORS headers, so other sites/tabs cannot drive this API).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::engine::{Engine, Ioc};
use crate::{discover, fix_targets, scan_targets};

const INDEX_HTML: &str = include_str!("../../polinrider.html");

struct Ctx { token: String }

fn make_token() -> String {
    let mut s = String::new();
    for _ in 0..2 {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        h.write_u32(std::process::id());
        s.push_str(&format!("{:016x}", h.finish()));
    }
    s
}

pub fn run(port: u16, open: bool) -> i32 {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => { eprintln!("cannot bind 127.0.0.1:{}: {}", port, e); return 1; }
    };
    let addr = match listener.local_addr() { Ok(a) => a, Err(e) => { eprintln!("{}", e); return 1; } };
    let ctx = Arc::new(Ctx { token: make_token() });
    let url = format!("http://127.0.0.1:{}/?t={}", addr.port(), ctx.token);
    println!("polinrider UI  →  {}", url);
    println!("Local API bound to 127.0.0.1 only, protected by a per-session token. Press Ctrl+C to stop.");
    if open { open_browser(&url); }
    for stream in listener.incoming() {
        if let Ok(s) = stream { let c = ctx.clone(); std::thread::spawn(move || handle(s, c)); }
    }
    0
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn(); }
    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").arg(url).spawn(); }
    #[cfg(all(unix, not(target_os = "macos")))]
    { let _ = std::process::Command::new("xdg-open").arg(url).spawn(); }
}

fn handle(mut stream: TcpStream, ctx: Arc<Ctx>) {
    let mut reader = BufReader::new(match stream.try_clone() { Ok(s) => s, Err(_) => return });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.is_empty() { return; }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (mut content_len, mut tok) = (0usize, String::new());
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() || h == "\r\n" || h == "\n" || h.is_empty() { break; }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") { content_len = v.trim().parse().unwrap_or(0); }
            if k.eq_ignore_ascii_case("x-polinrider-token") { tok = v.trim().to_string(); }
        }
    }
    if content_len > 16 * 1024 * 1024 { return; }
    let mut body = vec![0u8; content_len];
    if content_len > 0 && reader.read_exact(&mut body).is_err() { return; }
    let (path, query) = match target.split_once('?') { Some((p, q)) => (p.to_string(), q.to_string()), None => (target.clone(), String::new()) };
    let (status, ctype, out) = route(&ctx, &method, &path, &query, &tok, &body);
    let _ = write!(stream, "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
                   status, reason(status), ctype, out.len());
    let _ = stream.write_all(&out);
    let _ = stream.flush();
}

fn reason(s: u16) -> &'static str { match s { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 404 => "Not Found", _ => "Error" } }
fn jresp(status: u16, v: Value) -> (u16, &'static str, Vec<u8>) { (status, "application/json", serde_json::to_vec(&v).unwrap_or_default()) }

fn route(ctx: &Ctx, method: &str, path: &str, query: &str, tok: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    if method == "GET" && (path == "/" || path == "/index.html") {
        return (200, "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec());
    }
    if method == "GET" && path == "/favicon.ico" { return (204, "image/x-icon", Vec::new()); }
    if !path.starts_with("/api/") { return (404, "text/plain", b"not found".to_vec()); }
    if tok.is_empty() || tok != ctx.token { return jresp(401, json!({"error": "missing or invalid session token"})); }
    match (method, path) {
        ("GET", "/api/ping") => jresp(200, json!({
            "ok": true, "version": env!("CARGO_PKG_VERSION"), "git": crate::git::available(),
            "home": home(), "cwd": std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
            "os": std::env::consts::OS })),
        ("GET", "/api/iocs") => jresp(200, serde_json::to_value(Ioc::default()).unwrap_or(Value::Null)),
        ("GET", "/api/ls") => ls(query),
        ("POST", "/api/scan") => api_scan(body),
        ("POST", "/api/fix") => api_fix(body),
        ("POST", "/api/purge") => api_purge(body),
        _ => jresp(404, json!({"error": "unknown endpoint"})),
    }
}

fn home() -> String {
    std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_default()
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 + 0 => {
                if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) { out.push(v); i += 2; } else { out.push(b'%'); }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn query_param(query: &str, key: &str) -> String {
    query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| pct_decode(v)).unwrap_or_default()
}

fn ls(query: &str) -> (u16, &'static str, Vec<u8>) {
    let p = query_param(query, "path");
    let mut dirs: Vec<Value> = Vec::new();
    if p.is_empty() {
        #[cfg(target_os = "windows")]
        for c in b'A'..=b'Z' {
            let d = format!("{}:\\", c as char);
            if std::path::Path::new(&d).is_dir() { dirs.push(json!({"name": d, "path": d, "isRepo": false})); }
        }
        #[cfg(not(target_os = "windows"))]
        dirs.push(json!({"name": "/", "path": "/", "isRepo": false}));
        let h = home();
        if !h.is_empty() { dirs.push(json!({"name": "Home", "path": h, "isRepo": false})); }
        return jresp(200, json!({"path": "", "parent": null, "dirs": dirs, "home": home()}));
    }
    let pb = PathBuf::from(&p);
    let rd = match std::fs::read_dir(&pb) { Ok(r) => r, Err(e) => return jresp(400, json!({"error": format!("{}: {}", p, e)})) };
    for e in rd.flatten() {
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "node_modules" || name == ".git" { continue; }
            let path = e.path();
            dirs.push(json!({"name": name, "path": path.display().to_string(), "isRepo": path.join(".git").exists()}));
        }
    }
    dirs.sort_by(|a, b| a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase()));
    let parent = pb.parent().map(|x| x.display().to_string()).filter(|s| !s.is_empty());
    jresp(200, json!({"path": pb.display().to_string(), "parent": parent, "dirs": dirs, "isRepo": pb.join(".git").exists(), "home": home()}))
}

fn engine_from(v: &Value) -> Result<Engine, String> {
    let ioc: Ioc = match v.get("iocs") {
        Some(o) if o.is_object() => serde_json::from_value(o.clone()).map_err(|e| format!("bad iocs: {}", e))?,
        _ => Ioc::default(),
    };
    Engine::new(ioc)
}

fn paths_of(v: &Value) -> Vec<PathBuf> {
    v.get("paths").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).filter(|s| !s.trim().is_empty()).map(|s| PathBuf::from(s.trim())).collect()).unwrap_or_default()
}

fn api_scan(body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let v: Value = match serde_json::from_slice(body) { Ok(v) => v, Err(e) => return jresp(400, json!({"error": format!("bad json: {}", e)})) };
    let eng = match engine_from(&v) { Ok(e) => e, Err(e) => return jresp(400, json!({"error": e})) };
    let paths = paths_of(&v);
    if paths.is_empty() { return jresp(400, json!({"error": "no paths"})); }
    let all_branches = v.get("allBranches").and_then(|b| b.as_bool()).unwrap_or(true);
    let me = v.get("me").and_then(|m| m.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let git_ok = crate::git::available();
    let targets = discover(&paths);
    let reports = scan_targets(&eng, &targets, all_branches, me.as_deref(), git_ok);
    jresp(200, json!({"git": git_ok, "targets": targets.len(), "reports": reports}))
}

fn api_fix(body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let v: Value = match serde_json::from_slice(body) { Ok(v) => v, Err(e) => return jresp(400, json!({"error": format!("bad json: {}", e)})) };
    let eng = match engine_from(&v) { Ok(e) => e, Err(e) => return jresp(400, json!({"error": e})) };
    let paths = paths_of(&v);
    if paths.is_empty() { return jresp(400, json!({"error": "no paths"})); }
    let apply = v.get("apply").and_then(|b| b.as_bool()).unwrap_or(false);
    let commit = v.get("commit").and_then(|b| b.as_bool()).unwrap_or(false);
    let push = v.get("push").and_then(|b| b.as_bool()).unwrap_or(false);
    let only: Option<Vec<(String, String)>> = v.get("only").and_then(|a| a.as_array()).map(|a| {
        a.iter().filter_map(|o| Some((o.get("target")?.as_str()?.to_string(), o.get("path")?.as_str()?.to_string()))).collect()
    });
    let git_ok = crate::git::available();
    let targets = discover(&paths);
    let report = fix_targets(&eng, &targets, apply, commit, push, only.as_deref(), git_ok);
    jresp(200, json!({"apply": apply, "report": report}))
}

fn api_purge(body: &[u8]) -> (u16, &'static str, Vec<u8>) {
    let v: Value = match serde_json::from_slice(body) { Ok(v) => v, Err(e) => return jresp(400, json!({"error": format!("bad json: {}", e)})) };
    let (repo, branch, good) = match (v.get("repo").and_then(|x| x.as_str()), v.get("branch").and_then(|x| x.as_str()), v.get("good").and_then(|x| x.as_str())) {
        (Some(r), Some(b), Some(g)) => (PathBuf::from(r), b.to_string(), g.to_string()),
        _ => return jresp(400, json!({"error": "repo, branch and good are required"})),
    };
    if !crate::git::is_repo(&repo) { return jresp(400, json!({"error": "not a git repository"})); }
    let force_push = v.get("forcePush").and_then(|b| b.as_bool()).unwrap_or(false);
    let mut log: Vec<String> = Vec::new();
    for args in [vec!["checkout", branch.as_str()], vec!["reset", "--hard", good.as_str()]] {
        match crate::git::run(&repo, &args) { Ok(o) => log.push(format!("git {}: {}", args.join(" "), o.trim())), Err(e) => return jresp(400, json!({"error": format!("git {}: {}", args.join(" "), e), "log": log})) }
    }
    if force_push {
        match crate::git::run(&repo, &["push", "--force-with-lease", "origin", &branch]) { Ok(o) => log.push(format!("force-pushed: {}", o.trim())), Err(e) => return jresp(400, json!({"error": format!("push: {}", e), "log": log})) }
    }
    jresp(200, json!({"ok": true, "log": log}))
}
