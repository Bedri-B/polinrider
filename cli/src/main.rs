//! polinrider — scanner & fixer for the PolinRider / auth-con-firm / TaskJacker worm,
//! for LOCAL git repositories and plain project folders.
//!
//!   polinrider                           # = ui: opens the web tool in your browser with local mode enabled
//!   polinrider ui    [--port N] [--no-open]
//!   polinrider scan  <paths…>  [--all-branches] [--me NAME] [--iocs FILE] [--json OUT] [--md OUT]
//!   polinrider fix   <paths…>  [--apply] [--commit] [--push] [--iocs FILE]
//!   polinrider purge --repo DIR --branch BR --good SHA [--force-push] --yes
//!   polinrider iocs                      # print the default IOC database (web-tool compatible JSON)
//!
//! Exit codes: 0 clean · 2 infected · 1 error.

mod engine;
mod git;
mod server;

use engine::{fmt_b, Action, Engine, Ioc};
use serde::Serialize;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".output", ".venv", "venv", "target",
    "vendor", "__pycache__", ".cache", ".turbo", "coverage", ".svelte-kit", ".parcel-cache",
];
const PICKAXE_TERMS: &[&str] = &[
    "A9-4091", engine::DROP_KEY, "a322e5f3d311d3080e6f0121063e9adc2490ef1a", "RS260605",
    "rmcej%otb%", "Cot%3t=shtP", "temp_auto_push",
];
const FIX_MSG: &str = "security: remove PolinRider/TaskJacker payload";

#[derive(Serialize, Clone)]
pub struct Finding { pub target: String, pub branch: String, pub path: String, pub size: u64, pub signal: String, pub kind: String }

#[derive(Serialize)]
pub struct TargetReport { pub target: String, pub remote: Option<String>, pub branch: String, pub status: String, pub findings: Vec<Finding> }

#[derive(Serialize)]
pub struct FixRow { pub target: String, pub branch: String, pub path: String, pub method: String, pub result: String, pub changed: bool, pub needs_review: bool }

#[derive(Serialize, Default)]
pub struct FixReport { pub rows: Vec<FixRow>, pub notes: Vec<String> }

struct Opts {
    cmd: String, paths: Vec<PathBuf>, all_branches: bool, no_git: bool, iocs: Option<PathBuf>, me: Option<String>,
    json: Option<PathBuf>, md: Option<PathBuf>, apply: bool, commit: bool, push: bool,
    repo: Option<PathBuf>, branch: Option<String>, good: Option<String>, force_push: bool, yes: bool,
    color: bool, quiet: bool, port: u16, no_open: bool,
}

fn parse_args() -> Opts {
    let mut o = Opts {
        cmd: String::new(), paths: vec![], all_branches: false, no_git: false, iocs: None, me: None, json: None, md: None,
        apply: false, commit: false, push: false, repo: None, branch: None, good: None, force_push: false, yes: false,
        color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(), quiet: false, port: 0, no_open: false,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut val = |o: &mut Option<String>| { i += 1; *o = args.get(i).cloned(); };
        match a {
            "--all-branches" => o.all_branches = true,
            "--no-git" => o.no_git = true,
            "--apply" => o.apply = true,
            "--commit" => o.commit = true,
            "--push" => o.push = true,
            "--force-push" => o.force_push = true,
            "--yes" | "-y" => o.yes = true,
            "--no-color" => o.color = false,
            "--quiet" | "-q" => o.quiet = true,
            "--no-open" => o.no_open = true,
            "--version" | "-V" => o.cmd = "version".into(),
            "--help" | "-h" => o.cmd = "help".into(),
            "--iocs" => { let mut s = None; val(&mut s); o.iocs = s.map(PathBuf::from); }
            "--me" => { let mut s = None; val(&mut s); o.me = s; }
            "--json" => { let mut s = None; val(&mut s); o.json = s.map(PathBuf::from); }
            "--md" => { let mut s = None; val(&mut s); o.md = s.map(PathBuf::from); }
            "--repo" => { let mut s = None; val(&mut s); o.repo = s.map(PathBuf::from); }
            "--branch" => { let mut s = None; val(&mut s); o.branch = s; }
            "--good" => { let mut s = None; val(&mut s); o.good = s; }
            "--port" => { let mut s = None; val(&mut s); o.port = s.and_then(|v| v.parse().ok()).unwrap_or(0); }
            _ if a.starts_with('-') && a != "-" => { eprintln!("unknown option: {}", a); std::process::exit(1); }
            _ => { if o.cmd.is_empty() { o.cmd = a.to_string(); } else { o.paths.push(PathBuf::from(a)); } }
        }
        i += 1;
    }
    o
}

struct Paint(bool);
impl Paint {
    fn p(&self, code: &str, s: &str) -> String { if self.0 { format!("\x1b[{}m{}\x1b[0m", code, s) } else { s.to_string() } }
    fn red(&self, s: &str) -> String { self.p("31", s) }
    fn yel(&self, s: &str) -> String { self.p("33", s) }
    fn grn(&self, s: &str) -> String { self.p("32", s) }
    fn blu(&self, s: &str) -> String { self.p("34", s) }
    fn mag(&self, s: &str) -> String { self.p("35", s) }
    fn dim(&self, s: &str) -> String { self.p("2", s) }
    fn bold(&self, s: &str) -> String { self.p("1", s) }
    fn badge(&self, sig: &str) -> String {
        let (code, label) = if sig.starts_with("SIZE") { ("31", "size anomaly") }
            else if sig.starts_with("WARN") { ("34", "unverified") }
            else if sig.starts_with("KNOWN-PAYLOAD") { ("31", "known payload") }
            else if sig.starts_with("VSCODE") { ("31", "vscode autorun") }
            else if sig.starts_with("ARTIFACT") { ("31", "artifact") }
            else if sig.starts_with("FAKE-FONT") { ("31", "fake font") }
            else if sig.starts_with("HISTORY") { ("35", "history") }
            else if sig.starts_with("FOREIGN-TZ") { ("35", "foreign tz") }
            else if sig.starts_with("NPM") { ("33", "malicious pkg") }
            else if sig.starts_with("LIFECYCLE") { ("33", "lifecycle script") }
            else { ("33", "marker") };
        self.p(code, &format!("[{}]", label))
    }
}

fn is_skipped(e: &DirEntry) -> bool {
    e.depth() > 0 && e.file_type().is_dir() && e.file_name().to_str().map(|n| SKIP_DIRS.contains(&n)).unwrap_or(false)
}

/// Turn the given paths into scan targets: git repos found beneath them, or the folders themselves.
pub fn discover(paths: &[PathBuf]) -> Vec<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        let p = if p.is_absolute() { p.clone() } else { cwd.join(p) };
        if !p.is_dir() { eprintln!("skip: {} is not a directory", p.display()); continue; }
        if git::is_repo(&p) { out.push(p); continue; }
        let mut found: Vec<PathBuf> = Vec::new();
        for e in WalkDir::new(&p).max_depth(6).into_iter().filter_entry(|e| !is_skipped(e)).filter_map(|e| e.ok()) {
            if e.file_type().is_dir() && e.depth() > 0 && e.path().join(".git").exists() { found.push(e.path().to_path_buf()); }
        }
        if found.is_empty() { out.push(p); } else { out.extend(found); }
    }
    out.sort();
    out.dedup();
    out
}

fn scan_tree(eng: &Engine, root: &Path, target: &str, branch: &str, out: &mut Vec<Finding>) {
    for e in WalkDir::new(root).into_iter().filter_entry(|e| !is_skipped(e)).filter_map(|e| e.ok()) {
        if !e.file_type().is_file() { continue; }
        let rel = match e.path().strip_prefix(root) { Ok(r) => r.to_string_lossy().replace('\\', "/"), Err(_) => continue };
        if !eng.interesting(&rel) { continue; }
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        let abs = e.path().to_path_buf();
        let sig = eng.classify(&rel, size, || fs::read(&abs).ok());
        if !sig.is_empty() {
            out.push(Finding { target: target.into(), branch: branch.into(), path: rel, size, signal: sig, kind: "tree".into() });
        }
    }
}

fn scan_branches(eng: &Engine, root: &Path, target: &str, current: &str, out: &mut Vec<Finding>) {
    for br in git::local_branches(root) {
        if br == current { continue; }
        for (path, size) in git::ls_tree(root, &br) {
            if !eng.interesting(&path) { continue; }
            let sig = eng.classify(&path, size, || git::show(root, &br, &path));
            if !sig.is_empty() {
                out.push(Finding { target: target.into(), branch: br.clone(), path, size, signal: sig, kind: "branch".into() });
            }
        }
    }
}

fn scan_history(eng: &Engine, root: &Path, target: &str, me: Option<&str>, out: &mut Vec<Finding>) {
    for term in PICKAXE_TERMS {
        if let Some(first) = git::pickaxe(root, term).first() {
            out.push(Finding { target: target.into(), branch: "(history)".into(), path: format!("pickaxe:{}", term), size: 0,
                               signal: format!("HISTORY: {}", first), kind: "history".into() });
        }
    }
    if let Some(me) = me {
        let me_l = me.to_lowercase();
        for (ci, h, an, subj) in git::log_tz(root) {
            if eng.ioc.foreign_tz.iter().any(|tz| ci.contains(tz.as_str())) && an.to_lowercase().contains(&me_l) {
                out.push(Finding { target: target.into(), branch: "(history)".into(), path: format!("commit:{}", h), size: 0,
                                   signal: format!("FOREIGN-TZ {} | {}", ci, subj), kind: "history".into() });
            }
        }
    }
}

/// Scan every target and classify it: infected · history (payload only in past commits) · tz-note · clean.
pub fn scan_targets(eng: &Engine, targets: &[PathBuf], all_branches: bool, me: Option<&str>, git_ok: bool) -> Vec<TargetReport> {
    targets.iter().map(|root| {
        let name = root.display().to_string();
        let is_repo = git_ok && git::is_repo(root);
        let branch = if is_repo { git::current_branch(root) } else { "(folder)".to_string() };
        let mut f: Vec<Finding> = Vec::new();
        scan_tree(eng, root, &name, &branch, &mut f);
        if is_repo {
            if all_branches { scan_branches(eng, root, &name, &branch, &mut f); }
            scan_history(eng, root, &name, me, &mut f);
        }
        let files = f.iter().filter(|x| x.kind != "history" && !x.signal.starts_with("WARN")).count();
        let pick = f.iter().filter(|x| x.kind == "history" && x.signal.starts_with("HISTORY")).count();
        let tz = f.iter().filter(|x| x.kind == "history" && x.signal.starts_with("FOREIGN-TZ")).count();
        let status = if files > 0 { "infected" } else if pick > 0 { "history" } else if tz > 0 { "tz-note" } else { "clean" };
        TargetReport { target: name, remote: if is_repo { git::remote_url(root) } else { None }, branch, status: status.into(), findings: f }
    }).collect()
}

/// Fix the working tree of every target. `only` restricts to (target, path) pairs. Dry-run unless `apply`.
pub fn fix_targets(eng: &Engine, targets: &[PathBuf], apply: bool, commit: bool, push: bool,
                   only: Option<&[(String, String)]>, git_ok: bool) -> FixReport {
    let mut rep = FixReport::default();
    for root in targets {
        let name = root.display().to_string();
        let is_repo = git_ok && git::is_repo(root);
        let branch = if is_repo { git::current_branch(root) } else { "(folder)".to_string() };
        let mut findings: Vec<Finding> = Vec::new();
        scan_tree(eng, root, &name, &branch, &mut findings);
        let mut changed: Vec<String> = Vec::new();
        for f in findings.iter().filter(|f| !f.signal.starts_with("WARN")) {
            if let Some(o) = only { if !o.iter().any(|(t, p)| t == &f.target && p == &f.path) { continue; } }
            let abs = root.join(&f.path);
            let bytes = match fs::read(&abs) {
                Ok(b) => b,
                Err(e) => { rep.rows.push(FixRow { target: name.clone(), branch: branch.clone(), path: f.path.clone(), method: "—".into(), result: format!("read error: {}", e), changed: false, needs_review: true }); continue; }
            };
            let cur = String::from_utf8_lossy(&bytes).to_string();
            let hist_fn = || git::file_history(root, &f.path);
            let hist: Option<&dyn Fn() -> Vec<(String, Vec<u8>)>> = if is_repo && eng.is_cfg(&f.path) { Some(&hist_fn) } else { None };
            let plan = eng.plan(&f.path, &f.signal, &cur, hist);
            let outcome = eng.evaluate(&f.path, plan, &cur, bytes.len() as u64);
            let (mut result, mut did, mut review) = (outcome.result.clone(), false, false);
            match &outcome.action {
                Action::Delete => {
                    if apply { match fs::remove_file(&abs) { Ok(_) => { result = "deleted".into(); did = true; } Err(e) => { result = format!("delete failed: {}", e); review = true; } } }
                    else { result = format!("DRY {}", result); }
                }
                Action::Write(c) => {
                    if apply { match fs::write(&abs, c) { Ok(_) => { result = format!("written {}", outcome.result); did = true; } Err(e) => { result = format!("write failed: {}", e); review = true; } } }
                    else { result = format!("DRY {}", result); }
                }
                Action::None => { if !result.contains("already clean") { review = true; } }
            }
            if did { changed.push(f.path.clone()); }
            rep.rows.push(FixRow { target: name.clone(), branch: branch.clone(), path: f.path.clone(), method: outcome.method, result, changed: did, needs_review: review });
        }
        if apply && !changed.is_empty() && is_repo {
            if commit {
                let mut args: Vec<&str> = vec!["add", "-A", "--"];
                for c in &changed { args.push(c.as_str()); }
                match git::run(root, &args).and_then(|_| git::run(root, &["commit", "-m", FIX_MSG])) {
                    Ok(_) => {
                        rep.notes.push(format!("{}: committed {} file(s) on {}", name, changed.len(), branch));
                        if push { match git::run(root, &["push"]) { Ok(_) => rep.notes.push(format!("{}: pushed", name)), Err(e) => rep.notes.push(format!("{}: push failed: {}", name, e)) } }
                    }
                    Err(e) => rep.notes.push(format!("{}: commit failed: {}", name, e)),
                }
            } else {
                rep.notes.push(format!("{}: {} file(s) changed in the working tree — review with `git diff`, then commit", name, changed.len()));
            }
        }
    }
    rep
}

fn print_row(p: &Paint, f: &Finding) {
    let detail = f.signal.splitn(2, ": ").nth(1).unwrap_or(&f.signal);
    let size = if f.size > 0 { fmt_b(f.size) } else { String::new() };
    println!("   {:<28} {:<46} {:>9}  {} {}", p.dim(&f.branch), f.path, p.dim(&size), p.badge(&f.signal), detail);
}

fn write_reports(opts: &Opts, all: &[Finding]) {
    if let Some(j) = &opts.json {
        match serde_json::to_string_pretty(all) { Ok(s) => { let _ = fs::write(j, s); println!("wrote {}", j.display()); } Err(e) => eprintln!("json: {}", e) }
    }
    if let Some(m) = &opts.md {
        let mut md = String::from("# PolinRider local scan\n\n");
        let mut cur = String::new();
        for f in all {
            if f.target != cur { cur = f.target.clone(); md.push_str(&format!("\n## {}\n\n", cur)); }
            md.push_str(&format!("- `{}` · `{}` · {} · {}\n", f.branch, f.path, if f.size > 0 { fmt_b(f.size) } else { "—".into() }, f.signal));
        }
        let _ = fs::write(m, md);
        println!("wrote {}", m.display());
    }
}

fn cmd_scan(eng: &Engine, opts: &Opts, p: &Paint) -> i32 {
    let targets = discover(&opts.paths);
    if targets.is_empty() { eprintln!("Nothing to scan. Pass one or more folders."); return 1; }
    let git_ok = !opts.no_git && git::available();
    if !opts.no_git && !git_ok { eprintln!("{}", p.dim("note: git not found — scanning working trees only")); }
    println!("{} {} target(s){}", p.bold("Scanning"), targets.len(), if opts.all_branches && git_ok { " · all local branches" } else { "" });
    let reports = scan_targets(eng, &targets, opts.all_branches, opts.me.as_deref(), git_ok);
    let (mut infected, mut history_only, mut tz_only, mut clean) = (0usize, 0usize, 0usize, 0usize);
    let mut all: Vec<Finding> = Vec::new();
    for r in &reports {
        let remote = r.remote.as_ref().map(|u| format!("  {}", p.dim(u))).unwrap_or_default();
        let mut show_rows = true;
        match r.status.as_str() {
            "infected" => { infected += 1; println!("\n{} {}{}", p.red("INFECTED"), p.bold(&r.target), remote); }
            "history" => { history_only += 1; println!("\n{} {}{}  {}", p.mag("HISTORY "), p.bold(&r.target), remote, p.dim("(payload only in past commits — tip is clean)")); }
            "tz-note" => { tz_only += 1; show_rows = !opts.quiet; if !opts.quiet { println!("\n{} {}{}  {}", p.dim("TZ-NOTE "), p.bold(&r.target), remote, p.dim("(commits from a foreign timezone, no payload found — verify manually)")); } }
            _ => { clean += 1; if !opts.quiet { println!("{} {}", p.grn("clean   "), r.target); } }
        }
        if show_rows { for x in &r.findings { print_row(p, x); } }
        all.extend(r.findings.iter().cloned());
    }
    let files_total = all.iter().filter(|x| x.kind != "history" && !x.signal.starts_with("WARN")).count();
    let warns = all.iter().filter(|x| x.signal.starts_with("WARN")).count();
    println!("\n{}", p.bold("Summary"));
    println!("  targets: {}   infected: {}   history-only: {}   tz-notes: {}   clean: {}   flagged files: {}   unverified: {}",
             targets.len(), if infected > 0 { p.red(&infected.to_string()) } else { "0".into() }, history_only, tz_only, clean, files_total, warns);
    write_reports(opts, &all);
    if infected > 0 { 2 } else { 0 }
}

fn cmd_fix(eng: &Engine, opts: &Opts, p: &Paint) -> i32 {
    let targets = discover(&opts.paths);
    if targets.is_empty() { eprintln!("Nothing to fix. Pass one or more folders."); return 1; }
    let git_ok = !opts.no_git && git::available();
    println!("{} {} target(s)  {}", p.bold("Fixing"), targets.len(),
             if opts.apply { p.yel("APPLY — files will be modified") } else { p.blu("DRY RUN — nothing is written (add --apply)") });
    let rep = fix_targets(eng, &targets, opts.apply, opts.commit, opts.push, None, git_ok);
    let mut cur = String::new();
    let mut review = 0usize;
    for r in &rep.rows {
        if r.target != cur { cur = r.target.clone(); println!("\n{} {}", p.bold(&cur), p.dim(&format!("[{}]", r.branch))); }
        let res = if r.needs_review { review += 1; p.yel(&r.result) } else if r.changed { p.grn(&format!("✓ {}", r.result)) } else { r.result.clone() };
        println!("   {:<46} {:<20} {}", r.path, p.dim(&r.method), res);
    }
    for n in &rep.notes { println!("   {} {}", p.dim("→"), n); }
    if rep.rows.is_empty() { println!("{}", p.grn("Nothing to fix — all targets clean.")); }
    if review > 0 { println!("\n{} {} file(s) need manual review.", p.yel("!"), review); }
    0
}

fn cmd_purge(opts: &Opts, p: &Paint) -> i32 {
    let (repo, branch, good) = match (&opts.repo, &opts.branch, &opts.good) {
        (Some(r), Some(b), Some(g)) => (r, b, g),
        _ => { eprintln!("purge needs --repo DIR --branch BRANCH --good SHA [--force-push] --yes"); return 1; }
    };
    if !git::is_repo(repo) { eprintln!("{} is not a git repository", repo.display()); return 1; }
    println!("{} This rewrites `{}` in {} to {}{}.", p.red("DESTRUCTIVE"), branch, repo.display(), good,
             if opts.force_push { " and force-pushes it" } else { " (local only; add --force-push to publish)" });
    if !opts.yes { println!("Re-run with --yes to confirm."); return 1; }
    for args in [vec!["checkout", branch.as_str()], vec!["reset", "--hard", good.as_str()]] {
        if let Err(e) = git::run(repo, &args) { eprintln!("{} git {}: {}", p.red("✗"), args.join(" "), e); return 1; }
    }
    println!("{} {} now at {}", p.grn("✓"), branch, good);
    if opts.force_push {
        match git::run(repo, &["push", "--force-with-lease", "origin", branch]) {
            Ok(_) => println!("{} force-pushed {}", p.grn("✓"), branch),
            Err(e) => { eprintln!("{} push failed: {}", p.red("✗"), e); return 1; }
        }
    }
    0
}

fn help() {
    println!("polinrider {} — PolinRider / auth-con-firm / TaskJacker worm scanner & fixer for local repos and folders

USAGE
  polinrider                 same as `ui`: opens the web tool in your browser with local mode enabled
  polinrider ui    [--port N] [--no-open]
  polinrider scan  <paths…>  [--all-branches] [--me NAME] [--iocs FILE] [--json OUT] [--md OUT] [--no-git] [-q]
  polinrider fix   <paths…>  [--apply] [--commit] [--push] [--iocs FILE]
  polinrider purge --repo DIR --branch BRANCH --good SHA [--force-push] --yes
  polinrider iocs            print the default IOC database (import into the web tool, or edit and pass with --iocs)

UI     serves the web tool on 127.0.0.1 (random port, per-session token) and opens your browser. The page scans
       GitHub directly as before and gains a Local panel: folders/clones on this machine, git history, all branches.
SCAN   finds git repos under each path (or treats it as a plain folder) and checks: build-config injection,
       .env droppers, .vscode autorun (tasks/settings/launch), disguised .vscode files, fake fonts,
       temp_auto_push.bat, package.json malicious deps / lifecycle scripts, oversized root scripts.
       With git: history pickaxe for known markers; --all-branches scans every local branch without
       checking out; --me NAME flags commits authored as you but committed from a foreign timezone.
FIX    dry-run by default. Restores configs from the last clean commit (else reconstructs), strips
       .env droppers and package.json entries, deletes weaponized tasks.json / fake fonts / artifacts.
       Never writes a file that still matches the detectors. --commit makes one commit per repo; --push pushes.
PURGE  resets a branch to a known-good commit (history rewrite). Explicit and guarded.

EXIT   0 clean · 2 infected · 1 error", env!("CARGO_PKG_VERSION"));
}

fn main() {
    let opts = parse_args();
    let paint = Paint(opts.color);
    let cmd = if opts.cmd.is_empty() { "ui" } else { opts.cmd.as_str() };
    if cmd == "help" { help(); return; }
    if cmd == "version" { println!("polinrider {}", env!("CARGO_PKG_VERSION")); return; }
    if cmd == "iocs" { println!("{}", serde_json::to_string_pretty(&Ioc::default()).unwrap()); return; }
    if cmd == "ui" { std::process::exit(server::run(opts.port, !opts.no_open)); }
    let ioc: Ioc = match &opts.iocs {
        Some(pth) => match fs::read_to_string(pth).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str::<Ioc>(&t).map_err(|e| e.to_string())) {
            Ok(i) => i, Err(e) => { eprintln!("could not load IOC file {}: {}", pth.display(), e); std::process::exit(1); }
        },
        None => Ioc::default(),
    };
    let eng = match Engine::new(ioc) { Ok(e) => e, Err(e) => { eprintln!("{}", e); std::process::exit(1); } };
    let code = match cmd {
        "scan" => cmd_scan(&eng, &opts, &paint),
        "fix" => cmd_fix(&eng, &opts, &paint),
        "purge" => cmd_purge(&opts, &paint),
        other => { eprintln!("unknown command: {}\n", other); help(); 1 }
    };
    std::process::exit(code);
}
