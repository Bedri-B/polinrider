//! Thin wrappers around the `git` CLI. Everything degrades gracefully when git is absent.

use std::path::Path;
use std::process::Command;

pub fn available() -> bool {
    Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

pub fn is_repo(dir: &Path) -> bool { dir.join(".git").exists() }

pub fn run(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn run_bytes(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().map_err(|e| e.to_string())?;
    if !out.status.success() { return Err(String::from_utf8_lossy(&out.stderr).trim().to_string()); }
    Ok(out.stdout)
}

pub fn current_branch(dir: &Path) -> String {
    run(dir, &["rev-parse", "--abbrev-ref", "HEAD"]).map(|s| s.trim().to_string()).unwrap_or_else(|_| "HEAD".into())
}

pub fn remote_url(dir: &Path) -> Option<String> {
    run(dir, &["remote", "get-url", "origin"]).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub fn local_branches(dir: &Path) -> Vec<String> {
    run(dir, &["for-each-ref", "--format=%(refname:short)", "refs/heads"])
        .map(|s| s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

/// Files in a branch's tree: (path, size). Uses `git ls-tree -r -l` so nothing is checked out.
pub fn ls_tree(dir: &Path, branch: &str) -> Vec<(String, u64)> {
    let out = match run(dir, &["ls-tree", "-r", "-l", branch]) { Ok(o) => o, Err(_) => return Vec::new() };
    out.lines().filter_map(|line| {
        let (meta, path) = line.split_once('\t')?;
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() < 4 || parts[1] != "blob" { return None; }
        Some((path.to_string(), parts[3].parse::<u64>().unwrap_or(0)))
    }).collect()
}

pub fn show(dir: &Path, branch: &str, path: &str) -> Option<Vec<u8>> {
    run_bytes(dir, &["show", &format!("{}:{}", branch, path)]).ok()
}

/// Older versions of a file on the current branch, newest first: (sha, bytes). At most 30.
pub fn file_history(dir: &Path, path: &str) -> Vec<(String, Vec<u8>)> {
    let shas = match run(dir, &["log", "--format=%H", "-n", "30", "--", path]) { Ok(s) => s, Err(_) => return Vec::new() };
    shas.lines().filter_map(|sha| {
        let sha = sha.trim();
        if sha.is_empty() { return None; }
        show(dir, sha, path).map(|b| (sha.to_string(), b))
    }).collect()
}

/// Commits anywhere in history that added/removed a literal term (`git log --all -S`).
pub fn pickaxe(dir: &Path, term: &str) -> Vec<String> {
    run(dir, &["log", "--all", "-S", term, "--oneline"])
        .map(|s| s.lines().take(5).map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

/// All commits: (committer ISO date, short sha, author name, subject).
pub fn log_tz(dir: &Path) -> Vec<(String, String, String, String)> {
    run(dir, &["log", "--all", "--pretty=%cI|%h|%an|%s"])
        .map(|s| s.lines().filter_map(|l| {
            let mut it = l.splitn(4, '|');
            Some((it.next()?.to_string(), it.next()?.to_string(), it.next()?.to_string(), it.next().unwrap_or("").to_string()))
        }).collect())
        .unwrap_or_default()
}
