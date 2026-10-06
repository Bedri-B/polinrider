#!/usr/bin/env python3
"""
PolinRider Control Panel — a Gradio app to detect, fix, and purge the
"auth-con-firm" / PolinRider config-injection worm across local clones and
GitHub repositories.

Single-file. Run:
    pip install -r requirements.txt
    python polinrider_app.py           # opens http://localhost:7860
    python polinrider_app.py --share   # also creates a temporary public link

The worm injects a remote-code-execution loader into build config files
(postcss/next/vite/tailwind/eslint/... .config.*) — either as a ~30 KB
obfuscated blob after ~280 spaces on the `export default config;` line, or as
an `atob(AUTH_API_KEY)` + node-fetch + code-eval loader paired with a committed
`.env`. It hides by amending commits and force-pushing (committer-timezone tell).

This tool only READS suspect content — it never executes any payload.
"""
import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import gradio as gr

# --------------------------------------------------------------------------- #
#  Configuration                                                              #
# --------------------------------------------------------------------------- #
CONFIG_DIR = Path.home() / ".polinrider"
CONFIG_PATH = CONFIG_DIR / "config.json"

# markers assembled by concatenation so this source file itself stays clean
_DROP_KEY = "AUTH_API" + "_KEY"
_EVAL = "ev" + "al"
_B64 = "aHR0cHM6Ly9hdXRoLWNvbi1maXJt"  # base64 of https://auth-con-firm...

DEFAULT_CONFIG = {
    # file paths that the worm targets
    "config_regex": r"(postcss|next|vite|tailwind|eslint|astro|vue|webpack|jest|"
                    r"svelte|nuxt|rollup|remix|drizzle)\.config\.(js|cjs|mjs|ts)$",
    "env_regex": r"(^|/)\.env($|\.)",
    # high-signal literal markers (both variants)
    "markers": [
        "A9-4091", "A4-1928", "'4-1928'", "RS260605",
        _DROP_KEY, "auth-con-firm", _B64, _EVAL + "(proxyInfo)",
        "a322e5f3d311d3080e6f0121063e9adc2490ef1a",
        "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP",
        "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG",
        "bsc-dataseed", "trongrid",
    ],
    # regex markers for the obfuscated blob
    "marker_regex": r"A[0-9]-[0-9]{4}|C2[0-9]{5}A|RS2[0-9]{5}|_\$_[0-9a-f]{4,}|"
                    r"global\['[^']'\]=require|createRequire",
    # a config file bigger than this (bytes) is treated as payloaded
    "size_threshold": 8000,
    # a single line longer than this is a strong payload signal
    "line_threshold": 400,
    # committer timezones that are NOT yours (foreign-TZ tell). Comma list.
    "foreign_tz": ["-06:00", "+02:00"],
    # your own author name(s), used to distinguish your commits from upstream
    "author_match": "Bedri",
    # a commit whose file was scaffolded clean, used as restore source fallback
    "github_token": "",
    "local_roots": [str(Path.home() / "Projects")],
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return f"Saved to {CONFIG_PATH}"


CFG = load_config()

# --------------------------------------------------------------------------- #
#  git / shell helpers                                                        #
# --------------------------------------------------------------------------- #
def run(args, cwd=None, timeout=120):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # noqa
        return 1, "", str(e)


def git(repo, *args, timeout=120):
    return run(["git", "-C", str(repo), *args], timeout=timeout)


def find_git_repos(roots):
    repos = []
    for root in roots:
        root = root.strip()
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if ".git" in dirnames:
                repos.append(dirpath)
                dirnames[:] = [d for d in dirnames if d != ".git"]  # don't descend into .git
    return sorted(set(repos))


# --------------------------------------------------------------------------- #
#  GitHub API                                                                 #
# --------------------------------------------------------------------------- #
def gh_token(cfg):
    """Resolve a token: UI/config -> env -> gh CLI."""
    if cfg.get("github_token"):
        return cfg["github_token"].strip()
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    rc, out, _ = run(["gh", "auth", "token"])
    if rc == 0 and out.strip():
        return out.strip()
    return ""


def gh_api(path, token, params=None):
    url = "https://api.github.com/" + path.lstrip("/")
    if params:
        from urllib.parse import urlencode
        url += "?" + urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
    except Exception as e:  # noqa
        return None, str(e)


def gh_api_paginated(path, token, params=None):
    params = dict(params or {})
    params["per_page"] = 100
    page, out = 1, []
    while True:
        params["page"] = page
        data, err = gh_api(path, token, params)
        if err or not data:
            break
        out.extend(data)
        if len(data) < 100:
            break
        page += 1
        if page > 30:
            break
    return out


# --------------------------------------------------------------------------- #
#  Detection logic                                                            #
# --------------------------------------------------------------------------- #
def is_config(path, cfg):
    return re.search(cfg["config_regex"], path, re.I) is not None


def is_env(path, cfg):
    return re.search(cfg["env_regex"], path, re.I) is not None


def blob_signal(content, size, cfg, is_cfg):
    """Return a signal string if content looks infected, else ''."""
    if is_cfg and size and size > cfg["size_threshold"]:
        return f"SIZE-ANOMALY({size}b)"
    hits = set(re.findall(cfg["marker_regex"], content))
    for m in cfg["markers"]:
        if m in content:
            hits.add(m)
    # very long line
    longest = max((len(l) for l in content.splitlines()), default=0)
    if longest > cfg["line_threshold"] and is_cfg:
        hits.add(f"LONGLINE({longest})")
    return "MARKER:" + ",".join(sorted(hits)) if hits else ""


def scan_local_repo(repo, cfg, do_history=True):
    """Return list of findings dicts for one local repo."""
    findings = []
    # tracked files
    rc, out, _ = git(repo, "ls-files")
    tracked = out.splitlines() if rc == 0 else []
    for rel in tracked:
        if not (is_config(rel, cfg) or is_env(rel, cfg)):
            continue
        fp = Path(repo) / rel
        if not fp.exists():
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        sig = blob_signal(content, fp.stat().st_size, cfg, is_config(rel, cfg))
        if sig:
            findings.append({"repo": repo, "branch": "(working-tree)",
                             "file": rel, "size": fp.stat().st_size,
                             "signal": sig, "where": "tree"})
    # history pickaxe
    if do_history:
        for term in ["A9-4091", _DROP_KEY, "a322e5f3d311d3080e6f0121063e9adc2490ef1a"]:
            rc, out, _ = git(repo, "log", "--all", "-S", term, "--oneline")
            if rc == 0 and out.strip():
                first = out.strip().splitlines()[0]
                findings.append({"repo": repo, "branch": "(history)",
                                 "file": f"pickaxe:{term}", "size": 0,
                                 "signal": f"HISTORY:{first[:60]}", "where": "history"})
        # foreign-TZ commits authored by you
        rc, out, _ = git(repo, "log", "--all", "--pretty=%cI|%h|%an|%s")
        if rc == 0:
            for line in out.splitlines():
                parts = line.split("|", 3)
                if len(parts) < 4:
                    continue
                ci, h, an, subj = parts
                if any(tz in ci for tz in cfg["foreign_tz"]) and cfg["author_match"].lower() in an.lower():
                    findings.append({"repo": repo, "branch": "(history)",
                                     "file": f"commit:{h}", "size": 0,
                                     "signal": f"FOREIGN-TZ {ci}", "where": "history"})
    return findings


def scan_remote_repo(full, cfg, token, all_branches=True):
    """Scan a GitHub repo via API. Returns list of findings dicts."""
    findings = []
    if all_branches:
        branches = gh_api_paginated(f"repos/{full}/branches", token)
        refs = [(b["name"], b["commit"]["sha"]) for b in branches if isinstance(b, dict)]
    else:
        info, err = gh_api(f"repos/{full}", token)
        if err or not info:
            return [{"repo": full, "branch": "?", "file": "(error)", "size": 0,
                     "signal": err or "no data", "where": "remote"}]
        refs = [(info["default_branch"], info["default_branch"])]
    blob_cache = {}
    for br, sha in refs:
        tree, err = gh_api(f"repos/{full}/git/trees/{sha}", token, {"recursive": "1"})
        if err or not tree or "tree" not in tree:
            findings.append({"repo": full, "branch": br, "file": "(unverified)",
                             "size": 0, "signal": "WARN: tree fetch failed", "where": "remote"})
            continue
        for node in tree["tree"]:
            if node.get("type") != "blob":
                continue
            path = node["path"]
            if not (is_config(path, cfg) or is_env(path, cfg)):
                continue
            size = node.get("size", 0)
            sig = ""
            if is_config(path, cfg) and size > cfg["size_threshold"]:
                sig = f"SIZE-ANOMALY({size}b)"
            else:
                bsha = node["sha"]
                if bsha in blob_cache:
                    sig = blob_cache[bsha]
                else:
                    blob, berr = gh_api(f"repos/{full}/git/blobs/{bsha}", token)
                    if blob and blob.get("content"):
                        import base64
                        try:
                            content = base64.b64decode(blob["content"]).decode("utf-8", "replace")
                        except Exception:
                            content = ""
                        sig = blob_signal(content, size, cfg, is_config(path, cfg))
                    blob_cache[bsha] = sig
            if sig:
                findings.append({"repo": full, "branch": br, "file": path,
                                 "size": size, "signal": sig, "where": "remote"})
    return findings


# --------------------------------------------------------------------------- #
#  Fix logic                                                                  #
# --------------------------------------------------------------------------- #
def clean_history_blob(repo, rel, cfg):
    """Return (sha, content) of newest clean historical version of rel, or (None, None)."""
    rc, out, _ = git(repo, "log", "--all", "--format=%H", "--", rel)
    if rc != 0:
        return None, None
    for h in out.splitlines():
        rc2, sz, _ = git(repo, "cat-file", "-s", f"{h}:{rel}")
        if rc2 != 0:
            continue
        try:
            if int(sz.strip()) > cfg["size_threshold"]:
                continue
        except ValueError:
            continue
        rc3, content, _ = git(repo, "show", f"{h}:{rel}")
        if rc3 == 0 and not re.search(cfg["marker_regex"], content) \
                and not any(m in content for m in cfg["markers"]):
            return h, content
    return None, None


def fix_repo(repo, cfg, apply=False):
    """Clean infected config/.env files in the working tree. Returns log lines."""
    log = []
    rc, out, _ = git(repo, "ls-files")
    tracked = out.splitlines() if rc == 0 else []
    changed = 0
    for rel in tracked:
        fp = Path(repo) / rel
        if not fp.exists():
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        size = fp.stat().st_size
        if is_config(rel, cfg):
            sig = blob_signal(content, size, cfg, True)
            if not sig:
                continue
            h, clean = clean_history_blob(repo, rel, cfg)
            if clean is not None:
                log.append(f"  {rel}: restore from clean commit {h[:9]} ({size}b -> {len(clean)}b)")
                target = clean
            else:
                # reconstruct: drop long lines + trim whitespace runs
                lines = [l for l in content.splitlines() if len(l) <= cfg["line_threshold"]]
                target = "\n".join(re.sub(r"\s{80,}.*$", "", l) for l in lines) + "\n"
                log.append(f"  {rel}: RECONSTRUCTED (no clean history — REVIEW) ({size}b -> {len(target)}b)")
            if apply:
                fp.write_text(target, encoding="utf-8")
            changed += 1
        elif is_env(rel, cfg):
            if _DROP_KEY not in content:
                continue
            kept = [l for l in content.splitlines() if _DROP_KEY not in l]
            log.append(f"  {rel}: strip {_DROP_KEY} line(s)")
            if apply:
                if kept:
                    fp.write_text("\n".join(kept) + "\n", encoding="utf-8")
                else:
                    fp.unlink()
            changed += 1
    if not changed:
        log.append("  nothing to fix (already clean)")
    return log, changed


def commit_and_push(repo, message, do_push, branch=None):
    log = []
    git(repo, "add", "-A")
    rc, out, err = git(repo, "commit", "-m", message)
    log.append((out + err).strip() or "commit done")
    if do_push:
        args = ["push", "origin"]
        if branch:
            args.append(branch)
        rc, out, err = git(repo, *args)
        log.append((out + err).strip() or "push done")
    return "\n".join(log)


def history_purge(repo, branch, good_sha, force_push, cfg):
    """Reset a branch to a known-good commit and (optionally) force-push."""
    log = []
    rc, out, err = git(repo, "checkout", branch)
    log.append((out + err).strip())
    rc, out, err = git(repo, "reset", "--hard", good_sha)
    log.append((out + err).strip())
    if force_push:
        rc, out, err = git(repo, "push", "--force-with-lease", "origin", branch)
        log.append((out + err).strip())
    else:
        log.append("(dry-run: not pushed. Enable force-push to publish.)")
    return "\n".join(l for l in log if l)


# --------------------------------------------------------------------------- #
#  Batch fix (clone fresh -> fix all branches -> commit -> push)              #
# --------------------------------------------------------------------------- #
FIX_MSG = "security: remove injected RCE payload (PolinRider/auth-con-firm worm)"


def _rmtree(path):
    def onerr(func, p, _):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=onerr)


def clone_fresh(full, workdir, token):
    """Clone a repo (all branches) into workdir. Returns (path, error)."""
    dest = os.path.join(workdir, full.replace("/", "__"))
    _rmtree(dest)
    os.makedirs(workdir, exist_ok=True)
    rc, out, err = run(["gh", "repo", "clone", full, dest, "--", "--no-single-branch"],
                       timeout=300)
    if rc == 0:
        return dest, None
    url = (f"https://x-access-token:{token}@github.com/{full}.git"
           if token else f"https://github.com/{full}.git")
    rc, out, err = run(["git", "clone", "--no-single-branch", url, dest], timeout=300)
    return (dest, None) if rc == 0 else (None, (err or out).strip()[:120])


def remote_branches(repo):
    rc, out, _ = git(repo, "branch", "-r")
    brs = []
    for line in out.splitlines():
        line = line.strip()
        if "->" in line or not line.startswith("origin/"):
            continue
        brs.append(line.split("origin/", 1)[1])
    return brs


def process_repo(full, workdir, all_branches, do_push, apply, cfg, token):
    """Clone + fix one repo. Returns a table row: [repo, branches, fixed, files, status]."""
    dest, err = clone_fresh(full, workdir, token)
    if err:
        return [full, "-", "-", "-", "CLONE FAILED: " + err]
    branches = remote_branches(dest) if all_branches else \
        [git(dest, "symbolic-ref", "--short", "HEAD")[1].strip() or "master"]
    fixed, total = [], 0
    for br in branches:
        git(dest, "checkout", "-B", br, f"origin/{br}")
        log, n = fix_repo(dest, cfg, apply=apply)
        if n:
            total += n
            if apply:
                git(dest, "add", "-A")
                git(dest, "commit", "-m", FIX_MSG)
            fixed.append(br)
    pushed = ""
    if apply and do_push and fixed:
        ok = 0
        for br in fixed:
            git(dest, "checkout", br)
            rc, o, e = git(dest, "push", "origin", br)
            if rc == 0:
                ok += 1
        pushed = f"pushed {ok}/{len(fixed)}"
    elif apply:
        pushed = "committed (not pushed)" if fixed else "-"
    status = ("DRY-RUN: %d file(s) on %d branch" % (total, len(fixed))) if not apply \
        else ("FIXED %d file(s)" % total if total else "clean")
    fixed_disp = (", ".join(fixed[:4]) + (" +%d" % (len(fixed) - 4) if len(fixed) > 4 else "")) \
        if fixed else "-"
    return [full, len(branches), fixed_disp, total, pushed if apply else status]


def journal_load(path):
    recs = {}
    if os.path.exists(path):
        try:
            for line in open(path, encoding="utf-8"):
                line = line.strip()
                if line:
                    r = json.loads(line)
                    recs[r["repo"]] = r
        except Exception:
            pass
    return recs


def journal_append(path, rec):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
        f.flush()


def batch_fix(repos, workdir, all_branches, do_push, apply, cfg, token,
              batch_size=10, resume=True, journal_path=None):
    """Generator yielding (results_rows, skipped_count) as each repo completes.

    - Processes `repos` in chunks of `batch_size`.
    - Journals each completed repo to a JSONL file so a crash is resumable:
      re-running with resume=True skips repos already recorded.
    """
    workdir = workdir or str(CONFIG_DIR / "workdir")
    journal_path = journal_path or os.path.join(workdir, "batch_journal.jsonl")
    if not resume and os.path.exists(journal_path):
        try:
            os.remove(journal_path)
        except Exception:
            pass
    done = journal_load(journal_path) if resume else {}
    # seed the table with already-done repos that are part of this target list
    results = [list(done[r]["row"]) for r in repos if r in done]
    skipped = len(results)
    pending = [r for r in repos if r not in done]
    yield results, skipped  # show resumed rows immediately
    bs = max(1, int(batch_size))
    for start in range(0, len(pending), bs):
        chunk = pending[start:start + bs]
        for full in chunk:
            row = process_repo(full, workdir, all_branches, do_push, apply, cfg, token)
            journal_append(journal_path, {"repo": full, "row": row,
                                          "ts": time.time(),
                                          "mode": "apply" if apply else "dry"})
            results.append(row)
            yield results, skipped


# --------------------------------------------------------------------------- #
#  Gradio glue                                                                #
# --------------------------------------------------------------------------- #
def rows(findings):
    return [[f["repo"], f["branch"], f["file"], f["size"], f["signal"]] for f in findings]


def ui_local_scan(roots_text, progress=gr.Progress()):
    cfg = load_config()
    roots = [r for r in roots_text.splitlines() if r.strip()]
    progress(0, desc="Discovering repositories…")
    repos = find_git_repos(roots)
    n = len(repos)
    if not n:
        yield "No git repositories found under those roots.", []
        return
    all_f, infected = [], set()
    for i, r in enumerate(repos):
        progress((i + 1) / n, desc=f"{i + 1}/{n}  {os.path.basename(r)}")
        f = scan_local_repo(r, cfg)
        all_f.extend(f)
        if f:
            infected.add(r)
        yield (f"⏳ Scanning… **{i + 1}/{n}** repos · INFECTED **{len(infected)}** · "
               f"findings **{len(all_f)}**"), rows(all_f)
    yield (f"✅ Done. Scanned **{n}** repos · INFECTED **{len(infected)}** · "
           f"findings **{len(all_f)}**."), rows(all_f)


def ui_remote_scan(repos_text, use_all, all_branches, token_ui, progress=gr.Progress()):
    cfg = load_config()
    if token_ui.strip():
        cfg = dict(cfg); cfg["github_token"] = token_ui.strip()
    token = gh_token(cfg)
    if not token:
        yield "No GitHub token (paste one or run `gh auth login`).", []
        return
    progress(0, desc="Resolving repository list…")
    if use_all:
        data = gh_api_paginated("user/repos", token,
                               {"affiliation": "owner,organization_member,collaborator"})
        targets = [d["full_name"] for d in data if isinstance(d, dict)]
    else:
        targets = [r.strip() for r in repos_text.splitlines() if r.strip()]
    n = len(targets)
    if not n:
        yield "No repositories to scan.", []
        return
    all_f, infected = [], set()
    for i, full in enumerate(targets):
        progress((i + 1) / n, desc=f"{i + 1}/{n}  {full}")
        f = scan_remote_repo(full, cfg, token, all_branches)
        real = [x for x in f if not x["signal"].startswith("WARN")]
        all_f.extend(f)
        if real:
            infected.add(full)
        yield (f"⏳ Scanning GitHub… **{i + 1}/{n}** repos · INFECTED **{len(infected)}** · "
               f"findings **{len(all_f)}**"), rows(all_f)
    # persist the infected list so Batch Fix can auto-load it
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        (CONFIG_DIR / "last_remote_infected.json").write_text(
            json.dumps(sorted(infected)), encoding="utf-8")
    except Exception:
        pass
    summary = (f"✅ Done. Scanned **{n}** repos "
               f"({'all branches' if all_branches else 'default only'}) · "
               f"INFECTED **{len(infected)}** · findings **{len(all_f)}**. "
               f"_Saved list → Batch Fix can auto-load it._")
    yield summary, rows(all_f)


def load_last_infected():
    p = CONFIG_DIR / "last_remote_infected.json"
    if p.exists():
        try:
            return "\n".join(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass
    return ""


def ui_fix_preview(repo_path):
    cfg = load_config()
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return "Not a git repo: " + repo_path
    log, n = fix_repo(repo_path, cfg, apply=False)
    return f"DRY-RUN — {n} file(s) would change:\n" + "\n".join(log)


def ui_fix_apply(repo_path, do_commit, do_push, branch):
    cfg = load_config()
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return "Not a git repo: " + repo_path
    log, n = fix_repo(repo_path, cfg, apply=True)
    out = [f"APPLIED — {n} file(s) changed:"] + log
    if do_commit and n:
        msg = "security: remove injected RCE payload (PolinRider/auth-con-firm worm)"
        out.append("\n" + commit_and_push(repo_path, msg, do_push, branch or None))
    elif do_commit:
        out.append("(nothing changed; no commit)")
    return "\n".join(out)


def ui_purge(repo_path, branch, good_sha, force_push, confirm):
    if confirm.strip().upper() != "PURGE":
        return "Type PURGE to confirm this destructive history rewrite."
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return "Not a git repo: " + repo_path
    cfg = load_config()
    return history_purge(repo_path, branch, good_sha, force_push, cfg)


BATCH_HDRS = ["repo", "branches", "fixed branches", "files", "status / push"]


def ui_batch_fix(repos_text, workdir, all_branches, apply, do_push, confirm, token_ui,
                 batch_size, resume, progress=gr.Progress()):
    cfg = load_config()
    if token_ui.strip():
        cfg = dict(cfg); cfg["github_token"] = token_ui.strip()
    token = gh_token(cfg)
    repos = [r.strip() for r in repos_text.splitlines() if r.strip() and "/" in r]
    if not repos:
        yield "No valid OWNER/REPO lines.", []
        return
    if apply and do_push and confirm.strip().upper() != "PUSH":
        yield "To commit AND push, type PUSH in the confirm box. (Or uncheck push for a local-only fix.)", []
        return
    workdir = workdir.strip() or str(CONFIG_DIR / "workdir")
    journal = os.path.join(workdir, "batch_journal.jsonl")
    mode = "DRY-RUN" if not apply else ("APPLY+PUSH" if do_push else "APPLY (local commit)")
    n = len(repos)
    results = []
    progress(0, desc=f"Starting {mode} — {n} repos, {int(batch_size)}/batch…")
    for results, skipped in batch_fix(repos, workdir, all_branches, do_push, apply, cfg, token,
                                      batch_size=int(batch_size), resume=resume,
                                      journal_path=journal):
        done = len(results)
        cur = results[-1][0] if results else ""
        progress(min(done, n) / n, desc=f"{done}/{n}  {cur}")
        skip_txt = f" · resumed {skipped}" if skipped else ""
        yield (f"⏳ **{mode}** — {done}/{n} done{skip_txt} · batch {int(batch_size)} · "
               f"journal `{journal}`"), list(results)
    yield (f"✅ **{mode} complete** — {len(results)}/{n} repos"
           f"{f' ({skipped} resumed from journal)' if skipped else ''}. "
           f"Results saved to `{journal}` · clones in `{workdir}`."), list(results)


def ui_save_settings(config_regex, size_threshold, line_threshold, foreign_tz,
                     author_match, markers_text, token, roots_text):
    cfg = load_config()
    cfg["config_regex"] = config_regex
    cfg["size_threshold"] = int(size_threshold)
    cfg["line_threshold"] = int(line_threshold)
    cfg["foreign_tz"] = [t.strip() for t in foreign_tz.split(",") if t.strip()]
    cfg["author_match"] = author_match
    cfg["markers"] = [m.strip() for m in markers_text.splitlines() if m.strip()]
    cfg["github_token"] = token.strip()
    cfg["local_roots"] = [r.strip() for r in roots_text.splitlines() if r.strip()]
    return save_config(cfg)


HDRS = ["repo", "branch", "file", "size", "signal"]


def build_ui():
    cfg = load_config()
    with gr.Blocks(title="PolinRider Control Panel", theme=gr.themes.Soft()) as app:
        gr.Markdown("# 🛡️ PolinRider Control Panel\n"
                    "Detect, fix, and purge the **auth-con-firm / PolinRider** "
                    "config-injection worm across local clones and GitHub repos. "
                    "_Read-only scanning never executes payloads._")

        with gr.Tab("🔎 Local Scan"):
            roots = gr.Textbox(label="Root folders (one per line)",
                               value="\n".join(cfg["local_roots"]), lines=3)
            btn = gr.Button("Scan local repos", variant="primary")
            sm = gr.Markdown()
            tbl = gr.Dataframe(headers=HDRS, interactive=False, wrap=True)
            btn.click(ui_local_scan, [roots], [sm, tbl])

        with gr.Tab("🌐 Remote Scan"):
            with gr.Row():
                use_all = gr.Checkbox(label="Scan ALL accessible repos", value=False)
                all_br = gr.Checkbox(label="All branches (thorough)", value=True)
            repos_box = gr.Textbox(label="Repos (OWNER/REPO, one per line)", lines=4,
                                   placeholder="Bedri-B/orangecow")
            token_box = gr.Textbox(label="GitHub token (optional — else uses gh CLI / env)",
                                   type="password")
            rbtn = gr.Button("Scan GitHub", variant="primary")
            rsm = gr.Markdown()
            rtbl = gr.Dataframe(headers=HDRS, interactive=False, wrap=True)
            rbtn.click(ui_remote_scan, [repos_box, use_all, all_br, token_box], [rsm, rtbl])

        with gr.Tab("🧹 Fix (local clone)"):
            gr.Markdown("Cleans infected config/`.env` files by restoring the last "
                        "clean version from history. Preview first; apply writes files.")
            fpath = gr.Textbox(label="Path to local clone")
            with gr.Row():
                pbtn = gr.Button("Preview (dry-run)")
                abtn = gr.Button("Apply", variant="primary")
            with gr.Row():
                do_commit = gr.Checkbox(label="Also commit", value=False)
                do_push = gr.Checkbox(label="Also push (no force)", value=False)
                fbranch = gr.Textbox(label="Branch to push", scale=1)
            fout = gr.Textbox(label="Result", lines=14)
            pbtn.click(ui_fix_preview, [fpath], [fout])
            abtn.click(ui_fix_apply, [fpath, do_commit, do_push, fbranch], [fout])

        with gr.Tab("📦 Batch Fix"):
            gr.Markdown("Clone each repo **fresh** (all branches), remove the payload "
                        "from every infected branch, commit, and optionally push. "
                        "Fresh clones avoid the re-infection trap from your working copies.\n\n"
                        "**Preview first** (dry-run). To push, tick both boxes and type `PUSH`.")
            b_load = gr.Button("⤵ Load infected repos from last Remote Scan")
            b_repos = gr.Textbox(label="Repos to fix (OWNER/REPO, one per line)", lines=6,
                                 placeholder="Bedri-B/orangecow\nBedri-B/AutoBack")
            b_load.click(load_last_infected, [], [b_repos])
            with gr.Row():
                b_workdir = gr.Textbox(label="Clone workdir (blank = ~/.polinrider/workdir)", scale=2)
                b_allbr = gr.Checkbox(label="All branches", value=True)
            with gr.Row():
                b_batch = gr.Number(label="Batch size (repos per chunk)", value=10, precision=0,
                                    minimum=1)
                b_resume = gr.Checkbox(label="Resume (skip repos already in journal)", value=True)
            with gr.Row():
                b_apply = gr.Checkbox(label="Apply (write + commit)", value=False)
                b_push = gr.Checkbox(label="Also push", value=False)
                b_confirm = gr.Textbox(label="Type PUSH to confirm pushing", scale=1)
            b_token = gr.Textbox(label="GitHub token (optional — else gh CLI / env)", type="password")
            b_btn = gr.Button("Run batch", variant="primary")
            gr.Markdown("_Results are journaled per-repo to `batch_journal.jsonl` in the workdir. "
                        "If it crashes, just run again with **Resume** on — done repos are skipped. "
                        "Uncheck Resume to start fresh._")
            b_sm = gr.Markdown()
            b_tbl = gr.Dataframe(headers=BATCH_HDRS, interactive=False, wrap=True)
            b_btn.click(ui_batch_fix,
                        [b_repos, b_workdir, b_allbr, b_apply, b_push, b_confirm, b_token,
                         b_batch, b_resume],
                        [b_sm, b_tbl])

        with gr.Tab("💣 History Purge"):
            gr.Markdown("**Destructive.** Resets a branch to a known-good commit and "
                        "force-pushes (`--force-with-lease`). Use only after you know the "
                        "last clean SHA. Type **PURGE** to confirm.")
            ppath = gr.Textbox(label="Path to local clone")
            with gr.Row():
                pbranch = gr.Textbox(label="Branch")
                pgood = gr.Textbox(label="Known-good commit SHA")
            pforce = gr.Checkbox(label="Actually force-push (off = dry-run)", value=False)
            pconfirm = gr.Textbox(label="Type PURGE to confirm")
            pbtn2 = gr.Button("Run purge", variant="stop")
            pout = gr.Textbox(label="Result", lines=10)
            pbtn2.click(ui_purge, [ppath, pbranch, pgood, pforce, pconfirm], [pout])

        with gr.Tab("⚙️ Settings"):
            s_cfg = gr.Textbox(label="Config file regex", value=cfg["config_regex"])
            with gr.Row():
                s_size = gr.Number(label="Size threshold (bytes)", value=cfg["size_threshold"])
                s_line = gr.Number(label="Long-line threshold", value=cfg["line_threshold"])
            s_tz = gr.Textbox(label="Foreign committer TZs (comma)",
                              value=",".join(cfg["foreign_tz"]))
            s_auth = gr.Textbox(label="Your author-name match", value=cfg["author_match"])
            s_mark = gr.Textbox(label="IOC markers (one per line)",
                                value="\n".join(cfg["markers"]), lines=8)
            s_tok = gr.Textbox(label="GitHub token (stored in ~/.polinrider/config.json)",
                               type="password", value=cfg.get("github_token", ""))
            s_roots = gr.Textbox(label="Default local roots (one per line)",
                                 value="\n".join(cfg["local_roots"]), lines=2)
            s_btn = gr.Button("Save settings", variant="primary")
            s_out = gr.Markdown()
            s_btn.click(ui_save_settings,
                        [s_cfg, s_size, s_line, s_tz, s_auth, s_mark, s_tok, s_roots], [s_out])

        gr.Markdown("---\n_IOCs: `auth-con-firm.vercel.app`, `" + _DROP_KEY +
                    "`, `A9-4091`, ETH `0xa322e5f3…`, committer TZ tell. "
                    "Config: `~/.polinrider/config.json`._")
    return app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", action="store_true", help="create a temporary public link")
    ap.add_argument("--port", type=int, default=7860)
    args = ap.parse_args()
    app = build_ui()
    app.launch(share=args.share, server_port=args.port)


if __name__ == "__main__":
    main()
