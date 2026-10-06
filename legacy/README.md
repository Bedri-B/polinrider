# 🛡️ PolinRider Control Panel

A single-file **Gradio** app to detect, fix, and purge the **auth-con-firm / PolinRider**
config-injection worm across your local git clones and GitHub repositories.

The worm injects a remote-code-execution loader into build config files
(`postcss.config.*`, `next.config.*`, `vite.config.*`, `tailwind.config.*`,
`eslint.config.*`, …) — either as a ~30 KB obfuscated blob hidden after ~280
spaces on the `export default config;` line, or as an `atob(AUTH_API_KEY)` +
`node-fetch` + code-eval loader paired with a committed `.env`. It hides by
**amending commits and force-pushing** (the committer-timezone is the tell).

> **Scanning is read-only and never executes any payload.** Fix/commit/push and
> history-purge are explicit, gated actions.

## Install & run

Use a **clean virtual environment** (avoids dependency clashes with other tools):

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements.txt
python polinrider_app.py            # opens http://localhost:7860
python polinrider_app.py --share    # also creates a temporary public gradio.live link
python polinrider_app.py --port 8000
```

## Tabs

| Tab | What it does |
|---|---|
| **🔎 Local Scan** | Give it root folders; it finds every git repo under them and scans the working tree **and full history** (marker pickaxe + foreign-timezone commits). Read-only. |
| **🌐 Remote Scan** | Scans GitHub repos via the API **without cloning**. One repo, a list, or all accessible repos. All-branches by default. Uses your `gh` login / `GITHUB_TOKEN` / a pasted token. |
| **🧹 Fix** | Cleans infected config/`.env` files in a local clone by restoring the last clean version from history. Preview (dry-run) first; Apply writes files. Optional commit + push (never force). |
| **📦 Batch Fix** | Clones each repo in a list **fresh** (all branches), removes the payload from every infected branch, commits, and optionally pushes. Streams progress per repo. Processes in **chunks** (Batch size, default 10). Journals every completed repo to `batch_journal.jsonl` in the workdir — **if it crashes, re-run with Resume on and it skips what's done** (0-cost, no re-clone). Uncheck Resume to start fresh. Fresh clones avoid re-infection from your working copies. Dry-run by default; to push, tick both boxes and type `PUSH`. Also has **⤵ Load infected repos from last Remote Scan**. |
| **💣 History Purge** | Destructive: resets a branch to a known-good SHA and force-pushes (`--force-with-lease`). Type `PURGE` to confirm. |
| **⚙️ Settings** | Edit IOC markers, size/line thresholds, foreign timezones, your author name, GitHub token, and default roots. Saved to `~/.polinrider/config.json`. |

## Authentication

Remote scans need a GitHub token. The app resolves it in this order:
1. Token pasted in the Remote Scan tab (or saved in Settings)
2. `GITHUB_TOKEN` environment variable
3. `gh auth token` (GitHub CLI, if installed and logged in)

A read-only token (`repo`, `read:org`) is enough for scanning. Fix/push needs write.

## IOCs it looks for

- Domain `auth-con-firm.vercel.app` · base64 `aHR0cHM6Ly9hdXRoLWNvbi1maXJt`
- Env var `AUTH_API_KEY`, `atob(...)`, `node-fetch`, code-eval loader
- Obfuscation build-IDs `A9-4091`, `RS260605`, `createRequire`, `global['...']`
- Ethereum C2 wallet `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a`
- Config files far larger than a real config (default > 8 KB) or with a very long line
- Commits whose committer timezone isn't yours (default `-06:00`, `+02:00`)

All of these are configurable in the Settings tab.

## Notes

- **Fix works on a clone, not the remote.** To fix a GitHub repo: clone → Fix (Apply) → commit → push.
- **Your own infected working clones re-inject on merge** — always fix the clone you actually work from, or you'll re-seed the payload.
- A forward-fix makes the branch tip clean (builds pass); the payload remains in old
  history until you run **History Purge**.
