# polinrider — local CLI

Scanner & fixer for the **PolinRider / auth-con-firm / TaskJacker** worm, for **local git repositories
and plain project folders**. Single static binary, no runtime dependencies. Companion to the browser
tool (`polinrider.html` / https://polinder.bedri.space), sharing the same detectors and IOC database.

## Install
Download the binary for your OS and put it on your PATH:
- `polinrider-windows-x64.exe` — Windows
- `polinrider-linux-x64` — Linux (static, musl). After downloading: `chmod +x polinrider-linux-x64`
- `polinrider-macos-arm64` / `polinrider-macos-x64` — macOS (Apple Silicon / Intel). After downloading:
  `chmod +x polinrider-macos-arm64 && xattr -d com.apple.quarantine polinrider-macos-arm64` (unsigned binary → Gatekeeper)
- or build from source: `cargo build --release` (see *Build*).

## Use
```bash
# the easy way: open the full web UI in your browser with LOCAL mode (folders, clones, git history, branches)
polinrider                      # same as `polinrider ui`; add --no-open to just print the URL, --port N to pin a port
```
The UI binds to 127.0.0.1 only and every local API call must carry a per-session random token that is part of
the URL it opens — other websites or tabs cannot drive it. Remote GitHub scanning works in the same page as before.

```bash
# scan everything under a folder (finds every git repo beneath it; plain folders work too)
polinrider scan ~/Projects

# thorough: every local branch (no checkout needed) + flag commits from a foreign timezone made as you
polinrider scan ~/Projects --all-branches --me "Your Name"

# reports
polinrider scan ~/Projects --json results.json --md report.md

# preview fixes (dry run), then apply, then apply + commit per repo
polinrider fix ~/Projects
polinrider fix ~/Projects --apply
polinrider fix ~/Projects --apply --commit          # add --push to push too

# history rewrite (explicit, guarded)
polinrider purge --repo ./myrepo --branch main --good <clean-sha> --force-push --yes

# the IOC database — import into the web tool, or edit and pass back with --iocs
polinrider iocs > my-iocs.json
polinrider scan ~/Projects --iocs my-iocs.json
```
Exit code **2** means something is infected (handy in scripts/CI).

## What it detects
Build-config injection (whitespace-padded blob or `atob` + fetch loader), `.env` droppers,
`.vscode/tasks.json` autorun with hidden presentation, `settings.json` automatic-task presets,
`launch.json` abuse, disguised payloads in `.vscode`, JavaScript hidden in fake fonts (`.woff2`/`.ttf`/`.otf`/`.eot`/`.llf`, judged by magic bytes + known SHA-256),
`temp_auto_push.bat` / `config.bat`, known malicious npm packages and install-time lifecycle scripts,
and — with git — history pickaxe hits and foreign-timezone commits.

## How fixes work
Dry run by default. Configs are restored from the newest clean commit in history; if none exists the
payload is cut out (both variants). `.env` loses the dropper line; `package.json` loses malicious deps and
lifecycle scripts; weaponized `tasks.json`, fake fonts and artifacts are deleted; `settings.json`,
`launch.json` and root scripts are left for manual review. A file is **never** written if it still matches
the detectors or if cleaning would remove its export.

## Build
```bash
cargo build --release                                  # native
cargo build --release --target x86_64-unknown-linux-musl   # static Linux (from any host with the target installed)
```
