# PolinRider

Detect and remove the **PolinRider / auth-con-firm / TaskJacker** worm — a credential-stealing,
self-propagating campaign that injects a remote-code loader into build-config files
(`postcss`, `next`, `vite`, `tailwind`, `eslint`, …), drops VS Code autorun tasks, hides JavaScript in
fake font files, and spreads to every repository a stolen GitHub token can reach by **amending commits
and force-pushing** so nothing looks new.

Everything here runs **on your machine**. Nothing is sent anywhere except the GitHub API you point it at.

## Pick a tool

| | Best for | Install |
|---|---|---|
| **`polinrider.html`** — single-file web tool | Scanning and fixing repos **on GitHub** from any browser, any OS | none — open the file (or use the hosted copy) |
| **`cli/` — `polinrider` binary** | **Local clones & folders**, git history, all branches, plus the same web UI opened from the binary | download one executable |
| `polinrider_check*.sh`, `polinrider_fix.sh` | Bash-only quick checks | Git Bash / any shell |

Both tools share the **same detectors and the same IOC database** — export it from one, import into the other.

### Web tool
Open `polinrider.html` (or `https://polinder.bedri.space`), paste a GitHub token (`repo` scope), then
**Connect → Scan → Review → Fix**. Scans your own, organization and collaborator repositories, every branch,
resumably. Fixes are made through the GitHub Contents API as **normal commits** — never a force-push.

### Binary (local mode)
```bash
polinrider                      # opens the web UI with LOCAL mode: folders, clones, git history, all branches
polinrider scan ~/Projects --all-branches --me "Your Name"
polinrider fix  ~/Projects --apply --commit
polinrider iocs > iocs.json     # the shared IOC database
```
Binaries for **Windows, Linux, macOS (Apple Silicon and Intel)** are built by CI and published in
[Releases](https://github.com/Bedri-B/polinrider/releases) on every version tag. See [`cli/README.md`](cli/README.md).

macOS note: downloaded binaries are unsigned, so Gatekeeper blocks them once. Either right-click → Open, or:
```bash
chmod +x polinrider-macos-arm64 && xattr -d com.apple.quarantine polinrider-macos-arm64
```

## What it detects
- **Any build config, and entry points** — every `*.config.js/ts` (vite, vitest, jest, next, postcss, playwright, babel …), `.*rc.js` and gulp/grunt/knex file is inspected, not a fixed list; the same `atob` + fetch loader is also found spliced into `src/main.ts`, `index.ts`, `App.js`, `server.js` (root or under `src/`), which are content-scanned when small and cleaned by cutting the loader block only
- **Config injection** — a ~30 KB obfuscated blob hidden after ~280 spaces on the `export default` line,
  or an `atob(…)` + `node-fetch` + code-eval loader paired with a committed `.env`
- **VS Code autorun (TaskJacker)** — `.vscode/tasks.json` with `"runOn":"folderOpen"` and a hidden
  presentation running `curl | bash` or `node <disguised file>`; `settings.json` presets; `launch.json` abuse;
  disguised payloads in `.vscode` (judged by content, not name)
- **Fake fonts** — JavaScript inside `.woff2`/`.ttf`/`.otf`/`.eot` and invented extensions like `.llf` under `public/`, `assets/`, `fonts/` (real binary fonts pass a magic-byte check)
- **Artifacts** — the propagation scripts `temp_auto_push.bat` / `temp_interactive_push.bat` / `config.bat`, and `.gitignore` lines added to hide them
- **Known payloads** — exact SHA-256 matches of payload files from the 2026-10 B2 wave
- **Variants covered** — original `rmcej%otb%`/`_$_1e42`, rotated `Cot%3t=shtP`/`MDy`, variant A (`global.i='A8-…'`, also in `migrations/*.js`), and B2 (`global['!']='9-6516-2'` with a javascript-obfuscator `_0x…` string table, `jest.config.js`, `fa-solid-900.woff2` in decoy Font Awesome folders, forged commits from +0200)
- **npm vector** — known malicious packages and install-time lifecycle scripts in `package.json`
- **Git tells** — history pickaxe for known markers; commits authored as you but committed from a foreign
  timezone (the amend-and-force-push fingerprint)

## How fixes work
Dry-run by default. Config files are restored from the newest clean commit in history; if none exists the
payload is cut out (both variants). `.env` loses the dropper line; `package.json` loses malicious entries;
weaponized `tasks.json`, fake fonts and artifacts are deleted; `settings.json` loses only the worm's keys
(`task.allowAutomaticTasks`, the decoy `tasks` block, `terminal.integrated.hideOnStartup`, disabled workspace
trust) and is deleted when nothing legitimate is left; entry files and root scripts have the loader line or
block cut out; `launch.json` is left for manual review. A file is **never** written while it still matches the
detectors, or if cleaning would remove its export.

Owners or repositories listed under **Exclude** on the scan page are never scanned and never fixed, even when
they are part of a ticked scope. The list is remembered in the browser.

## After cleaning — do this too
The worm steals tokens. Rotate GitHub PATs and revoke OAuth grants (including the GitHub CLI's), rotate
SSH keys and any secrets in affected repos, check `github.com/settings/security-log`, and warn
collaborators whose repos your token could push to.

## Repository layout
```
polinrider.html            the web tool (also embedded into the binary at build time)
cli/                       Rust CLI + local UI server (Cargo project)
deploy/                    Cloudflare Worker config that serves the web tool
polinrider_check.sh        bash: local scan (working tree + git history)
polinrider_check_remote.sh bash: GitHub API scan without cloning
polinrider_fix.sh          bash: local fix
legacy/                    original Python/Gradio app (superseded)
```

## Credits
Campaign research: [OpenSourceMalware / PolinRider](https://github.com/OpenSourceMalware/PolinRider),
[Abstract Security](https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector),
[JFrog Security Research](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/),
and the GitHub community discussions that first documented the config-injection variant.

## Contributing & branch policy
`main` is protected: no force-pushes or history rewrites, linear history, and every change lands through a
pull request that must pass CI (Rust build + HTML syntax + security audit). This is deliberate — the worm
this project fights spreads by force-pushing amended commits.

## License
MIT — see [LICENSE](LICENSE). Provided as-is; always review a dry run before committing fixes.
