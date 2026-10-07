//! Detection + fix engine.
//!
//! A faithful port of the detectors in `polinrider.html`, so the CLI and the web tool share one
//! IOC database (this loads the exact JSON the web tool exports) and one set of rules.
//! Nothing here ever executes repository content — it only reads and rewrites text.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

// Marker strings are assembled at compile time so this source never contains the literals.
pub const DROP_KEY: &str = concat!("AUTH_API", "_KEY");
pub const EVAL_MARK: &str = concat!("ev", "al(proxyInfo)");
const B64SIG: &str = "aHR0cHM6Ly9hdXRoLWNvbi1maXJt";

/// IOC database. Field names serialize as camelCase — identical to the web tool's export.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Ioc {
    pub config_regex: String,
    pub env_regex: String,
    pub vscode_regex: String,
    pub vscode_exec_regex: String,
    pub vscode_aux_regex: String,
    pub artifact_regex: String,
    /// `.gitignore` files are scanned for entries that hide the propagation scripts.
    pub gitignore_regex: String,
    /// Exact SHA-256 hashes of known payload files — a match is certain.
    pub known_hashes: Vec<String>,
    pub font_regex: String,
    pub font_max_bytes: u64,
    pub script_regex: String,
    /// Entry points (src/main.ts, index.ts, App.js …) the auth-con-firm loader is spliced into.
    pub entry_regex: String,
    /// Entry files above this size are bundles and are not downloaded.
    pub entry_max_bytes: u64,
    pub package_regex: String,
    pub npm_packages: Vec<String>,
    pub lifecycle_regex: String,
    pub marker_regex: String,
    pub markers: Vec<String>,
    pub size_threshold: u64,
    pub line_threshold: usize,
    /// Committer timezones that are not yours (the amend/force-push tell). CLI-only.
    pub foreign_tz: Vec<String>,
}

fn default_entry_regex() -> String { r"^(main|index|app|server|App)\.(js|cjs|mjs|ts|mts|cts)$|(^|/)src/(main|index|app|server|App)\.(js|cjs|mjs|ts|mts|cts)$".into() }
fn default_entry_max_bytes() -> u64 { 20_000 }

impl Default for Ioc {
    fn default() -> Self {
        Ioc {
            config_regex: r"(^|/)[A-Za-z0-9_.-]*\.(config|conf)\.(js|cjs|mjs|ts|mts|cts)$|(^|/)\.[a-z-]+rc\.(js|cjs|mjs)$|(^|/)(gulpfile|gruntfile|knexfile)\.(js|cjs|mjs|ts)$".into(),
            env_regex: r"(^|/)\.env($|\.)".into(),
            vscode_regex: r"(^|/)\.vscode/(tasks|settings|launch)\.json$".into(),
            vscode_exec_regex: r"curl\b|wget\b|powershell|Invoke-|\biex\b|\bnode\b|\bbash\b|\bsh\b|\bcmd\b|\|\s*(ba)?sh\b|base64|atob\(|\.(woff2?|ttf|otf|eot|llf|fnt|dict|svg|png|jpe?g|css)\b|vercel\.app|onrender\.com|short\.gy".into(),
            vscode_aux_regex: r"(^|/)\.vscode/[^/]+\.(dict|txt|log|dat|bin)$".into(),
            artifact_regex: r"(^|/)(temp_auto_push\.bat|temp_interactive_push\.bat|config\.bat)$".into(),
            gitignore_regex: r"(^|/)\.gitignore$".into(),
            known_hashes: [
                "ce20d9cfa23ac3a25ac41fa9d9da5935102996249934233df5d85c74551a647a", // root api.js dropper (Sales-pro, Sep/Oct 2026, hex-array obfuscator)
                "8b8ee2a11453ca691a51ccaa18de0c1f94d5237fddd7aaf425aceb550290d38c", // babel.config.js with global['!']='8-9153-15' blob (Sales-pro)
                "3b572a613f5013a64e1877dfed3873f2bcbd52e5259b199d41e02c33840abbcb", // fa-solid-300.llf (cashier/backend kit, Sep 2026)
                "7922bce938af965008c1481f5f47d6c85b09217e10147fa35979e8aa4585ff8d", // B2 jest.config.js
                "586e1904c8e8d69ab58e9e1c77fc5e7a044d910bb57b3f3b8d587368b4f84d15", // B2 fake fa-solid-900.woff2
                "d16f87b70496999cfbb907ff3a7693cdfea6db5ecd21d6faafbb8320530ff2a4", // B2 .vscode/tasks.json
                "92823600a82bdc05b1474176504f94e725068852764577f58c9529dedb7c35ed", // B2 .vscode/tasks.json (variant)
                "1abb6c799080b3641d88dc541d0eafbc5a8c153d05d482745191e8887a1debf5", // B2 .vscode/settings.json
            ].iter().map(|s| s.to_string()).collect(),
            font_regex: r"(^|/)(public|static|assets|webfonts|fonts)/.*\.(woff2?|ttf|otf|eot|llf|fnt|bin|dat)$".into(),
            font_max_bytes: 524_288,
            script_regex: r"^[A-Za-z0-9_.-]+\.(js|cjs|mjs)$|(^|/)migrations/[^/]+\.(js|cjs|mjs|ts)$".into(),
            entry_regex: default_entry_regex(),
            entry_max_bytes: default_entry_max_bytes(),
            package_regex: r"(^|/)package\.json$".into(),
            npm_packages: [
                "tailwindcss-style-animate", "tailwind-mainanimation", "tailwind-autoanimation", "tailwind-animationbased",
                "tailwindcss-typography-style", "tailwindcss-style-modify", "tailwindcss-animate-style", "jsonwebauth",
            ].iter().map(|s| s.to_string()).collect(),
            lifecycle_regex: r"\bnode\s+-e\b|curl\b|wget\b|powershell|Invoke-Expression|\biex\b|bash\s+-c|\|\s*(ba)?sh\b|base64\s+(-d|--decode)|certutil|bitsadmin".into(),
            marker_regex: r#"A[0-9]-[0-9]{4}|C2[0-9]{5}A|RS2[0-9]{5}|_\$_[0-9a-f]{4,}|createRequire|global\['|function MDy\(|rmcej%otb%|Cot%3t=shtP|8-st[0-9]+|_0x[0-9a-f]{4,}|global\.i\s*=\s*['"][A-Z]?[0-9]{1,2}(-[0-9]{3,4})?['"]|=\s*\[\s*'[0-9a-f]{16,}'\s*,\s*'[0-9a-f]{16,}'"#.into(),
            markers: default_markers(),
            size_threshold: 8000,
            line_threshold: 400,
            foreign_tz: vec!["-06:00".into(), "+02:00".into()],
        }
    }
}

fn default_markers() -> Vec<String> {
    let mut m: Vec<String> = [
        // loader strings
        "A9-4091", "A4-1928", "RS260605", "9-4091", "9-3333", "9-1591-1", "9-6516-2", "8-9153-15", "A8-1817-3", "A9-3947-2",
        DROP_KEY, "auth-con-firm", B64SIG, EVAL_MARK, "rmcej%otb%", "Cot%3t=shtP",
        "_$_1e42", "LAST_COMMIT_DATE", "temp_auto_push", "temp_interactive_push", "Sec-V",
        // XOR keys and template fingerprint
        "2[gWfGj;<:-93Z^C", "m6:tTh^D)cBz?NM]", "ThZG+0jfXE6VAGOJ", "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9",
        // blockchain dead-drops (ETH / TRON / Aptos)
        "a322e5f3d311d3080e6f0121063e9adc2490ef1a", "0xE1f2395ee43e45A1556EC6438a88c31B83493103",
        "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP", "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG", "TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v",
        "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e",
        "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3",
        "0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1",
        "api.trongrid.io", "fullnode.mainnet.aptoslabs.com", "bsc-dataseed", "bsc-rpc.publicnode.com", "trongrid",
        // C2 / staging hosts
        "260120.vercel.app", "default-configuration.vercel.app", "vscode-settings-bootstrap.vercel.app",
        "vscode-settings-config.vercel.app", "vscode-bootstrapper.vercel.app", "vscode-load-config.vercel.app",
        "vscode-toolkit-bootstrap.vercel.app", "vscodesettingstask.vercel.app", "vscode-config-settings.vercel.app",
        "vscode-extension-260120.vercel.app", "regioncheck.xyz", "vscodeconfig.com", "vscode-load.onrender.com",
        "jsonkeeper.com", "jsonsilo.com", "npoint.io", "npm-cache.com",
        // C2 IPs
        "166.88.54.158", "166.88.134.62", "198.105.127.210", "23.27.202.27", "154.91.0.103", "136.0.9.8", "188.43.33.249",
        // Telegram exfil bot token prefix
        "7870147428:AAG",
    ].iter().map(|s| s.to_string()).collect();
    m.dedup();
    m
}

fn ci(re: &str) -> Result<Regex, String> {
    RegexBuilder::new(re).case_insensitive(true).build().map_err(|e| format!("invalid regex `{}`: {}", re, e))
}
fn cs(re: &str) -> Result<Regex, String> {
    Regex::new(re).map_err(|e| format!("invalid regex `{}`: {}", re, e))
}

pub fn fmt_b(n: u64) -> String {
    if n >= 1_048_576 { format!("{:.1} MB", n as f64 / 1_048_576.0) }
    else if n >= 1024 { format!("{:.1} KB", n as f64 / 1024.0) }
    else { format!("{} B", n) }
}

pub struct Engine {
    pub ioc: Ioc,
    cfg: Regex, env: Regex, vsc: Regex, vsc_exec: Regex, aux: Regex, art: Regex, font: Regex,
    script: Regex, entry: Regex, pkg: Regex, lifecycle: Regex, marker: Regex, gitignore: Regex, gi_hide: Regex, chain: Regex,
    decoy_tasks: Regex, hide_term: Regex,
    run_on: Regex, hidden: Regex, padded: Regex, js_font: Regex, hexrun: Regex, code_aux: Regex,
    iife_start: Regex, iife_end: Regex, ws80: Regex, import_dotenv: Regex, cr_import: Regex, cr_const: Regex,
    require_call: Regex, export_re: Regex, blank3: Regex,
    pre_launch: Regex, disguised_prog: Regex, allow_auto: Regex, trust_off: Regex,
}

/// What the fixer intends to do with one file.
pub enum Plan {
    Delete(String),
    Review(String),
    Rewrite { content: String, method: String },
}

/// Final decision after safety gates.
pub struct Outcome {
    pub method: String,
    pub result: String,
    pub action: Action,
}
pub enum Action { None, Delete, Write(String) }

impl Engine {
    pub fn new(ioc: Ioc) -> Result<Self, String> {
        Ok(Engine {
            cfg: ci(&ioc.config_regex)?, env: ci(&ioc.env_regex)?, vsc: ci(&ioc.vscode_regex)?,
            vsc_exec: ci(&ioc.vscode_exec_regex)?, aux: ci(&ioc.vscode_aux_regex)?, art: ci(&ioc.artifact_regex)?,
            font: ci(&ioc.font_regex)?, script: ci(&ioc.script_regex)?, entry: ci(&ioc.entry_regex)?, pkg: ci(&ioc.package_regex)?,
            lifecycle: ci(&ioc.lifecycle_regex)?, marker: cs(&ioc.marker_regex)?,
            gitignore: ci(&ioc.gitignore_regex)?,
            gi_hide: ci(r"temp_auto_push|temp_interactive_push|^\s*config\.bat\s*$")?,
            chain: cs(r"(^|&&|;|\|\|)\s*node\s+(\./)?([A-Za-z0-9_.-]+\.(?:js|cjs|mjs))\s*&&")?,
            decoy_tasks: ci(r#""tasks"\s*:\s*\{[\s\S]{0,600}?"runOn"\s*:\s*"folderOpen""#)?,
            hide_term: ci(r#""terminal\.integrated\.hideOnStartup"\s*:\s*"always""#)?,
            run_on: ci(r#""runOn"\s*:\s*"folderOpen""#)?,
            hidden: ci(r#""hide"\s*:\s*true|"reveal"\s*:\s*"(never|silent)"|"echo"\s*:\s*false|"close"\s*:\s*true"#)?,
            padded: cs(r"\S[ \t]{80,}\S")?,
            js_font: cs(r"\b(function|require|const|var|let|return|process)\b|=>|\.(call|apply)\(")?,
            hexrun: ci(r"[0-9a-f]{200,}")?,
            code_aux: cs(r"\brequire\s*\(|\bfunction\b|=>|\bprocess\.|child_process|Buffer\.from|\bglobal\[|https?://")?,
            iife_start: cs(r"^\s*\(\s*(async\s*)?(function\b|\(\s*\)\s*=>)")?,
            iife_end: cs(r"^\s*\}\s*\)\s*\(\s*\)\s*;?\s*$")?,
            ws80: cs(r"\s{80,}.*$")?,
            import_dotenv: cs(r#"^\s*import\s+['"]dotenv/config['"];?\s*$"#)?,
            cr_import: cs(r"import[ {].*createRequire.*from .module.")?,
            cr_const: cs(r"const +require *= *createRequire")?,
            require_call: cs(r"require\s*\(")?,
            export_re: cs(r"export\s+default|module\.exports")?,
            blank3: cs(r"\n{3,}")?,
            pre_launch: ci(r#""preLaunchTask""#)?,
            disguised_prog: ci(r#""(runtimeExecutable|program)"\s*:\s*"[^"]*\.(woff2?|ttf|otf|eot|llf|fnt|dict|svg|png|jpe?g|css)""#)?,
            allow_auto: ci(r#""task\.allowAutomaticTasks"\s*:\s*"?(on|true)"?"#)?,
            trust_off: ci(r#""security\.workspace\.trust\.enabled"\s*:\s*false"#)?,
            ioc,
        })
    }

    // ---- path classifiers (paths use forward slashes, relative to the repo/folder root) ----
    pub fn is_cfg(&self, p: &str) -> bool { self.cfg.is_match(p) }
    pub fn is_env(&self, p: &str) -> bool { self.env.is_match(p) }
    pub fn is_vscode(&self, p: &str) -> bool { self.vsc.is_match(p) }
    pub fn is_vscode_aux(&self, p: &str) -> bool { self.aux.is_match(p) }
    pub fn is_artifact(&self, p: &str) -> bool { self.art.is_match(p) }
    pub fn is_font(&self, p: &str) -> bool { self.font.is_match(p) }
    pub fn is_script(&self, p: &str) -> bool { self.script.is_match(p) }
    /// Entry points (src/main.ts, index.ts, App.js …) the auth-con-firm loader is spliced into; content-scanned when small.
    pub fn is_entry(&self, p: &str) -> bool { self.entry.is_match(p) && !self.is_cfg(p) }
    pub fn is_pkg(&self, p: &str) -> bool { self.pkg.is_match(p) }
    pub fn is_gitignore(&self, p: &str) -> bool { self.gitignore.is_match(p) }
    pub fn interesting(&self, p: &str) -> bool {
        self.is_cfg(p) || self.is_env(p) || self.is_vscode(p) || self.is_vscode_aux(p) || self.is_artifact(p)
            || self.is_font(p) || self.is_script(p) || self.is_entry(p) || self.is_pkg(p) || self.is_gitignore(p)
    }

    /// `.gitignore` lines the worm adds so its propagation scripts never show up in `git status`.
    pub fn gitignore_signal(&self, content: &str) -> String {
        let hits: Vec<&str> = content.lines().filter(|l| self.gi_hide.is_match(l)).map(|l| l.trim()).collect();
        if hits.is_empty() { String::new() } else { format!("ARTIFACT: .gitignore hides propagation script ({})", hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ")) }
    }

    fn known_hash(&self, bytes: &[u8]) -> Option<String> {
        if self.ioc.known_hashes.is_empty() { return None; }
        let hex = format!("{:x}", Sha256::digest(bytes));
        if self.ioc.known_hashes.iter().any(|h| h.eq_ignore_ascii_case(&hex)) { Some(hex) } else { None }
    }

    fn longest_line(c: &str) -> usize { c.split('\n').map(|l| l.chars().count()).max().unwrap_or(0) }
    fn strip_marker(s: String) -> String { s.trim_start_matches("MARKER:").trim().to_string() }

    /// Core text detector: markers, obfuscation regex, size and long-line rules.
    pub fn signal(&self, content: &str, size: u64, cfg: bool) -> String {
        if cfg && size > self.ioc.size_threshold { return format!("SIZE-ANOMALY({})", fmt_b(size)); }
        let mut hits: Vec<String> = Vec::new();
        for m in self.marker.find_iter(content) {
            let s = m.as_str().to_string();
            if !hits.contains(&s) { hits.push(s); }
        }
        for m in &self.ioc.markers {
            if !m.is_empty() && content.contains(m.as_str()) && !hits.contains(m) { hits.push(m.clone()); }
        }
        let longest = Self::longest_line(content);
        if cfg && longest > self.ioc.line_threshold { hits.push(format!("LONGLINE({})", longest)); }
        if hits.is_empty() { String::new() } else { format!("MARKER: {}", hits.iter().take(4).cloned().collect::<Vec<_>>().join(", ")) }
    }

    /// `.vscode/{tasks,settings,launch}.json` — TaskJacker autorun dropper.
    pub fn vscode_signal(&self, path: &str, content: &str) -> String {
        let base = path.rsplit('/').next().unwrap_or(path).to_lowercase();
        let mut h: Vec<String> = Vec::new();
        let folder_open = self.run_on.is_match(content);
        let hidden = self.hidden.is_match(content);
        let exec = self.vsc_exec.is_match(content);
        let padded = self.padded.is_match(content);
        let m = Self::strip_marker(self.signal(content, content.len() as u64, false));
        if base == "tasks.json" {
            if folder_open {
                h.push("runOn folderOpen".into());
                if exec { h.push("shell/node exec".into()); }
                if hidden { h.push("hidden task".into()); }
                if padded { h.push("whitespace-padded".into()); }
                if !m.is_empty() { h.push(m); }
                return format!("VSCODE-AUTORUN: {}", h.join(", "));
            }
            if !m.is_empty() { h.push(m); }
            if exec && hidden { h.push("hidden shell task".into()); }
            return if h.is_empty() { String::new() } else { format!("VSCODE-AUTORUN: {}", h.join(", ")) };
        }
        if base == "settings.json" {
            if self.allow_auto.is_match(content) { h.push("task.allowAutomaticTasks preset".into()); }
            if self.trust_off.is_match(content) { h.push("workspace trust disabled".into()); }
            if self.decoy_tasks.is_match(content) { h.push("decoy folderOpen task block".into()); }
            if self.hide_term.is_match(content) { h.push("terminal hidden on startup".into()); }
            if !m.is_empty() { h.push(m); }
            return if h.is_empty() { String::new() } else { format!("VSCODE-SETTINGS: {}", h.join(", ")) };
        }
        if self.pre_launch.is_match(content) && exec { h.push("preLaunchTask + exec".into()); }
        if self.disguised_prog.is_match(content) { h.push("runs disguised file".into()); }
        if !m.is_empty() { h.push(m); }
        if h.is_empty() { String::new() } else { format!("VSCODE-LAUNCH: {}", h.join(", ")) }
    }

    /// Fonts under asset folders: real fonts start with a binary magic; the campaign hides JS text in them.
    pub fn font_signal(&self, bytes: &[u8]) -> String {
        if bytes.len() >= 4 {
            let head = &bytes[..4];
            if head == b"wOF2" || head == b"wOFF" || head == b"OTTO" || head == b"true" || head == b"ttcf" || head == [0, 1, 0, 0] {
                return String::new();
            }
        }
        let sample = &bytes[..bytes.len().min(4000)];
        if sample.is_empty() { return String::new(); }
        let printable = sample.iter().filter(|&&c| (32..127).contains(&c) || c == 9 || c == 10 || c == 13).count();
        if (printable as f64) / (sample.len() as f64) < 0.9 { return String::new(); }
        let text = String::from_utf8_lossy(bytes).to_string();
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let js = self.js_font.is_match(&text) || self.hexrun.is_match(&compact);
        let m = Self::strip_marker(self.signal(&text, text.len() as u64, false));
        if js || !m.is_empty() {
            format!("FAKE-FONT: text/JavaScript inside font file{}", if m.is_empty() { String::new() } else { format!(", {}", m) })
        } else { String::new() }
    }

    /// Non-JSON files under `.vscode`: a real dictionary/log is plain words; a disguised payload is code/hex.
    pub fn disguised_signal(&self, content: &str) -> String {
        let compact: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        let code = self.code_aux.is_match(content) || self.hexrun.is_match(&compact);
        let ln = Self::longest_line(content);
        let m = Self::strip_marker(self.signal(content, content.len() as u64, false));
        if !(code || !m.is_empty() || ln > self.ioc.line_threshold) { return String::new(); }
        let mut s = String::from("ARTIFACT: disguised payload in .vscode");
        if !m.is_empty() { s.push_str(&format!(", {}", m)); }
        if ln > self.ioc.line_threshold { s.push_str(&format!(", LONGLINE({})", ln)); }
        s
    }

    /// `package.json`: known malicious dependencies and install-time lifecycle scripts.
    pub fn pkg_signal(&self, content: &str) -> String {
        let mut h: Vec<String> = Vec::new();
        if let Ok(j) = serde_json::from_str::<Value>(content) {
            for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
                if let Some(Value::Object(d)) = j.get(k) {
                    for n in &self.ioc.npm_packages { if d.contains_key(n) { h.push(format!("pkg {}", n)); } }
                }
            }
            if let Some(Value::Object(s)) = j.get("scripts") {
                for k in ["preinstall", "install", "postinstall", "prepare", "prepublish"] {
                    if let Some(Value::String(v)) = s.get(k) { if self.lifecycle.is_match(v) { h.push(format!("script {}", k)); } }
                }
                // "dev": "node api.js && expo start" — a root-level node file chained before the real command
                for (k, v) in s.iter() {
                    if let Value::String(v) = v { if let Some(c) = self.chain.captures(v) { if !self.is_cfg(&c[3]) { h.push(format!("chain {} runs root {}", k, &c[3])); } } }
                }
            }
        }
        let m = Self::strip_marker(self.signal(content, content.len() as u64, false));
        if !m.is_empty() { h.push(m); }
        if h.is_empty() { return String::new(); }
        let kind = if h.iter().any(|x| x.starts_with("pkg ")) { "NPM-PACKAGE: " }
            else if h.iter().any(|x| x.starts_with("script ")) { "LIFECYCLE-SCRIPT: " }
            else if h.iter().any(|x| x.starts_with("chain ")) { "SCRIPT-CHAIN: " } else { "MARKER: " };
        format!("{}{}", kind, h.join(", "))
    }

    /// Root `App.js` / `index.js` (only inspected when unusually large): long line or markers, never size alone.
    pub fn script_signal(&self, content: &str, size: u64) -> String {
        let ln = Self::longest_line(content);
        let m = self.signal(content, size, false);
        if ln > self.ioc.line_threshold {
            if m.is_empty() { format!("MARKER: LONGLINE({})", ln) } else { format!("{}, LONGLINE({})", m, ln) }
        } else { m }
    }

    /// Classify one file given its path, size and (optionally) content/bytes.
    /// `read` is called lazily only when content is needed.
    pub fn classify<F>(&self, path: &str, size: u64, mut read: F) -> String
    where F: FnMut() -> Option<Vec<u8>> {
        if self.is_artifact(path) { return "ARTIFACT: propagation script (temp_auto_push)".into(); }
        let cfg = self.is_cfg(path);
        if cfg && size > self.ioc.size_threshold { return format!("SIZE-ANOMALY({})", fmt_b(size)); }
        let font = self.is_font(path);
        if font && size > self.ioc.font_max_bytes { return String::new(); }
        let scr = self.is_script(path);
        let ent = self.is_entry(path);
        if ent && size > self.ioc.entry_max_bytes { return String::new(); }            // big entry files are bundles
        if scr && !ent && !cfg && size <= self.ioc.size_threshold { return String::new(); }
        let bytes = match read() { Some(b) => b, None => return "WARN: unable to read file".into() };
        if let Some(hex) = self.known_hash(&bytes) {
            let what = if font { "fake font" } else if self.is_vscode(path) { "vscode file" } else if cfg { "config" } else { "file" };
            return format!("KNOWN-PAYLOAD: sha256 {}… exact match ({})", &hex[..12], what);
        }
        if font { return self.font_signal(&bytes); }
        let text = String::from_utf8_lossy(&bytes).to_string();
        if self.is_gitignore(path) { return self.gitignore_signal(&text); }
        if self.is_vscode_aux(path) { return self.disguised_signal(&text); }
        if self.is_vscode(path) { return self.vscode_signal(path, &text); }
        if self.is_pkg(path) { return self.pkg_signal(&text); }
        if (scr || ent) && !cfg { return self.script_signal(&text, size); }
        self.signal(&text, size, cfg)
    }

    // ---- fix ----

    fn has_marker(&self, line: &str) -> bool {
        self.ioc.markers.iter().any(|m| !m.is_empty() && line.contains(m.as_str())) || self.marker.is_match(line)
    }

    /// Rebuild a clean config when no clean historical version exists. Handles both variants:
    /// whitespace-padded blob (drop 80+-space runs / payload-length lines / injected createRequire prelude)
    /// and the auth-con-firm loader (cut the statement block containing an IOC marker + its orphaned imports).
    pub fn reconstruct(&self, c: &str) -> String { self.reconstruct_with(c, true) }

    /// `strict` (configs): every over-long line goes. Lenient (scripts/entry files): only over-long lines that carry a marker.
    pub fn reconstruct_with(&self, c: &str, strict: bool) -> String {
        let mut lines: Vec<String> = c.split('\n')
            .map(|l| self.ws80.replace(l, "").to_string())
            .filter(|l| l.chars().count() <= self.ioc.line_threshold || (!strict && !self.has_marker(l)))
            .collect();
        let mut i = 0usize;
        while i < lines.len() {
            if !self.has_marker(&lines[i]) { i += 1; continue; }
            let (mut s, mut e) = (i, i);
            while s > 0 && i - s < 60 && !self.iife_start.is_match(&lines[s]) { s -= 1; }
            while e + 1 < lines.len() && e - i < 60 && !self.iife_end.is_match(&lines[e]) { e += 1; }
            if self.iife_start.is_match(&lines[s]) && self.iife_end.is_match(&lines[e]) {
                lines.drain(s..=e); i = s;            // cut the enclosing IIFE
            } else {
                lines.remove(i);                       // fallback: cut the marker line
            }
        }
        let joined = lines.join("\n");
        let fetch_refs = joined.matches("node-fetch").count();
        let lines: Vec<String> = lines.into_iter()
            .filter(|l| !self.import_dotenv.is_match(l) && !(fetch_refs == 1 && l.contains("node-fetch")))
            .collect();
        let rest: Vec<&String> = lines.iter().filter(|l| !self.cr_import.is_match(l) && !self.cr_const.is_match(l)).collect();
        let rest_txt = rest.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
        let out = if lines.iter().any(|l| l.contains("createRequire")) && !self.require_call.is_match(&rest_txt) { rest_txt } else { lines.join("\n") };
        self.blank3.replace_all(&out, "\n\n").to_string()
    }

    /// `.vscode/settings.json`: drop only the worm's keys, keep the developer's own settings;
    /// delete when nothing legitimate is left.
    fn strip_settings(&self, cur: &str) -> Plan {
        let mut j: Value = match serde_json::from_str(cur) { Ok(v) => v, Err(_) => return Plan::Review("manual review (settings.json has comments)".into()) };
        let obj = match j.as_object_mut() { Some(o) => o, None => return Plan::Review("manual review".into()) };
        let mut changed = false;
        let auto_on = obj.get("task.allowAutomaticTasks").map(|v| matches!(v, Value::Bool(true))
            || v.as_str().map(|s| s.eq_ignore_ascii_case("on") || s.eq_ignore_ascii_case("true")).unwrap_or(false)).unwrap_or(false);
        if auto_on { obj.shift_remove("task.allowAutomaticTasks"); changed = true; }
        if obj.get("security.workspace.trust.enabled") == Some(&Value::Bool(false)) { obj.shift_remove("security.workspace.trust.enabled"); changed = true; }
        if obj.get("terminal.integrated.hideOnStartup").and_then(|v| v.as_str()) == Some("always") { obj.shift_remove("terminal.integrated.hideOnStartup"); changed = true; }
        let decoy_tasks = obj.get("tasks").map(|t| t.to_string().contains("\"runOn\":\"folderOpen\"")).unwrap_or(false);
        if decoy_tasks { obj.shift_remove("tasks"); changed = true; }
        if !changed { return Plan::Review("manual review".into()); }
        if obj.is_empty() { return Plan::Delete("delete settings.json (nothing legitimate left)".into()); }
        let mut out = serde_json::to_string_pretty(&j).unwrap_or_else(|_| cur.to_string());
        if cur.ends_with('\n') { out.push('\n'); }
        Plan::Rewrite { content: out, method: "strip settings.json".into() }
    }

    /// `flagged_root`: root-level script files already flagged in this target (so a chained `node api.js &&` can be dropped safely).
    fn strip_package(&self, cur: &str, flagged_root: &[String]) -> Plan {
        let mut j: Value = match serde_json::from_str(cur) { Ok(v) => v, Err(_) => return Plan::Review("manual review".into()) };
        let mut changed = false;
        if let Some(Value::Object(s)) = j.get_mut("scripts") {
            let keys: Vec<String> = s.keys().cloned().collect();
            for k in keys {
                let nv = match s.get(&k) {
                    Some(Value::String(v)) => match self.chain.captures(v) {
                        Some(c) if flagged_root.iter().any(|f| f == &c[3]) => Some(self.chain.replace(v, "$1 ").trim().to_string()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(nv) = nv { s.insert(k, Value::String(nv)); changed = true; }
            }
        }
        for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            if let Some(Value::Object(d)) = j.get_mut(k) {
                for n in &self.ioc.npm_packages { if d.shift_remove(n).is_some() { changed = true; } }
            }
        }
        if let Some(Value::Object(s)) = j.get_mut("scripts") {
            let keys: Vec<String> = s.keys().cloned().collect();
            for k in keys {
                if ["preinstall", "install", "postinstall", "prepare", "prepublish"].contains(&k.as_str()) {
                    if let Some(Value::String(v)) = s.get(&k) { if self.lifecycle.is_match(v) { s.shift_remove(&k); changed = true; } }
                }
            }
        }
        if !changed { return Plan::Review("manual review".into()); }
        let mut out = serde_json::to_string_pretty(&j).unwrap_or_else(|_| cur.to_string());
        if cur.ends_with('\n') { out.push('\n'); }
        Plan::Rewrite { content: out, method: "strip package.json".into() }
    }

    /// Decide how to clean one file. `history` yields (sha, bytes) of older versions, newest first.
    pub fn plan(&self, path: &str, sig: &str, cur: &str, history: Option<&dyn Fn() -> Vec<(String, Vec<u8>)>>) -> Plan {
        self.plan_with(path, sig, cur, history, &[])
    }

    /// Like `plan`, with the list of root-level script files already flagged in the same target
    /// (lets `package.json` drop a chained `node api.js &&` only when api.js itself is infected).
    pub fn plan_with(&self, path: &str, sig: &str, cur: &str, history: Option<&dyn Fn() -> Vec<(String, Vec<u8>)>>, flagged_root: &[String]) -> Plan {
        if self.is_gitignore(path) {
            let kept: Vec<&str> = cur.split('\n').filter(|l| !self.gi_hide.is_match(l)).collect();
            let kept = kept.join("\n");
            return if kept == cur { Plan::Review("manual review".into()) } else { Plan::Rewrite { content: kept, method: "strip .gitignore".into() } };
        }
        if self.is_artifact(path) || sig.starts_with("FAKE-FONT") || sig.starts_with("ARTIFACT")
            || (self.is_font(path) && sig.starts_with("KNOWN-PAYLOAD")) {
            return Plan::Delete("delete file".into());
        }
        if self.is_vscode(path) {
            let base = path.rsplit('/').next().unwrap_or(path).to_lowercase();
            if base == "tasks.json" {
                return if sig.starts_with("VSCODE-AUTORUN") || sig.starts_with("KNOWN-PAYLOAD") { Plan::Delete("delete tasks.json".into()) }
                       else { Plan::Review("manual review".into()) };
            }
            if base == "settings.json" {
                if sig.starts_with("KNOWN-PAYLOAD") { return Plan::Delete("delete settings.json".into()); }
                return self.strip_settings(cur);
            }
            return Plan::Review("manual review".into());
        }
        if self.is_pkg(path) { return self.strip_package(cur, flagged_root); }
        if self.is_env(path) {
            let kept: Vec<&str> = cur.split('\n').filter(|l| !l.contains(DROP_KEY)).collect();
            return Plan::Rewrite { content: kept.join("\n"), method: "strip dropper".into() };
        }
        if self.is_entry(path) || (self.is_script(path) && !self.is_cfg(path)) {
            // entry files & scripts: cut the loader line/block + orphaned imports; never restore old application code from history
            let out = self.reconstruct_with(cur, false);
            return if out == cur { Plan::Review("manual review".into()) }
                   else if out.trim().is_empty() { Plan::Delete("delete file (nothing legitimate left)".into()) }
                   else { Plan::Rewrite { content: out, method: "reconstruct".into() } };
        }
        if let Some(h) = history {
            for (sha, bytes) in h() {
                let t = String::from_utf8_lossy(&bytes).to_string();
                let sz = bytes.len() as u64;
                if sz <= self.ioc.size_threshold && self.signal(&t, sz, true).is_empty() {
                    let short: String = sha.chars().take(7).collect();
                    return Plan::Rewrite { content: t, method: format!("restore {}", short) };
                }
            }
        }
        Plan::Rewrite { content: self.reconstruct(cur), method: "reconstruct".into() }
    }

    /// Apply the safety gates: never call a file clean, and never write a copy, while detectors still fire.
    pub fn evaluate(&self, path: &str, plan: Plan, cur: &str, cur_size: u64) -> Outcome {
        match plan {
            Plan::Delete(m) => Outcome { method: m, result: format!("delete ({})", fmt_b(cur_size)), action: Action::Delete },
            Plan::Review(m) => Outcome { method: m, result: "Review manually — not auto-fixed".into(), action: Action::None },
            Plan::Rewrite { content, method } => {
                let still_bad = !self.signal(&content, content.len() as u64, self.is_cfg(path)).is_empty()
                    || (self.is_vscode(path) && !self.vscode_signal(path, &content).is_empty());
                if content == cur {
                    return if still_bad {
                        Outcome { method: "manual review".into(), result: "Could not auto-clean — review manually".into(), action: Action::None }
                    } else {
                        Outcome { method, result: "already clean".into(), action: Action::None }
                    };
                }
                if still_bad {
                    return Outcome { method, result: "Cleaned copy still matches IOCs — review manually (not written)".into(), action: Action::None };
                }
                if self.export_re.is_match(cur) && !self.export_re.is_match(&content) {
                    return Outcome { method: "manual review".into(), result: "Cleaning would remove the config's export — review manually (not written)".into(), action: Action::None };
                }
                let result = format!("{} → {}", fmt_b(cur_size), fmt_b(content.len() as u64));
                Outcome { method, result, action: Action::Write(content) }
            }
        }
    }
}
