//! Finding values in a project that belong in the pit, and reading secret
//! files (.env, JSON, YAML) for import. Read-only: nothing here writes to the
//! folder being looked at. Findings carry names, places and lengths for display;
//! the values themselves are only ever handed to the agent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

pub struct Found {
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
    pub description: String,
    /// Set for whole-file secrets (keys, certificates, service accounts).
    pub filename: Option<String>,
    pub what: String,
    pub places: Vec<String>,
    /// Some place holding it is tracked by git.
    pub committed: bool,
    pub confidence: Confidence,
}

// ---------------------------------------------------------------------------
// reading files for import

/// Entries of a .env / shell-export file, a flat JSON object, or a top-level
/// YAML mapping. Comment lines directly above a key become its description.
pub fn read_source(path: &Path, text: &str) -> Result<Vec<(String, Zeroizing<String>, String)>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "json" => read_json(text),
        "yml" | "yaml" => Ok(read_yaml(text)),
        _ => Ok(read_env(text)),
    }
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let mut s = String::new();
        let mut it = v[1..v.len() - 1].chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some(o) => s.push(o),
                    None => {}
                }
            } else {
                s.push(c);
            }
        }
        s
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_string()
    } else {
        // An unquoted value ends at ` #` (an inline comment).
        match v.find(" #") {
            Some(i) => v[..i].trim_end().to_string(),
            None => v.to_string(),
        }
    }
}

pub fn read_env(text: &str) -> Vec<(String, Zeroizing<String>, String)> {
    let mut out = vec![];
    let mut comment: Vec<String> = vec![];
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim_end_matches('\r');
        let l = line.trim_start();
        if l.is_empty() {
            comment.clear();
            continue;
        }
        if let Some(c) = l.strip_prefix('#') {
            let c = c.trim();
            if !c.is_empty() && !c.starts_with('─') && !c.starts_with("---") {
                comment.push(c.to_string());
            }
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else {
            comment.clear();
            continue;
        };
        let k = k.trim();
        if k.is_empty()
            || !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            comment.clear();
            continue;
        }
        // A double-quoted value may run over several lines (PEM keys often do).
        let mut raw = v.trim().to_string();
        if raw.starts_with('"') && (raw.len() == 1 || !raw.ends_with('"')) {
            for more in lines.by_ref() {
                raw.push('\n');
                raw.push_str(more.trim_end_matches('\r'));
                if more.trim_end().ends_with('"') {
                    break;
                }
            }
        }
        let value = Zeroizing::new(unquote(&raw));
        out.push((k.to_string(), value, comment.join(" ")));
        comment.clear();
    }
    out
}

fn read_json(text: &str) -> Result<Vec<(String, Zeroizing<String>, String)>> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let mut out = vec![];
    fn walk(
        prefix: &str,
        v: &serde_json::Value,
        out: &mut Vec<(String, Zeroizing<String>, String)>,
    ) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    let name = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}_{k}")
                    };
                    walk(&name, x, out);
                }
            }
            serde_json::Value::String(s) => {
                out.push((prefix.to_string(), Zeroizing::new(s.clone()), String::new()))
            }
            serde_json::Value::Number(n) => out.push((
                prefix.to_string(),
                Zeroizing::new(n.to_string()),
                String::new(),
            )),
            serde_json::Value::Bool(b) => out.push((
                prefix.to_string(),
                Zeroizing::new(b.to_string()),
                String::new(),
            )),
            _ => {}
        }
    }
    if !v.is_object() {
        return Err(Error::Invalid(
            "expected a JSON object of names to values".into(),
        ));
    }
    walk("", &v, &mut out);
    Ok(out)
}

fn read_yaml(text: &str) -> Vec<(String, Zeroizing<String>, String)> {
    let mut out = vec![];
    let mut comment: Vec<String> = vec![];
    for line in text.lines() {
        if line.trim().is_empty() {
            comment.clear();
            continue;
        }
        if let Some(c) = line.trim_start().strip_prefix('#') {
            comment.push(c.trim().to_string());
            continue;
        }
        // Top-level `key: value` only.
        if line.starts_with(' ') || line.starts_with('\t') || line.starts_with('-') {
            comment.clear();
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if !k.is_empty()
                && !v.trim().is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
            {
                out.push((k.to_string(), Zeroizing::new(unquote(v)), comment.join(" ")));
            }
        }
        comment.clear();
    }
    out
}

/// `apiKey`, `api-key`, `stripe.secret` → `API_KEY`, `STRIPE_SECRET`.
pub fn env_name(s: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            out.push('_');
        }
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "SECRET".into()
    } else if out
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("_{out}")
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// what looks sensitive

const SENSITIVE_WORDS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "PRIVATE",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "AUTH",
    "DSN",
    "SIGNING",
    "WEBHOOK",
    "SALT",
    "COOKIE",
    "SESSION",
    "ENCRYPTION",
    "_KEY",
    "CLIENT_SECRET",
    "DATABASE_URL",
    "CONNECTION",
];

/// Names that are configuration, not secrets, even when they contain `KEY`.
const PUBLIC_HINTS: &[&str] = &[
    "PUBLIC",
    "PUBLISHABLE",
    "NEXT_PUBLIC_",
    "VITE_",
    "EXPO_PUBLIC_",
    "_ID",
];

pub fn name_is_sensitive(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    SENSITIVE_WORDS.iter().any(|w| n.contains(w)) && !PUBLIC_HINTS.iter().any(|w| n.contains(w))
}

fn entropy(s: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "your",
        "xxx",
        "changeme",
        "change-me",
        "change_me",
        "example",
        "placeholder",
        "dummy",
        "<",
        "${",
        "{{",
        "process.env",
        "os.environ",
        "getenv",
        "todo",
        "replace",
        "insert",
        "redacted",
        "*****",
        "...",
    ];
    WORDS.iter().any(|w| l.contains(w))
        || matches!(
            l.as_str(),
            "password" | "secret" | "test" | "token" | "none" | "null" | "true" | "false"
        )
        || v.chars().collect::<BTreeSet<_>>().len() <= 2
}

/// Well-known credential formats: (what, suggested name, pattern).
fn patterns() -> &'static Vec<(&'static str, &'static str, Regex)> {
    static P: OnceLock<Vec<(&str, &str, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        let list: &[(&str, &str, &str)] = &[
            (
                "private key",
                "PRIVATE_KEY",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
            ),
            (
                "AWS access key ID",
                "AWS_ACCESS_KEY_ID",
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            ),
            (
                "GitHub token",
                "GITHUB_TOKEN",
                r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
            ),
            (
                "Anthropic API key",
                "ANTHROPIC_API_KEY",
                r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
            ),
            (
                "OpenAI API key",
                "OPENAI_API_KEY",
                r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}",
            ),
            (
                "Stripe key",
                "STRIPE_SECRET_KEY",
                r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",
            ),
            (
                "Stripe webhook secret",
                "STRIPE_WEBHOOK_SECRET",
                r"\bwhsec_[A-Za-z0-9]{24,}",
            ),
            (
                "Slack token",
                "SLACK_TOKEN",
                r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
            ),
            (
                "Slack webhook",
                "SLACK_WEBHOOK_URL",
                r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}",
            ),
            (
                "Google API key",
                "GOOGLE_API_KEY",
                r"\bAIza[0-9A-Za-z_\-]{35}",
            ),
            (
                "SendGrid key",
                "SENDGRID_API_KEY",
                r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            ),
            ("npm token", "NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{36}\b"),
            (
                "Fly.io token",
                "FLY_API_TOKEN",
                r"\bFlyV1 fm[12][a-z]?_[A-Za-z0-9+/=_,\-]{20,}",
            ),
            (
                "Supabase token",
                "SUPABASE_ACCESS_TOKEN",
                r"\bsbp_[a-f0-9]{40}\b",
            ),
            ("Hugging Face token", "HF_TOKEN", r"\bhf_[A-Za-z]{34}\b"),
            (
                "Shopify token",
                "SHOPIFY_ACCESS_TOKEN",
                r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
            ),
            (
                "Resend key",
                "RESEND_API_KEY",
                r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}",
            ),
            (
                "credentials in a URL",
                "DATABASE_URL",
                r#"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@'"`]+:[^\s@/'"`]{3,}@[^\s'"`<>]+"#,
            ),
            (
                "JSON web token",
                "JWT",
                r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            ),
        ];
        list.iter()
            .map(|(w, n, p)| (*w, *n, Regex::new(p).expect("valid pattern")))
            .collect()
    })
}

fn assignment() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?i)\b([A-Za-z0-9_.\-]*(?:secret|token|api[_\-]?key|apikey|password|passwd|private[_\-]?key|access[_\-]?key|auth[_\-]?key|signing[_\-]?key|client[_\-]?secret)[A-Za-z0-9_]*)["']?\s*(?::=|=>|=|:)\s*["'`]([^"'`\s]{8,})["'`]"#,
        )
        .expect("valid pattern")
    })
}

fn known(value: &str) -> Option<(&'static str, &'static str)> {
    patterns()
        .iter()
        .find(|(_, _, re)| re.find(value).map(|m| m.as_str() == value).unwrap_or(false))
        .map(|(w, n, _)| (*w, *n))
}

fn url_name(url: &str) -> &'static str {
    match url.split("://").next().unwrap_or("") {
        s if s.starts_with("postgres") || s.starts_with("mysql") || s.starts_with("mongodb") => {
            "DATABASE_URL"
        }
        s if s.starts_with("redis") || s.starts_with("rediss") => "REDIS_URL",
        s if s.starts_with("amqp") => "AMQP_URL",
        _ => "SERVICE_URL",
    }
}

fn judge_env(name: &str, value: &str) -> Option<(Confidence, String)> {
    if value.trim().is_empty() || placeholder(value) {
        return None;
    }
    if let Some((what, _)) = known(value) {
        return Some((Confidence::High, what.to_string()));
    }
    if name_is_sensitive(name) {
        return Some((Confidence::High, "sensitive name".into()));
    }
    if value.len() >= 20 && entropy(value) >= 3.5 && !value.contains(' ') {
        return Some((Confidence::Medium, "random-looking value".into()));
    }
    Some((Confidence::Low, "setting".into()))
}

// ---------------------------------------------------------------------------
// walking a project

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".output",
    "vendor",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".cache",
    "coverage",
    "Pods",
    ".gradle",
    "DerivedData",
    ".idea",
    ".terraform",
    ".expo",
    "bower_components",
];
const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "Gemfile.lock",
    "poetry.lock",
    "composer.lock",
    "go.sum",
    "bun.lockb",
    ".pit.toml",
];
const KEY_EXTS: &[&str] = &[
    "pem",
    "key",
    "p8",
    "p12",
    "pfx",
    "jks",
    "keystore",
    "ppk",
    "mobileprovision",
];
const KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".npmrc",
    ".pypirc",
    ".netrc",
];
const MAX_FILE: u64 = 1 << 20;
const MAX_FILES: usize = 50_000;

fn is_env_file(name: &str) -> bool {
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == ".envrc"
        || name == ".dev.vars"
        || name == ".flaskenv"
}

fn is_example(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["example", "sample", "template", ".dist", "defaults"]
        .iter()
        .any(|w| n.contains(w))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 16 || out.len() >= MAX_FILES {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(ft) = e.file_type() else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) && name != "output" {
                walk(&e.path(), out, depth + 1);
            }
        } else if ft.is_file()
            && !SKIP_FILES.contains(&name.as_str())
            && !name.ends_with(".min.js")
            && !name.ends_with(".map")
        {
            out.push(e.path());
        }
    }
}

fn git_tracked(dir: &Path) -> BTreeSet<PathBuf> {
    let Ok(o) = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["ls-files", "-z", "--full-name"])
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return BTreeSet::new();
    };
    let Ok(top) = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return BTreeSet::new();
    };
    let top = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim());
    o.stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| top.join(String::from_utf8_lossy(p).as_ref()))
        .filter_map(|p| p.canonicalize().ok())
        .collect()
}

struct Hit {
    name: String,
    value: Zeroizing<Vec<u8>>,
    description: String,
    filename: Option<String>,
    what: String,
    place: String,
    path: PathBuf,
    confidence: Confidence,
    from_env: bool,
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|b| *b == b'\n').count() + 1
}

fn scan_file(root: &Path, path: &Path, hits: &mut Vec<Hit>) {
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let example = is_example(&fname);

    // Whole files that are credentials in themselves.
    if KEY_EXTS.contains(&ext.as_str()) || KEY_NAMES.contains(&fname.as_str()) {
        if meta.len() > MAX_FILE {
            return;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let bytes = Zeroizing::new(bytes);
        let text = String::from_utf8_lossy(&bytes);
        let is_key = !text.contains("-----BEGIN") || text.contains("PRIVATE KEY");
        if is_key && !bytes.is_empty() && !example {
            hits.push(Hit {
                name: env_name(&fname),
                value: Zeroizing::new(bytes.to_vec()),
                description: format!("from {rel}"),
                filename: Some(fname.clone()),
                what: "key file".into(),
                place: rel,
                path: path.to_path_buf(),
                confidence: Confidence::High,
                from_env: false,
            });
        }
        return;
    }
    if meta.len() > MAX_FILE {
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let bytes = Zeroizing::new(bytes);
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return;
    };

    // Service-account style JSON: the whole file is the credential.
    if ext == "json" && text.contains("\"private_key\"") && text.contains("\"client_email\"") {
        hits.push(Hit {
            name: env_name(fname.trim_end_matches(".json")),
            value: Zeroizing::new(bytes.to_vec()),
            description: format!("service account from {rel}"),
            filename: Some(fname.clone()),
            what: "service account file".into(),
            place: rel,
            path: path.to_path_buf(),
            confidence: Confidence::High,
            from_env: false,
        });
        return;
    }

    if is_env_file(&fname) {
        let line_for = |k: &str| {
            text.lines()
                .position(|l| {
                    let l = l.trim_start();
                    let l = l.strip_prefix("export ").unwrap_or(l);
                    l.starts_with(&format!("{k}="))
                })
                .map(|i| i + 1)
                .unwrap_or(0)
        };
        for (k, v, desc) in read_env(text) {
            let Some((confidence, what)) = judge_env(&k, &v) else {
                continue;
            };
            let confidence = if example { Confidence::Low } else { confidence };
            hits.push(Hit {
                name: k.clone(),
                value: Zeroizing::new(v.as_bytes().to_vec()),
                description: desc,
                filename: None,
                what,
                place: format!("{rel}:{}", line_for(&k)),
                path: path.to_path_buf(),
                confidence,
                from_env: true,
            });
        }
        return;
    }

    // Anything else: known credential formats, then `secret = "…"` assignments.
    let mut covered: Vec<(usize, usize)> = vec![];
    for (what, name, re) in patterns() {
        for m in re.find_iter(text) {
            if covered.iter().any(|(a, b)| m.start() < *b && *a < m.end())
                || placeholder(m.as_str())
            {
                continue;
            }
            covered.push((m.start(), m.end()));
            let name = if *what == "credentials in a URL" {
                url_name(m.as_str())
            } else {
                name
            };
            hits.push(Hit {
                name: name.to_string(),
                value: Zeroizing::new(m.as_str().as_bytes().to_vec()),
                description: String::new(),
                filename: None,
                what: what.to_string(),
                place: format!("{rel}:{}", line_of(text, m.start())),
                path: path.to_path_buf(),
                confidence: if example || *what == "JSON web token" {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                from_env: false,
            });
        }
    }
    for c in assignment().captures_iter(text) {
        let (Some(var), Some(val)) = (c.get(1), c.get(2)) else {
            continue;
        };
        if covered
            .iter()
            .any(|(a, b)| val.start() < *b && *a < val.end())
        {
            continue;
        }
        let v = val.as_str();
        if placeholder(v) || entropy(v) < 3.0 || v.contains('(') || v.starts_with('$') {
            continue;
        }
        covered.push((val.start(), val.end()));
        hits.push(Hit {
            name: env_name(var.as_str()),
            value: Zeroizing::new(v.as_bytes().to_vec()),
            description: String::new(),
            filename: None,
            what: "hard-coded value".into(),
            place: format!("{rel}:{}", line_of(text, val.start())),
            path: path.to_path_buf(),
            confidence: if example {
                Confidence::Low
            } else {
                Confidence::Medium
            },
            from_env: false,
        });
    }
}

/// Look through a folder for values that belong in the pit. Read-only.
pub fn scan(dir: &Path) -> Result<Vec<Found>> {
    let root = dir.canonicalize()?;
    if !root.is_dir() {
        return Err(Error::Invalid(format!("{} is not a folder", dir.display())));
    }
    let mut files = vec![];
    walk(&root, &mut files, 0);
    let tracked = git_tracked(&root);
    let mut hits = vec![];
    for f in &files {
        scan_file(&root, f, &mut hits);
    }

    // The same value in several places is one finding; a name from an env file
    // wins over a guessed one.
    let mut by_value: BTreeMap<String, Found> = BTreeMap::new();
    let mut order: Vec<String> = vec![];
    let mut env_named: BTreeSet<String> = BTreeSet::new();
    for h in hits {
        let id = crate::crypto::sha256_hex(&h.value);
        let committed = h
            .path
            .canonicalize()
            .map(|p| tracked.contains(&p))
            .unwrap_or(false);
        match by_value.get_mut(&id) {
            Some(f) => {
                f.places.push(h.place);
                f.committed |= committed;
                f.confidence = f.confidence.max(h.confidence);
                if h.from_env && env_named.insert(id.clone()) {
                    f.name = h.name;
                    f.description = h.description;
                }
            }
            None => {
                if h.from_env {
                    env_named.insert(id.clone());
                }
                order.push(id.clone());
                by_value.insert(
                    id,
                    Found {
                        name: h.name,
                        value: h.value,
                        description: h.description,
                        filename: h.filename,
                        what: h.what,
                        places: vec![h.place],
                        committed,
                        confidence: h.confidence,
                    },
                );
            }
        }
    }
    let mut out: Vec<Found> = order
        .into_iter()
        .filter_map(|id| by_value.remove(&id))
        .collect();

    // Different values under one name get `NAME@where`, which is still
    // delivered as NAME.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for f in &out {
        *counts.entry(f.name.clone()).or_default() += 1;
    }
    let mut used = BTreeSet::new();
    for f in out.iter_mut() {
        if counts[&f.name] > 1 {
            let file = f.places[0].split(':').next().unwrap_or("");
            let tag: String = Path::new(file)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("x")
                .trim_start_matches('.')
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let mut n = format!("{}@{}", f.name, tag);
            let mut i = 2;
            while used.contains(&n) {
                n = format!("{}@{}{}", f.name, tag, i);
                i += 1;
            }
            f.name = n;
        }
        used.insert(f.name.clone());
        if f.description.is_empty() {
            f.description = format!("found in {}", f.places.join(", "));
        }
    }
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.places[0].cmp(&b.places[0]))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsing() {
        let t = "# The database.\nexport DB_URL=\"postgres://a:b@h/db\"\nPORT=3000 # web\nKEY='x y'\nPEM=\"-----BEGIN\nabc\n-----END\"\n";
        let e = read_env(t);
        assert_eq!(e[0].0, "DB_URL");
        assert_eq!(e[0].1.as_str(), "postgres://a:b@h/db");
        assert_eq!(e[0].2, "The database.");
        assert_eq!(e[1].1.as_str(), "3000");
        assert_eq!(e[2].1.as_str(), "x y");
        assert_eq!(e[3].1.as_str(), "-----BEGIN\nabc\n-----END");
    }

    #[test]
    fn names() {
        assert_eq!(env_name("stripeSecretKey"), "STRIPE_SECRET_KEY");
        assert_eq!(env_name("api-key"), "API_KEY");
        assert!(name_is_sensitive("STRIPE_SECRET_KEY"));
        assert!(!name_is_sensitive("NEXT_PUBLIC_SUPABASE_KEY"));
    }

    #[test]
    fn placeholders_ignored() {
        assert!(placeholder("your-api-key-here"));
        assert!(placeholder("${TOKEN}"));
        assert!(!placeholder("q8Zr2kLmN0pXv7"));
    }
}
