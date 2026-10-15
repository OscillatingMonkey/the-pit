//! Destinations on this machine: rendered .env files and dropped files.
//!
//! Every file is written owner-only (0600) and atomically. A file inside a git
//! work tree must be git-ignored. A push never silently erases a value that
//! exists only in the destination.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::{Ctx, Item, Report};
use crate::error::{Error, Result};
use crate::paths;

/// Resolve where a write would really land — following `..` and symlinks in
/// every existing ancestor — and refuse it if that is The Pit's own folder, a
/// symlink, or an un-ignored file in a git repository. Returns the resolved path,
/// which is the one written to.
fn guard_location(p: &Path) -> Result<PathBuf> {
    if !p.is_absolute() {
        return Err(Error::Invalid(format!(
            "{} must be an absolute path",
            p.display()
        )));
    }
    let mut tail: Vec<std::ffi::OsString> = vec![];
    let mut base = p.to_path_buf();
    for c in p.components().rev() {
        if base.exists() {
            break;
        }
        match c {
            std::path::Component::Normal(n) => tail.push(n.to_os_string()),
            _ => {
                return Err(Error::Invalid(format!(
                    "{} is not a plain path",
                    p.display()
                )))
            }
        }
        base.pop();
    }
    let mut resolved = fs::canonicalize(&base)?;
    for n in tail.iter().rev() {
        resolved.push(n);
    }
    if let Ok(md) = fs::symlink_metadata(&resolved) {
        if md.file_type().is_symlink() {
            return Err(Error::Refused(format!(
                "{} is a symbolic link; point the destination at the real file",
                p.display()
            )));
        }
    }
    let home = fs::canonicalize(paths::home()).unwrap_or_else(|_| paths::home());
    if resolved.starts_with(&home) || resolved.starts_with(paths::home()) {
        return Err(Error::Refused(
            "cannot write inside The Pit's own folder".into(),
        ));
    }
    if let Some(repo) = paths::in_git_tree(&resolved) {
        if !paths::git_ignored(&repo, &resolved) {
            return Err(Error::Refused(format!(
                "{} is inside the git repository {} and is not ignored — add it to .gitignore first",
                p.display(),
                repo.display()
            )));
        }
    }
    Ok(resolved)
}

fn needs_quotes(v: &str) -> bool {
    v.is_empty()
        || v.chars()
            .any(|c| c.is_whitespace() || "#\"'`$\\".contains(c))
}

fn quote(v: &str) -> String {
    let mut s = String::from("\"");
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '$' => s.push_str("\\$"),
            _ => s.push(c),
        }
    }
    s.push('"');
    s
}

pub fn parse_dotenv(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim_start();
        let l = l.strip_prefix("export ").unwrap_or(l);
        if l.starts_with('#') || !l.contains('=') {
            continue;
        }
        let (k, v) = l.split_once('=').unwrap_or((l, ""));
        let k = k.trim();
        if k.is_empty()
            || !k
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            continue;
        }
        let v = v.trim_end_matches('\r');
        let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            let inner = &v[1..v.len() - 1];
            let mut s = String::new();
            let mut it = inner.chars();
            while let Some(c) = it.next() {
                if c == '\\' {
                    match it.next() {
                        Some('n') => s.push('\n'),
                        Some('r') => s.push('\r'),
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
            v.to_string()
        };
        out.insert(k.to_string(), v);
    }
    out
}

pub fn render(ctx: &Ctx, items: &[Item]) -> Result<Zeroizing<String>> {
    let format = ctx.opt("format").unwrap_or("dotenv");
    let q = ctx.opt("quote").unwrap_or("auto");
    let mut s = Zeroizing::new(String::new());
    if format == "json" {
        let mut m = serde_json::Map::new();
        for it in items {
            m.insert(
                it.name.clone(),
                serde_json::Value::String(it.text()?.to_string()),
            );
        }
        s.push_str(&serde_json::to_string_pretty(&m)?);
        s.push('\n');
        return Ok(s);
    }
    s.push_str(&format!(
        "# {} · {} · {} — written by The Pit. Do not edit: change the value in the pit and run `pit push`.\n",
        ctx.project, ctx.channel, ctx.dest_name
    ));
    for it in items {
        let v = it.text()?;
        let val = match q {
            "always" => quote(v),
            "never" => {
                if v.contains('\n') {
                    return Err(Error::Invalid(format!(
                        "{} has a newline; it needs quote = auto or always",
                        it.name
                    )));
                }
                v.to_string()
            }
            _ => {
                if needs_quotes(v) {
                    quote(v)
                } else {
                    v.to_string()
                }
            }
        };
        if format == "export" {
            s.push_str("export ");
        }
        s.push_str(&format!("{}={}\n", it.name, val));
    }
    Ok(s)
}

pub fn push_dotenv(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let path = guard_location(&paths::expand_tilde(ctx.req("path")?))?;
    let mut rep = Report {
        address: format!("file:{}", path.display()),
        ..Default::default()
    };
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("path has no folder".into()))?;
    if !parent.is_dir() {
        return Err(Error::Invalid(format!(
            "{} does not exist",
            parent.display()
        )));
    }
    if path.exists() && !ctx.force {
        let existing = parse_dotenv(&Zeroizing::new(
            fs::read_to_string(&path).unwrap_or_default(),
        ));
        let incoming: std::collections::BTreeSet<&str> =
            items.iter().map(|i| i.name.as_str()).collect();
        let lost: Vec<&String> = existing
            .iter()
            .filter(|(k, v)| !v.is_empty() && !incoming.contains(k.as_str()))
            .map(|(k, _)| k)
            .collect();
        if !lost.is_empty() {
            return Err(Error::Refused(format!(
                "{} holds values the pit does not: {}. Bring them in with `pit absorb`, or push with --force to drop them",
                path.display(),
                lost.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )));
        }
    }
    let text = render(ctx, items)?;
    rep.sent = items.iter().map(|i| i.name.clone()).collect();
    if ctx.dry_run {
        return Ok(rep);
    }
    paths::write_private(&path, text.as_bytes())?;
    Ok(rep)
}

fn safe_join(dir: &Path, name: &str) -> Result<PathBuf> {
    if !crate::model::safe_relative(name) {
        return Err(Error::Invalid(format!("{} is not a safe file name", name)));
    }
    Ok(dir.join(name))
}

fn file_target(dir: &Path, it: &Item) -> Result<PathBuf> {
    safe_join(dir, &it.filename.clone().unwrap_or_else(|| it.name.clone()))
}

pub fn push_files(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let dir = paths::expand_tilde(ctx.req("dir")?);
    let mut rep = Report {
        address: format!("dir:{}", dir.display()),
        ..Default::default()
    };
    for it in items {
        let target = guard_location(&file_target(&dir, it)?)?;
        if !ctx.dry_run {
            if let Some(p) = target.parent() {
                paths::private_dir(p)?;
            }
            paths::write_private(&target, &it.value)?;
        }
        rep.sent.push(it.name.clone());
    }
    Ok(rep)
}

pub fn dotenv_names(ctx: &Ctx) -> Result<Vec<String>> {
    let path = paths::expand_tilde(ctx.req("path")?);
    let text = Zeroizing::new(fs::read_to_string(&path).unwrap_or_default());
    Ok(parse_dotenv(&text).into_keys().collect())
}

/// Read a rendered destination back, for `pit absorb`.
pub fn read_back(
    kind: &str,
    ctx: &Ctx,
    names: &[(String, Option<String>)],
) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    match kind {
        "dotenv" => {
            let path = paths::expand_tilde(ctx.req("path")?);
            let text = Zeroizing::new(fs::read_to_string(&path)?);
            Ok(parse_dotenv(&text)
                .into_iter()
                .map(|(k, v)| (k, Zeroizing::new(v.into_bytes())))
                .collect())
        }
        "files" => {
            let dir = paths::expand_tilde(ctx.req("dir")?);
            let mut out = vec![];
            for (name, filename) in names {
                let rel = filename.clone().unwrap_or_else(|| name.clone());
                let p = safe_join(&dir, &rel)?;
                if let Ok(b) = fs::read(&p) {
                    out.push((name.clone(), Zeroizing::new(b)));
                }
            }
            Ok(out)
        }
        _ => Err(Error::Invalid(format!(
            "{kind} destinations cannot be read back"
        ))),
    }
}
