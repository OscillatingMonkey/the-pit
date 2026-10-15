//! Import a folder laid out the "secret pit" way:
//!
//!   <root>/<project>/<environment>/<destination>.env   KEY=value lines, comments describe keys
//!   <root>/<project>/<environment>/pit.env             addresses and door keys
//!   <root>/<project>/<environment>/<anything else>     stored as a file secret
//!
//! Projects become projects, environment folders become channels, and the
//! comment block above each key becomes its description. A map file names the
//! destinations each environment pushes to.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::agent::Session;
use crate::error::{invalid, Error, Result};
use crate::model::{now, Destination, Kind, Library, Project, Protection, Scope};
use crate::ops::{new_channel, new_secret};
use crate::{crypto, paths, values};

#[derive(Debug, Default, Deserialize)]
pub struct Map {
    #[serde(default)]
    pub channels: BTreeMap<String, String>,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectMap>,
    #[serde(default, rename = "dest")]
    pub dests: Vec<DestMap>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ProjectMap {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelMap>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ChannelMap {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub protected: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct DestMap {
    pub project: String,
    pub folder: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub select: Vec<String>,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub connection: Option<String>,
}

const SENSITIVE_HINTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "KEY",
    "PASSWORD",
    "PASS",
    "PRIVATE",
    "CREDENTIAL",
    "DSN",
    "URI",
    "URL",
];

fn is_backup_name(n: &str) -> bool {
    n.contains(".bak") || n.ends_with('~') || n == ".DS_Store"
}

struct Parsed {
    key: String,
    value: String,
    description: String,
}

/// KEY=value, value verbatim after the first `=`. A run of `#` lines directly
/// above a key (no blank line between) is that key's description.
fn parse_env(text: &str) -> Vec<Parsed> {
    let mut out = vec![];
    let mut comment: Vec<String> = vec![];
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            comment.clear();
            continue;
        }
        if let Some(c) = line.strip_prefix('#') {
            comment.push(c.strip_prefix(' ').unwrap_or(c).to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let description = comment
                    .iter()
                    .filter(|l| !l.trim_start().starts_with('─') && !l.trim().is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push(Parsed {
                    key: k.to_string(),
                    value: v.to_string(),
                    description,
                });
            }
        }
        comment.clear();
    }
    out
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, base, out)?;
        } else {
            out.push(p);
        }
    }
    let _ = base;
    Ok(())
}

pub fn import(s: &mut Session, dir: &str, map_text: &str, dry: bool) -> Result<Value> {
    let root = paths::expand_tilde(dir);
    if !root.is_dir() {
        return invalid(format!("{} is not a folder", root.display()));
    }
    let map: Map = if map_text.trim().is_empty() {
        Map::default()
    } else {
        toml::from_str(map_text)?
    };
    let mut lib: Library = s.lib.clone();
    let mut details = vec![];
    let (mut n_proj, mut n_chan, mut n_set, mut n_empty, mut n_files, mut n_dest) =
        (0, 0, 0, 0, 0, 0);
    let mut skipped = vec![];
    let mut renamed = vec![];
    let mut kept = vec![];

    let mut projects: Vec<PathBuf> = fs::read_dir(&root)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    projects.sort();
    for pdir in projects {
        let pname = pdir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if pname.starts_with('.') {
            continue;
        }
        crate::model::valid_slug("project", &pname)?;
        let pm = map.projects.get(&pname);
        if !lib.projects.contains_key(&pname) {
            lib.projects.insert(
                pname.clone(),
                Project {
                    name: pname.clone(),
                    description: pm.map(|m| m.description.clone()).unwrap_or_default(),
                    created: now(),
                    secrets: BTreeMap::new(),
                    channels: BTreeMap::new(),
                },
            );
            n_proj += 1;
        }

        let mut entries: Vec<PathBuf> = fs::read_dir(&pdir)?.flatten().map(|e| e.path()).collect();
        entries.sort();
        for entry in entries {
            let ename = entry
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if is_backup_name(&ename) {
                if ename != ".DS_Store" {
                    skipped.push(format!("{pname}/{ename}"));
                }
                continue;
            }
            if entry.is_file() {
                // A file directly under the project: a project-level file secret.
                let scope = Scope::Project(pname.clone());
                import_file(s, &mut lib, &scope, &entry, &ename, dry, &mut kept)?;
                n_files += 1;
                details.push(json!({"scope": pname, "file": ename}));
                continue;
            }
            let folder = ename.clone();
            let mut files = vec![];
            walk(&entry, &entry, &mut files)?;
            if !files.iter().any(|f| {
                !is_backup_name(
                    f.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(".DS_Store"),
                )
            }) {
                continue;
            }
            let cname = map
                .channels
                .get(&folder)
                .cloned()
                .unwrap_or_else(|| folder.clone());
            crate::model::valid_slug("channel", &cname)?;
            let cm = pm.and_then(|m| m.channels.get(&cname));
            {
                let proj = lib.project_mut(&pname)?;
                if !proj.channels.contains_key(&cname) {
                    let protected = cm
                        .and_then(|c| c.protected)
                        .unwrap_or(cname == "production");
                    let desc = cm
                        .map(|c| c.description.clone())
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| format!("Imported from secret-pit/{pname}/{folder}"));
                    proj.channels
                        .insert(cname.clone(), new_channel(&cname, &desc, protected));
                    n_chan += 1;
                }
            }
            let scope = Scope::Channel(pname.clone(), cname.clone());

            // pit.env first, so the addressing names are the ones that win.
            files.sort_by_key(|p| {
                (
                    p.file_name().and_then(|n| n.to_str()) != Some("pit.env"),
                    p.clone(),
                )
            });
            let mut stored_names: BTreeMap<(String, String), String> = BTreeMap::new();
            let mut chan_detail = json!({"scope": scope.to_string(), "from": format!("{pname}/{folder}"), "env_files": [], "files": [], "renamed": []});

            for f in files {
                let rel = f
                    .strip_prefix(&entry)
                    .unwrap_or(&f)
                    .to_string_lossy()
                    .to_string();
                let fname = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                if is_backup_name(&fname) {
                    if fname != ".DS_Store" {
                        skipped.push(format!("{pname}/{folder}/{rel}"));
                    }
                    continue;
                }
                let top_env = !rel.contains('/') && fname.ends_with(".env");
                if !top_env {
                    import_file(s, &mut lib, &scope, &f, &rel, dry, &mut kept)?;
                    n_files += 1;
                    chan_detail["files"]
                        .as_array_mut()
                        .expect("array")
                        .push(json!(rel));
                    continue;
                }
                let stem = fname.trim_end_matches(".env").to_string();
                let text = zeroize::Zeroizing::new(fs::read_to_string(&f)?);
                let parsed = parse_env(&text);
                let (mut set, mut empty) = (0, 0);
                for p in parsed {
                    let address = stem == "pit"
                        || (stem.starts_with("github-")
                            && (p.key == "GITHUB_REPO" || p.key == "GITHUB_ENVIRONMENT"));
                    let protection =
                        if address && !SENSITIVE_HINTS.iter().any(|h| p.key.contains(h)) {
                            Protection::Plain
                        } else {
                            Protection::Sealed
                        };
                    let mut tags = vec![stem.clone()];
                    if address {
                        tags.push("address".into());
                    }
                    let fp = crypto::fingerprint(&s.keys.fp, p.value.as_bytes());
                    let map_ = lib.secrets_mut(&scope)?;
                    let name = match map_.get_mut(&p.key) {
                        None => p.key.clone(),
                        Some(existing) => {
                            let same = match existing.fingerprint() {
                                Some(efp) => efp == fp,
                                None => p.value.is_empty(),
                            };
                            if same {
                                for t in tags.iter() {
                                    if !existing.has_tag(t) {
                                        existing.tags.push(t.clone());
                                    }
                                }
                                stored_names.insert((stem.clone(), p.key.clone()), p.key.clone());
                                continue;
                            }
                            let n = format!("{}@{}", p.key, stem);
                            renamed.push(format!("{scope}: {} in {stem}.env → {n} (differs from the {} already imported)", p.key, p.key));
                            chan_detail["renamed"]
                                .as_array_mut()
                                .expect("array")
                                .push(json!(n));
                            n
                        }
                    };
                    if map_.contains_key(&name) {
                        kept.push(format!("{scope}:{name}"));
                        stored_names.insert((stem.clone(), p.key.clone()), name);
                        continue;
                    }
                    let mut sec = new_secret(&name, protection, Kind::Text);
                    sec.description = p.description.clone();
                    sec.tags = tags;
                    if !p.value.is_empty() {
                        if !dry {
                            values::set(&s.keys, &mut sec, p.value.as_bytes())?;
                        } else {
                            // A dry run keeps only the fingerprint, so conflicts are still detected.
                            sec.value = Some(crate::model::Stored {
                                fp,
                                set_at: now(),
                                len: 0,
                                data: crate::model::StoredData::Plain { bytes: vec![] },
                            });
                        }
                        set += 1;
                    } else {
                        empty += 1;
                    }
                    stored_names.insert((stem.clone(), p.key.clone()), name.clone());
                    lib.secrets_mut(&scope)?.insert(name, sec);
                }
                n_set += set;
                n_empty += empty;
                chan_detail["env_files"]
                    .as_array_mut()
                    .expect("array")
                    .push(json!({"file": fname, "set": set, "empty": empty}));

                if stem.starts_with("github-") {
                    let repo = stored_names
                        .get(&(stem.clone(), "GITHUB_REPO".into()))
                        .cloned()
                        .unwrap_or("GITHUB_REPO".into());
                    let env = stored_names
                        .get(&(stem.clone(), "GITHUB_ENVIRONMENT".into()))
                        .cloned()
                        .unwrap_or("GITHUB_ENVIRONMENT".into());
                    let d = Destination {
                        name: stem.clone(),
                        kind: "github".into(),
                        description: format!("GitHub Actions secrets (from {fname})"),
                        select: vec![
                            format!("tag:{stem}"),
                            "!GITHUB_REPO".into(),
                            "!GITHUB_ENVIRONMENT".into(),
                        ],
                        config: BTreeMap::from([
                            ("repo".into(), format!("{{{repo}}}")),
                            ("environment".into(), format!("{{{env}}}")),
                        ]),
                        connection: None,
                    };
                    let ch = lib.channel_mut(&pname, &cname)?;
                    if !ch.destinations.contains_key(&stem) {
                        ch.destinations.insert(stem.clone(), d);
                        n_dest += 1;
                    }
                }
            }

            for dm in map
                .dests
                .iter()
                .filter(|d| d.project == pname && d.folder == folder)
            {
                crate::rail::kind_info(&dm.kind)?;
                let ch = lib.channel_mut(&pname, &cname)?;
                if ch.destinations.contains_key(&dm.name) {
                    continue;
                }
                ch.destinations.insert(
                    dm.name.clone(),
                    Destination {
                        name: dm.name.clone(),
                        kind: dm.kind.clone(),
                        description: dm.description.clone(),
                        select: if dm.select.is_empty() {
                            vec![format!("tag:{}", dm.name)]
                        } else {
                            dm.select.clone()
                        },
                        config: dm.config.clone(),
                        connection: dm.connection.clone(),
                    },
                );
                n_dest += 1;
            }
            let dests: Vec<Value> = lib
                .channel(&pname, &cname)?
                .destinations
                .values()
                .map(|d| {
                    json!(format!(
                        "{} → {}",
                        d.name,
                        crate::rail::address(&d.kind, &d.config)
                    ))
                })
                .collect();
            chan_detail["destinations"] = json!(dests);
            details.push(chan_detail);
        }
    }

    if !dry {
        s.lib = lib;
    }
    Ok(json!({
        "dry_run": dry,
        "summary": {
            "projects_created": n_proj, "channels_created": n_chan, "secrets_with_values": n_set,
            "secrets_empty": n_empty, "files": n_files, "destinations": n_dest,
            "skipped_backups": skipped.len(), "renamed_conflicts": renamed.len(), "already_present": kept.len(),
        },
        "channels": details,
        "renamed": renamed,
        "skipped": skipped,
        "already_present": kept,
    }))
}

fn import_file(
    s: &Session,
    lib: &mut Library,
    scope: &Scope,
    path: &Path,
    rel: &str,
    dry: bool,
    kept: &mut Vec<String>,
) -> Result<()> {
    let name = rel.replace(' ', "_");
    crate::model::valid_name("file secret", &name)?;
    let map = lib.secrets_mut(scope)?;
    if map.contains_key(&name) {
        kept.push(format!("{scope}:{name}"));
        return Ok(());
    }
    let bytes = zeroize::Zeroizing::new(
        fs::read(path).map_err(|e| Error::Invalid(format!("{}: {e}", path.display())))?,
    );
    let mut sec = new_secret(
        &name,
        Protection::Sealed,
        Kind::File {
            filename: rel.to_string(),
        },
    );
    sec.description = format!("File {rel}");
    if let Some(parent) = Path::new(rel)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|p| !p.is_empty())
    {
        sec.tags.push(parent.to_string());
    }
    if !dry && !bytes.is_empty() {
        values::set(&s.keys, &mut sec, &bytes)?;
    }
    map.insert(name, sec);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_descriptions_and_verbatim_values() {
        let t = "# file header\n\n# What it is.\n# More.\nA=x = y # not a comment\nB=\n\n#orphan\n\nC=1";
        let p = parse_env(t);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].key, "A");
        assert_eq!(p[0].value, "x = y # not a comment");
        assert_eq!(p[0].description, "What it is. More.");
        assert_eq!(p[1].value, "");
        assert_eq!(p[2].description, "");
    }
}
