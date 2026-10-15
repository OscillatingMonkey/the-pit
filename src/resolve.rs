//! Which secrets a channel sees, and which of them a destination receives.
//!
//! A channel sees its own secrets, then (if it inherits) its project's, and a
//! channel secret overrides a project secret of the same name. Global secrets
//! are only included where a destination names them (`global:NAME`).

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::model::{Destination, Library, Protection, Secret};

#[derive(Clone, Debug)]
pub struct Visible<'a> {
    pub secret: &'a Secret,
}

pub fn channel_view<'a>(
    lib: &'a Library,
    project: &str,
    channel: &str,
) -> Result<BTreeMap<String, Visible<'a>>> {
    let p = lib.project(project)?;
    let c = lib.channel(project, channel)?;
    let mut out = BTreeMap::new();
    if c.inherit {
        for (k, s) in &p.secrets {
            out.insert(k.clone(), Visible { secret: s });
        }
    }
    for (k, s) in &c.secrets {
        out.insert(k.clone(), Visible { secret: s });
    }
    Ok(out)
}

/// A secret chosen for a destination, under the name it will be delivered as.
#[derive(Clone, Debug)]
pub struct Selected<'a> {
    pub deliver_as: String,
    pub secret: &'a Secret,
}

pub fn select<'a>(
    lib: &'a Library,
    project: &str,
    channel: &str,
    dest: &Destination,
) -> Result<Vec<Selected<'a>>> {
    let view = channel_view(lib, project, channel)?;
    let mut chosen: BTreeMap<String, Selected<'a>> = BTreeMap::new();
    let mut excluded: Vec<String> = vec![];
    let selectors: Vec<String> = if dest.select.is_empty() {
        vec!["*".into()]
    } else {
        dest.select.clone()
    };
    // Wildcards only pick up file secrets for destinations that take files.
    let wants_files = dest.kind == "files";
    let fits = |s: &Secret| wants_files || matches!(s.kind, crate::model::Kind::Text);

    for raw in &selectors {
        let sel = raw.trim();
        if let Some(name) = sel.strip_prefix('!') {
            excluded.push(name.trim().to_string());
            continue;
        }
        let (target, alias) = match sel.split_once(" as ") {
            Some((a, b)) => (a.trim(), Some(b.trim().to_string())),
            None => (sel, None),
        };
        if target == "*" {
            for (k, v) in &view {
                if !v.secret.has_tag("address") && fits(v.secret) {
                    chosen.insert(
                        k.clone(),
                        Selected {
                            deliver_as: deliver_name(k),
                            secret: v.secret,
                        },
                    );
                }
            }
        } else if let Some(tag) = target.strip_prefix("tag:") {
            for (k, v) in &view {
                if v.secret.has_tag(tag) && fits(v.secret) {
                    chosen.insert(
                        k.clone(),
                        Selected {
                            deliver_as: deliver_name(k),
                            secret: v.secret,
                        },
                    );
                }
            }
        } else if let Some(g) = target.strip_prefix("global:") {
            let s = lib
                .globals
                .get(g)
                .ok_or_else(|| Error::NotFound(format!("global secret {g}")))?;
            let name = alias.unwrap_or_else(|| deliver_name(g));
            chosen.insert(
                format!("global:{g}"),
                Selected {
                    deliver_as: name,
                    secret: s,
                },
            );
        } else {
            let v = view.get(target).ok_or_else(|| {
                Error::NotFound(format!("secret {target} in {project}/{channel}"))
            })?;
            let name = alias.unwrap_or_else(|| deliver_name(target));
            chosen.insert(
                target.to_string(),
                Selected {
                    deliver_as: name,
                    secret: v.secret,
                },
            );
        }
    }
    for x in &excluded {
        chosen.remove(x);
        chosen.retain(|_, s| &s.deliver_as != x);
    }
    let mut seen = std::collections::BTreeSet::new();
    for s in chosen.values() {
        if !seen.insert(s.deliver_as.clone()) {
            return Err(Error::Invalid(format!(
                "destination {} would receive {} twice — use `NAME as ALIAS` to disambiguate",
                dest.name, s.deliver_as
            )));
        }
    }
    Ok(chosen.into_values().collect())
}

/// `KEY@variant` is delivered as `KEY`; files keep their path's last component.
pub fn deliver_name(stored: &str) -> String {
    stored.split('@').next().unwrap_or(stored).to_string()
}

/// Expand `{NAME}` references in destination settings using the channel's
/// plain or sealed values. Unknown names are an error, not an empty string.
pub fn template(
    input: &str,
    lookup: &mut dyn FnMut(&str) -> Result<Option<String>>,
) -> Result<String> {
    let mut out = String::new();
    let mut rest = input;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let j = after
            .find('}')
            .ok_or_else(|| Error::Invalid(format!("unclosed {{ in '{input}'")))?;
        let name = &after[..j];
        match lookup(name)? {
            Some(v) => out.push_str(&v),
            None => {
                return Err(Error::Invalid(format!(
                    "'{input}' refers to {name}, which has no value"
                )))
            }
        }
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub fn pushable(s: &Secret) -> std::result::Result<(), &'static str> {
    if s.protection == Protection::Hashed {
        return Err("stored one-way");
    }
    if s.value.is_none() {
        return Err("empty");
    }
    Ok(())
}

/// Every destination that would deliver this secret (or use it as its access
/// token), as `project/channel → destination (kind)`.
pub fn receivers(lib: &Library, secret_id: &str) -> Vec<String> {
    let mut out = vec![];
    for (pn, p) in &lib.projects {
        for (cn, c) in &p.channels {
            let view = channel_view(lib, pn, cn).unwrap_or_default();
            for d in c.destinations.values() {
                let delivered = select(lib, pn, cn, d)
                    .map(|sel| sel.iter().any(|x| x.secret.id == secret_id))
                    .unwrap_or(false);
                let token = d
                    .config
                    .get("token_from")
                    .and_then(|t| view.get(t.as_str()))
                    .map(|v| v.secret.id == secret_id)
                    .unwrap_or(false);
                if delivered || token {
                    out.push(format!("{pn}/{cn} → {} ({})", d.name, d.kind));
                }
            }
        }
    }
    out
}

/// Secrets a destination would select but can never deliver because they are
/// stored one-way.
pub fn one_way_selected(
    lib: &Library,
    project: &str,
    channel: &str,
    dest: &Destination,
) -> Vec<String> {
    select(lib, project, channel, dest)
        .map(|sel| {
            sel.iter()
                .filter(|x| x.secret.protection == Protection::Hashed)
                .map(|x| x.deliver_as.clone())
                .collect()
        })
        .unwrap_or_default()
}
