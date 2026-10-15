//! Vercel: REST API, one idempotent upsert per variable.

use std::collections::BTreeMap;

use serde_json::json;

use super::http::{agent, api_error, send};
use super::{Ctx, Item, Report};
use crate::error::{Error, Result};

const API: &str = "https://api.vercel.com";

fn team_q(team: Option<&str>, first: bool) -> String {
    match team {
        Some(t) => format!("{}teamId={}", if first { "?" } else { "&" }, urlencode(t)),
        None => String::new(),
    }
}

pub fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn targets(ctx: &Ctx) -> Result<Vec<String>> {
    let t: Vec<String> = ctx
        .req("target")?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for x in &t {
        if !["production", "preview", "development"].contains(&x.as_str()) {
            return Err(Error::Invalid(format!(
                "vercel target must be production, preview or development (got {x})"
            )));
        }
    }
    if t.iter().any(|x| x == "production") && !ctx.protected {
        return Err(Error::Refused(format!(
            "{}/{} is not a protected channel and must not write to Vercel's production target — protect the channel or change the target",
            ctx.project, ctx.channel
        )));
    }
    if t.iter().any(|x| x != "production") && ctx.protected && t.len() > 1 {
        return Err(Error::Refused(
            "a protected channel writes to one Vercel target only — production values in preview reach every pull request".into(),
        ));
    }
    Ok(t)
}

pub fn push(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let project = ctx.req("project")?;
    let team = ctx.opt("team");
    let targets = targets(ctx)?;
    let kind = ctx.opt("type").unwrap_or("encrypted");
    if !["encrypted", "sensitive", "plain"].contains(&kind) {
        return Err(Error::Invalid(
            "vercel type must be encrypted, sensitive or plain".into(),
        ));
    }
    let mut rep = Report {
        address: format!("vercel:{project}@{}", targets.join(",")),
        ..Default::default()
    };
    if ctx.dry_run {
        rep.sent = items.iter().map(|i| i.name.clone()).collect();
        return Ok(rep);
    }
    let token = ctx.token()?;
    let a = agent();
    for it in items {
        let mut body = json!({
            "key": it.name,
            "value": it.text()?,
            "type": kind,
            "target": targets,
        });
        if let Some(b) = ctx.opt("git_branch") {
            body["gitBranch"] = json!(b);
        }
        let url = format!(
            "{API}/v10/projects/{}/env?upsert=true{}",
            urlencode(project),
            team_q(team, false)
        );
        let r = send(
            a.post(&url)
                .set("Authorization", &format!("Bearer {token}")),
            Some(&body),
        )?;
        if !(200..300).contains(&r.status) {
            return Err(Error::Remote(format!(
                "{} (while setting {}; {} set before it)",
                api_error("Vercel", &r),
                it.name,
                rep.sent.len()
            )));
        }
        rep.sent.push(it.name.clone());
    }
    rep.notes
        .push("Vercel applies new values on the next deployment.".into());
    Ok(rep)
}

pub fn names(ctx: &Ctx) -> Result<Vec<String>> {
    let project = ctx.req("project")?;
    let token = ctx.token()?;
    let targets = targets(ctx)?;
    let url = format!(
        "{API}/v9/projects/{}/env{}",
        urlencode(project),
        team_q(ctx.opt("team"), true)
    );
    let r = send(
        agent()
            .get(&url)
            .set("Authorization", &format!("Bearer {token}")),
        None,
    )?;
    if r.status != 200 {
        return Err(api_error("Vercel", &r));
    }
    let mut out = vec![];
    for e in r
        .body
        .get("envs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let t: Vec<String> = e
            .get("target")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if t.iter().any(|x| targets.contains(x)) {
            if let Some(k) = e.get("key").and_then(|v| v.as_str()) {
                out.push(k.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

pub fn whoami(token: &str, cfg: &BTreeMap<String, String>) -> Result<String> {
    let r = send(
        agent()
            .get(&format!("{API}/v2/user"))
            .set("Authorization", &format!("Bearer {token}")),
        None,
    )?;
    if r.status != 200 {
        return Err(api_error("Vercel", &r));
    }
    let user = r
        .body
        .pointer("/user/username")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    Ok(match cfg.get("team") {
        Some(t) if !t.is_empty() => format!("{user} (team {t})"),
        _ => user,
    })
}
