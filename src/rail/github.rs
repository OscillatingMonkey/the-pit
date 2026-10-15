//! GitHub Actions secrets. GitHub requires each value to be encrypted on the
//! client to the repository's (or environment's) public key with a libsodium
//! sealed box before it is sent; the plaintext never reaches GitHub's API.

use crypto_box::PublicKey;
use serde_json::json;

use super::http::{agent, api_error, send};
use super::vercel::urlencode;
use super::{Ctx, Item, Report};
use crate::crypto::{b64d, b64e};
use crate::error::{Error, Result};

const API: &str = "https://api.github.com";

/// Accepts `owner/name`, `git@github.com:owner/name.git` and `https://github.com/owner/name`.
pub fn normalize_repo(r: &str) -> String {
    let r = r.trim();
    let r = r
        .strip_prefix("git@github.com:")
        .or_else(|| r.strip_prefix("https://github.com/"))
        .or_else(|| r.strip_prefix("ssh://git@github.com/"))
        .unwrap_or(r);
    r.trim_end_matches('/').trim_end_matches(".git").to_string()
}

fn repo(ctx: &Ctx) -> Result<String> {
    Ok(normalize_repo(ctx.req("repo")?))
}

fn base(ctx: &Ctx) -> Result<String> {
    let repo = repo(ctx)?;
    let (owner, name) = repo
        .split_once('/')
        .filter(|(o, n)| !o.is_empty() && !n.is_empty() && !n.contains('/'))
        .ok_or_else(|| Error::Invalid(format!("github repo must be owner/name (got {repo})")))?;
    let root = format!("{API}/repos/{}/{}", urlencode(owner), urlencode(name));
    Ok(match ctx.opt("environment") {
        Some(env) => format!("{root}/environments/{}/secrets", urlencode(env)),
        None => format!("{root}/actions/secrets"),
    })
}

fn req(a: &ureq::Agent, method: &str, url: &str, token: &str) -> ureq::Request {
    a.request(method, url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
}

fn ensure_environment(ctx: &Ctx, a: &ureq::Agent, token: &str) -> Result<()> {
    if let Some(env) = ctx.opt("environment") {
        let repo = repo(ctx)?;
        let (owner, name) = repo.split_once('/').unwrap_or((repo.as_str(), ""));
        let url = format!(
            "{API}/repos/{}/{}/environments/{}",
            urlencode(owner),
            urlencode(name),
            urlencode(env)
        );
        let r = send(req(a, "GET", &url, token), None)?;
        if r.status == 404 {
            let r = send(req(a, "PUT", &url, token), Some(&json!({})))?;
            if !(200..300).contains(&r.status) {
                return Err(api_error("GitHub (creating the environment)", &r));
            }
        }
    }
    Ok(())
}

pub fn push(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let url = base(ctx)?;
    let mut rep = Report {
        address: crate::rail::address("github", &ctx.config),
        ..Default::default()
    };
    if ctx.dry_run {
        rep.sent = items.iter().map(|i| i.name.clone()).collect();
        return Ok(rep);
    }
    let token = ctx.token()?;
    let a = agent();
    ensure_environment(ctx, &a, token)?;
    let r = send(req(&a, "GET", &format!("{url}/public-key"), token), None)?;
    if r.status != 200 {
        return Err(api_error("GitHub", &r));
    }
    let key_id = r
        .body
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Remote("GitHub sent no key id".into()))?;
    let key_b64 = r
        .body
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Remote("GitHub sent no key".into()))?;
    let pk_bytes: [u8; 32] = b64d(key_b64)?
        .try_into()
        .map_err(|_| Error::Remote("GitHub public key has the wrong length".into()))?;
    let pk = PublicKey::from(pk_bytes);
    for it in items {
        if !it
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || it.name.starts_with("GITHUB_")
        {
            return Err(Error::Invalid(format!(
                "{} is not a valid GitHub secret name",
                it.name
            )));
        }
        let sealed = pk
            .seal(&mut rand_core::OsRng, &it.value)
            .map_err(|_| Error::Crypto("sealed box".into()))?;
        let body = json!({"encrypted_value": b64e(&sealed), "key_id": key_id});
        let r = send(
            req(&a, "PUT", &format!("{url}/{}", urlencode(&it.name)), token),
            Some(&body),
        )?;
        if !(200..300).contains(&r.status) {
            return Err(Error::Remote(format!(
                "{} (while setting {}; {} set before it)",
                api_error("GitHub", &r),
                it.name,
                rep.sent.len()
            )));
        }
        rep.sent.push(it.name.clone());
    }
    Ok(rep)
}

pub fn names(ctx: &Ctx) -> Result<Vec<String>> {
    let url = base(ctx)?;
    let token = ctx.token()?;
    let r = send(
        req(&agent(), "GET", &format!("{url}?per_page=100"), token),
        None,
    )?;
    if r.status != 200 {
        return Err(api_error("GitHub", &r));
    }
    let mut out: Vec<String> = r
        .body
        .get("secrets")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    Ok(out)
}

pub fn whoami(token: &str) -> Result<String> {
    let r = send(req(&agent(), "GET", &format!("{API}/user"), token), None)?;
    if r.status != 200 {
        return Err(api_error("GitHub", &r));
    }
    let login = r
        .body
        .get("login")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let scopes = r
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-oauth-scopes"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    Ok(if scopes.is_empty() {
        login
    } else {
        format!("{login} (scopes: {scopes})")
    })
}
