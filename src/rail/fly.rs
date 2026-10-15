//! Fly.io: `flyctl secrets import`, values on stdin, token in the environment.

use std::io::Write;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use super::{Ctx, Item, Report};
use crate::error::{Error, Result};

fn flyctl() -> Command {
    let mut c = Command::new("flyctl");
    c.env("PATH", crate::paths::tool_path());
    c.env_remove("FLY_API_TOKEN");
    c.env_remove("FLY_ACCESS_TOKEN");
    c
}

fn with_token(c: &mut Command, token: Option<&str>) {
    if let Some(t) = token {
        c.env("FLY_API_TOKEN", t);
    }
}

pub fn push(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let app = ctx.req("app")?;
    let stage = ctx.opt("stage").map(|s| s != "false").unwrap_or(true);
    let mut rep = Report {
        address: format!("fly:{app}"),
        ..Default::default()
    };
    if ctx.dry_run {
        rep.sent = items.iter().map(|i| i.name.clone()).collect();
        return Ok(rep);
    }
    let mut payload = Zeroizing::new(String::new());
    for it in items {
        let v = it.text()?;
        if v.contains("\"\"\"") {
            return Err(Error::Invalid(format!(
                "{} contains a triple quote, which Fly's import format cannot carry",
                it.name
            )));
        }
        if v.contains('\n') {
            payload.push_str(&format!("{}=\"\"\"{}\"\"\"\n", it.name, v));
        } else {
            payload.push_str(&format!("{}={}\n", it.name, v));
        }
    }
    let mut c = flyctl();
    c.args(["secrets", "import", "--app", app]);
    if stage {
        c.arg("--stage");
    }
    with_token(&mut c, ctx.token.as_deref().map(|s| s.as_str()));
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error::Invalid("flyctl is not installed (brew install flyctl)".into()))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .to_string();
        return Err(Error::Remote(format!("flyctl refused: {first}")));
    }
    rep.sent = items.iter().map(|i| i.name.clone()).collect();
    rep.notes.push(if stage {
        format!("Staged on {app}. They apply on the next `fly deploy`.")
    } else {
        format!("Set on {app}; Fly is restarting its machines.")
    });
    Ok(rep)
}

pub fn names(ctx: &Ctx) -> Result<Vec<String>> {
    let app = ctx.req("app")?;
    let mut c = flyctl();
    c.args(["secrets", "list", "--app", app, "--json"]);
    with_token(&mut c, ctx.token.as_deref().map(|s| s.as_str()));
    let out = c
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error::Invalid("flyctl is not installed".into()))?;
    if !out.status.success() {
        return Err(Error::Remote(format!(
            "flyctl could not list secrets for {app}"
        )));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    let mut names: Vec<String> = v
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    s.get("Name")
                        .or_else(|| s.get("name"))
                        .and_then(|n| n.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    Ok(names)
}

pub fn whoami(token: Option<&str>) -> Result<String> {
    let mut c = flyctl();
    c.args(["auth", "whoami"]);
    with_token(&mut c, token);
    let out = c
        .stderr(Stdio::null())
        .output()
        .map_err(|_| Error::Invalid("flyctl is not installed".into()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else if token.is_some() {
        // Deploy and org-scoped tokens cannot answer whoami; they are still valid for their scope.
        Ok("scoped token (not a user token)".into())
    } else {
        Err(Error::Invalid(
            "flyctl is not signed in — run `fly auth login`".into(),
        ))
    }
}
