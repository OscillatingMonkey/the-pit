//! Any program that can read secrets on stdin.

use std::io::Write;
use std::process::{Command, Stdio};

use super::{Ctx, Item, Report};
use crate::error::{Error, Result};

pub fn push(ctx: &Ctx, items: &[Item]) -> Result<Report> {
    let run = ctx.req("run")?;
    let argv =
        shell_words::split(run).map_err(|_| Error::Invalid("could not parse `run`".into()))?;
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| Error::Invalid("`run` is empty".into()))?;
    let mut rep = Report {
        address: format!("command:{prog}"),
        ..Default::default()
    };
    rep.sent = items.iter().map(|i| i.name.clone()).collect();
    if ctx.dry_run {
        return Ok(rep);
    }
    let input = match ctx.opt("input").unwrap_or("dotenv") {
        "json" => {
            let mut m = serde_json::Map::new();
            for it in items {
                m.insert(
                    it.name.clone(),
                    serde_json::Value::String(it.text()?.to_string()),
                );
            }
            zeroize::Zeroizing::new(serde_json::to_string(&m)?)
        }
        _ => super::local::render(ctx, items)?,
    };
    let mut c = Command::new(prog);
    c.args(args)
        .env("PATH", crate::paths::tool_path())
        .env("PIT_PROJECT", ctx.project)
        .env("PIT_CHANNEL", ctx.channel)
        .env("PIT_DESTINATION", ctx.dest_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(d) = ctx.opt("cwd") {
        c.current_dir(crate::paths::expand_tilde(d));
    }
    let mut child = c
        .spawn()
        .map_err(|e| Error::Invalid(format!("could not start {prog}: {e}")))?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(Error::Remote(format!("{prog} exited with {}", out.status)));
    }
    Ok(rep)
}
