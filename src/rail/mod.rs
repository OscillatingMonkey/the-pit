//! The integration rail: one adapter per kind of place secrets can go.
//!
//! Every adapter receives already-selected values and delivers them over an
//! encrypted channel (HTTPS, or the vendor CLI's own TLS), or to a local file
//! written owner-only. Values never appear in argv, URLs or logs.

use std::collections::BTreeMap;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub mod command;
pub mod fly;
pub mod github;
pub mod http;
pub mod local;
pub mod vercel;

pub struct Item {
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
    pub filename: Option<String>,
}

impl Item {
    pub fn text(&self) -> Result<&str> {
        std::str::from_utf8(&self.value).map_err(|_| {
            Error::Invalid(format!(
                "{} is binary; only file destinations can take it",
                self.name
            ))
        })
    }
}

pub struct Ctx<'a> {
    pub project: &'a str,
    pub channel: &'a str,
    pub protected: bool,
    pub dest_name: &'a str,
    pub config: BTreeMap<String, String>,
    pub token: Option<Zeroizing<String>>,
    pub dry_run: bool,
    pub force: bool,
}

impl Ctx<'_> {
    pub fn req(&self, k: &str) -> Result<&str> {
        self.config
            .get(k)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Invalid(format!("destination {} needs `{k}`", self.dest_name)))
    }
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.config
            .get(k)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }
    pub fn token(&self) -> Result<&str> {
        self.token.as_deref().map(|s| s.as_str()).ok_or_else(|| {
            Error::Invalid(format!(
                "destination {} has no connection — run `pit connect`",
                self.dest_name
            ))
        })
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub address: String,
    pub sent: Vec<String>,
    pub notes: Vec<String>,
}

pub struct KindInfo {
    pub kind: &'static str,
    pub summary: &'static str,
    pub config: &'static [(&'static str, &'static str)],
    pub needs_connection: bool,
}

pub const KINDS: &[KindInfo] = &[
    KindInfo {
        kind: "fly",
        summary: "Fly.io app secrets (staged; they apply on the next deploy)",
        config: &[
            ("app", "the Fly app name"),
            (
                "stage",
                "true (default) to stage, false to deploy immediately",
            ),
        ],
        needs_connection: true,
    },
    KindInfo {
        kind: "vercel",
        summary: "Vercel project environment variables",
        config: &[
            ("project", "project name or id"),
            (
                "target",
                "production | preview | development (comma-separated for several)",
            ),
            ("team", "team id, if the project belongs to a team"),
            ("type", "encrypted (default) | sensitive"),
            ("git_branch", "preview only: limit to one branch"),
        ],
        needs_connection: true,
    },
    KindInfo {
        kind: "github",
        summary: "GitHub Actions secrets (repository or environment)",
        config: &[
            ("repo", "owner/name"),
            (
                "environment",
                "environment name; omit for repository secrets",
            ),
        ],
        needs_connection: true,
    },
    KindInfo {
        kind: "dotenv",
        summary: "a .env file on this machine, written owner-only",
        config: &[
            ("path", "where to write it"),
            ("format", "dotenv (default) | export | json"),
            ("quote", "auto (default) | always | never"),
        ],
        needs_connection: false,
    },
    KindInfo {
        kind: "files",
        summary: "each secret as its own file in a folder (keys, certificates, JSON credentials)",
        config: &[("dir", "the folder to write into")],
        needs_connection: false,
    },
    KindInfo {
        kind: "command",
        summary: "pipe the secrets to a program on stdin (anything without a native adapter)",
        config: &[
            ("run", "the command line"),
            ("input", "dotenv (default) | json"),
            ("cwd", "working directory"),
        ],
        needs_connection: false,
    },
];

pub fn kind_info(kind: &str) -> Result<&'static KindInfo> {
    KINDS.iter().find(|k| k.kind == kind).ok_or_else(|| {
        Error::Invalid(format!(
            "unknown destination kind {kind} (fly, vercel, github, dotenv, files, command)"
        ))
    })
}

/// Where a destination points, for logs and status.
pub fn address(kind: &str, cfg: &BTreeMap<String, String>) -> String {
    let g = |k: &str| cfg.get(k).cloned().unwrap_or_default();
    match kind {
        "fly" => format!("fly:{}", g("app")),
        "vercel" => format!("vercel:{}@{}", g("project"), g("target")),
        "github" => match cfg.get("environment").filter(|s| !s.is_empty()) {
            Some(e) => format!("github:{}#{}", github::normalize_repo(&g("repo")), e),
            None => format!("github:{}", github::normalize_repo(&g("repo"))),
        },
        "dotenv" => format!("file:{}", g("path")),
        "files" => format!("dir:{}", g("dir")),
        "command" => format!(
            "command:{}",
            g("run").split_whitespace().next().unwrap_or("")
        ),
        _ => kind.to_string(),
    }
}

pub fn push(kind: &str, ctx: &Ctx, items: &[Item]) -> Result<Report> {
    match kind {
        "fly" => fly::push(ctx, items),
        "vercel" => vercel::push(ctx, items),
        "github" => github::push(ctx, items),
        "dotenv" => local::push_dotenv(ctx, items),
        "files" => local::push_files(ctx, items),
        "command" => command::push(ctx, items),
        _ => Err(Error::Invalid(format!("unknown destination kind {kind}"))),
    }
}

/// Names currently set at the destination, where the service can list them.
pub fn remote_names(kind: &str, ctx: &Ctx) -> Result<Option<Vec<String>>> {
    match kind {
        "fly" => fly::names(ctx).map(Some),
        "vercel" => vercel::names(ctx).map(Some),
        "github" => github::names(ctx).map(Some),
        "dotenv" => local::dotenv_names(ctx).map(Some),
        _ => Ok(None),
    }
}

/// Check a connection's credential with its issuer. Returns the account it belongs to.
pub fn verify_connection(
    kind: &str,
    token: Option<&str>,
    cfg: &BTreeMap<String, String>,
) -> Result<String> {
    match kind {
        "vercel" => vercel::whoami(
            token.ok_or_else(|| Error::Invalid("vercel needs a token".into()))?,
            cfg,
        ),
        "github" => {
            github::whoami(token.ok_or_else(|| Error::Invalid("github needs a token".into()))?)
        }
        "fly" => fly::whoami(token),
        _ => Err(Error::Invalid(format!("{kind} does not use connections"))),
    }
}

/// Borrow a vendor CLI's current sign-in (connection mode `cli`).
pub fn cli_token(kind: &str) -> Result<Option<Zeroizing<String>>> {
    match kind {
        "github" => {
            let out = std::process::Command::new("gh")
                .args(["auth", "token"])
                .env("PATH", crate::paths::tool_path())
                .output()
                .map_err(|_| Error::Invalid("the gh CLI is not installed".into()))?;
            if !out.status.success() {
                return Err(Error::Invalid(
                    "gh is not signed in — run `gh auth login`".into(),
                ));
            }
            Ok(Some(Zeroizing::new(
                String::from_utf8_lossy(&out.stdout).trim().to_string(),
            )))
        }
        // flyctl uses its own session when no token is given.
        "fly" => Ok(None),
        _ => Err(Error::Invalid(format!(
            "{kind} cannot borrow a CLI sign-in; give it a token"
        ))),
    }
}
