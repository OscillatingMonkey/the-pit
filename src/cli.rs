//! The `pit` command line. Every command is a thin client of the agent; this
//! file only gathers input (hidden, from the terminal), asks for approval when
//! the agent requires it, and prints names, fingerprints and outcomes.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::error::{invalid, Error, Result};
use crate::model::Scope;
use crate::protocol::{self, Auth};
use crate::{backup, crypto, paths, presence, service, ui};

#[derive(Parser, Debug)]
#[command(
    name = "pit",
    version,
    about = "The Pit — an encrypted, local secrets vault with an integration rail.",
    long_about = "The Pit keeps your secrets encrypted on this machine and pushes them where they need to go.\n\nRun `pit` with no arguments for the interactive console. Start with `pit init`.",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create your vault: password, recovery code, second factor.
    Init(InitArgs),
    /// Open the pit for a while (password + second factor, or Touch ID quick unlock).
    Unlock(UnlockArgs),
    /// Close the pit now. Keys are wiped from memory.
    Lock,
    /// Is the pit open, for how long, and what is waiting for approval.
    Status,
    /// Approve once and keep sensitive actions open for a few minutes.
    Elevate {
        /// e.g. 5m, 10m, 1h (max 1h)
        #[arg(long = "for", default_value = "5m")]
        dur: String,
        /// Also cover requests from AI clients (MCP) during the window.
        #[arg(long)]
        ai: bool,
    },
    /// Approve a pending request (from an AI client or another terminal).
    Approve { ticket: Option<String> },
    /// List requests waiting for approval.
    Approvals,

    /// Show projects, channels, secrets (names and fingerprints only) and destinations.
    Ls { target: Option<String> },
    /// Secrets that are declared but still empty.
    Needs { project: Option<String> },
    /// Manage projects.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Manage channels (production, staging, development, …).
    #[command(subcommand)]
    Channel(ChannelCmd),

    /// Set a secret's value (prompted, piped, from a file, or generated).
    Set(SetArgs),
    /// Declare a secret with no value yet.
    Declare(DeclareArgs),
    /// Set a secret's description.
    Describe {
        /// [SCOPE] NAME TEXT
        #[arg(num_args = 2..=3)]
        args: Vec<String>,
    },
    /// Rename, re-tag or change how a secret is protected.
    Edit(EditArgs),
    /// Delete a secret.
    Rm {
        #[arg(num_args = 1..=2)]
        args: Vec<String>,
    },
    /// Move a secret to another scope (global, a project, or project/channel).
    Mv {
        #[arg(num_args = 2..=3)]
        args: Vec<String>,
    },
    /// Show a secret's value (needs approval).
    Reveal(RevealArgs),
    /// Check a candidate value against a secret without revealing it (works for one-way secrets).
    Verify {
        #[arg(num_args = 1..=2)]
        args: Vec<String>,
    },
    /// Put a secret's previous value back.
    Rollback {
        #[arg(num_args = 1..=2)]
        args: Vec<String>,
    },

    /// Where a channel's secrets go.
    #[command(subcommand)]
    Dest(DestCmd),
    /// Delegate access to a service so The Pit can push there (vercel, github, fly).
    Connect(ConnectArgs),
    /// List connections.
    Connections,
    /// Remove a connection.
    Disconnect { name: String },

    /// Push a channel's secrets to its destinations.
    Push(PushArgs),
    /// Compare what a channel holds with what each destination has (names only).
    Diff { target: Option<String> },
    /// Bring values a tool wrote into a rendered file back into the pit.
    Absorb {
        target: String,
        destination: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Run a program with a channel's secrets in its environment (nothing written to disk).
    Run(RunArgs),
    /// Link the current folder to a project/channel (writes .pit.toml, no secrets).
    Link { target: String },

    /// The audit log: every push, reveal, unlock and change.
    Log(LogArgs),
    /// Backups, bundles and remote backup targets.
    #[command(subcommand)]
    Backup(BackupCmd),
    /// Encrypt any file with a passphrase.
    Seal {
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Remove the original after sealing.
        #[arg(long)]
        remove: bool,
    },
    /// Decrypt a file made by `pit seal`.
    Unseal {
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Recovery code: rotate it, or split it into shares.
    #[command(subcommand)]
    Recovery(RecoveryCmd),
    /// Lost your password? Open the pit with the recovery code (or shares) and set a new one.
    Recover,
    /// Change your password.
    Password,
    /// Second factors: Touch ID and authenticator codes.
    #[command(subcommand)]
    Mfa(MfaCmd),
    /// Touch ID quick unlock on this Mac (on|off).
    QuickUnlock { state: String },
    /// Show or change settings (session length, idle lock, …).
    Settings {
        key: Option<String>,
        value: Option<String>,
    },
    /// Earlier versions of the whole library, and restoring one.
    History {
        #[arg(long)]
        restore: Option<u64>,
    },
    /// Your identity key, for receiving bundles from someone else.
    Identity,
    /// Last resort: dump everything out, or destroy the vault.
    #[command(subcommand)]
    Emergency(EmergencyCmd),

    /// Import secrets: a .env/JSON/YAML file, or a folder of them.
    #[command(subcommand)]
    Import(ImportCmd),
    /// Look through a project for secrets and offer to copy them in. Never edits the project.
    Scan(ScanArgs),
    /// Run The Pit's agent as a login service (launchd / systemd).
    Service { action: String },
    /// Health check: permissions, agent, factors, backups, leftovers.
    Doctor,
    /// Run the MCP server on stdio (for AI assistants).
    Mcp,
    /// Print the MCP configuration for Claude Code and other clients.
    McpConfig,
    /// Run the agent in the foreground.
    Agent {
        #[arg(long)]
        foreground: bool,
    },
    /// Open the interactive console.
    Console,
    #[command(hide = true)]
    ClipClear { secs: u64 },
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[arg(long)]
    name: Option<String>,
    /// Do not require Touch ID as a second factor.
    #[arg(long)]
    no_touch_id: bool,
}

#[derive(Args, Debug)]
pub struct UnlockArgs {
    /// Use the password even if Touch ID quick unlock is available.
    #[arg(long)]
    password: bool,
    /// Session length for this unlock, e.g. 30m, 2h.
    #[arg(long = "for")]
    dur: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    Add {
        name: String,
        #[arg(short, long)]
        description: Option<String>,
        /// Channels to create, e.g. production,staging,development
        #[arg(long, value_delimiter = ',')]
        channels: Vec<String>,
    },
    List,
    Edit {
        name: String,
        #[arg(long)]
        rename: Option<String>,
        #[arg(short, long)]
        description: Option<String>,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ChannelCmd {
    /// pit channel add PROJECT/NAME
    Add {
        target: String,
        #[arg(short, long)]
        description: Option<String>,
        /// Require approval for every push and reveal (default for `production`).
        #[arg(long)]
        protected: bool,
        #[arg(long)]
        unprotected: bool,
        /// Do not see the project's own secrets.
        #[arg(long)]
        no_inherit: bool,
    },
    Edit {
        target: String,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(long)]
        protected: bool,
        #[arg(long)]
        unprotected: bool,
        #[arg(long)]
        inherit: Option<bool>,
        #[arg(long)]
        rename: Option<String>,
    },
    Rm {
        target: String,
    },
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// [SCOPE] NAME — scope is global, PROJECT or PROJECT/CHANNEL (defaults to .pit.toml)
    #[arg(num_args = 1..=2)]
    args: Vec<String>,
    /// Read the value from a file (stored as a file secret).
    #[arg(long)]
    file: Option<PathBuf>,
    /// Generate a random value of this length.
    #[arg(long)]
    generate: Option<u64>,
    /// Alphabet for --generate: base64url (default), alnum, hex, symbols.
    #[arg(long)]
    charset: Option<String>,
    #[arg(short, long)]
    description: Option<String>,
    /// sealed (two-way, default) | hashed (one-way) | plain
    #[arg(short, long)]
    protection: Option<String>,
    #[arg(long, value_delimiter = ',')]
    tag: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DeclareArgs {
    #[arg(num_args = 1..=2)]
    args: Vec<String>,
    #[arg(short, long)]
    description: Option<String>,
    #[arg(short, long)]
    protection: Option<String>,
    #[arg(long, value_delimiter = ',')]
    tag: Vec<String>,
}

#[derive(Args, Debug)]
pub struct EditArgs {
    #[arg(num_args = 1..=2)]
    args: Vec<String>,
    #[arg(long)]
    rename: Option<String>,
    #[arg(short, long)]
    protection: Option<String>,
    #[arg(long, value_delimiter = ',')]
    tags: Option<Vec<String>>,
    #[arg(short, long)]
    description: Option<String>,
}

#[derive(Args, Debug)]
pub struct RevealArgs {
    #[arg(num_args = 1..=2)]
    args: Vec<String>,
    /// Copy to the clipboard (cleared automatically) instead of printing.
    #[arg(long)]
    copy: bool,
    /// Write to a file (0600) instead of printing.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum DestCmd {
    /// pit dest add PROJECT/CHANNEL NAME --kind fly --set app=my-app
    Add(DestArgs),
    Edit(DestArgs),
    Rm {
        target: String,
        name: String,
    },
    List {
        target: Option<String>,
    },
    /// What each kind of destination takes.
    Kinds,
}

#[derive(Args, Debug)]
pub struct DestArgs {
    target: String,
    name: String,
    #[arg(long)]
    kind: Option<String>,
    /// key=value (repeatable). Values may reference channel secrets as {NAME}.
    #[arg(long = "set")]
    sets: Vec<String>,
    /// Which secrets: *, tag:<t>, NAME, "NAME as ALIAS", global:NAME, !NAME (repeatable).
    #[arg(long)]
    select: Vec<String>,
    #[arg(long)]
    connection: Option<String>,
    #[arg(short, long)]
    description: Option<String>,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// vercel | github | fly
    kind: Option<String>,
    #[arg(long)]
    name: Option<String>,
    /// Borrow the vendor CLI's own sign-in instead of storing a token (github, fly).
    #[arg(long)]
    use_cli: bool,
    /// Vercel team id the token belongs to.
    #[arg(long)]
    team: Option<String>,
    /// Re-check an existing connection with its service.
    #[arg(long)]
    verify: Option<String>,
}

#[derive(Args, Debug)]
pub struct PushArgs {
    /// PROJECT/CHANNEL (defaults to .pit.toml)
    target: Option<String>,
    /// Only these destinations.
    destinations: Vec<String>,
    #[arg(long)]
    dry_run: bool,
    /// Overwrite local files even if they hold values the pit does not.
    #[arg(long)]
    force: bool,
    #[arg(short, long)]
    yes: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// PROJECT/CHANNEL (defaults to .pit.toml)
    #[arg(short = 'c', long = "channel")]
    target: Option<String>,
    /// Only these secrets (repeatable; same syntax as destination select).
    #[arg(long)]
    only: Vec<String>,
    /// Use a destination's selection.
    #[arg(long)]
    dest: Option<String>,
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct LogArgs {
    #[arg(short = 'n', long, default_value_t = 30)]
    limit: u64,
    #[arg(long)]
    project: Option<String>,
    /// push | reveal | unlock | …
    #[arg(long)]
    event: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum BackupCmd {
    /// Where backups go, whether each holds the current vault, and any errors.
    #[command(alias = "targets")]
    Status,
    /// Send the current vault to every target that does not have it yet.
    Sync {
        #[arg(long)]
        quiet: bool,
    },
    /// Send a fresh snapshot to every target (or --to some) right now.
    Now {
        #[arg(long = "to")]
        to: Vec<String>,
        #[arg(long)]
        quiet: bool,
    },
    /// Add a remote or local backup target.
    Target(TargetArgs),
    /// Remove a backup target.
    Untarget { name: String },
    /// Back up after every change: on (default) or off.
    Auto { state: String },
    /// Every backup on every target, newest first.
    List {
        /// Only this target, or one written out: dir:PATH, ssh:USER@HOST:PATH, rclone:REMOTE:PATH
        #[arg(long)]
        from: Option<String>,
    },
    /// What changed between two backups, or between a backup and now (names and fingerprints only).
    Diff {
        /// A backup: a number from `pit backup list`, `latest`, TARGET:N, a file name or a .pitvault path.
        a: String,
        /// Another backup; omitted, the comparison is with the vault as it is now.
        b: Option<String>,
        #[arg(long)]
        from: Option<String>,
        /// Ask for the password the backup was made with (for a backup of a different vault).
        #[arg(long)]
        password: bool,
    },
    /// Export chosen projects (or everything) as an encrypted bundle.
    Bundle {
        #[arg(long = "project")]
        projects: Vec<String>,
        #[arg(long)]
        out: PathBuf,
        /// Also protect it with a passphrase (so it opens without this vault).
        #[arg(long)]
        passphrase: bool,
        /// Encrypt it to someone's identity (from `pit identity`).
        #[arg(long)]
        to_identity: Option<String>,
        #[arg(long)]
        with_connections: bool,
    },
    /// Import a bundle into this vault.
    Import {
        file: PathBuf,
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        replace: bool,
        /// Also take the bundle's destinations and connections. Only for bundles you made yourself.
        #[arg(long)]
        with_destinations: bool,
    },
    /// Replace this vault with a backup: a number from `pit backup list`, `latest`, TARGET:N, or a .pitvault file.
    Restore {
        what: String,
        #[arg(long)]
        from: Option<String>,
    },
    /// Show what a snapshot or bundle contains, without opening it.
    Inspect { file: PathBuf },
}

#[derive(Args, Debug)]
pub struct TargetArgs {
    name: String,
    /// dir | ssh | s3 | rclone
    #[arg(long)]
    kind: String,
    /// dir: folder (iCloud Drive, Dropbox, an external disk…)
    #[arg(long)]
    path: Option<String>,
    /// ssh: user@host:/path
    #[arg(long)]
    dest: Option<String>,
    /// rclone: remote:path (Google Drive, OneDrive, Dropbox, B2… via rclone)
    #[arg(long)]
    remote: Option<String>,
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long)]
    region: Option<String>,
    /// s3: https://… for R2, B2, MinIO; omit for AWS
    #[arg(long)]
    endpoint: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum RecoveryCmd {
    /// Replace the recovery code. The old one stops working.
    Rotate {
        /// Split into shares, e.g. 2-of-3
        #[arg(long)]
        split: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum MfaCmd {
    /// Require Touch ID after the password (on|off).
    Touchid { state: String },
    /// Enroll an authenticator app (RFC 6238).
    Totp,
    /// Remove the authenticator app.
    TotpOff,
}

#[derive(Subcommand, Debug)]
pub enum EmergencyCmd {
    /// Dump every secret out of the vault (needs any working way in).
    Export {
        #[arg(long)]
        out: PathBuf,
        /// Write plaintext: one folder per project/channel with .env files and files.
        #[arg(long)]
        plaintext: bool,
    },
    /// Destroy the vault: crypto-shred every key slot and delete everything. Needs no key.
    Destroy,
}

#[derive(Subcommand, Debug)]
pub enum ImportCmd {
    /// Import a .env / shell-export / JSON / YAML file (`-` reads stdin).
    /// pit import env .env.local --to my-app/development
    #[command(alias = "file")]
    Env(ImportEnvArgs),
    /// Import a folder laid out as PROJECT/ENVIRONMENT/*.env (see docs/importing.md).
    SecretPit {
        dir: PathBuf,
        #[arg(long)]
        map: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args, Debug)]
pub struct ImportEnvArgs {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Where they go: global, PROJECT or PROJECT/CHANNEL (defaults to .pit.toml).
    #[arg(long)]
    to: Option<String>,
    /// sealed (two-way, default) | hashed (one-way) | plain
    #[arg(short, long)]
    protection: Option<String>,
    /// Replace existing values that differ (old values stay in history).
    #[arg(long)]
    overwrite: bool,
    /// Keys to leave out.
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    tag: Vec<String>,
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// The project folder (default: here).
    dir: Option<PathBuf>,
    /// Where accepted findings go: PROJECT or PROJECT/CHANNEL (defaults to .pit.toml).
    #[arg(long)]
    to: Option<String>,
    /// Also list ordinary settings (ports, hosts, flags).
    #[arg(long)]
    all: bool,
    /// Only report; do not offer to import.
    #[arg(long)]
    report: bool,
    /// Report as JSON (names, places and lengths — never values).
    #[arg(long)]
    json: bool,
    #[arg(short, long)]
    protection: Option<String>,
}

// ---------------------------------------------------------------------------
// input

pub fn tty() -> bool {
    std::io::stdin().is_terminal()
}

pub fn prompt_hidden(msg: &str) -> Result<Zeroizing<String>> {
    if !tty() {
        return invalid(format!("{msg} — needs a terminal"));
    }
    rpassword::prompt_password(msg)
        .map(Zeroizing::new)
        .map_err(Error::from)
}

pub fn prompt_line(msg: &str) -> Result<String> {
    eprint!("{msg}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

pub fn confirm(msg: &str) -> Result<bool> {
    if !tty() {
        return Ok(false);
    }
    let a = prompt_line(&format!("{msg} [y/N] "))?;
    Ok(matches!(a.to_lowercase().as_str(), "y" | "yes"))
}

/// NIST SP 800-63B: length over composition, and screening against guessable
/// passwords. Minimum 12 characters, and an estimated 10^12 guesses or more —
/// the vault file can be attacked offline, so online-attack strength is not enough.
pub fn password_policy(pw: &str, name: &str) -> Result<()> {
    let n = pw.chars().count();
    if n < 12 {
        return invalid("use at least 12 characters — a few random words work well");
    }
    if n > 1024 {
        return invalid("that password is too long");
    }
    let est = zxcvbn::zxcvbn(pw, &[name, "the pit", "pit", "secret", "password"]);
    if est.guesses_log10() < 12.0 {
        let hint = est
            .feedback()
            .and_then(|f| f.warning().map(|w| w.to_string()))
            .unwrap_or_else(|| "it is too easy to guess".into());
        return invalid(format!("password is too weak: {hint}"));
    }
    Ok(())
}

fn new_password(name: &str) -> Result<Zeroizing<String>> {
    loop {
        let a = prompt_hidden("New password: ")?;
        if let Err(e) = password_policy(&a, name) {
            ui::warn(&e.to_string());
            continue;
        }
        let b = prompt_hidden("Repeat it: ")?;
        if !crypto::ct_eq(a.as_bytes(), b.as_bytes()) {
            ui::warn("they do not match");
            continue;
        }
        return Ok(a);
    }
}

fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n
        .parse()
        .map_err(|_| Error::Invalid(format!("bad duration {s}")))?;
    Ok(match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return invalid(format!("bad duration {s} (use s, m, h or d)")),
    })
}

// ---------------------------------------------------------------------------
// project links (.pit.toml)

#[derive(serde::Deserialize, serde::Serialize)]
struct Link {
    project: String,
    #[serde(default)]
    channel: Option<String>,
}

fn find_link() -> Option<(PathBuf, Link)> {
    let mut d = std::env::current_dir().ok()?;
    loop {
        let p = d.join(".pit.toml");
        if let Ok(t) = std::fs::read_to_string(&p) {
            if let Ok(l) = toml::from_str::<Link>(&t) {
                return Some((p, l));
            }
        }
        if !d.pop() {
            return None;
        }
    }
}

fn target_or_link(t: Option<&str>) -> Result<(String, String)> {
    let t = match t {
        Some(t) => t.to_string(),
        None => {
            let (_, l) = find_link().ok_or_else(|| {
                Error::Invalid(
                    "give PROJECT/CHANNEL, or run `pit link PROJECT/CHANNEL` in this folder".into(),
                )
            })?;
            match l.channel {
                Some(c) => format!("{}/{}", l.project, c),
                None => return invalid(".pit.toml names no channel; give PROJECT/CHANNEL"),
            }
        }
    };
    match Scope::parse(&t)? {
        Scope::Channel(p, c) => Ok((p, c)),
        _ => invalid(format!("{t} is not PROJECT/CHANNEL")),
    }
}

/// `[SCOPE] NAME` → (scope, name). One argument uses the linked channel.
fn scope_name(args: &[String]) -> Result<(String, String)> {
    match args {
        [scope, name] => {
            Scope::parse(scope)?;
            Ok((scope.clone(), name.clone()))
        }
        [name] => {
            let (p, c) = target_or_link(None)?;
            Ok((format!("{p}/{c}"), name.clone()))
        }
        _ => invalid("expected [SCOPE] NAME"),
    }
}

// ---------------------------------------------------------------------------
// calling the agent

/// Call the agent, handling the things a person at a terminal can answer:
/// unlocking, approvals and authenticator codes.
pub fn call(op: &str, args: Value) -> Result<Value> {
    call_as("cli", op, args)
}

pub fn call_as(client: &str, op: &str, mut args: Value) -> Result<Value> {
    let mut auth: Option<Auth> = None;
    let mut tries = 0;
    let mut unlocked = false;
    let mut asked: Option<(String, Vec<String>)> = None;
    loop {
        let sent_auth = auth.is_some();
        let (reason, methods) = match protocol::call(client, op, args.clone(), auth.take()) {
            Err(Error::Locked) if tty() && !unlocked => {
                unlocked = true;
                ui::note("the pit is locked");
                unlock(&UnlockArgs {
                    password: false,
                    dur: None,
                })?;
                continue;
            }
            Err(Error::ApprovalRequired {
                reason, methods, ..
            }) if tty() && tries < 3 => (reason, methods),
            Err(Error::Confirm(msg)) if tty() && args.get("confirmed").is_none() => {
                ui::warn(&msg);
                if !confirm("Store it one-way anyway?")? {
                    return Err(Error::Refused("nothing changed".into()));
                }
                args["confirmed"] = json!(true);
                continue;
            }
            Err(Error::Denied) if sent_auth && tty() && tries < 3 => {
                ui::warn("that did not match");
                asked.clone().ok_or(Error::Denied)?
            }
            other => return other,
        };
        tries += 1;
        asked = Some((reason.clone(), methods.clone()));
        ui::note(&format!("approval needed: {reason}"));
        let totp = methods.iter().any(|m| m == "totp");
        let ask = if totp {
            "Authenticator code or password: "
        } else {
            "Password: "
        };
        let answer = prompt_hidden(ask)?;
        let is_code = answer.len() == 6 && answer.chars().all(|c| c.is_ascii_digit());
        auth = Some(if is_code && totp {
            Auth::with_totp(answer.to_string())
        } else {
            Auth::with_password(answer.to_string())
        });
    }
}

// ---------------------------------------------------------------------------
// commands

pub fn run(cli: Cli) -> Result<i32> {
    let Some(cmd) = cli.cmd else {
        return crate::console::run().map(|_| 0);
    };
    match cmd {
        Cmd::Init(a) => init(a)?,
        Cmd::Unlock(a) => unlock(&a)?,
        Cmd::Lock => {
            if protocol::agent_running() {
                protocol::call("cli", "lock", json!({}), None)?;
            }
            ui::ok("locked");
        }
        Cmd::Status => status()?,
        Cmd::Elevate { dur, ai } => {
            let secs = parse_duration(&dur)?;
            let r = call("elevate", json!({"secs": secs, "ai": ai}))?;
            ui::ok(&format!(
                "sensitive actions open for {} min{}",
                r["elevated_for"].as_u64().unwrap_or(0) / 60,
                if ai { " (including AI clients)" } else { "" }
            ));
        }
        Cmd::Approvals => approvals()?,
        Cmd::Approve { ticket } => {
            let ticket = match ticket {
                Some(t) => t,
                None => {
                    let r = call("approvals", json!({}))?;
                    let list = r["pending"].as_array().cloned().unwrap_or_default();
                    match list.as_slice() {
                        [] => {
                            ui::note("nothing is waiting for approval");
                            return Ok(0);
                        }
                        [one] => one["ticket"].as_str().unwrap_or("").to_string(),
                        _ => {
                            approvals()?;
                            return invalid("several requests are waiting; give a ticket");
                        }
                    }
                }
            };
            call("approve", json!({"ticket": ticket}))?;
            ui::ok(&format!("approved {ticket} — the requester can retry now"));
        }

        Cmd::Ls { target } => ls(target.as_deref())?,
        Cmd::Needs { project } => {
            let r = call("needs", json!({"project": project}))?;
            let list = r["empty"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                ui::ok("nothing is waiting for a value");
            }
            for e in list {
                println!(
                    "  {:<36} {:<32} {}",
                    e["scope"].as_str().unwrap_or(""),
                    e["name"].as_str().unwrap_or(""),
                    ui::dim(e["description"].as_str().unwrap_or(""))
                );
            }
        }
        Cmd::Project(p) => project(p)?,
        Cmd::Channel(c) => channel(c)?,

        Cmd::Set(a) => set(a)?,
        Cmd::Declare(a) => {
            let (scope, name) = scope_name(&a.args)?;
            let r = call(
                "secret.declare",
                json!({"scope": scope, "name": name, "description": a.description, "protection": a.protection, "tags": a.tag}),
            )?;
            ui::ok(&format!(
                "declared {scope}:{} ({})",
                name,
                r["protection"].as_str().unwrap_or("")
            ));
        }
        Cmd::Describe { args } => {
            let (sn, text) = args.split_at(args.len() - 1);
            let (scope, name) = scope_name(sn)?;
            call(
                "secret.edit",
                json!({"scope": scope, "name": name, "description": text[0]}),
            )?;
            ui::ok(&format!("described {scope}:{name}"));
        }
        Cmd::Edit(a) => {
            let (scope, name) = scope_name(&a.args)?;
            let mut args = json!({"scope": scope, "name": name});
            if let Some(r) = a.rename {
                args["rename"] = json!(r);
            }
            if let Some(p) = a.protection {
                if p.starts_with("hash") && !confirm("One-way storage cannot be undone: the value can be verified but never read or pushed again. Continue?")? {
                    ui::note("nothing changed (switching to one-way needs a terminal to confirm)");
                    return Ok(1);
                }
                args["protection"] = json!(p);
            }
            if let Some(t) = a.tags {
                args["tags"] = json!(t);
            }
            if let Some(d) = a.description {
                args["description"] = json!(d);
            }
            let r = call("secret.edit", args)?;
            ui::ok(&format!(
                "{scope}:{} updated ({})",
                r["name"].as_str().unwrap_or(""),
                r["protection"].as_str().unwrap_or("")
            ));
        }
        Cmd::Rm { args } => {
            let (scope, name) = scope_name(&args)?;
            if tty() && !confirm(&format!("Delete {scope}:{name} and its history?"))? {
                return Ok(1);
            }
            call("secret.rm", json!({"scope": scope, "name": name}))?;
            ui::ok(&format!("deleted {scope}:{name}"));
        }
        Cmd::Mv { args } => {
            let (sn, to) = args.split_at(args.len() - 1);
            let (scope, name) = scope_name(sn)?;
            call(
                "secret.move",
                json!({"scope": scope, "name": name, "to": to[0]}),
            )?;
            ui::ok(&format!("moved {name} → {}", to[0]));
        }
        Cmd::Reveal(a) => reveal(a)?,
        Cmd::Verify { args } => {
            let (scope, name) = scope_name(&args)?;
            let cand = read_value_interactive(&format!("Value to check against {name}: "))?;
            let r = call(
                "secret.verify",
                json!({"scope": scope, "name": name, "value_b64": crypto::b64e(&cand)}),
            )?;
            if r["match"].as_bool() == Some(true) {
                ui::ok("match");
            } else {
                ui::warn("no match");
                return Ok(1);
            }
        }
        Cmd::Rollback { args } => {
            let (scope, name) = scope_name(&args)?;
            let r = call("secret.rollback", json!({"scope": scope, "name": name}))?;
            ui::ok(&format!(
                "{name} is back to {}",
                r["fp"].as_str().unwrap_or("")
            ));
        }

        Cmd::Dest(d) => dest(d)?,
        Cmd::Connect(a) => connect(a)?,
        Cmd::Connections => {
            let r = call("tree", json!({}))?;
            let list = r["connections"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                ui::note("no connections yet — `pit connect vercel|github|fly`");
            }
            for c in list {
                println!(
                    "  {:<20} {:<8} {:<6} {:<40} verified {}",
                    c["name"].as_str().unwrap_or(""),
                    c["kind"].as_str().unwrap_or(""),
                    c["mode"].as_str().unwrap_or(""),
                    c["account"].as_str().unwrap_or(""),
                    c["verified"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Disconnect { name } => {
            let r = call("conn.rm", json!({"name": name}))?;
            ui::ok(&format!("removed {name}"));
            ui::note(r["note"].as_str().unwrap_or(""));
        }

        Cmd::Push(a) => return push(a),
        Cmd::Diff { target } => diff(target.as_deref())?,
        Cmd::Absorb {
            target,
            destination,
            dry_run,
        } => {
            let (p, c) = target_or_link(Some(&target))?;
            let r = call(
                "absorb",
                json!({"project": p, "channel": c, "destination": destination, "dry_run": dry_run}),
            )?;
            let changed = r["changed"].as_array().cloned().unwrap_or_default();
            if changed.is_empty() {
                ui::ok("the pit already matches");
            } else {
                for n in &changed {
                    println!(
                        "  {} {}",
                        if dry_run { "would update" } else { "updated" },
                        n.as_str().unwrap_or("")
                    );
                }
            }
            for n in r["project_level"].as_array().cloned().unwrap_or_default() {
                ui::warn(&format!(
                    "{} is a project-wide secret; absorb leaves it alone — set it with `pit set {} {}` if the change is right",
                    n.as_str().unwrap_or(""),
                    target.split('/').next().unwrap_or(""),
                    n.as_str().unwrap_or("")
                ));
            }
            for n in r["not_in_pit"].as_array().cloned().unwrap_or_default() {
                ui::warn(&format!(
                    "{} is in the file but not selected in the pit — add it with `pit set`",
                    n.as_str().unwrap_or("")
                ));
            }
        }
        Cmd::Run(a) => return run_with_env(a),
        Cmd::Link { target } => {
            let (p, c) = target_or_link(Some(&target))?;
            let path = std::env::current_dir()?.join(".pit.toml");
            let text = format!(
                "# This folder belongs to The Pit project `{p}`, channel `{c}`.\n# No secrets here. `pit push`, `pit run -- …` and `pit set NAME` use it.\nproject = \"{p}\"\nchannel = \"{c}\"\n"
            );
            std::fs::write(&path, text)?;
            ui::ok(&format!("linked {} → {p}/{c}", path.display()));
        }

        Cmd::Log(a) => log(a)?,
        Cmd::Backup(b) => backup_cmd(b)?,
        Cmd::Seal { file, out, remove } => seal_file(&file, out, remove)?,
        Cmd::Unseal { file, out } => unseal_file(&file, out)?,

        Cmd::Recovery(RecoveryCmd::Rotate { split }) => {
            let args = match split {
                Some(s) => {
                    let (k, n) = s
                        .split_once("-of-")
                        .ok_or_else(|| Error::Invalid("use e.g. --split 2-of-3".into()))?;
                    json!({"threshold": k.parse::<u64>().unwrap_or(0), "shares": n.parse::<u64>().unwrap_or(0)})
                }
                None => json!({}),
            };
            let r = call("recovery.rotate", args)?;
            show_recovery(&r)?;
        }
        Cmd::Recover => recover()?,
        Cmd::Password => {
            let r = call("status", json!({}))?;
            let name = r["owner"].as_str().unwrap_or("").to_string();
            let old = prompt_hidden("Current password: ")?;
            let new = new_password(&name)?;
            protocol::call(
                "cli",
                "password.change",
                json!({"new_password": new.as_str()}),
                Some(Auth::with_password(old.to_string())),
            )?;
            ui::ok("password changed");
        }
        Cmd::Mfa(m) => mfa(m)?,
        Cmd::QuickUnlock { state } => {
            let on = on_off(&state)?;
            call("device.set", json!({"enable": on}))?;
            ui::ok(if on {
                "Touch ID quick unlock is on"
            } else {
                "Touch ID quick unlock is off"
            });
        }
        Cmd::Settings { key, value } => match (key, value) {
            (Some(k), Some(v)) => {
                let v = if k.ends_with("_secs") {
                    parse_duration(&v)?.to_string()
                } else {
                    v
                };
                let r = call("settings.set", json!({"key": k, "value": v}))?;
                ui::print_json(&r);
            }
            _ => ui::print_json(&call("settings.get", json!({}))?),
        },
        Cmd::History { restore } => match restore {
            Some(g) => {
                let r = call("history.restore", json!({"generation": g}))?;
                ui::ok(&format!("restored generation {g} (saved as {})", r["now"]));
            }
            None => {
                let r = call("history.list", json!({}))?;
                println!("current generation {}", r["current"]);
                for g in r["generations"].as_array().cloned().unwrap_or_default() {
                    println!(
                        "  {:>6}  {}",
                        g["generation"],
                        g["saved"].as_str().unwrap_or("")
                    );
                }
            }
        },
        Cmd::Identity => {
            let r = call("identity", json!({}))?;
            println!("{}", r["identity"].as_str().unwrap_or(""));
            ui::note("share this freely: it lets someone encrypt a bundle that only you can open");
        }
        Cmd::Emergency(e) => emergency(e)?,

        Cmd::Import(ImportCmd::Env(a)) => import_env(a)?,
        Cmd::Scan(a) => scan(a)?,
        Cmd::Import(ImportCmd::SecretPit { dir, map, dry_run }) => {
            import_secret_pit(&dir, map.as_deref(), dry_run)?
        }
        Cmd::Service { action } => service::cmd(&action)?,
        Cmd::Doctor => return doctor(),
        Cmd::Mcp => crate::mcp::serve()?,
        Cmd::McpConfig => {
            let exe = paths::self_exe();
            println!(
                "Claude Code:\n  claude mcp add the-pit -- {} mcp\n",
                exe.display()
            );
            println!("Any MCP client (JSON):");
            ui::print_json(
                &json!({"mcpServers": {"the-pit": {"command": exe.display().to_string(), "args": ["mcp"]}}}),
            );
        }
        Cmd::Agent { foreground } => crate::agent::run(foreground)?,
        Cmd::Console => crate::console::run()?,
        Cmd::ClipClear { secs } => clip_clear(secs),
    }
    Ok(0)
}

fn on_off(s: &str) -> Result<bool> {
    match s {
        "on" | "true" | "yes" | "enable" => Ok(true),
        "off" | "false" | "no" | "disable" => Ok(false),
        _ => invalid("use on or off"),
    }
}

fn init(a: InitArgs) -> Result<()> {
    if crate::vault::exists() {
        return invalid(format!(
            "there is already a vault at {}",
            paths::home().display()
        ));
    }
    ui::title("The Pit — new vault");
    println!("Your secrets will be encrypted with keys only you hold. There are three ways in:");
    println!("  1. your password                 — every day");
    println!("  2. a recovery code               — if you forget the password. Shown once.");
    println!("  3. Touch ID on this Mac          — quick unlock and approvals\n");
    let default_name = std::env::var("USER").unwrap_or_else(|_| "owner".into());
    let name = match a.name {
        Some(n) => n,
        None if tty() => {
            let n = prompt_line(&format!("Your name [{default_name}]: "))?;
            if n.is_empty() {
                default_name
            } else {
                n
            }
        }
        None => default_name,
    };
    println!("Choose a password: at least 12 characters. Several unrelated words are easy to remember and hard to guess.");
    let pw = new_password(&name)?;
    let touch = !a.no_touch_id
        && presence::available()
        && (!tty() || confirm("Require Touch ID as a second factor and for approvals?")?);
    let r = protocol::call(
        "cli",
        "init",
        json!({"name": name, "touch_id": touch, "quick_unlock": touch}),
        Some(Auth::with_password(pw.to_string())),
    )?;
    let code = r["recovery_code"].as_str().unwrap_or("").to_string();
    println!();
    ui::title("Your recovery code");
    println!("{code}\n");
    println!("Write it down on paper, or store it in a password manager that is NOT on this Mac.");
    println!("It opens your vault without the password. Anyone holding it can do the same.");
    println!("It is shown once. You can replace it later with `pit recovery rotate`, or split it");
    println!("into shares with `pit recovery rotate --split 2-of-3`.\n");
    if tty() {
        loop {
            let last = code.rsplit('-').nth(1).unwrap_or("");
            let typed =
                prompt_line("To confirm you have it, type the last group before the checksum: ")?;
            if typed.eq_ignore_ascii_case(last) {
                break;
            }
            ui::warn("that does not match — check what you wrote down");
        }
        print!("\x1b[2J\x1b[H");
    }
    ui::ok(&format!("vault created at {}", paths::home().display()));
    if touch {
        ui::ok("Touch ID is your second factor; quick unlock is on");
    }
    println!("\nNext:");
    println!("  pit mfa totp            add an authenticator app as a backup second factor");
    println!("  pit service install     keep the agent running in the background");
    println!("  pit project add myapp --channels production,development");
    Ok(())
}

pub fn unlock(a: &UnlockArgs) -> Result<()> {
    let st = protocol::call("cli", "status", json!({}), None)?;
    if st["initialized"] != json!(true) {
        return invalid("no vault yet — run `pit init`");
    }
    let mut args = json!({});
    if let Some(d) = &a.dur {
        args["ttl_secs"] = json!(parse_duration(d)?);
    }
    if !a.password && st["quick_unlock"] == json!(true) && presence::available() {
        let mut qa = args.clone();
        qa["method"] = json!("touchid");
        match protocol::call("cli", "unlock", qa, None) {
            Ok(r) => {
                ui::ok(&format!(
                    "unlocked for {}",
                    ui::dur(r["expires_in"].as_u64().unwrap_or(0))
                ));
                return Ok(());
            }
            Err(Error::Refused(m)) => ui::note(&m),
            Err(Error::Denied) => ui::note("Touch ID did not confirm — use your password"),
            Err(e) => ui::note(&e.to_string()),
        }
    }
    let pw = prompt_hidden("Password: ")?;
    args["method"] = json!("password");
    let r = match protocol::call(
        "cli",
        "unlock",
        args.clone(),
        Some(Auth::with_password(pw.to_string())),
    ) {
        Err(Error::ApprovalRequired { .. }) => {
            let code = prompt_line("Authenticator code: ")?;
            protocol::call(
                "cli",
                "unlock",
                args,
                Some(Auth {
                    password: Some(pw.to_string()),
                    totp: Some(code),
                    ticket: None,
                }),
            )?
        }
        other => other?,
    };
    ui::ok(&format!(
        "unlocked for {}",
        ui::dur(r["expires_in"].as_u64().unwrap_or(0))
    ));
    Ok(())
}

fn recover() -> Result<()> {
    ui::title("Recover with your recovery code");
    println!("Paste the recovery code (PIT-R-…), or the shares (PIT-S-…) separated by commas.");
    let code = prompt_hidden("Code: ")?;
    let r = protocol::call(
        "cli",
        "unlock",
        json!({"method": "recovery", "code": code.as_str()}),
        None,
    )?;
    ui::ok("opened with the recovery code");
    if r["must_reset_password"] == json!(true) {
        let st = call("status", json!({}))?;
        let name = st["owner"].as_str().unwrap_or("").to_string();
        println!("Set a new password now.");
        let new = new_password(&name)?;
        call("password.change", json!({"new_password": new.as_str()}))?;
        ui::ok("password replaced");
        ui::note(
            "your recovery code still works. If it may be exposed, run `pit recovery rotate`.",
        );
    }
    Ok(())
}

fn status() -> Result<()> {
    let r = protocol::call("cli", "status", json!({}), None)?;
    if r["initialized"] != json!(true) {
        println!(
            "no vault at {} — run `pit init`",
            r["home"].as_str().unwrap_or("")
        );
        return Ok(());
    }
    if r["unlocked"] == json!(true) {
        ui::ok(&format!(
            "open — {} projects · locks in {} (or after {} idle)",
            r["projects"],
            ui::dur(r["expires_in"].as_u64().unwrap_or(0)),
            ui::dur(r["idle_in"].as_u64().unwrap_or(0))
        ));
        if r["elevated_in"].as_u64().unwrap_or(0) > 0 {
            ui::warn(&format!(
                "sensitive actions open for {}",
                ui::dur(r["elevated_in"].as_u64().unwrap_or(0))
            ));
        }
        println!(
            "  second factor: {}{}",
            if r["mfa"]["touch_id"] == json!(true) {
                "Touch ID "
            } else {
                ""
            },
            if r["mfa"]["totp"] == json!(true) {
                "authenticator"
            } else {
                ""
            }
        );
    } else {
        println!("locked — `pit unlock`");
    }
    let pending = r["pending_approvals"].as_u64().unwrap_or(0);
    if pending > 0 {
        ui::warn(&format!("{pending} request(s) waiting — `pit approvals`"));
    }
    if let Some((p, l)) = find_link() {
        println!(
            "  this folder → {}/{} ({})",
            l.project,
            l.channel.unwrap_or_default(),
            p.display()
        );
    }
    Ok(())
}

fn approvals() -> Result<()> {
    let r = protocol::call("cli", "approvals", json!({}), None)?;
    let list = r["pending"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        ui::note("nothing is waiting for approval");
    }
    for p in list {
        println!(
            "  {}  {}  ({}s ago)",
            p["ticket"].as_str().unwrap_or(""),
            p["reason"].as_str().unwrap_or(""),
            p["age_secs"]
        );
    }
    Ok(())
}

fn ls(target: Option<&str>) -> Result<()> {
    let (only_project, only_channel) = match target.map(Scope::parse).transpose()? {
        Some(Scope::Channel(p, c)) => (Some(p), Some(c)),
        Some(Scope::Project(p)) => (Some(p), None),
        _ => (None, None),
    };
    let r = call("tree", json!({"project": only_project}))?;
    if only_project.is_none() {
        let g = r["globals"].as_array().cloned().unwrap_or_default();
        if !g.is_empty() {
            ui::title("global");
            for s in g {
                ui::secret_line(&s, "  ");
            }
        }
    }
    let projects = r["projects"].as_array().cloned().unwrap_or_default();
    if projects.is_empty() && only_project.is_none() {
        ui::note("no projects yet — `pit project add NAME --channels production,development`");
    }
    for p in projects {
        ui::title(&format!(
            "{}  {}",
            p["name"].as_str().unwrap_or(""),
            ui::dim(p["description"].as_str().unwrap_or(""))
        ));
        for s in p["secrets"].as_array().cloned().unwrap_or_default() {
            ui::secret_line(&s, "  ");
        }
        for c in p["channels"].as_array().cloned().unwrap_or_default() {
            if only_channel
                .as_deref()
                .map(|oc| c["name"].as_str() != Some(oc))
                .unwrap_or(false)
            {
                continue;
            }
            let flags = format!(
                "{}{}",
                if c["protected"] == json!(true) {
                    " [protected]"
                } else {
                    ""
                },
                if c["inherit"] == json!(false) {
                    " [no inherit]"
                } else {
                    ""
                }
            );
            println!(
                "  {}{}  {}",
                ui::bold(&format!("/{}", c["name"].as_str().unwrap_or(""))),
                flags,
                ui::dim(c["description"].as_str().unwrap_or(""))
            );
            for s in c["secrets"].as_array().cloned().unwrap_or_default() {
                ui::secret_line(&s, "    ");
            }
            for d in c["destinations"].as_array().cloned().unwrap_or_default() {
                println!(
                    "    → {:<16} {:<8} {}  {}",
                    d["name"].as_str().unwrap_or(""),
                    d["kind"].as_str().unwrap_or(""),
                    d["address"].as_str().unwrap_or(""),
                    ui::dim(
                        &d["select"]
                            .as_array()
                            .map(|a| a
                                .iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(" "))
                            .unwrap_or_default()
                    )
                );
            }
        }
    }
    Ok(())
}

fn project(p: ProjectCmd) -> Result<()> {
    match p {
        ProjectCmd::Add {
            name,
            description,
            channels,
        } => {
            call(
                "project.add",
                json!({"name": name, "description": description, "channels": channels}),
            )?;
            ui::ok(&format!(
                "project {name}{}",
                if channels.is_empty() {
                    String::new()
                } else {
                    format!(" with {}", channels.join(", "))
                }
            ));
            if channels.iter().any(|c| c == "production") {
                ui::note("production is protected: every push and reveal there asks for approval");
            }
        }
        ProjectCmd::List => {
            let r = call("tree", json!({}))?;
            for p in r["projects"].as_array().cloned().unwrap_or_default() {
                let chans: Vec<String> = p["channels"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|c| c["name"].as_str().map(String::from))
                    .collect();
                println!(
                    "  {:<20} {:<40} {}",
                    p["name"].as_str().unwrap_or(""),
                    chans.join(", "),
                    ui::dim(p["description"].as_str().unwrap_or(""))
                );
            }
        }
        ProjectCmd::Edit {
            name,
            rename,
            description,
        } => {
            call(
                "project.edit",
                json!({"name": name, "rename": rename, "description": description}),
            )?;
            ui::ok("updated");
        }
        ProjectCmd::Rm { name } => {
            if tty() && !confirm(&format!("Delete project {name} and every secret in it?"))? {
                return Ok(());
            }
            call("project.rm", json!({"name": name}))?;
            ui::ok(&format!("deleted {name}"));
        }
    }
    Ok(())
}

fn channel(c: ChannelCmd) -> Result<()> {
    match c {
        ChannelCmd::Add {
            target,
            description,
            protected,
            unprotected,
            no_inherit,
        } => {
            let (p, n) = target_or_link(Some(&target))?;
            let mut args = json!({"project": p, "name": n, "description": description, "inherit": !no_inherit});
            if protected || unprotected {
                args["protected"] = json!(protected && !unprotected);
            }
            let r = call("channel.add", args)?;
            ui::ok(&format!(
                "channel {}{}",
                r["channel"].as_str().unwrap_or(""),
                if r["protected"] == json!(true) {
                    " (protected)"
                } else {
                    ""
                }
            ));
        }
        ChannelCmd::Edit {
            target,
            description,
            protected,
            unprotected,
            inherit,
            rename,
        } => {
            let (p, n) = target_or_link(Some(&target))?;
            let mut args =
                json!({"project": p, "channel": n, "description": description, "rename": rename});
            if protected || unprotected {
                args["protected"] = json!(protected && !unprotected);
            }
            if let Some(i) = inherit {
                args["inherit"] = json!(i);
            }
            let r = call("channel.edit", args)?;
            ui::ok(&format!(
                "updated (protected: {}, inherit: {})",
                r["protected"], r["inherit"]
            ));
        }
        ChannelCmd::Rm { target } => {
            let (p, n) = target_or_link(Some(&target))?;
            if tty() && !confirm(&format!("Delete channel {p}/{n} and every secret in it?"))? {
                return Ok(());
            }
            call("channel.rm", json!({"project": p, "channel": n}))?;
            ui::ok("deleted");
        }
    }
    Ok(())
}

fn read_value_interactive(msg: &str) -> Result<Zeroizing<Vec<u8>>> {
    if tty() {
        let v = prompt_hidden(msg)?;
        Ok(Zeroizing::new(v.as_bytes().to_vec()))
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.ends_with(b"\n") {
            buf.pop();
            if buf.ends_with(b"\r") {
                buf.pop();
            }
        }
        Ok(buf)
    }
}

fn set(a: SetArgs) -> Result<()> {
    let (scope, name) = scope_name(&a.args)?;
    if a.protection
        .as_deref()
        .map(|p| p.starts_with("hash"))
        .unwrap_or(false)
    {
        ui::note("one-way: the value can be verified later but never read back or pushed — services like Vercel need the real value, so pushed secrets should stay sealed");
    }
    let mut args = json!({"scope": scope, "name": name, "description": a.description, "protection": a.protection, "tags": a.tag});
    let op = if let Some(n) = a.generate {
        args["length"] = json!(n);
        args["charset"] = json!(a.charset);
        "secret.generate"
    } else if let Some(f) = &a.file {
        let bytes = Zeroizing::new(std::fs::read(f)?);
        args["value_b64"] = json!(crypto::b64e(&bytes));
        args["filename"] = json!(f.file_name().and_then(|n| n.to_str()).unwrap_or("file"));
        "secret.set"
    } else {
        let v = read_value_interactive(&format!("Value for {name} (hidden): "))?;
        if v.is_empty() {
            return invalid("empty value — use `pit declare` to declare a secret without one");
        }
        args["value_b64"] = json!(crypto::b64e(&v));
        "secret.set"
    };
    let r = call(op, args)?;
    ui::ok(&format!(
        "{scope}:{name} set · {} · fp {}",
        r["protection"].as_str().unwrap_or(""),
        r["fp"].as_str().unwrap_or("")
    ));
    Ok(())
}

fn reveal(a: RevealArgs) -> Result<()> {
    let (scope, name) = scope_name(&a.args)?;
    let r = call("secret.reveal", json!({"scope": scope, "name": name}))?;
    let v = Zeroizing::new(crypto::b64d(r["value_b64"].as_str().unwrap_or(""))?);
    if let Some(out) = a.out {
        paths::write_private(&out, &v)?;
        ui::ok(&format!("written to {} (0600)", out.display()));
        return Ok(());
    }
    if a.copy {
        let mut child = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        child.stdin.take().expect("piped").write_all(&v)?;
        child.wait()?;
        let secs = r["clipboard_secs"].as_u64().unwrap_or(30);
        // The helper learns a salted digest over stdin, so it can tell whether the
        // clipboard still holds this value without the value or a plain hash of it
        // ever being visible in a process listing.
        let salt = crypto::random_bytes(32);
        let digest = crypto::sha256_hex(&[salt.as_slice(), &v].concat());
        if let Ok(mut child) = std::process::Command::new(paths::self_exe())
            .args(["clip-clear", &secs.to_string()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            if let Some(mut si) = child.stdin.take() {
                let _ = writeln!(si, "{} {}", hex::encode(&salt), digest);
            }
        }
        ui::ok(&format!("copied — the clipboard clears in {secs}s"));
        return Ok(());
    }
    if r["is_text"] != json!(true) {
        return invalid(format!("{name} is a file; use --out PATH"));
    }
    std::io::stdout().write_all(&v)?;
    if std::io::stdout().is_terminal() {
        println!();
    }
    Ok(())
}

fn clip_clear(secs: u64) {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let mut parts = line.split_whitespace();
    let (Some(salt), Some(digest)) = (parts.next().and_then(|h| hex::decode(h).ok()), parts.next())
    else {
        return;
    };
    std::thread::sleep(std::time::Duration::from_secs(secs));
    if let Ok(out) = std::process::Command::new("pbpaste").output() {
        let cur = Zeroizing::new(out.stdout);
        if crypto::sha256_hex(&[salt.as_slice(), &cur].concat()) == digest {
            if let Ok(mut c) = std::process::Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                let _ = c.stdin.take().map(|mut s| s.write_all(b""));
                let _ = c.wait();
            }
        }
    }
}

fn dest(d: DestCmd) -> Result<()> {
    match d {
        DestCmd::Add(a) => dest_upsert("dest.add", a)?,
        DestCmd::Edit(a) => dest_upsert("dest.edit", a)?,
        DestCmd::Rm { target, name } => {
            let (p, c) = target_or_link(Some(&target))?;
            call("dest.rm", json!({"project": p, "channel": c, "name": name}))?;
            ui::ok(&format!("removed {name}"));
        }
        DestCmd::List { target } => {
            let t = target.map(Some).unwrap_or_else(|| {
                find_link().and_then(|(_, l)| l.channel.map(|c| format!("{}/{}", l.project, c)))
            });
            ls(t.as_deref())?;
        }
        DestCmd::Kinds => {
            for k in crate::rail::KINDS {
                println!("{}  {}", ui::bold(k.kind), k.summary);
                for (key, help) in k.config {
                    println!("    --set {key}=…   {help}");
                }
                if k.needs_connection {
                    println!("    connection: `pit connect {}`", k.kind);
                }
            }
        }
    }
    Ok(())
}

fn dest_upsert(op: &str, a: DestArgs) -> Result<()> {
    let (p, c) = target_or_link(Some(&a.target))?;
    let mut config = BTreeMap::new();
    for kv in &a.sets {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| Error::Invalid(format!("--set takes key=value (got {kv})")))?;
        config.insert(k.to_string(), v.to_string());
    }
    let mut args = json!({"project": p, "channel": c, "name": a.name, "kind": a.kind, "config": config, "connection": a.connection, "description": a.description});
    if !a.select.is_empty() {
        args["select"] = json!(a.select);
    }
    let r = call(op, args)?;
    ui::ok(&format!(
        "{} → {}",
        r["name"].as_str().unwrap_or(""),
        r["address"].as_str().unwrap_or("")
    ));
    let one_way: Vec<&str> = r["one_way"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !one_way.is_empty() {
        ui::warn(&format!(
            "this destination selects one-way secrets it can never receive: {}. \
             Services need the real value — set them again as sealed to push them.",
            one_way.join(", ")
        ));
    }
    Ok(())
}

fn connect(a: ConnectArgs) -> Result<()> {
    if let Some(name) = a.verify {
        let r = call("conn.verify", json!({"name": name}))?;
        ui::ok(&format!("{name}: {}", r["account"].as_str().unwrap_or("")));
        return Ok(());
    }
    let kind = a
        .kind
        .ok_or_else(|| Error::Invalid("which service? vercel, github or fly".into()))?;
    let name = a.name.unwrap_or_else(|| kind.clone());
    let mut config = BTreeMap::new();
    if let Some(t) = &a.team {
        config.insert("team".to_string(), t.clone());
    }
    if a.use_cli {
        ui::note(&format!(
            "The Pit will borrow the {kind} CLI's sign-in at push time and store nothing."
        ));
        let r = call(
            "conn.add",
            json!({"name": name, "kind": kind, "mode": "cli", "config": config}),
        )?;
        ui::ok(&format!("{name} → {}", r["account"].as_str().unwrap_or("")));
        return Ok(());
    }
    ui::title(&format!("Delegate access to {kind}"));
    match kind.as_str() {
        "vercel" => {
            println!("1. Open https://vercel.com/account/tokens");
            println!("2. Create a token. Scope it to the team that owns your projects, and give it an expiry.");
            println!("3. Paste it below. It is checked with Vercel, then sealed in your vault.");
        }
        "github" => {
            println!("1. Open https://github.com/settings/personal-access-tokens/new (fine-grained token)");
            println!("2. Repository access: only the repositories The Pit pushes to.");
            println!("   Permissions: Secrets → Read and write; Environments → Read and write (to create them).");
            println!("3. Paste it below. Or run `pit connect github --use-cli` to use `gh`'s sign-in instead.");
        }
        "fly" => {
            println!("1. For one app:  fly tokens create deploy -a <app> --expiry 8760h");
            println!("   For an org:   fly tokens create org <org> --expiry 8760h");
            println!("2. Paste it below. Or run `pit connect fly --use-cli` to use flyctl's own sign-in.");
        }
        _ => return invalid("connections exist for vercel, github and fly"),
    }
    let token = prompt_hidden("Token: ")?;
    let r = call(
        "conn.add",
        json!({"name": name, "kind": kind, "mode": "token", "token": token.as_str(), "config": config}),
    )?;
    ui::ok(&format!(
        "{name} → {} (sealed)",
        r["account"].as_str().unwrap_or("")
    ));
    Ok(())
}

fn push(a: PushArgs) -> Result<i32> {
    let (p, c) = target_or_link(a.target.as_deref())?;
    let args = json!({"project": p, "channel": c, "destinations": a.destinations, "dry_run": a.dry_run, "force": a.force});
    if !a.dry_run && !a.yes && tty() {
        let preview = call(
            "push",
            json!({"project": p, "channel": c, "destinations": a.destinations, "dry_run": true}),
        )?;
        print_push(&preview, true);
        if !confirm(&format!("Push {p}/{c}?"))? {
            return Ok(1);
        }
    }
    let r = call("push", args)?;
    print_push(&r, a.dry_run);
    let failed = r["results"]
        .as_array()
        .map(|a| a.iter().any(|x| x["ok"] != json!(true)))
        .unwrap_or(false);
    Ok(if failed { 1 } else { 0 })
}

fn print_push(r: &Value, dry: bool) {
    for res in r["results"].as_array().cloned().unwrap_or_default() {
        let v = &res["result"];
        if res["ok"] == json!(true) {
            let sent = v["sent"].as_array().map(|a| a.len()).unwrap_or(0);
            let head = format!(
                "{} → {}  {} key(s){}",
                v["destination"].as_str().unwrap_or(""),
                v["address"].as_str().unwrap_or(""),
                sent,
                if dry { " (dry run)" } else { "" }
            );
            if dry {
                ui::note(&head)
            } else {
                ui::ok(&head)
            }
            if dry {
                let names: Vec<&str> = v["sent"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                println!("      {}", ui::dim(&names.join(" ")));
            }
            for sk in v["skipped"].as_array().cloned().unwrap_or_default() {
                let why = sk["why"].as_str().unwrap_or("");
                let line = format!(
                    "      skipped {} ({why})",
                    sk["name"].as_str().unwrap_or("")
                );
                if why.contains("one-way") {
                    ui::warn(&format!(
                        "{} NOT sent: it is stored one-way, so there is no value to give the service. \
                         Set it again as sealed (`pit set … -p sealed`) to push it.",
                        sk["name"].as_str().unwrap_or("")
                    ));
                } else {
                    println!("{line}");
                }
            }
            for n in v["notes"].as_array().cloned().unwrap_or_default() {
                if !dry {
                    println!("      {}", ui::dim(n.as_str().unwrap_or("")));
                }
            }
        } else {
            ui::warn(&format!(
                "{}: {}",
                v["destination"].as_str().unwrap_or(""),
                v["error"].as_str().unwrap_or("")
            ));
        }
    }
}

fn diff(target: Option<&str>) -> Result<()> {
    let (p, c) = target_or_link(target)?;
    let r = call("remote", json!({"project": p, "channel": c}))?;
    for d in r["destinations"].as_array().cloned().unwrap_or_default() {
        println!(
            "{} → {}",
            ui::bold(d["destination"].as_str().unwrap_or("")),
            d["address"].as_str().unwrap_or("")
        );
        if let Some(e) = d["error"].as_str() {
            ui::warn(e);
            continue;
        }
        if let Some(n) = d["note"].as_str() {
            println!("    {}", ui::dim(n));
            continue;
        }
        println!("    in both: {}", d["in_both"]);
        for n in d["missing_there"].as_array().cloned().unwrap_or_default() {
            println!("    not pushed yet: {}", n.as_str().unwrap_or(""));
        }
        for n in d["only_there"].as_array().cloned().unwrap_or_default() {
            println!("    only there:     {}", n.as_str().unwrap_or(""));
        }
    }
    Ok(())
}

fn run_with_env(a: RunArgs) -> Result<i32> {
    let (p, c) = target_or_link(a.target.as_deref())?;
    let r = call(
        "run.env",
        json!({"project": p, "channel": c, "select": a.only, "destination": a.dest}),
    )?;
    let (prog, rest) = a
        .command
        .split_first()
        .ok_or_else(|| Error::Invalid("nothing to run".into()))?;
    let mut cmd = std::process::Command::new(prog);
    cmd.args(rest);
    if let Some(env) = r["env"].as_object() {
        for (k, v) in env {
            cmd.env(k, v.as_str().unwrap_or(""));
        }
    }
    let files = r["files"].as_array().cloned().unwrap_or_default();
    let tmp = if files.is_empty() {
        None
    } else {
        let dir = std::env::temp_dir().join(format!("pit-run-{}", &crypto::random_id()[..12]));
        paths::private_dir(&dir)?;
        for f in &files {
            let name = f["name"].as_str().unwrap_or("file");
            let fname = f["filename"]
                .as_str()
                .unwrap_or(name)
                .rsplit('/')
                .next()
                .unwrap_or(name)
                .to_string();
            let path = dir.join(&fname);
            paths::write_private(
                &path,
                &Zeroizing::new(crypto::b64d(f["b64"].as_str().unwrap_or(""))?),
            )?;
            let var: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_uppercase()
                    } else {
                        '_'
                    }
                })
                .collect();
            cmd.env(format!("PIT_FILE_{var}"), &path);
        }
        cmd.env("PIT_FILES_DIR", &dir);
        Some(dir)
    };
    cmd.env("PIT_PROJECT", &p).env("PIT_CHANNEL", &c);
    // Ctrl-C and hang-ups go to the program; `pit` stays alive to clean up after
    // it. A handler (not SIG_IGN) is used so the program still gets the default.
    extern "C" fn wait_for_child(_: libc::c_int) {}
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        unsafe {
            libc::signal(sig, wait_for_child as *const () as libc::sighandler_t);
        }
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Invalid(format!("could not run {prog}: {e}")));
    if let Some(dir) = tmp {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                if let Ok(md) = e.metadata() {
                    let _ = paths::write_private(&e.path(), &vec![0u8; md.len() as usize]);
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(status?.code().unwrap_or(1))
}

fn log(a: LogArgs) -> Result<()> {
    let r = call(
        "log",
        json!({"limit": a.limit, "project": a.project, "event": a.event}),
    )?;
    if a.json {
        ui::print_json(&r);
        return Ok(());
    }
    for e in r["events"].as_array().cloned().unwrap_or_default() {
        let d = &e["data"];
        let summary = match e["event"].as_str().unwrap_or("") {
            "push" => format!(
                "{}/{} {} → {} via {} · {} key(s){}{}",
                d["project"].as_str().unwrap_or(""),
                d["channel"].as_str().unwrap_or(""),
                d["destination"].as_str().unwrap_or(""),
                d["address"].as_str().unwrap_or(""),
                d["via"].as_str().unwrap_or("-"),
                d["keys"].as_array().map(|k| k.len()).unwrap_or(0),
                if d["dry_run"] == json!(true) {
                    " (dry run)"
                } else {
                    ""
                },
                if d["result"] == json!("error") {
                    format!(" FAILED: {}", d["error"].as_str().unwrap_or(""))
                } else {
                    String::new()
                }
            ),
            _ => d.to_string(),
        };
        println!(
            "{:>5}  {}  {:<16} {}  {}",
            e["seq"],
            e["time"].as_str().unwrap_or(""),
            e["event"].as_str().unwrap_or(""),
            summary,
            ui::dim(e["actor"].as_str().unwrap_or(""))
        );
    }
    if r["intact"] == json!(true) {
        ui::ok(&format!(
            "log intact — {} entries, every link verified",
            r["total"]
        ));
    } else {
        ui::warn(&format!(
            "THE LOG HAS BEEN ALTERED at entry {}",
            r["broken_at"]
        ));
    }
    Ok(())
}

fn backup_cmd(b: BackupCmd) -> Result<()> {
    match b {
        BackupCmd::Now { to, quiet } => report_sync(backup::sync(true, &to)?, quiet)?,
        BackupCmd::Sync { quiet } => report_sync(backup::sync(false, &[])?, quiet)?,
        BackupCmd::Status => backup_status()?,
        BackupCmd::Target(t) => {
            let mut c = backup::Config::load()?;
            crate::model::valid_slug("target", &t.name)?;
            if t.name == "local" || c.targets.iter().any(|x| x.name == t.name) {
                return Err(Error::Exists(format!("target {}", t.name)));
            }
            let target = backup::Target {
                name: t.name.clone(),
                kind: t.kind.clone(),
                path: t.path,
                dest: t.dest,
                remote: t.remote,
                bucket: t.bucket,
                region: t.region,
                endpoint: t.endpoint,
                prefix: t.prefix,
            };
            match t.kind.as_str() {
                "dir" if target.path.is_none() => return invalid("--path is required"),
                "ssh" if target.dest.is_none() => {
                    return invalid("--dest user@host:path is required")
                }
                "rclone" if target.remote.is_none() => {
                    return invalid("--remote name:path is required")
                }
                "s3" => {
                    if target.bucket.is_none() {
                        return invalid("--bucket is required");
                    }
                    println!("Use keys that can only write to this bucket (no read, no delete): a leaked key then cannot read your backups. To restore later, add the target again with read keys.");
                    let ak = prompt_hidden("Access key id: ")?;
                    let sk = prompt_hidden("Secret access key: ")?;
                    crate::keychain::set(
                        &backup::s3_account(&t.name),
                        format!("{}\n{}", ak.as_str(), sk.as_str()).as_bytes(),
                    )?;
                }
                "dir" | "ssh" | "rclone" => {}
                k => return invalid(format!("unknown kind {k} (dir, ssh, s3, rclone)")),
            }
            c.targets.push(target);
            c.save()?;
            ui::ok(&format!("added {}", t.name));
            match backup::sync(false, std::slice::from_ref(&t.name)) {
                Ok(r) => report_sync(r, false)?,
                Err(e) => ui::warn(&format!("first backup to {} failed: {e}", t.name)),
            }
        }
        BackupCmd::Untarget { name } => {
            let mut c = backup::Config::load()?;
            c.targets.retain(|t| t.name != name);
            c.save()?;
            let _ = crate::keychain::delete(&backup::s3_account(&name));
            ui::ok(&format!(
                "removed {name} (the backups already there are left in place)"
            ));
        }
        BackupCmd::Auto { state } => {
            let on = match state.as_str() {
                "on" => true,
                "off" => false,
                _ => return invalid("use: pit backup auto on|off"),
            };
            let mut c = backup::Config::load()?;
            c.auto = on;
            c.save()?;
            service::backup_catchup(on)?;
            if on {
                ui::ok("every change is backed up within seconds; anything that cannot be sent is retried until it is");
            } else {
                ui::warn("automatic backups are off — run `pit backup now` yourself");
            }
        }
        BackupCmd::List { from } => backup_list(from.as_deref())?,
        BackupCmd::Diff {
            a,
            b,
            from,
            password,
        } => backup_diff(&a, b.as_deref(), from.as_deref(), password)?,
        BackupCmd::Bundle {
            projects,
            out,
            passphrase,
            to_identity,
            with_connections,
        } => {
            let pass = if passphrase {
                Some(new_bundle_passphrase()?)
            } else {
                None
            };
            let r = call(
                "bundle.export",
                json!({"projects": projects, "passphrase": pass.as_deref().map(|p| p.as_str()), "recipient": to_identity, "connections": with_connections}),
            )?;
            paths::write_private(&out, &crypto::b64d(r["bundle_b64"].as_str().unwrap_or(""))?)?;
            ui::ok(&format!("bundle written to {} (encrypted)", out.display()));
        }
        BackupCmd::Import {
            file,
            passphrase,
            replace,
            with_destinations,
        } => {
            let data = std::fs::read(&file)?;
            let pass = if passphrase {
                Some(prompt_hidden("Bundle passphrase: ")?)
            } else {
                None
            };
            let r = call(
                "bundle.import",
                json!({"bundle_b64": crypto::b64e(&data), "passphrase": pass.as_deref().map(|p| p.as_str()), "replace": replace, "with_destinations": with_destinations}),
            )?;
            ui::print_json(&r);
        }
        BackupCmd::Restore { what, from } => {
            if !tty() {
                return invalid("restoring replaces the vault, so it needs a person at a terminal");
            }
            let targets = backup_targets(from.as_deref())?;
            let (label, data) = backup::load_ref(&what, &targets)?;
            let snap = backup::inspect_snapshot(&data)?;
            println!(
                "{label}\n  vault {} · taken {} · generation {}",
                &snap.vault_id[..8],
                crate::model::fmt_time(snap.created),
                snap.generation
            );
            // Show what restoring would change, when the pit is open to compare.
            if protocol::agent_running() {
                match protocol::call(
                    "cli",
                    "backup.diff",
                    json!({"a_b64": crypto::b64e(&data)}),
                    None,
                ) {
                    Ok(r) => {
                        let changes = r["changes"].as_array().cloned().unwrap_or_default();
                        if changes.is_empty() {
                            ui::note("it holds the same secrets and settings as the vault now");
                        } else {
                            ui::note("going back to it would undo these changes made since:");
                            print_changes(&changes, true);
                        }
                    }
                    Err(Error::Locked) => {
                        ui::note("unlock first to see what would change (`pit backup diff`)")
                    }
                    Err(_) => {}
                }
            }
            if !confirm("Replace the current vault with it? (the current one is saved first)")? {
                return Ok(());
            }
            if protocol::agent_running() {
                let _ = protocol::call("cli", "shutdown", json!({}), None);
            }
            let saved = backup::restore_snapshot(&data)?;
            if let Some(p) = saved {
                ui::note(&format!("the previous vault was saved to {}", p.display()));
            }
            ui::ok("restored — unlock it with the password (or recovery code) that was current when it was taken");
        }
        BackupCmd::Inspect { file } => {
            let data = std::fs::read(&file)?;
            if let Ok(s) = backup::inspect_snapshot(&data) {
                println!(
                    "snapshot · vault {} · {} · files: {}",
                    &s.vault_id[..8],
                    crate::model::fmt_time(s.created),
                    s.files.keys().cloned().collect::<Vec<_>>().join(", ")
                );
                ui::ok("checksums verified");
            } else if let Ok(v) = serde_json::from_slice::<Value>(&data) {
                println!(
                    "{} · created {} · contents: {}",
                    v["format"].as_str().unwrap_or("?"),
                    crate::model::fmt_time(v["created"].as_i64().unwrap_or(0)),
                    v["contents"]
                );
                let kinds: Vec<&str> = v["slots"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|s| s["kind"].as_str()).collect())
                    .unwrap_or_default();
                println!("opens with: {}", kinds.join(", "));
            } else {
                return invalid("not a snapshot or bundle");
            }
        }
    }
    Ok(())
}

fn report_sync(results: Vec<backup::Outcome>, quiet: bool) -> Result<()> {
    let mut failed = vec![];
    for r in &results {
        if !r.ok {
            failed.push(r.target.clone());
            ui::warn(&format!("{}: {} — will retry", r.target, r.detail));
        } else if !quiet {
            if r.sent {
                ui::ok(&format!("{}: {}", r.target, r.detail));
            } else {
                ui::note(&format!("{}: already up to date", r.target));
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Error::Remote(format!(
            "not backed up yet: {}",
            failed.join(", ")
        )))
    }
}

fn backup_status() -> Result<()> {
    let c = backup::Config::load()?;
    let st = backup::sync_state();
    let current = backup::content_id().ok();
    for t in c.all_targets() {
        let s = st.targets.get(&t.name).cloned().unwrap_or_default();
        let state = if current.as_deref() == Some(s.sent.as_str()) {
            format!("✓ up to date (sent {})", crate::model::fmt_time(s.sent_at))
        } else if s.sent_at > 0 {
            format!("… behind (last sent {})", crate::model::fmt_time(s.sent_at))
        } else {
            "… nothing sent yet".to_string()
        };
        println!("  {:<12} {:<7} {}", t.name, t.kind, backup::describe(&t));
        println!("               {state}");
        if let Some(e) = &s.error {
            if current.as_deref() != Some(s.sent.as_str()) {
                println!(
                    "               ✗ {e} ({} failed attempt(s), last {})",
                    s.failures,
                    crate::model::fmt_time(s.failed_at)
                );
            }
        }
    }
    println!(
        "\nafter every change: {} · catch-up check every 15 min{}",
        if c.auto {
            "on"
        } else {
            "OFF (`pit backup auto on`)"
        },
        if service::catchup_installed() {
            ""
        } else {
            " (not installed — `pit backup auto on`)"
        }
    );
    Ok(())
}

/// Configured targets, or the single one named/written in --from.
fn backup_targets(from: Option<&str>) -> Result<Vec<backup::Target>> {
    let c = backup::Config::load()?;
    match from {
        None => Ok(c.all_targets()),
        Some(f) => c
            .target(f)
            .or_else(|| backup::adhoc_target(f))
            .map(|t| vec![t])
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "{f} is not a target here; write it out as dir:PATH, ssh:USER@HOST:PATH or rclone:REMOTE:PATH"
                ))
            }),
    }
}

fn backup_list(from: Option<&str>) -> Result<()> {
    let targets = backup_targets(from)?;
    let (by_name, errors) = backup::catalog(&targets);
    for (t, e) in &errors {
        ui::warn(&format!("{t}: {e}"));
    }
    let order = backup::newest_first(&by_name);
    if order.is_empty() {
        ui::note("no backups found");
        return Ok(());
    }
    let reachable: Vec<&backup::Target> = targets
        .iter()
        .filter(|t| !errors.iter().any(|(n, _)| n == &t.name))
        .collect();
    print!("  {:>3}  {:<19} {:>6}", "#", "taken", "gen");
    for t in &reachable {
        print!("  {:<8}", t.name.chars().take(8).collect::<String>());
    }
    println!();
    for (i, n) in order.iter().enumerate() {
        let (when, generation) = backup::parse_name(n).unwrap_or((0, None));
        print!(
            "  {:>3}  {:<19} {:>6}",
            i + 1,
            crate::model::fmt_time(when),
            generation
                .map(|g| g.to_string())
                .unwrap_or_else(|| "?".into())
        );
        let holders = &by_name[n];
        for t in &reachable {
            print!(
                "  {:<8}",
                if holders.contains(&t.name) {
                    "✓"
                } else {
                    "·"
                }
            );
        }
        println!();
    }
    ui::note("compare with `pit backup diff N [M]`, restore with `pit backup restore N`");
    Ok(())
}

fn print_changes(changes: &[Value], reverse: bool) {
    for c in changes {
        let mut sign = c["change"].as_str().unwrap_or("?").to_string();
        if reverse {
            sign = match sign.as_str() {
                "+" => "-".into(),
                "-" => "+".into(),
                s => s.into(),
            };
        }
        let line = format!(
            "  {sign} {:<13} {}{}",
            c["what"].as_str().unwrap_or(""),
            c["name"].as_str().unwrap_or(""),
            match c["detail"].as_str() {
                Some(d) if !d.is_empty() => format!("  ({d})"),
                _ => String::new(),
            }
        );
        match sign.as_str() {
            "+" => ui::ok(line.trim_start()),
            "-" => ui::error(line.trim_start()),
            _ => ui::note(line.trim_start()),
        }
    }
}

fn backup_diff(a: &str, b: Option<&str>, from: Option<&str>, password: bool) -> Result<()> {
    let targets = backup_targets(from)?;
    let (la, da) = backup::load_ref(a, &targets)?;
    let mut args = json!({"a_b64": crypto::b64e(&da)});
    let lb = match b {
        Some(b) => {
            let (lb, db) = backup::load_ref(b, &targets)?;
            args["b_b64"] = json!(crypto::b64e(&db));
            lb
        }
        None => "the vault now".to_string(),
    };
    let pw;
    if password {
        pw = prompt_hidden("Password the backup was made with: ")?;
        args["password"] = json!(pw.as_str());
    }
    let r = call("backup.diff", args)?;
    println!(
        "{la} ({}, generation {})\n  → {lb} ({}, generation {})",
        r["a"]["taken"].as_str().unwrap_or(""),
        r["a"]["generation"],
        r["b"]["taken"].as_str().unwrap_or(""),
        r["b"]["generation"]
    );
    let changes = r["changes"].as_array().cloned().unwrap_or_default();
    if changes.is_empty() {
        ui::ok("no differences in secrets, destinations, connections or settings");
    } else {
        print_changes(&changes, false);
    }
    Ok(())
}

fn new_bundle_passphrase() -> Result<Zeroizing<String>> {
    loop {
        let a = prompt_hidden("Bundle passphrase: ")?;
        if let Err(e) = password_policy(&a, "") {
            ui::warn(&e.to_string());
            continue;
        }
        let b = prompt_hidden("Repeat it: ")?;
        if crypto::ct_eq(a.as_bytes(), b.as_bytes()) {
            return Ok(a);
        }
        ui::warn("they do not match");
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedFile {
    format: String,
    name: String,
    kdf: crypto::KdfParams,
    sealed: crypto::Sealed,
}

fn seal_file(file: &Path, out: Option<PathBuf>, remove: bool) -> Result<()> {
    let data = Zeroizing::new(std::fs::read(file)?);
    let pw = new_bundle_passphrase()?;
    let kdf = crypto::KdfParams::new_password();
    let key = kdf.derive(pw.as_bytes())?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let sealed = crypto::seal(
        &key,
        &data,
        format!("the-pit-sealed-file/1|{name}").as_bytes(),
    );
    let out = out.unwrap_or_else(|| PathBuf::from(format!("{}.pitsealed", file.display())));
    paths::write_private(
        &out,
        &serde_json::to_vec(&SealedFile {
            format: "the-pit-sealed-file/1".into(),
            name,
            kdf,
            sealed,
        })?,
    )?;
    ui::ok(&format!("sealed → {}", out.display()));
    if remove {
        let len = data.len();
        paths::write_private(file, &crypto::random_bytes(len))?;
        std::fs::remove_file(file)?;
        ui::ok(&format!("removed {}", file.display()));
    }
    Ok(())
}

fn unseal_file(file: &Path, out: Option<PathBuf>) -> Result<()> {
    let sf: SealedFile = serde_json::from_slice(&std::fs::read(file)?)
        .map_err(|_| Error::Invalid("not a sealed file".into()))?;
    let pw = prompt_hidden("Passphrase: ")?;
    let key = sf.kdf.derive(pw.as_bytes())?;
    let data = crypto::open(
        &key,
        &sf.sealed,
        format!("{}|{}", sf.format, sf.name).as_bytes(),
    )?;
    let out = out.unwrap_or_else(|| file.with_file_name(&sf.name));
    if out.exists() {
        return Err(Error::Exists(out.display().to_string()));
    }
    paths::write_private(&out, &data)?;
    ui::ok(&format!("unsealed → {} (0600)", out.display()));
    Ok(())
}

fn show_recovery(r: &Value) -> Result<()> {
    if let Some(code) = r["recovery_code"].as_str() {
        ui::title("New recovery code (the old one no longer works)");
        println!("{code}\n");
    } else if let Some(shares) = r["shares"].as_array() {
        ui::title(&format!(
            "Recovery shares — any {} of these open the vault (the old code no longer works)",
            r["threshold"]
        ));
        for (i, s) in shares.iter().enumerate() {
            println!("  share {}: {}", i + 1, s.as_str().unwrap_or(""));
        }
        println!("\nKeep each share in a different place: paper in a safe, a password manager, a trusted person.");
        println!("Fewer than the threshold reveal nothing at all.\n");
    }
    if tty() {
        prompt_line("Press Enter once it is written down. The screen will be cleared.")?;
        print!("\x1b[2J\x1b[H");
    }
    Ok(())
}

fn mfa(m: MfaCmd) -> Result<()> {
    match m {
        MfaCmd::Touchid { state } => {
            let on = on_off(&state)?;
            call("mfa.touchid", json!({"enable": on}))?;
            ui::ok(if on {
                "Touch ID is required after your password"
            } else {
                "Touch ID is no longer required"
            });
        }
        MfaCmd::Totp => {
            let r = call("mfa.totp.begin", json!({}))?;
            let uri = r["uri"].as_str().unwrap_or("");
            ui::title("Add The Pit to your authenticator app");
            if let Ok(q) = qrcode::QrCode::new(uri.as_bytes()) {
                let s = q
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build();
                println!("{s}");
            }
            println!(
                "Or enter this key by hand: {}\n",
                r["secret"].as_str().unwrap_or("")
            );
            loop {
                let code = prompt_line("Code shown in the app: ")?;
                match call(
                    "mfa.totp.confirm",
                    json!({"secret": r["secret"], "code": code}),
                ) {
                    Ok(_) => break,
                    Err(Error::Denied) => {
                        ui::warn("that code did not match — wait for the next one and try again")
                    }
                    Err(e) => return Err(e),
                }
            }
            print!("\x1b[2J\x1b[H");
            ui::ok("authenticator enrolled — it works as a second factor and for approvals");
        }
        MfaCmd::TotpOff => {
            call("mfa.totp.disable", json!({}))?;
            ui::ok("authenticator removed");
        }
    }
    Ok(())
}

fn emergency(e: EmergencyCmd) -> Result<()> {
    match e {
        EmergencyCmd::Export { out, plaintext } => {
            ui::title("Emergency export");
            println!("This takes every secret out of The Pit.");
            let pass = if plaintext {
                println!(
                    "PLAINTEXT was requested: the result is readable by anyone who can read {}.",
                    out.display()
                );
                if !confirm("Continue?")? {
                    return Ok(());
                }
                None
            } else {
                println!("The export will be encrypted with a passphrase you choose now; any new vault can import it.");
                Some(new_bundle_passphrase()?)
            };
            let r = call(
                "emergency.export",
                json!({"passphrase": pass.as_deref().map(|p| p.as_str())}),
            )?;
            let data = Zeroizing::new(crypto::b64d(r["export_b64"].as_str().unwrap_or(""))?);
            if plaintext {
                write_plain_tree(&out, &data)?;
                ui::ok(&format!(
                    "every secret written to {} (folders 0700, files 0600)",
                    out.display()
                ));
                ui::warn("destroy that folder as soon as you are done with it");
            } else {
                paths::write_private(&out, &data)?;
                ui::ok(&format!("encrypted export written to {}", out.display()));
                println!(
                    "Bring it into a fresh vault with: pit backup import {} --passphrase",
                    out.display()
                );
            }
        }
        EmergencyCmd::Destroy => {
            ui::title("Destroy the vault");
            println!("This crypto-shreds every key slot and deletes the vault, its history, the log and the");
            println!(
                "keychain items under {}. Nobody — including you — can open it afterwards.",
                paths::home().display()
            );
            println!("Backups you sent elsewhere are not touched; delete those yourself.");
            if !tty() {
                return invalid("destroy needs a terminal");
            }
            let id = crate::vault::Header::load()
                .map(|h| h.vault_id[..8].to_string())
                .unwrap_or_default();
            let typed = prompt_line(&format!("Type DESTROY {id} to continue: "))?;
            if typed != format!("DESTROY {id}") {
                ui::note("nothing was destroyed");
                return Ok(());
            }
            if protocol::agent_running() {
                let _ = protocol::call("cli", "shutdown", json!({}), None);
            }
            crate::vault::destroy()?;
            ui::ok("the vault is gone");
        }
    }
    Ok(())
}

fn write_plain_tree(out: &Path, data: &[u8]) -> Result<()> {
    let v: Value = serde_json::from_slice(data)?;
    let payload: backup::Payload = serde_json::from_value(v["payload"].clone())?;
    paths::private_dir(out)?;
    let render = |dir: &Path, secrets: &BTreeMap<String, crate::model::Secret>| -> Result<()> {
        paths::private_dir(dir)?;
        let mut env = Zeroizing::new(String::new());
        let mut notes = String::new();
        for (name, s) in secrets {
            let bytes: Option<&[u8]> = match s.value.as_ref().map(|v| &v.data) {
                Some(crate::model::StoredData::Plain { bytes }) => Some(bytes),
                Some(crate::model::StoredData::Hashed { .. }) => {
                    notes.push_str(&format!("{name}: one-way — cannot be exported\n"));
                    None
                }
                _ => None,
            };
            if !s.description.is_empty() {
                notes.push_str(&format!("{name}: {}\n", s.description));
            }
            match (&s.kind, bytes) {
                (crate::model::Kind::File { filename }, Some(b)) => {
                    let p = dir.join("files").join(filename);
                    if let Some(parent) = p.parent() {
                        paths::private_dir(parent)?;
                    }
                    paths::write_private(&p, b)?;
                }
                (_, Some(b)) => env.push_str(&format!("{}={}\n", name, String::from_utf8_lossy(b))),
                (_, None) => env.push_str(&format!("{name}=\n")),
            }
        }
        paths::write_private(&dir.join("secrets.env"), env.as_bytes())?;
        if !notes.is_empty() {
            paths::write_private(&dir.join("descriptions.txt"), notes.as_bytes())?;
        }
        Ok(())
    };
    render(&out.join("_global"), &payload.globals)?;
    for (pn, p) in &payload.projects {
        render(&out.join(pn).join("_project"), &p.secrets)?;
        for (cn, c) in &p.channels {
            render(&out.join(pn).join(cn), &c.secrets)?;
        }
    }
    let mut conns = Zeroizing::new(String::new());
    for (n, c) in &payload.connections {
        if let Some(crate::model::StoredData::Plain { bytes }) = c.token.as_ref().map(|t| &t.data) {
            conns.push_str(&format!(
                "{n} ({}, {})={}\n",
                c.kind,
                c.account,
                String::from_utf8_lossy(bytes)
            ));
        }
    }
    if !conns.is_empty() {
        paths::write_private(&out.join("connections.txt"), conns.as_bytes())?;
    }
    Ok(())
}

/// Where imported values go: `--to`, else the folder's .pit.toml, else ask.
fn import_scope(to: Option<String>) -> Result<String> {
    if let Some(t) = to {
        Scope::parse(&t)?;
        return Ok(t);
    }
    if let Some((_, l)) = find_link() {
        return Ok(match l.channel {
            Some(c) => format!("{}/{c}", l.project),
            None => l.project,
        });
    }
    if !tty() {
        return invalid("give --to PROJECT/CHANNEL (or run `pit link` in this folder)");
    }
    let t = prompt_line("Import into which PROJECT/CHANNEL (or PROJECT, or global)? ")?;
    Scope::parse(&t)?;
    Ok(t)
}

/// Offer to create a missing project or channel before importing into it.
fn ensure_scope(scope: &str) -> Result<()> {
    let sc = Scope::parse(scope)?;
    let tree = call("tree", json!({}))?;
    let projects = tree["projects"].as_array().cloned().unwrap_or_default();
    let (p, c) = match &sc {
        Scope::Global => return Ok(()),
        Scope::Project(p) => (p.clone(), None),
        Scope::Channel(p, c) => (p.clone(), Some(c.clone())),
    };
    let project = projects.iter().find(|x| x["name"] == json!(p));
    if project.is_none() {
        if !confirm(&format!("project {p} does not exist — create it?"))? {
            return invalid(format!("no project {p}"));
        }
        call("project.add", json!({"name": p}))?;
        ui::ok(&format!("created project {p}"));
    }
    if let Some(c) = c {
        let has = project
            .and_then(|x| x["channels"].as_array())
            .map(|a| a.iter().any(|ch| ch["name"] == json!(c)))
            .unwrap_or(false);
        if !has {
            if !confirm(&format!("channel {p}/{c} does not exist — create it?"))? {
                return invalid(format!("no channel {p}/{c}"));
            }
            call("channel.add", json!({"project": p, "name": c}))?;
            ui::ok(&format!("created channel {p}/{c}"));
        }
    }
    Ok(())
}

fn names_of(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Send values to the agent in one batch: a dry run first to show what would
/// change, then (after confirmation where values differ) the real thing.
fn import_items(
    scope: &str,
    items: Vec<Value>,
    protection: Option<&str>,
    overwrite: bool,
    dry_run: bool,
    source: &str,
) -> Result<()> {
    if items.is_empty() {
        ui::note("nothing to import");
        return Ok(());
    }
    ensure_scope(scope)?;
    let mut args = json!({"scope": scope, "items": items, "protection": protection, "dry_run": true, "source": source});
    let plan = call("secret.import", args.clone())?;
    let added = names_of(&plan["added"]);
    let differs = names_of(&plan["differs"]);
    let unchanged = names_of(&plan["unchanged"]);
    for r in plan["rejected"].as_array().cloned().unwrap_or_default() {
        ui::warn(&format!(
            "{}: {}",
            r["name"].as_str().unwrap_or(""),
            r["why"].as_str().unwrap_or("")
        ));
    }
    if !added.is_empty() {
        ui::note(&format!("new in {scope}: {}", added.join(" ")));
    }
    if !unchanged.is_empty() {
        ui::note(&format!(
            "already there, same value: {}",
            unchanged.join(" ")
        ));
    }
    if !differs.is_empty() {
        ui::warn(&format!(
            "already there with a DIFFERENT value: {}",
            differs.join(" ")
        ));
    }
    if dry_run {
        ui::note("dry run — nothing changed");
        return Ok(());
    }
    let replace = !differs.is_empty()
        && (overwrite
            || confirm(&format!(
                "Replace those {} value(s)? (the old values stay in history)",
                differs.len()
            ))?);
    if added.is_empty() && !replace {
        ui::ok("nothing to change");
        return Ok(());
    }
    args["dry_run"] = json!(false);
    args["overwrite"] = json!(replace);
    let r = call("secret.import", args)?;
    let n = names_of(&r["added"]).len();
    let m = names_of(&r["replaced"]).len();
    ui::ok(&format!(
        "{n} added{} in {scope}",
        if m > 0 {
            format!(", {m} replaced")
        } else {
            String::new()
        }
    ));
    if !replace && !differs.is_empty() {
        ui::note(&format!("kept the pit's values for: {}", differs.join(" ")));
    }
    Ok(())
}

fn import_env(a: ImportEnvArgs) -> Result<()> {
    let scope = import_scope(a.to)?;
    let mut items: Vec<Value> = vec![];
    let mut seen = BTreeMap::new();
    let mut sources = vec![];
    for f in &a.files {
        let (path, text) = if f.as_os_str() == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            (PathBuf::from("stdin.env"), Zeroizing::new(s))
        } else {
            (f.clone(), Zeroizing::new(std::fs::read_to_string(f)?))
        };
        sources.push(f.display().to_string());
        for (k, v, desc) in crate::scan::read_source(&path, &text)? {
            if a.skip.contains(&k) {
                continue;
            }
            if v.is_empty() {
                ui::note(&format!(
                    "{k} has no value — skipped (declare it with `pit declare {scope} {k}`)"
                ));
                continue;
            }
            if let Some(prev) = seen.insert(k.clone(), f.display().to_string()) {
                ui::warn(&format!(
                    "{k} appears in {prev} and {} — the later one is used",
                    f.display()
                ));
                items.retain(|i| i["name"] != json!(k));
            }
            items.push(
                json!({"name": k, "value_b64": crypto::b64e(v.as_bytes()), "description": desc}),
            );
        }
    }
    if !a.tag.is_empty() {
        for i in items.iter_mut() {
            i["tags"] = json!(a.tag);
        }
    }
    import_items(
        &scope,
        items,
        a.protection.as_deref(),
        a.overwrite,
        a.dry_run,
        &sources.join(", "),
    )?;
    if !a.dry_run {
        ui::note("the file is unchanged — delete it once nothing reads it, or point the app at `pit run`");
    }
    Ok(())
}

/// Turn "1,3-5" / "all" into indexes (1-based in, 0-based out).
fn pick(input: &str, n: usize) -> Result<Vec<usize>> {
    let input = input.trim().to_ascii_lowercase();
    if input == "a" || input == "all" {
        return Ok((0..n).collect());
    }
    if input.is_empty() || input == "n" || input == "none" {
        return Ok(vec![]);
    }
    let mut out = std::collections::BTreeSet::new();
    for part in input.split([',', ' ']).filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (a, b): (usize, usize) = (
            a.trim()
                .parse()
                .map_err(|_| Error::Invalid(format!("not a number: {part}")))?,
            b.trim()
                .parse()
                .map_err(|_| Error::Invalid(format!("not a number: {part}")))?,
        );
        if a == 0 || b > n || a > b {
            return invalid(format!("{part} is out of range 1–{n}"));
        }
        out.extend(a - 1..b);
    }
    Ok(out.into_iter().collect())
}

fn scan(a: ScanArgs) -> Result<()> {
    use crate::scan::Confidence;
    let dir = a.dir.unwrap_or_else(|| PathBuf::from("."));
    let mut found = crate::scan::scan(&dir)?;
    let hidden = found
        .iter()
        .filter(|f| f.confidence == Confidence::Low)
        .count();
    if !a.all {
        found.retain(|f| f.confidence > Confidence::Low);
    }
    if a.json {
        ui::print_json(&json!({
            "folder": dir.display().to_string(),
            "findings": found.iter().map(|f| json!({
                "name": f.name, "what": f.what, "places": f.places, "length": f.value.len(),
                "committed_to_git": f.committed, "file": f.filename.is_some(),
                "confidence": format!("{:?}", f.confidence).to_lowercase(),
            })).collect::<Vec<_>>(),
            "settings_not_shown": if a.all { 0 } else { hidden },
        }));
        return Ok(());
    }
    if found.is_empty() {
        ui::ok(&format!(
            "nothing that looks like a secret in {}",
            dir.display()
        ));
        if hidden > 0 {
            ui::note(&format!(
                "{hidden} ordinary setting(s) not shown — `--all` to include them"
            ));
        }
        return Ok(());
    }
    ui::title(&format!(
        "Found in {} (values are not shown)",
        dir.display()
    ));
    for (i, f) in found.iter().enumerate() {
        let level = match f.confidence {
            Confidence::High => "",
            Confidence::Medium => " (maybe)",
            Confidence::Low => " (setting)",
        };
        let mut places = f.places.clone();
        if places.len() > 3 {
            let more = places.len() - 3;
            places.truncate(3);
            places.push(format!("+{more} more"));
        }
        println!(
            "{:>3}  {:<32} {}{}",
            i + 1,
            f.name,
            ui::dim(&format!("{}, {} chars", f.what, f.value.len())),
            level
        );
        println!("       {}", ui::dim(&places.join(", ")));
        if f.committed {
            println!("       ! committed to git — after moving it into the pit, rotate it at the service");
        }
    }
    if hidden > 0 && !a.all {
        ui::note(&format!(
            "{hidden} ordinary setting(s) not shown — `--all` to include them"
        ));
    }
    if a.report || !tty() {
        ui::note(
            "nothing changed. Run `pit scan` in a terminal to choose what to copy into the pit.",
        );
        return Ok(());
    }
    let chosen = pick(
        &prompt_line("\nCopy which into the pit? [all / none / numbers like 1,3-5] ")?,
        found.len(),
    )?;
    if chosen.is_empty() {
        ui::note("nothing changed");
        return Ok(());
    }
    let mut picked: Vec<crate::scan::Found> = vec![];
    for (i, f) in found.into_iter().enumerate() {
        if chosen.contains(&i) {
            picked.push(f);
        }
    }
    loop {
        let r = prompt_line("Rename any? (e.g. 2=STRIPE_KEY; Enter to keep the names) ")?;
        if r.is_empty() {
            break;
        }
        for pair in r.split([',', ' ']).filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some((n, new)) => match n.trim().parse::<usize>() {
                    Ok(i) if i >= 1 && i <= chosen.len() => {
                        picked[i - 1].name = new.trim().to_string();
                        ui::note(&format!("{i} → {}", new.trim()));
                    }
                    _ => ui::warn(&format!("{n} is not one of 1–{}", chosen.len())),
                },
                None => ui::warn(&format!("use NUMBER=NAME (got {pair})")),
            }
        }
    }
    let scope = import_scope(a.to)?;
    let items: Vec<Value> = picked
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "value_b64": crypto::b64e(&f.value),
                "description": f.description,
                "filename": f.filename,
            })
        })
        .collect();
    import_items(
        &scope,
        items,
        a.protection.as_deref(),
        false,
        false,
        &format!("scan of {}", dir.display()),
    )?;
    ui::note(&format!(
        "{} was not changed. To have it read from the pit: `pit run -- <command>`, or a dotenv destination (see docs/importing.md).",
        dir.display()
    ));
    if picked.iter().any(|f| f.committed) {
        ui::warn(
            "some of these were committed to git — the old values are in its history; rotate them",
        );
    }
    Ok(())
}

fn import_secret_pit(dir: &Path, map: Option<&Path>, dry: bool) -> Result<()> {
    let map_text = match map {
        Some(m) => std::fs::read_to_string(m)?,
        None => String::new(),
    };
    let dir = std::fs::canonicalize(dir)?;
    let r = call(
        "import.secretpit",
        json!({"dir": dir.display().to_string(), "map": map_text, "dry_run": dry}),
    )?;
    ui::title(if dry {
        "Import preview (nothing written)"
    } else {
        "Imported"
    });
    for c in r["channels"].as_array().cloned().unwrap_or_default() {
        if let Some(f) = c["file"].as_str() {
            println!("  {}  file {f}", c["scope"].as_str().unwrap_or(""));
            continue;
        }
        println!(
            "  {}  ← {}",
            ui::bold(c["scope"].as_str().unwrap_or("")),
            c["from"].as_str().unwrap_or("")
        );
        for e in c["env_files"].as_array().cloned().unwrap_or_default() {
            println!(
                "      {:<24} {} set, {} empty",
                e["file"].as_str().unwrap_or(""),
                e["set"],
                e["empty"]
            );
        }
        let files: Vec<&str> = c["files"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if !files.is_empty() {
            println!("      files: {}", files.join(", "));
        }
        for d in c["destinations"].as_array().cloned().unwrap_or_default() {
            println!("      → {}", d.as_str().unwrap_or(""));
        }
    }
    for n in r["renamed"].as_array().cloned().unwrap_or_default() {
        ui::note(&format!("renamed: {}", n.as_str().unwrap_or("")));
    }
    for n in r["skipped"].as_array().cloned().unwrap_or_default() {
        println!("  skipped old backup: {}", n.as_str().unwrap_or(""));
    }
    println!();
    ui::print_json(&r["summary"]);
    if dry {
        println!("\nRun again without --dry-run to import.");
    }
    Ok(())
}

fn doctor() -> Result<i32> {
    let mut bad = 0;
    let mut check = |ok: bool, good: &str, badmsg: &str| {
        if ok {
            ui::ok(good);
        } else {
            ui::warn(badmsg);
            bad += 1;
        }
    };
    let home = paths::home();
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(&home).ok();
    check(
        md.as_ref().map(|m| m.mode() & 0o077 == 0).unwrap_or(false),
        &format!("{} is private (0700)", home.display()),
        &format!("{} is missing or readable by others", home.display()),
    );
    check(
        crate::vault::exists(),
        "vault present",
        "no vault — run `pit init`",
    );
    check(
        paths::in_git_tree(&home).is_none(),
        "the pit is outside any git repository",
        "THE PIT IS INSIDE A GIT REPOSITORY",
    );
    check(
        protocol::agent_running(),
        "agent running",
        "agent not running — `pit service install` (or any pit command starts it)",
    );
    check(
        service::installed(),
        "agent runs as a login service",
        "agent is not a login service — `pit service install`",
    );
    if let Ok(h) = crate::vault::Header::load() {
        check(
            h.has("recovery"),
            "recovery code configured",
            "no recovery slot — `pit recovery rotate`",
        );
        check(h.has("password"), "password configured", "no password slot");
    }
    if let Ok(st) = protocol::call("cli", "status", json!({}), None) {
        if st["unlocked"] == json!(true) {
            check(
                st["mfa"]["touch_id"] == json!(true) || st["mfa"]["totp"] == json!(true),
                "a second factor is required",
                "no second factor — `pit mfa totp` or `pit mfa touchid on`",
            );
            check(st["mfa"]["totp"] == json!(true), "authenticator enrolled (works where Touch ID cannot)", "no authenticator — `pit mfa totp` gives a second factor that works without Touch ID");
        }
    }
    let cfg = backup::Config::load().unwrap_or_default();
    check(
        !cfg.targets.is_empty(),
        "off-machine backup target configured",
        "backups only go to this Mac — `pit backup target NAME --kind …`",
    );
    check(
        cfg.auto,
        "backups follow every change",
        "automatic backups are off — `pit backup auto on`",
    );
    let behind = backup::pending();
    check(
        behind.is_empty(),
        "every backup target holds the current vault",
        &format!(
            "not yet backed up to: {} — `pit backup status`",
            behind.join(", ")
        ),
    );
    let legacy = dirs::home_dir()
        .map(|h| h.join("secret-pit"))
        .filter(|p| p.exists());
    check(legacy.is_none(), "no plaintext ~/secret-pit left behind", "~/secret-pit still holds plaintext secrets — after importing, `pit seal` a copy and remove it");
    Ok(if bad == 0 { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::password_policy;

    #[test]
    fn password_policy_needs_offline_strength() {
        assert!(password_policy("password password", "x").is_err());
        assert!(password_policy("tester tester tester", "tester").is_err());
        assert!(password_policy("Password1234!", "x").is_err());
        assert!(password_policy("correct horse battery staple lantern", "x").is_ok());
    }
}
