//! The library: everything the vault holds, as one document. The document is
//! encrypted as a whole at rest; sealed values inside it are encrypted again,
//! individually, so they stay ciphertext in memory until a push or a reveal
//! actually needs them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{b64, KdfParams, Sealed};
use crate::error::{invalid, Result};

pub const LIBRARY_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Library {
    pub version: u32,
    pub owner: Owner,
    pub settings: Settings,
    #[serde(default)]
    pub globals: BTreeMap<String, Secret>,
    #[serde(default)]
    pub projects: BTreeMap<String, Project>,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
    #[serde(default)]
    pub mfa: Mfa,
    /// People this vault has shared secrets with, by identity key (`PIT-ID-…`).
    /// An identity is added once the owner has confirmed it belongs to that person.
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
    #[serde(default)]
    pub last_password_unlock: i64,
    /// The newest audit entry when the library was last saved.
    #[serde(default)]
    pub log_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Owner {
    pub name: String,
    /// X25519 identity. Used to receive bundles encrypted to this user.
    #[serde(with = "b64")]
    pub identity_public: Vec<u8>,
    #[serde(with = "b64")]
    pub identity_secret: Vec<u8>,
    pub created: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub added: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// How long an unlocked session stays open, at most.
    pub session_secs: u64,
    /// A session locks itself after this long without a request.
    pub idle_secs: u64,
    /// How long an approval keeps sensitive actions open after `pit elevate`.
    pub elevate_secs: u64,
    /// Touch ID alone may reopen the pit if the password was used within this many days.
    pub password_recheck_days: u64,
    /// Every push requested by an AI client (MCP) needs a human approval.
    pub ai_push_needs_approval: bool,
    /// Revealed values copied to the clipboard are cleared after this long.
    pub clipboard_secs: u64,
    /// `pit run` hands values to a program, so it asks for approval too (one
    /// Touch ID tap, or covered by `pit elevate`). Any process running as you
    /// can invoke `pit run`; this keeps an unlocked session from being enough.
    #[serde(default = "yes")]
    pub run_needs_approval: bool,
    /// After you approve a change, more changes to the same channel (or project)
    /// from the same terminal go ahead without asking for this long. 0 = ask every time.
    #[serde(default = "approval_window")]
    pub approval_window_secs: u64,
}

fn approval_window() -> u64 {
    5 * 60
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            session_secs: 8 * 3600,
            idle_secs: 30 * 60,
            elevate_secs: 5 * 60,
            password_recheck_days: 7,
            ai_push_needs_approval: true,
            clipboard_secs: 30,
            run_needs_approval: true,
            approval_window_secs: approval_window(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Mfa {
    /// Require a second factor after the password: Touch ID (or Apple Watch).
    #[serde(default)]
    pub touch_id: bool,
    /// RFC 6238 authenticator secret, if enrolled.
    #[serde(default, with = "opt_b64")]
    pub totp_secret: Option<Vec<u8>>,
    #[serde(default)]
    pub totp_last_step: u64,
}

impl Mfa {
    pub fn any(&self) -> bool {
        self.touch_id || self.totp_secret.is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub created: i64,
    #[serde(default)]
    pub secrets: BTreeMap<String, Secret>,
    #[serde(default)]
    pub channels: BTreeMap<String, Channel>,
}

/// A channel. Channels nest: `production/eu/fra` is a channel inside
/// `production/eu`, inside `production`. A project keeps every channel in one
/// map keyed by its full path, and `name` is that path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Channel {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// The parent's secrets (the project's, for a top-level channel) are visible
    /// in this channel unless it overrides them.
    #[serde(default = "yes")]
    pub inherit: bool,
    /// Protected channels (production) need an approval for every push and reveal.
    /// Every channel inside a protected channel is protected too.
    #[serde(default)]
    pub protected: bool,
    #[serde(default)]
    pub secrets: BTreeMap<String, Secret>,
    #[serde(default)]
    pub destinations: BTreeMap<String, Destination>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    /// Two-way: encrypted, revealable by the owner with approval, pushable.
    Sealed,
    /// One-way: only an Argon2id hash is kept. Verifiable, never revealable or pushable.
    Hashed,
    /// Not sensitive (an app name, a public URL). Still encrypted at rest inside
    /// the vault, but readable whenever the pit is unlocked, without approval.
    Plain,
}

impl std::str::FromStr for Protection {
    type Err = crate::error::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "sealed" | "two-way" | "encrypted" => Ok(Protection::Sealed),
            "hashed" | "one-way" | "hash" => Ok(Protection::Hashed),
            "plain" | "plaintext" | "text" => Ok(Protection::Plain),
            _ => invalid(format!(
                "protection must be sealed, hashed or plain (got {s})"
            )),
        }
    }
}

impl std::fmt::Display for Protection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Protection::Sealed => "sealed",
            Protection::Hashed => "hashed",
            Protection::Plain => "plain",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Kind {
    Text,
    File { filename: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub protection: Protection,
    pub kind: Kind,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub value: Option<Stored>,
    #[serde(default)]
    pub history: Vec<Stored>,
    pub created: i64,
    pub updated: i64,
}

impl Secret {
    pub fn is_set(&self) -> bool {
        self.value.is_some()
    }
    pub fn fingerprint(&self) -> Option<&str> {
        self.value.as_ref().map(|v| v.fp.as_str())
    }
    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|x| x == t)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stored {
    pub fp: String,
    pub set_at: i64,
    #[serde(default)]
    pub len: usize,
    pub data: StoredData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "as", rename_all = "lowercase")]
pub enum StoredData {
    Plain {
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    Sealed {
        sealed: Sealed,
    },
    Hashed {
        params: KdfParams,
        #[serde(with = "b64")]
        digest: Vec<u8>,
    },
}

/// Where a channel's secrets go.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Destination {
    pub name: String,
    /// fly | vercel | github | dotenv | files | command
    pub kind: String,
    #[serde(default)]
    pub description: String,
    /// Which secrets: `*`, `tag:<t>`, `<NAME>`, `<NAME> as <ALIAS>`, `global:<NAME>`, `!<NAME>`.
    #[serde(default)]
    pub select: Vec<String>,
    /// Kind-specific settings. Values may reference channel secrets as `{NAME}`.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    /// The connection whose delegated access is used. Defaults to the one named after the kind.
    #[serde(default)]
    pub connection: Option<String>,
}

/// Delegated access to a service: the token The Pit uses to push there.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub description: String,
    /// `token`: a credential you handed The Pit. `cli`: The Pit borrows the
    /// vendor CLI's own sign-in at push time and stores nothing.
    pub mode: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub token: Option<Stored>,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    pub created: i64,
    #[serde(default)]
    pub verified_at: i64,
}

pub fn valid_name(kind: &str, s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.@/".contains(c))
        && !s.starts_with('/')
        && !s.contains("..");
    if ok {
        Ok(())
    } else {
        invalid(format!(
            "{kind} name '{s}' may use letters, digits and _ - . @ / only"
        ))
    }
}

/// A relative path with only normal components (no `..`, no root, not empty).
pub fn safe_relative(name: &str) -> bool {
    let p = std::path::Path::new(name);
    !name.is_empty()
        && !p.is_absolute()
        && p.components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// A channel path: one or more slugs joined by `/` (`production/eu/fra`).
pub fn valid_channel(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 512 {
        return invalid(format!("channel name '{s}' must be 1 to 512 characters"));
    }
    s.split('/').try_for_each(|seg| valid_slug("channel", seg))
}

/// The channel a channel sits in: `production/eu` for `production/eu/fra`.
pub fn parent_channel(c: &str) -> Option<&str> {
    c.rsplit_once('/').map(|(p, _)| p)
}

/// A channel and every channel above it, outermost first:
/// `a/b/c` → `a`, `a/b`, `a/b/c`.
pub fn channel_lineage(c: &str) -> Vec<&str> {
    c.match_indices('/')
        .map(|(i, _)| &c[..i])
        .chain(std::iter::once(c))
        .collect()
}

/// Whether `c` is `ancestor` itself or sits somewhere inside it.
pub fn within(c: &str, ancestor: &str) -> bool {
    c == ancestor
        || c.strip_prefix(ancestor)
            .map(|r| r.starts_with('/'))
            .unwrap_or(false)
}

pub fn valid_slug(kind: &str, s: &str) -> Result<()> {
    // `.` and `..` are refused: names also become folder names in exports.
    let ok = !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
    if ok {
        Ok(())
    } else {
        invalid(format!(
            "{kind} name '{s}' may use letters, digits and _ - . only"
        ))
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn fmt_time(t: i64) -> String {
    if t == 0 {
        return "—".into();
    }
    time::OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|d| {
            d.format(&time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second]Z"
            ))
            .ok()
        })
        .unwrap_or_else(|| t.to_string())
}

pub mod opt_b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let o = Option::<String>::deserialize(d)?;
        o.map(|s| {
            STANDARD
                .decode(s.as_bytes())
                .map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

/// A reference to where a secret lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Global,
    Project(String),
    Channel(String, String),
}

impl Scope {
    /// Parses `global`, `<project>` or `<project>/<channel>[/<channel>…]`.
    pub fn parse(s: &str) -> Result<Scope> {
        if s == "global" || s == "@" {
            return Ok(Scope::Global);
        }
        match s.split_once('/') {
            Some((p, c)) => {
                valid_slug("project", p)?;
                valid_channel(c)?;
                Ok(Scope::Channel(p.into(), c.into()))
            }
            None => {
                valid_slug("project", s)?;
                Ok(Scope::Project(s.into()))
            }
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Global => f.write_str("global"),
            Scope::Project(p) => f.write_str(p),
            Scope::Channel(p, c) => write!(f, "{p}/{c}"),
        }
    }
}

impl Library {
    pub fn secrets(&self, scope: &Scope) -> Result<&BTreeMap<String, Secret>> {
        Ok(match scope {
            Scope::Global => &self.globals,
            Scope::Project(p) => &self.project(p)?.secrets,
            Scope::Channel(p, c) => &self.channel(p, c)?.secrets,
        })
    }

    pub fn secrets_mut(&mut self, scope: &Scope) -> Result<&mut BTreeMap<String, Secret>> {
        Ok(match scope {
            Scope::Global => &mut self.globals,
            Scope::Project(p) => &mut self.project_mut(p)?.secrets,
            Scope::Channel(p, c) => &mut self.channel_mut(p, c)?.secrets,
        })
    }

    pub fn project(&self, p: &str) -> Result<&Project> {
        self.projects
            .get(p)
            .ok_or_else(|| crate::error::Error::NotFound(format!("project {p}")))
    }

    pub fn project_mut(&mut self, p: &str) -> Result<&mut Project> {
        self.projects
            .get_mut(p)
            .ok_or_else(|| crate::error::Error::NotFound(format!("project {p}")))
    }

    pub fn channel(&self, p: &str, c: &str) -> Result<&Channel> {
        self.project(p)?
            .channels
            .get(c)
            .ok_or_else(|| crate::error::Error::NotFound(format!("channel {p}/{c}")))
    }

    /// A channel is protected if it, or any channel it sits in, is.
    pub fn channel_protected(&self, p: &str, c: &str) -> bool {
        channel_lineage(c)
            .into_iter()
            .any(|a| self.channel(p, a).map(|ch| ch.protected).unwrap_or(false))
    }

    /// The scopes whose secrets a channel sees, outermost first, so that a
    /// nearer scope's secret overrides a farther one of the same name. The
    /// chain climbs while each channel inherits: the channel, its parent, and
    /// so on up to the project.
    pub fn channel_sees(&self, p: &str, c: &str) -> Result<Vec<Scope>> {
        let mut out = vec![];
        let mut at = c;
        loop {
            let ch = self.channel(p, at)?;
            out.push(Scope::Channel(p.into(), at.into()));
            if !ch.inherit {
                break;
            }
            match parent_channel(at) {
                Some(up) => at = up,
                None => {
                    out.push(Scope::Project(p.into()));
                    break;
                }
            }
        }
        out.reverse();
        Ok(out)
    }

    pub fn channel_mut(&mut self, p: &str, c: &str) -> Result<&mut Channel> {
        self.project_mut(p)?
            .channels
            .get_mut(c)
            .ok_or_else(|| crate::error::Error::NotFound(format!("channel {p}/{c}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_paths() {
        assert!(valid_channel("production/eu/fra").is_ok());
        assert!(valid_channel("production//fra").is_err());
        assert!(valid_channel("production/").is_err());
        assert!(valid_channel("../x").is_err());
        assert_eq!(channel_lineage("a/b/c"), vec!["a", "a/b", "a/b/c"]);
        assert_eq!(channel_lineage("a"), vec!["a"]);
        assert_eq!(parent_channel("a/b/c"), Some("a/b"));
        assert_eq!(parent_channel("a"), None);
        assert!(within("a/b", "a") && within("a", "a") && !within("ab", "a"));
        assert_eq!(
            Scope::parse("app/a/b/c").unwrap(),
            Scope::Channel("app".into(), "a/b/c".into())
        );
    }
}
