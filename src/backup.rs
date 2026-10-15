//! Backups and bundles.
//!
//! * A **snapshot** is a copy of the encrypted vault files. It needs no unlock
//!   (so scheduled backups run while the pit is locked) and restores with the
//!   password or the recovery code that were current when it was taken.
//! * A **bundle** is a chosen set of projects re-encrypted under a fresh key,
//!   wrapped for this vault and, optionally, for a passphrase or for another
//!   person's identity key. Bundles move projects between vaults.
//!
//! Neither ever leaves this machine unencrypted. Remote targets receive the
//! same ciphertext a local folder would.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::agent::Session;
use crate::crypto::{self, b64, KdfParams, Key, Sealed};
use crate::error::{invalid, Error, Result};
use crate::model::{fmt_time, now, Connection, Project, Protection, Secret, StoredData};
use crate::{codes, keychain, paths, s3, values};

// ---------------------------------------------------------------------------
// bundles

#[derive(Serialize, Deserialize)]
struct Bundle {
    format: String,
    created: i64,
    from_vault: String,
    contents: Vec<String>,
    slots: Vec<BundleSlot>,
    payload: Sealed,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum BundleSlot {
    Vault {
        wrapped: Sealed,
    },
    Passphrase {
        kdf: KdfParams,
        wrapped: Sealed,
    },
    Recipient {
        #[serde(with = "b64")]
        sealed: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Default)]
pub struct Payload {
    #[serde(default)]
    pub projects: BTreeMap<String, Project>,
    #[serde(default)]
    pub globals: BTreeMap<String, Secret>,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
}

const BUNDLE_FORMAT: &str = "the-pit-bundle/1";

fn bundle_aad(created: i64, from: &str) -> Vec<u8> {
    format!("{BUNDLE_FORMAT}|{created}|{from}").into_bytes()
}

/// Replace every sealed value with its plaintext (the whole payload is
/// encrypted again before it goes anywhere). History is not carried.
fn portable_secret(s: &Session, sec: &Secret) -> Result<Secret> {
    let mut out = sec.clone();
    out.history.clear();
    if let Some(st) = &sec.value {
        if let StoredData::Sealed { .. } = st.data {
            let v = values::open_stored(&s.keys, &sec.id, st)?;
            let mut st2 = st.clone();
            st2.data = StoredData::Plain { bytes: v.to_vec() };
            out.value = Some(st2);
        }
    }
    Ok(out)
}

fn portable_project(s: &Session, p: &Project) -> Result<Project> {
    let mut out = p.clone();
    for sec in out.secrets.values_mut() {
        *sec = portable_secret(s, sec)?;
    }
    for ch in out.channels.values_mut() {
        for sec in ch.secrets.values_mut() {
            *sec = portable_secret(s, sec)?;
        }
    }
    Ok(out)
}

fn portable_connection(s: &Session, c: &Connection) -> Result<Connection> {
    let mut out = c.clone();
    if let Some(st) = &c.token {
        let v = values::open_stored(&s.keys, &format!("connection:{}", c.name), st)?;
        let mut st2 = st.clone();
        st2.data = StoredData::Plain { bytes: v.to_vec() };
        out.token = Some(st2);
    }
    Ok(out)
}

pub fn payload(
    s: &Session,
    projects: &[String],
    with_globals: bool,
    with_connections: bool,
) -> Result<Payload> {
    let mut p = Payload::default();
    for (name, proj) in &s.lib.projects {
        if projects.is_empty() || projects.contains(name) {
            p.projects.insert(name.clone(), portable_project(s, proj)?);
        }
    }
    for want in projects {
        if !s.lib.projects.contains_key(want) {
            return Err(Error::NotFound(format!("project {want}")));
        }
    }
    if with_globals {
        for (n, g) in &s.lib.globals {
            p.globals.insert(n.clone(), portable_secret(s, g)?);
        }
    }
    if with_connections {
        for (n, c) in &s.lib.connections {
            p.connections.insert(n.clone(), portable_connection(s, c)?);
        }
    }
    Ok(p)
}

fn seal_bundle(
    s: Option<&Session>,
    p: &Payload,
    passphrase: Option<&str>,
    recipient: Option<&str>,
) -> Result<Vec<u8>> {
    let bk = Key::generate();
    let created = now();
    let from = s.map(|s| s.header.vault_id.clone()).unwrap_or_default();
    let pt = Zeroizing::new(serde_json::to_vec(p)?);
    let payload = crypto::seal(&bk, &pt, &bundle_aad(created, &from));
    let mut slots = vec![];
    if let Some(s) = s {
        slots.push(BundleSlot::Vault {
            wrapped: crypto::seal(&s.keys.vmk.derive("bundle-wrap"), bk.as_bytes(), b"bundle"),
        });
    }
    if let Some(pw) = passphrase {
        let kdf = KdfParams::new_password();
        let kek = kdf.derive(pw.as_bytes())?;
        slots.push(BundleSlot::Passphrase {
            wrapped: crypto::seal(&kek, bk.as_bytes(), b"bundle"),
            kdf,
        });
    }
    if let Some(r) = recipient {
        let pk: [u8; 32] = codes::decode("ID", r)?
            .to_vec()
            .try_into()
            .map_err(|_| Error::Invalid("identity has the wrong length".into()))?;
        let pk = crypto_box::PublicKey::from(pk);
        let sealed = pk
            .seal(&mut rand_core::OsRng, bk.as_bytes())
            .map_err(|_| Error::Crypto("sealed box".into()))?;
        slots.push(BundleSlot::Recipient { sealed });
    }
    if slots.is_empty() {
        return invalid("a bundle needs at least one way to open it");
    }
    let mut contents: Vec<String> = p.projects.keys().cloned().collect();
    if !p.globals.is_empty() {
        contents.push("(globals)".into());
    }
    if !p.connections.is_empty() {
        contents.push("(connections)".into());
    }
    let b = Bundle {
        format: BUNDLE_FORMAT.into(),
        created,
        from_vault: from,
        contents,
        slots,
        payload,
    };
    Ok(serde_json::to_vec_pretty(&b)?)
}

pub fn export_bundle(
    s: &Session,
    projects: &[String],
    passphrase: Option<&str>,
    recipient: Option<&str>,
    connections: bool,
) -> Result<Vec<u8>> {
    let p = payload(s, projects, projects.is_empty(), connections)?;
    seal_bundle(Some(s), &p, passphrase, recipient)
}

/// Everything, decrypted. With a passphrase it is wrapped as a bundle that any
/// fresh vault can import; without one it is plaintext JSON.
pub fn emergency_export(s: &Session, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let p = payload(s, &[], true, true)?;
    match passphrase {
        Some(pw) => seal_bundle(None, &p, Some(pw), None),
        None => {
            let doc = json!({
                "warning": "PLAINTEXT. Every secret in this file is readable by anyone who can read the file. Import it into a new vault, then destroy it.",
                "format": "the-pit-plain-export/1",
                "exported": fmt_time(now()),
                "owner": s.lib.owner.name,
                "payload": p,
            });
            Ok(serde_json::to_vec_pretty(&doc)?)
        }
    }
}

fn open_bundle(s: &Session, data: &[u8], passphrase: Option<&str>) -> Result<Payload> {
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        if v.get("format").and_then(|f| f.as_str()) == Some("the-pit-plain-export/1") {
            return Ok(serde_json::from_value(v["payload"].clone())?);
        }
    }
    let b: Bundle =
        serde_json::from_slice(data).map_err(|_| Error::Invalid("not a bundle".into()))?;
    if b.format != BUNDLE_FORMAT {
        return invalid(format!("unknown bundle format {}", b.format));
    }
    let mut bk: Option<Key> = None;
    for slot in &b.slots {
        let k = match slot {
            BundleSlot::Vault { wrapped } => {
                crypto::open(&s.keys.vmk.derive("bundle-wrap"), wrapped, b"bundle").ok()
            }
            BundleSlot::Recipient { sealed } => {
                let sk: [u8; 32] = s
                    .lib
                    .owner
                    .identity_secret
                    .clone()
                    .try_into()
                    .map_err(|_| Error::Crypto("identity".into()))?;
                crypto_box::SecretKey::from(sk)
                    .unseal(sealed)
                    .ok()
                    .map(Zeroizing::new)
            }
            BundleSlot::Passphrase { kdf, wrapped } => match passphrase {
                Some(pw) => crypto::open(&kdf.derive(pw.as_bytes())?, wrapped, b"bundle").ok(),
                None => None,
            },
        };
        if let Some(k) = k {
            bk = Some(Key::from_bytes(&k)?);
            break;
        }
    }
    let bk = bk.ok_or_else(|| {
        if b.slots
            .iter()
            .any(|s| matches!(s, BundleSlot::Passphrase { .. }))
            && passphrase.is_none()
        {
            Error::Invalid("this bundle needs its passphrase (--passphrase)".into())
        } else {
            Error::Denied
        }
    })?;
    let pt = crypto::open(&bk, &b.payload, &bundle_aad(b.created, &b.from_vault))?;
    Ok(serde_json::from_slice(&pt)?)
}

/// Re-seal portable values under this vault's keys.
fn adopt_secret(s: &Session, sec: &mut Secret) -> Result<()> {
    sec.history.clear();
    if let Some(st) = sec.value.take() {
        sec.value = Some(match (&st.data, sec.protection) {
            (StoredData::Plain { bytes }, Protection::Sealed) => {
                values::store(&s.keys, &sec.id, Protection::Sealed, bytes)?
            }
            (StoredData::Sealed { .. }, _) => {
                return invalid(format!(
                    "{} arrived still sealed to another vault",
                    sec.name
                ))
            }
            _ => st,
        });
    }
    Ok(())
}

pub fn import_bundle(
    s: &mut Session,
    data: &[u8],
    passphrase: Option<&str>,
    replace: bool,
    with_destinations: bool,
) -> Result<Value> {
    let mut p = open_bundle(s, data, passphrase)?;
    // A bundle is untrusted input: anyone who knows your identity can make one.
    // Names are validated, and where secrets go (destinations, connections) is
    // only taken from it when explicitly asked for.
    let mut dropped: Vec<String> = vec![];
    for (pn, proj) in p.projects.iter_mut() {
        crate::model::valid_slug("project", pn)?;
        for sec in proj.secrets.values() {
            check_imported_secret(sec)?;
        }
        for (cn, ch) in proj.channels.iter_mut() {
            crate::model::valid_slug("channel", cn)?;
            for sec in ch.secrets.values() {
                check_imported_secret(sec)?;
            }
            if !with_destinations {
                for d in std::mem::take(&mut ch.destinations).into_values() {
                    dropped.push(format!("{pn}/{cn} → {} ({})", d.name, d.kind));
                }
            } else {
                for d in ch.destinations.values() {
                    crate::model::valid_slug("destination", &d.name)?;
                    crate::rail::kind_info(&d.kind)?;
                }
            }
        }
    }
    for g in p.globals.values() {
        check_imported_secret(g)?;
    }
    if !with_destinations {
        for (n, c) in std::mem::take(&mut p.connections) {
            dropped.push(format!("connection {n} ({})", c.kind));
        }
    }
    let mut added = vec![];
    let mut merged = vec![];
    let mut kept = vec![];
    for (name, mut proj) in std::mem::take(&mut p.projects) {
        for sec in proj.secrets.values_mut() {
            adopt_secret(s, sec)?;
        }
        for ch in proj.channels.values_mut() {
            for sec in ch.secrets.values_mut() {
                adopt_secret(s, sec)?;
            }
        }
        match s.lib.projects.get_mut(&name) {
            None => {
                s.lib.projects.insert(name.clone(), proj);
                added.push(name);
            }
            Some(cur) if replace => {
                *cur = proj;
                merged.push(format!("{name} (replaced)"));
            }
            Some(cur) => {
                for (k, v) in proj.secrets {
                    match cur.secrets.entry(k) {
                        std::collections::btree_map::Entry::Occupied(e) => {
                            kept.push(format!("{name}:{}", e.key()))
                        }
                        std::collections::btree_map::Entry::Vacant(e) => {
                            e.insert(v);
                        }
                    }
                }
                for (cn, ch) in proj.channels {
                    match cur.channels.get_mut(&cn) {
                        None => {
                            cur.channels.insert(cn, ch);
                        }
                        Some(cc) => {
                            for (k, v) in ch.secrets {
                                match cc.secrets.entry(k) {
                                    std::collections::btree_map::Entry::Occupied(e) => {
                                        kept.push(format!("{name}/{cn}:{}", e.key()))
                                    }
                                    std::collections::btree_map::Entry::Vacant(e) => {
                                        e.insert(v);
                                    }
                                }
                            }
                            for (k, v) in ch.destinations {
                                cc.destinations.entry(k).or_insert(v);
                            }
                        }
                    }
                }
                merged.push(name);
            }
        }
    }
    for (n, mut g) in std::mem::take(&mut p.globals) {
        adopt_secret(s, &mut g)?;
        if replace || !s.lib.globals.contains_key(&n) {
            s.lib.globals.insert(n, g);
        } else {
            kept.push(format!("global:{n}"));
        }
    }
    for (n, mut c) in std::mem::take(&mut p.connections) {
        if let Some(st) = c.token.take() {
            if let StoredData::Plain { bytes } = &st.data {
                c.token = Some(values::store(
                    &s.keys,
                    &format!("connection:{n}"),
                    Protection::Sealed,
                    bytes,
                )?);
            }
        }
        if replace || !s.lib.connections.contains_key(&n) {
            s.lib.connections.insert(n, c);
        }
    }
    Ok(json!({"added": added, "merged": merged, "kept_existing": kept, "not_imported": dropped}))
}

fn check_imported_secret(sec: &Secret) -> Result<()> {
    crate::model::valid_name("secret", &sec.name)?;
    if let crate::model::Kind::File { filename } = &sec.kind {
        if !crate::model::safe_relative(filename) {
            return invalid(format!("{} has an unsafe file name", sec.name));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// snapshots

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub format: String,
    pub created: i64,
    pub vault_id: String,
    /// The library generation it holds (0 for snapshots made before this was recorded).
    #[serde(default)]
    pub generation: u64,
    pub files: BTreeMap<String, String>,
    pub sha256: BTreeMap<String, String>,
}

impl Snapshot {
    pub fn file(&self, rel: &str) -> Result<Vec<u8>> {
        crypto::b64d(
            self.files
                .get(rel)
                .ok_or_else(|| Error::Invalid(format!("snapshot has no {rel}")))?,
        )
    }
}

const SNAPSHOT_FORMAT: &str = "the-pit-snapshot/1";
const SNAPSHOT_FILES: &[&str] = &[
    "vault/header.json",
    "vault/library.sealed",
    "log/audit.log",
    "log/anchor.sealed",
];

/// Identifies the vault's current contents: a backup is due when this changes.
pub fn content_id() -> Result<String> {
    let mut h = Vec::new();
    for rel in ["vault/header.json", "vault/library.sealed"] {
        h.extend_from_slice(&fs::read(paths::home().join(rel))?);
        h.push(0);
    }
    Ok(crypto::sha256_hex(&h))
}

pub fn snapshot() -> Result<(String, Vec<u8>)> {
    let h = crate::vault::Header::load()?;
    let mut files = BTreeMap::new();
    let mut sums = BTreeMap::new();
    let mut generation = 0;
    for rel in SNAPSHOT_FILES {
        let p = paths::home().join(rel);
        if let Ok(b) = fs::read(&p) {
            if *rel == "vault/library.sealed" {
                generation = crate::vault::generation_of(&b);
            }
            sums.insert(rel.to_string(), crypto::sha256_hex(&b));
            files.insert(rel.to_string(), crypto::b64e(&b));
        }
    }
    let created = now();
    let snap = Snapshot {
        format: SNAPSHOT_FORMAT.into(),
        created,
        vault_id: h.vault_id.clone(),
        generation,
        files,
        sha256: sums,
    };
    let name = format!(
        "the-pit-{}-{}-g{}.pitvault",
        &h.vault_id[..8],
        stamp(created),
        generation
    );
    Ok((name, serde_json::to_vec(&snap)?))
}

fn stamp(t: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(t)
        .ok()
        .and_then(|d| {
            d.format(&time::macros::format_description!(
                "[year][month][day]-[hour][minute][second]"
            ))
            .ok()
        })
        .unwrap_or_else(|| t.to_string())
}

/// When a snapshot was taken and which generation it holds, from its file name
/// alone (so listing a remote needs no downloads).
pub fn parse_name(name: &str) -> Option<(i64, Option<u64>)> {
    let rest = name.strip_prefix("the-pit-")?.strip_suffix(".pitvault")?;
    let mut parts = rest.split('-');
    let _vault = parts.next()?;
    let day = parts.next()?;
    let clock = parts.next()?;
    let generation = parts
        .next()
        .and_then(|g| g.strip_prefix('g'))
        .and_then(|g| g.parse().ok());
    let fmt = time::macros::format_description!("[year][month][day][hour][minute][second]");
    let t = time::PrimitiveDateTime::parse(&format!("{day}{clock}"), &fmt).ok()?;
    Some((t.assume_utc().unix_timestamp(), generation))
}

pub fn inspect_snapshot(data: &[u8]) -> Result<Snapshot> {
    let s: Snapshot = serde_json::from_slice(data)
        .map_err(|_| Error::Invalid("not a The Pit snapshot".into()))?;
    if s.format != SNAPSHOT_FORMAT {
        return invalid(format!("unknown snapshot format {}", s.format));
    }
    for (rel, b) in &s.files {
        if !SNAPSHOT_FILES.contains(&rel.as_str()) {
            return invalid(format!(
                "snapshot holds an unexpected file ({rel}); refusing it"
            ));
        }
        let bytes = crypto::b64d(b)?;
        if s.sha256
            .get(rel)
            .map(|h| h != &crypto::sha256_hex(&bytes))
            .unwrap_or(true)
        {
            return invalid(format!(
                "snapshot is damaged ({rel} does not match its checksum)"
            ));
        }
    }
    if !s.files.contains_key("vault/header.json") || !s.files.contains_key("vault/library.sealed") {
        return invalid("snapshot is missing the vault");
    }
    Ok(s)
}

/// Restore a snapshot into The Pit's home. The current vault, if any, is first
/// saved as a snapshot beside the backups so a restore is itself reversible.
pub fn restore_snapshot(data: &[u8]) -> Result<Option<PathBuf>> {
    let snap = inspect_snapshot(data)?;
    paths::ensure_layout()?;
    let mut saved = None;
    if crate::vault::exists() {
        let (name, bytes) = snapshot()?;
        let p = paths::backups_dir().join(format!("before-restore-{name}"));
        paths::write_private(&p, &bytes)?;
        saved = Some(p);
    }
    for (rel, b) in &snap.files {
        let p = paths::home().join(rel);
        if let Some(parent) = p.parent() {
            paths::private_dir(parent)?;
        }
        paths::write_private(&p, &crypto::b64d(b)?)?;
    }
    crate::vault::reset_generation(&snap.vault_id);
    for rel in ["log/audit.log", "log/anchor.sealed"] {
        if !snap.files.contains_key(rel) {
            let _ = fs::remove_file(paths::home().join(rel));
        }
    }
    Ok(saved)
}

// ---------------------------------------------------------------------------
// targets

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Every snapshot from the last two days is kept; older ones thin out to
    /// one a day, then one a month. At least this many are always kept.
    #[serde(default = "default_keep")]
    pub keep: usize,
    /// Back up after every change (on by default).
    #[serde(default = "yes")]
    pub auto: bool,
    #[serde(default, rename = "target")]
    pub targets: Vec<Target>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            keep: default_keep(),
            auto: true,
            targets: vec![],
        }
    }
}

fn default_keep() -> usize {
    30
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Target {
    pub name: String,
    /// dir | ssh | s3 | rclone
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

impl Config {
    pub fn load() -> Result<Config> {
        match fs::read_to_string(paths::backup_config()) {
            Ok(t) => {
                let mut c: Config = toml::from_str(&t)?;
                if c.keep == 0 {
                    c.keep = default_keep();
                }
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        let mut text = String::from(
            "# The Pit backup targets. No secrets in here: S3 keys live in the OS keychain.\n",
        );
        text.push_str(&toml::to_string_pretty(self).map_err(|e| Error::Invalid(e.to_string()))?);
        paths::write_private(&paths::backup_config(), text.as_bytes())
    }

    /// The built-in local folder, then the configured targets.
    pub fn all_targets(&self) -> Vec<Target> {
        let mut v = vec![local_target()];
        v.extend(self.targets.iter().cloned());
        v
    }

    pub fn target(&self, name: &str) -> Option<Target> {
        self.all_targets().into_iter().find(|t| t.name == name)
    }
}

pub fn local_target() -> Target {
    Target {
        name: "local".into(),
        kind: "dir".into(),
        path: Some(paths::backups_dir().display().to_string()),
        ..Default::default()
    }
}

/// A target written on the command line, for reaching backups from a machine
/// that has no configuration yet: `dir:PATH`, `ssh:USER@HOST:PATH`,
/// `rclone:REMOTE:PATH`.
pub fn adhoc_target(spec: &str) -> Option<Target> {
    let (kind, rest) = spec.split_once(':')?;
    let mut t = Target {
        name: spec.to_string(),
        kind: kind.to_string(),
        ..Default::default()
    };
    match kind {
        "dir" => t.path = Some(rest.into()),
        "ssh" if rest.contains(':') => t.dest = Some(rest.into()),
        "rclone" if rest.contains(':') => t.remote = Some(rest.into()),
        _ => return None,
    }
    Some(t)
}

pub fn s3_account(target: &str) -> String {
    format!("backup-s3-{target}")
}

pub fn describe(t: &Target) -> String {
    match t.kind.as_str() {
        "dir" => t.path.clone().unwrap_or_default(),
        "ssh" => t.dest.clone().unwrap_or_default(),
        "rclone" => t.remote.clone().unwrap_or_default(),
        "s3" => format!(
            "s3://{}/{}{}",
            t.bucket.clone().unwrap_or_default(),
            t.prefix.clone().unwrap_or_default(),
            t.endpoint
                .as_ref()
                .map(|e| format!(" via {e}"))
                .unwrap_or_default()
        ),
        _ => "?".into(),
    }
}

const SSH_OPTS: &[&str] = &[
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=3",
];
const RCLONE_OPTS: &[&str] = &[
    "--contimeout",
    "15s",
    "--timeout",
    "2m",
    "--retries",
    "2",
    "-q",
];

/// `user@host:path` → (`user@host`, `path`). A leading `~/` is dropped: the
/// remote shell starts in the home folder.
fn ssh_parts(dest: &str) -> Result<(String, String)> {
    let (host, path) = dest
        .split_once(':')
        .ok_or_else(|| Error::Invalid("ssh target needs dest (user@host:path)".into()))?;
    let path = path
        .strip_prefix("~/")
        .unwrap_or(path)
        .trim_end_matches('/');
    let path = if path.is_empty() || path == "~" {
        "."
    } else {
        path
    };
    Ok((host.to_string(), path.to_string()))
}

fn ssh(host: &str, cmd: &str) -> Result<Vec<u8>> {
    let out = Command::new("ssh")
        .args(SSH_OPTS)
        .arg(host)
        .arg("--")
        .arg(cmd)
        .env("PATH", paths::tool_path())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Remote(format!("ssh: {e}")))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(Error::Remote(format!(
            "ssh {host}: {}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("failed (key-based login is required)")
        )))
    }
}

fn rclone(args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("rclone")
        .args(args)
        .args(RCLONE_OPTS)
        .env("PATH", paths::tool_path())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Remote(format!("rclone is not installed or failed to start ({e})")))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(Error::Remote(format!(
            "rclone: {}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("failed")
        )))
    }
}

fn s3_store<R>(t: &Target, f: impl FnOnce(&s3::Store) -> Result<R>) -> Result<R> {
    let creds = keychain::get(&s3_account(&t.name))?.ok_or_else(|| {
        Error::Invalid(format!(
            "no S3 keys for {} in the keychain — re-add the target",
            t.name
        ))
    })?;
    let creds = Zeroizing::new(String::from_utf8_lossy(&creds).into_owned());
    let (ak, sk) = creds
        .split_once('\n')
        .ok_or_else(|| Error::Invalid("stored S3 keys are malformed".into()))?;
    let store = s3::Store {
        endpoint: t.endpoint.as_deref(),
        bucket: t
            .bucket
            .as_deref()
            .ok_or_else(|| Error::Invalid("s3 target needs a bucket".into()))?,
        region: t.region.as_deref().unwrap_or("us-east-1"),
        access: ak,
        secret: sk,
    };
    f(&store)
}

fn dir_of(t: &Target) -> Result<PathBuf> {
    Ok(paths::expand_tilde(t.path.as_deref().ok_or_else(|| {
        Error::Invalid("dir target needs a path".into())
    })?))
}

fn require<'a>(v: &'a Option<String>, what: &str) -> Result<&'a str> {
    v.as_deref()
        .ok_or_else(|| Error::Invalid(format!("target needs {what}")))
}

pub fn send(t: &Target, name: &str, data: &[u8]) -> Result<String> {
    match t.kind.as_str() {
        "dir" => {
            let dir = dir_of(t)?;
            paths::private_dir(&dir)?;
            let p = dir.join(name);
            paths::write_private(&p, data)?;
            Ok(p.display().to_string())
        }
        "ssh" => {
            let (host, path) = ssh_parts(require(&t.dest, "dest (user@host:path)")?)?;
            ssh(
                &host,
                &format!("mkdir -p -m 700 {}", shell_words::quote(&path)),
            )?;
            let tmp = staged(name, data)?;
            let target = format!("{host}:{path}/{name}");
            let out = Command::new("scp")
                .args(["-q", "-p"])
                .args(SSH_OPTS)
                .arg(&tmp)
                .arg(&target)
                .env("PATH", paths::tool_path())
                .stdin(std::process::Stdio::null())
                .output();
            let _ = fs::remove_file(&tmp);
            match out {
                Ok(o) if o.status.success() => Ok(target),
                Ok(o) => Err(Error::Remote(format!(
                    "scp to {host}: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ))),
                Err(e) => Err(Error::Remote(format!("scp: {e}"))),
            }
        }
        "rclone" => {
            let remote = require(&t.remote, "remote (name:path)")?;
            let tmp = staged(name, data)?;
            let target = format!("{}/{}", remote.trim_end_matches('/'), name);
            let r = rclone(&["copyto", &tmp.display().to_string(), &target]);
            let _ = fs::remove_file(&tmp);
            r.map(|_| target)
        }
        "s3" => {
            let key = format!("{}{}", t.prefix.clone().unwrap_or_default(), name);
            s3_store(t, |s| s.put(&key, data))?;
            Ok(format!(
                "s3://{}/{}",
                t.bucket.clone().unwrap_or_default(),
                key
            ))
        }
        k => invalid(format!(
            "unknown backup target kind {k} (dir, ssh, s3, rclone)"
        )),
    }
}

fn is_snapshot_name(n: &str) -> bool {
    n.starts_with("the-pit-") && n.ends_with(".pitvault")
}

/// Snapshot file names held by a target, oldest first.
pub fn list(t: &Target) -> Result<Vec<String>> {
    let mut names: Vec<String> = match t.kind.as_str() {
        "dir" => match fs::read_dir(dir_of(t)?) {
            Ok(rd) => rd
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.into()),
        },
        "ssh" => {
            let (host, path) = ssh_parts(require(&t.dest, "dest")?)?;
            let q = shell_words::quote(&path);
            let out = ssh(&host, &format!("if [ -d {q} ]; then ls -1 {q}; fi"))?;
            String::from_utf8_lossy(&out)
                .lines()
                .map(String::from)
                .collect()
        }
        "rclone" => {
            let remote = require(&t.remote, "remote")?;
            match rclone(&["lsf", "--files-only", remote]) {
                Ok(out) => String::from_utf8_lossy(&out)
                    .lines()
                    .map(String::from)
                    .collect(),
                Err(e) if e.to_string().contains("directory not found") => vec![],
                Err(e) => return Err(e),
            }
        }
        "s3" => {
            let prefix = t.prefix.clone().unwrap_or_default();
            s3_store(t, |s| s.list(&prefix))?
                .into_iter()
                .map(|k| k.strip_prefix(&prefix).unwrap_or(&k).to_string())
                .collect()
        }
        k => return invalid(format!("unknown backup target kind {k}")),
    };
    names.retain(|n| is_snapshot_name(n));
    names.sort_by_key(|n| parse_name(n).map(|(t, _)| t).unwrap_or(0));
    Ok(names)
}

pub fn fetch(t: &Target, name: &str) -> Result<Vec<u8>> {
    if !is_snapshot_name(name) || name.contains('/') {
        return invalid(format!("{name} is not a snapshot name"));
    }
    match t.kind.as_str() {
        "dir" => Ok(fs::read(dir_of(t)?.join(name))?),
        "ssh" => {
            let (host, path) = ssh_parts(require(&t.dest, "dest")?)?;
            ssh(
                &host,
                &format!("cat {}", shell_words::quote(&format!("{path}/{name}"))),
            )
        }
        "rclone" => {
            let remote = require(&t.remote, "remote")?;
            rclone(&["cat", &format!("{}/{}", remote.trim_end_matches('/'), name)])
        }
        "s3" => {
            let key = format!("{}{}", t.prefix.clone().unwrap_or_default(), name);
            s3_store(t, |s| s.get(&key))
        }
        k => invalid(format!("unknown backup target kind {k}")),
    }
}

fn remove(t: &Target, name: &str) -> Result<()> {
    match t.kind.as_str() {
        "dir" => Ok(fs::remove_file(dir_of(t)?.join(name))?),
        "ssh" => {
            let (host, path) = ssh_parts(require(&t.dest, "dest")?)?;
            ssh(
                &host,
                &format!("rm -f {}", shell_words::quote(&format!("{path}/{name}"))),
            )
            .map(|_| ())
        }
        "rclone" => {
            let remote = require(&t.remote, "remote")?;
            rclone(&[
                "deletefile",
                &format!("{}/{}", remote.trim_end_matches('/'), name),
            ])
            .map(|_| ())
        }
        // S3 keys should be write-only; expiry belongs to a bucket lifecycle rule.
        _ => Ok(()),
    }
}

/// Which snapshots to let go of: everything from the last two days stays, then
/// the newest of each day for 60 days, then the newest of each month. The most
/// recent `keep` always stay.
pub fn thin(names: &[String], keep: usize, now: i64) -> Vec<String> {
    let mut dated: Vec<(i64, &String)> = names
        .iter()
        .filter_map(|n| parse_name(n).map(|(t, _)| (t, n)))
        .collect();
    dated.sort_by_key(|d| std::cmp::Reverse(d.0));
    let mut seen_buckets = std::collections::BTreeSet::new();
    let mut drop = vec![];
    for (i, (t, n)) in dated.iter().enumerate() {
        let age = now - t;
        let bucket = if i < keep || age < 2 * 86_400 {
            None
        } else if age < 60 * 86_400 {
            Some(format!("d{}", t / 86_400))
        } else {
            let d = time::OffsetDateTime::from_unix_timestamp(*t).ok();
            Some(format!(
                "m{}",
                d.map(|d| d.year() * 12 + d.month() as i32).unwrap_or(0)
            ))
        };
        if let Some(b) = bucket {
            if !seen_buckets.insert(b) {
                drop.push((*n).clone());
            }
        }
    }
    drop
}

fn prune(t: &Target, keep: usize) {
    if let Ok(names) = list(t) {
        for n in thin(&names, keep, now()) {
            let _ = remove(t, &n);
        }
    }
}

fn staged(name: &str, data: &[u8]) -> Result<PathBuf> {
    let dir = paths::state_dir().join("outgoing");
    paths::private_dir(&dir)?;
    let p = dir.join(name);
    paths::write_private(&p, data)?;
    Ok(p)
}

// ---------------------------------------------------------------------------
// keeping every target up to date

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TargetState {
    /// Content id of the newest vault this target holds.
    #[serde(default)]
    pub sent: String,
    #[serde(default)]
    pub sent_at: i64,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub failed_at: i64,
    #[serde(default)]
    pub failures: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SyncState {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub checked_at: i64,
    #[serde(default)]
    pub targets: BTreeMap<String, TargetState>,
}

pub fn status_path() -> PathBuf {
    paths::state_dir().join("backup-sync.json")
}

pub fn sync_state() -> SyncState {
    fs::read(status_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// One sync at a time; a second caller waits for the first.
struct SyncLock(fs::File);

impl SyncLock {
    fn take() -> Result<SyncLock> {
        paths::private_dir(&paths::state_dir())?;
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(paths::state_dir().join("backup.lock"))?;
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(SyncLock(f))
    }
}

impl Drop for SyncLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub struct Outcome {
    pub target: String,
    pub ok: bool,
    /// Where it went, or why it did not.
    pub detail: String,
    /// False when the target already had the current vault.
    pub sent: bool,
}

/// Send the current vault to every target that does not have it yet (all of
/// them with `force`). Only encrypted files move, so the pit need not be unlocked.
pub fn sync(force: bool, only: &[String]) -> Result<Vec<Outcome>> {
    let _lock = SyncLock::take()?;
    if !crate::vault::exists() {
        return Ok(vec![]);
    }
    let cfg = Config::load()?;
    let id = content_id()?;
    let mut st = sync_state();
    st.content = id.clone();
    st.checked_at = now();
    let targets: Vec<Target> = cfg
        .all_targets()
        .into_iter()
        .filter(|t| only.is_empty() || only.contains(&t.name) || t.name == "local")
        .collect();
    let mut out = vec![];
    let mut snap: Option<(String, Vec<u8>)> = None;
    for t in &targets {
        let ts = st.targets.entry(t.name.clone()).or_default();
        if !force && ts.sent == id {
            out.push(Outcome {
                target: t.name.clone(),
                ok: true,
                detail: ts.location.clone(),
                sent: false,
            });
            continue;
        }
        if snap.is_none() {
            snap = Some(snapshot()?);
        }
        let (name, data) = snap.as_ref().expect("taken above");
        match send(t, name, data) {
            Ok(loc) => {
                ts.sent = id.clone();
                ts.sent_at = now();
                ts.location = loc.clone();
                ts.error = None;
                ts.failures = 0;
                prune(t, cfg.keep);
                out.push(Outcome {
                    target: t.name.clone(),
                    ok: true,
                    detail: loc,
                    sent: true,
                });
            }
            Err(e) => {
                ts.error = Some(e.to_string());
                ts.failed_at = now();
                ts.failures += 1;
                out.push(Outcome {
                    target: t.name.clone(),
                    ok: false,
                    detail: e.to_string(),
                    sent: false,
                });
            }
        }
    }
    st.targets
        .retain(|k, _| cfg.all_targets().iter().any(|t| &t.name == k));
    let _ = paths::write_private(&status_path(), &serde_json::to_vec_pretty(&st)?);
    Ok(out)
}

/// Targets that do not yet hold the current vault.
pub fn pending() -> Vec<String> {
    let Ok(id) = content_id() else { return vec![] };
    let st = sync_state();
    Config::load()
        .map(|c| c.all_targets())
        .unwrap_or_default()
        .into_iter()
        .filter(|t| {
            st.targets
                .get(&t.name)
                .map(|s| s.sent != id)
                .unwrap_or(true)
        })
        .map(|t| t.name)
        .collect()
}

// ---------------------------------------------------------------------------
// finding a backup

/// Snapshot name → the targets holding it, and (target, error) for targets
/// that could not be reached.
pub type Catalog = (BTreeMap<String, Vec<String>>, Vec<(String, String)>);

/// Every snapshot on the given targets.
pub fn catalog(targets: &[Target]) -> Catalog {
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut errors = vec![];
    for t in targets {
        match list(t) {
            Ok(names) => {
                for n in names {
                    by_name.entry(n).or_default().push(t.name.clone());
                }
            }
            Err(e) => errors.push((t.name.clone(), e.to_string())),
        }
    }
    (by_name, errors)
}

/// Snapshot names, newest first.
pub fn newest_first(by_name: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut v: Vec<String> = by_name.keys().cloned().collect();
    v.sort_by_key(|n| std::cmp::Reverse(parse_name(n).map(|(t, _)| t).unwrap_or(0)));
    v
}

/// Load a snapshot named by REF:
/// - a path to a `.pitvault` file
/// - `N` or `latest` (= 1): the Nth newest across all targets
/// - `TARGET:N`, `TARGET:latest`, `TARGET:NAME`
/// - a snapshot file name, found on whichever target has it
///
/// `targets` are where to look (all configured ones, or one given with --from).
pub fn load_ref(spec: &str, targets: &[Target]) -> Result<(String, Vec<u8>)> {
    let p = paths::expand_tilde(spec);
    if spec.ends_with(".pitvault") && p.is_file() {
        return Ok((p.display().to_string(), fs::read(&p)?));
    }
    let (scope, what) = match spec.split_once(':') {
        Some((t, w)) if targets.iter().any(|x| x.name == t) => (Some(t), w),
        _ => (None, spec),
    };
    let pool: Vec<Target> = targets
        .iter()
        .filter(|t| scope.map(|s| s == t.name).unwrap_or(true))
        .cloned()
        .collect();
    let (by_name, errors) = catalog(&pool);
    let order = newest_first(&by_name);
    let index = if what == "latest" {
        Some(1)
    } else {
        what.parse::<usize>().ok()
    };
    let name = match index {
        Some(i) if i >= 1 && i <= order.len() => order[i - 1].clone(),
        Some(i) => {
            return Err(Error::NotFound(format!(
                "backup #{i} (there are {} reachable{})",
                order.len(),
                if errors.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; unreachable: {}",
                        errors
                            .iter()
                            .map(|e| e.0.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            )))
        }
        None => what.to_string(),
    };
    let holders = by_name
        .get(&name)
        .ok_or_else(|| Error::NotFound(format!("backup {name}")))?;
    let mut last_err = None;
    for h in holders {
        let t = pool
            .iter()
            .find(|t| &t.name == h)
            .expect("listed from pool");
        match fetch(t, &name) {
            Ok(b) => return Ok((format!("{h}:{name}"), b)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(Error::NotFound(name)))
}

// ---------------------------------------------------------------------------
// comparing two libraries (names and fingerprints only)

fn all_secrets(lib: &crate::model::Library) -> BTreeMap<String, &Secret> {
    let mut m = BTreeMap::new();
    for (n, s) in &lib.globals {
        m.insert(format!("global {n}"), s);
    }
    for (pn, p) in &lib.projects {
        for (n, s) in &p.secrets {
            m.insert(format!("{pn} {n}"), s);
        }
        for (cn, c) in &p.channels {
            for (n, s) in &c.secrets {
                m.insert(format!("{pn}/{cn} {n}"), s);
            }
        }
    }
    m
}

fn change(kind: &str, what: &str, name: &str, detail: String) -> Value {
    json!({"change": kind, "what": what, "name": name, "detail": detail})
}

fn compare_maps<T>(
    out: &mut Vec<Value>,
    what: &str,
    a: &BTreeMap<String, T>,
    b: &BTreeMap<String, T>,
    detail: impl Fn(&T, &T) -> Vec<String>,
) {
    for (k, va) in a {
        match b.get(k) {
            None => out.push(change("-", what, k, String::new())),
            Some(vb) => {
                let d = detail(va, vb);
                if !d.is_empty() {
                    out.push(change("~", what, k, d.join("; ")));
                }
            }
        }
    }
    for k in b.keys().filter(|k| !a.contains_key(*k)) {
        out.push(change("+", what, k, String::new()));
    }
}

/// What changed going from `a` to `b`. Values are compared by fingerprint only.
pub fn diff(a: &crate::model::Library, b: &crate::model::Library) -> Vec<Value> {
    let mut out = vec![];
    let projects = |l: &crate::model::Library| -> BTreeMap<String, String> {
        l.projects
            .iter()
            .map(|(k, p)| (k.clone(), p.description.clone()))
            .collect()
    };
    compare_maps(&mut out, "project", &projects(a), &projects(b), |x, y| {
        if x != y {
            vec!["description changed".into()]
        } else {
            vec![]
        }
    });
    let channels = |l: &crate::model::Library| -> BTreeMap<String, (bool, bool)> {
        l.projects
            .iter()
            .flat_map(|(pn, p)| {
                p.channels
                    .iter()
                    .map(move |(cn, c)| (format!("{pn}/{cn}"), (c.inherit, c.protected)))
            })
            .collect()
    };
    compare_maps(&mut out, "channel", &channels(a), &channels(b), |x, y| {
        let mut d = vec![];
        if x.0 != y.0 {
            d.push(format!("inherit {} → {}", x.0, y.0));
        }
        if x.1 != y.1 {
            d.push(format!("protected {} → {}", x.1, y.1));
        }
        d
    });
    compare_maps(
        &mut out,
        "secret",
        &all_secrets(a),
        &all_secrets(b),
        |x, y| {
            let mut d = vec![];
            match (x.fingerprint(), y.fingerprint()) {
                (Some(f), Some(g)) if f != g => d.push(format!("value changed ({f} → {g})")),
                (None, Some(g)) => d.push(format!("value set ({g})")),
                (Some(f), None) => d.push(format!("value removed (was {f})")),
                _ => {}
            }
            if x.protection != y.protection {
                d.push(format!("{} → {}", x.protection, y.protection));
            }
            if x.description != y.description {
                d.push("description changed".into());
            }
            if x.tags != y.tags {
                d.push("tags changed".into());
            }
            d
        },
    );
    let dests = |l: &crate::model::Library| -> BTreeMap<String, Value> {
        l.projects
            .iter()
            .flat_map(|(pn, p)| {
                p.channels.iter().flat_map(move |(cn, c)| {
                    c.destinations.values().map(move |d| {
                        (format!("{pn}/{cn} {}", d.name), json!({"kind": d.kind, "select": d.select, "config": d.config, "connection": d.connection}))
                    })
                })
            })
            .collect()
    };
    compare_maps(&mut out, "destination", &dests(a), &dests(b), |x, y| {
        let mut d = vec![];
        for k in ["kind", "select", "config", "connection"] {
            if x[k] != y[k] {
                d.push(format!("{k} changed"));
            }
        }
        d
    });
    let conns = |l: &crate::model::Library| -> BTreeMap<String, Value> {
        l.connections
            .iter()
            .map(|(k, c)| (k.clone(), json!({"kind": c.kind, "mode": c.mode, "account": c.account, "token": c.token.as_ref().map(|t| t.fp.clone())})))
            .collect()
    };
    compare_maps(&mut out, "connection", &conns(a), &conns(b), |x, y| {
        let mut d = vec![];
        if x["account"] != y["account"] {
            d.push("account changed".into());
        }
        if x["token"] != y["token"] {
            d.push("token replaced".into());
        }
        if x["mode"] != y["mode"] {
            d.push("mode changed".into());
        }
        d
    });
    let settings = |l: &crate::model::Library| -> BTreeMap<String, Value> {
        serde_json::to_value(&l.settings)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .map(|m| m.into_iter().collect())
            .unwrap_or_default()
    };
    compare_maps(&mut out, "setting", &settings(a), &settings(b), |x, y| {
        if x != y {
            vec![format!("{x} → {y}")]
        } else {
            vec![]
        }
    });
    let factors = |l: &crate::model::Library| -> BTreeMap<String, bool> {
        [
            ("authenticator app".to_string(), l.mfa.totp_secret.is_some()),
            ("Touch ID".to_string(), l.mfa.touch_id),
        ]
        .into_iter()
        .filter(|(_, on)| *on)
        .collect()
    };
    compare_maps(
        &mut out,
        "second factor",
        &factors(a),
        &factors(b),
        |_, _| vec![],
    );
    out
}

/// Open a snapshot's library: with this vault's keys when it is the same vault,
/// otherwise with the password that was current when it was taken.
pub fn open_snapshot(
    s: &Session,
    data: &[u8],
    password: Option<&str>,
) -> Result<(crate::model::Library, Snapshot)> {
    let snap = inspect_snapshot(data)?;
    let lib_bytes = snap.file("vault/library.sealed")?;
    if snap.vault_id == s.header.vault_id {
        if let Ok((lib, _)) = crate::vault::open_library_bytes(&snap.vault_id, &s.keys, &lib_bytes)
        {
            return Ok((lib, snap));
        }
    }
    let pw = password.ok_or_else(|| {
        Error::Invalid(
            "this backup is from a different vault; give the password it was made with (--password)".into(),
        )
    })?;
    let h: crate::vault::Header = serde_json::from_slice(&snap.file("vault/header.json")?)?;
    let vmk = h.unwrap(crate::vault::Unlocker::Password(pw.as_bytes()))?;
    let keys = crate::vault::Keys::from(vmk);
    let (lib, _) = crate::vault::open_library_bytes(&snap.vault_id, &keys, &lib_bytes)?;
    Ok((lib, snap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_at(t: i64) -> String {
        format!("the-pit-abcdef12-{}-g1.pitvault", stamp(t))
    }

    #[test]
    fn names_round_trip() {
        let n = name_at(1_760_000_000);
        assert_eq!(parse_name(&n), Some((1_760_000_000, Some(1))));
        assert_eq!(
            parse_name("the-pit-abcdef12-20251014-101010.pitvault").map(|x| x.1),
            Some(None)
        );
    }

    #[test]
    fn thinning_keeps_recent_and_one_per_day() {
        let now = 1_760_000_000;
        let mut names = vec![];
        for h in 0..24 * 10 {
            names.push(name_at(now - h * 3600));
        }
        let drop = thin(&names, 5, now);
        let kept = names.len() - drop.len();
        // 48 from the last two days, then one for each of the remaining ~8 days.
        assert!((55..=58).contains(&kept), "kept {kept}");
        assert!(!drop.contains(&names[0]));
    }
}
