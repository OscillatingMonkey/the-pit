//! The vault on disk.
//!
//! A random 256-bit vault key encrypts everything. That key is never stored as
//! is; it is wrapped once per *slot*, and any one slot opens the vault:
//!
//!   password  — Argon2id(password) wraps the vault key
//!   recovery  — the recovery key (shown once at setup) wraps the vault key
//!   device    — a random key kept in the OS keychain wraps the vault key;
//!               used only together with Touch ID, for quick unlock
//!
//! Changing the password rewraps one slot; nothing else is re-encrypted.

use std::fs;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key, Sealed};
use crate::error::{Error, Result};
use crate::model::{now, Library};
use crate::{keychain, paths};

pub const FORMAT: &str = "the-pit/1";
const HISTORY_KEEP: usize = 30;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub format: String,
    pub vault_id: String,
    pub created: i64,
    pub slots: Vec<Slot>,
    #[serde(default)]
    pub identity_public: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Slot {
    pub id: String,
    pub kind: String,
    pub created: i64,
    #[serde(default)]
    pub kdf: Option<KdfParams>,
    pub wrapped: Sealed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LibraryFile {
    pub format: String,
    pub vault_id: String,
    pub generation: u64,
    pub sealed: Sealed,
}

pub enum Unlocker<'a> {
    Password(&'a [u8]),
    Recovery(&'a [u8]),
    Device,
}

impl Header {
    pub fn load() -> Result<Header> {
        let raw = fs::read(paths::header_path()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound("no vault here — run `pit init`".into())
            } else {
                e.into()
            }
        })?;
        let h: Header = serde_json::from_slice(&raw)?;
        if h.format != FORMAT {
            return Err(Error::Invalid(format!("unknown vault format {}", h.format)));
        }
        Ok(h)
    }

    pub fn save(&self) -> Result<()> {
        paths::write_private(&paths::header_path(), &serde_json::to_vec_pretty(self)?)
    }

    fn aad(&self, slot_id: &str, kind: &str) -> Vec<u8> {
        format!("{FORMAT}|slot|{}|{}|{}", self.vault_id, slot_id, kind).into_bytes()
    }

    pub fn has(&self, kind: &str) -> bool {
        self.slots.iter().any(|s| s.kind == kind)
    }

    fn device_account(&self) -> String {
        format!("vault-{}-device", self.vault_id)
    }

    /// Unwrap the vault key with one unlocker.
    pub fn unwrap(&self, how: Unlocker) -> Result<Key> {
        match how {
            Unlocker::Password(pw) => {
                for s in self.slots.iter().filter(|s| s.kind == "password") {
                    let kdf = s.kdf.as_ref().ok_or(Error::Denied)?;
                    let kek = kdf.derive(pw)?;
                    if let Ok(k) = crypto::open(&kek, &s.wrapped, &self.aad(&s.id, &s.kind)) {
                        return Key::from_bytes(&k);
                    }
                }
                Err(Error::Denied)
            }
            Unlocker::Recovery(rk) => {
                let kek = Key::from_bytes(rk)?.derive("recovery-slot");
                for s in self.slots.iter().filter(|s| s.kind == "recovery") {
                    if let Ok(k) = crypto::open(&kek, &s.wrapped, &self.aad(&s.id, &s.kind)) {
                        return Key::from_bytes(&k);
                    }
                }
                Err(Error::Denied)
            }
            Unlocker::Device => {
                let dk = keychain::get(&self.device_account())?.ok_or(Error::Denied)?;
                let kek = Key::from_bytes(&dk)?.derive("device-slot");
                for s in self.slots.iter().filter(|s| s.kind == "device") {
                    if let Ok(k) = crypto::open(&kek, &s.wrapped, &self.aad(&s.id, &s.kind)) {
                        return Key::from_bytes(&k);
                    }
                }
                Err(Error::Denied)
            }
        }
    }

    fn wrap(&self, kind: &str, kek: &Key, vmk: &Key, kdf: Option<KdfParams>) -> Slot {
        let id = crypto::random_id()[..12].to_string();
        let wrapped = crypto::seal(kek, vmk.as_bytes(), &self.aad(&id, kind));
        Slot {
            id,
            kind: kind.into(),
            created: now(),
            kdf,
            wrapped,
        }
    }

    /// Replace the password slot.
    pub fn set_password(&mut self, vmk: &Key, password: &[u8]) -> Result<()> {
        let kdf = KdfParams::new_password();
        let kek = kdf.derive(password)?;
        let slot = self.wrap("password", &kek, vmk, Some(kdf));
        self.slots.retain(|s| s.kind != "password");
        self.slots.push(slot);
        Ok(())
    }

    /// Replace the recovery slot. Returns the new recovery key (show once).
    pub fn new_recovery(&mut self, vmk: &Key) -> Result<Zeroizing<Vec<u8>>> {
        let rk = Zeroizing::new(crypto::random_bytes(32));
        let kek = Key::from_bytes(&rk)?.derive("recovery-slot");
        let slot = self.wrap("recovery", &kek, vmk, None);
        self.slots.retain(|s| s.kind != "recovery");
        self.slots.push(slot);
        Ok(rk)
    }

    /// Create (or replace) the device slot and its keychain item.
    pub fn enable_device(&mut self, vmk: &Key) -> Result<()> {
        let dk = Key::generate();
        keychain::set(&self.device_account(), dk.as_bytes())?;
        let slot = self.wrap("device", &dk.derive("device-slot"), vmk, None);
        self.slots.retain(|s| s.kind != "device");
        self.slots.push(slot);
        Ok(())
    }

    pub fn disable_device(&mut self) -> Result<()> {
        self.slots.retain(|s| s.kind != "device");
        keychain::delete(&self.device_account())
    }
}

/// Keys derived from the vault key, one per purpose.
pub struct Keys {
    pub vmk: Key,
    pub doc: Key,
    pub value: Key,
    pub log: Key,
    pub fp: Key,
}

impl Keys {
    pub fn from(vmk: Key) -> Keys {
        Keys {
            doc: vmk.derive("library"),
            value: vmk.derive("values"),
            log: vmk.derive("audit-log"),
            fp: vmk.derive("fingerprint"),
            vmk,
        }
    }
}

fn library_aad(vault_id: &str, generation: u64) -> Vec<u8> {
    format!("{FORMAT}|library|{vault_id}|{generation}").into_bytes()
}

fn generation_account(vault_id: &str) -> String {
    format!("vault-{vault_id}-generation")
}

/// The newest library generation saved on this computer, kept in the OS
/// keychain (outside the vault folder) so an older library file cannot be
/// swapped back in unnoticed.
fn recorded_generation(h: &Header) -> Option<u64> {
    keychain::get(&generation_account(&h.vault_id))
        .ok()
        .flatten()
        .and_then(|b| std::str::from_utf8(&b).ok().and_then(|s| s.parse().ok()))
}

fn record_generation(h: &Header, generation: u64) {
    if recorded_generation(h)
        .map(|g| generation > g)
        .unwrap_or(true)
    {
        let _ = keychain::set(
            &generation_account(&h.vault_id),
            generation.to_string().as_bytes(),
        );
    }
}

/// Forget the recorded generation (a deliberate restore of an older vault).
pub fn reset_generation(vault_id: &str) {
    let _ = keychain::delete(&generation_account(vault_id));
}

pub fn exists() -> bool {
    paths::header_path().exists()
}

/// Create a new vault. Returns (header, keys, recovery key).
pub fn create(password: &[u8], lib: &Library) -> Result<(Header, Keys, Zeroizing<Vec<u8>>, u64)> {
    if exists() {
        return Err(Error::Exists(format!(
            "a vault at {}",
            paths::home().display()
        )));
    }
    paths::ensure_layout()?;
    let vmk = Key::generate();
    let mut h = Header {
        format: FORMAT.into(),
        vault_id: crypto::random_id(),
        created: now(),
        slots: vec![],
        identity_public: crypto::b64e(&lib.owner.identity_public),
    };
    h.set_password(&vmk, password)?;
    let rk = h.new_recovery(&vmk)?;
    let keys = Keys::from(vmk);
    let generation = save_library(&h, &keys, lib, 0)?;
    h.save()?;
    Ok((h, keys, rk, generation))
}

pub fn load_library(h: &Header, keys: &Keys) -> Result<(Library, u64)> {
    let raw = fs::read(paths::library_path())?;
    let f: LibraryFile = serde_json::from_slice(&raw)?;
    if f.vault_id != h.vault_id {
        return Err(Error::Invalid(
            "library does not belong to this vault".into(),
        ));
    }
    let pt = crypto::open(
        &keys.doc,
        &f.sealed,
        &library_aad(&h.vault_id, f.generation),
    )?;
    let lib: Library = serde_json::from_slice(&pt)?;
    if let Some(min) = recorded_generation(h) {
        if f.generation < min {
            return Err(Error::Refused(format!(
                "the library on disk is older than the last one this computer saved (generation {} < {min}). \
                 If you restored a backup, use `pit backup restore`; otherwise the vault files may have been replaced",
                f.generation
            )));
        }
    }
    Ok((lib, f.generation))
}

/// Encrypt and write the library as a new generation; keep the previous one in history.
pub fn save_library(h: &Header, keys: &Keys, lib: &Library, prev_generation: u64) -> Result<u64> {
    let generation = prev_generation + 1;
    let pt = Zeroizing::new(serde_json::to_vec(lib)?);
    let sealed = crypto::seal(&keys.doc, &pt, &library_aad(&h.vault_id, generation));
    let file = LibraryFile {
        format: FORMAT.into(),
        vault_id: h.vault_id.clone(),
        generation,
        sealed,
    };
    let lp = paths::library_path();
    if lp.exists() {
        let hist = paths::history_dir().join(format!("library.{:08}.sealed", prev_generation));
        let _ = fs::copy(&lp, &hist);
        prune_history();
    }
    paths::write_private(&lp, &serde_json::to_vec(&file)?)?;
    record_generation(h, generation);
    Ok(generation)
}

fn prune_history() {
    if let Ok(rd) = fs::read_dir(paths::history_dir()) {
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        if files.len() > HISTORY_KEEP {
            for f in &files[..files.len() - HISTORY_KEEP] {
                let _ = fs::remove_file(f);
            }
        }
    }
}

/// List earlier generations that can be restored.
pub fn history() -> Vec<(u64, std::path::PathBuf)> {
    let mut out = vec![];
    if let Ok(rd) = fs::read_dir(paths::history_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if let Some(g) = p
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("library."))
                .and_then(|n| n.strip_suffix(".sealed"))
                .and_then(|n| n.parse::<u64>().ok())
            {
                out.push((g, p));
            }
        }
    }
    out.sort();
    out
}

/// Open a library file's bytes (from a backup) with this vault's keys.
pub fn open_library_bytes(vault_id: &str, keys: &Keys, bytes: &[u8]) -> Result<(Library, u64)> {
    let f: LibraryFile = serde_json::from_slice(bytes)?;
    if f.vault_id != vault_id {
        return Err(Error::Invalid(
            "that library belongs to a different vault".into(),
        ));
    }
    let pt = crypto::open(&keys.doc, &f.sealed, &library_aad(vault_id, f.generation))?;
    Ok((serde_json::from_slice(&pt)?, f.generation))
}

/// The generation number a library file carries (readable without keys).
pub fn generation_of(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<LibraryFile>(bytes)
        .map(|f| f.generation)
        .unwrap_or(0)
}

pub fn load_generation(h: &Header, keys: &Keys, path: &std::path::Path) -> Result<Library> {
    let f: LibraryFile = serde_json::from_slice(&fs::read(path)?)?;
    let pt = crypto::open(
        &keys.doc,
        &f.sealed,
        &library_aad(&h.vault_id, f.generation),
    )?;
    Ok(serde_json::from_slice(&pt)?)
}

/// Crypto-shred: overwrite every key slot with random bytes, delete the vault,
/// the history, the log and the keychain items. Without the slots the
/// ciphertext is unrecoverable even from a disk image.
pub fn destroy() -> Result<()> {
    if let Ok(mut h) = Header::load() {
        let _ = h.disable_device();
        for s in h.slots.iter_mut() {
            s.wrapped.c = crypto::random_bytes(s.wrapped.c.len());
            s.wrapped.n = crypto::random_bytes(s.wrapped.n.len());
            if let Some(k) = s.kdf.as_mut() {
                k.salt = crypto::random_bytes(k.salt.len());
            }
        }
        let _ = h.save();
        let _ = keychain::delete(&format!("vault-{}-device", h.vault_id));
        reset_generation(&h.vault_id);
    }
    for p in [
        paths::header_path(),
        paths::library_path(),
        paths::log_path(),
    ] {
        overwrite_and_remove(&p);
    }
    if let Ok(rd) = fs::read_dir(paths::history_dir()) {
        for e in rd.flatten() {
            overwrite_and_remove(&e.path());
        }
    }
    let _ = fs::remove_dir_all(paths::vault_dir());
    let _ = fs::remove_dir_all(paths::home().join("log"));
    let _ = fs::remove_dir_all(paths::state_dir());
    Ok(())
}

fn overwrite_and_remove(p: &std::path::Path) {
    if let Ok(md) = fs::metadata(p) {
        let _ = paths::write_private(p, &crypto::random_bytes(md.len() as usize));
        let _ = fs::remove_file(p);
    }
}
