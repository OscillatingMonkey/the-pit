//! Where The Pit keeps things. Everything lives under one directory
//! (`$PIT_HOME`, default `~/.the-pit`), owner-only.
//!
//!   vault/header.json        key slots (wrapped keys only)
//!   vault/library.sealed     the encrypted library
//!   vault/history/           the previous generations, encrypted
//!   log/audit.log            the hash-chained, encrypted audit log
//!   run/agent.sock           the agent's socket
//!   state/                   throttling and agent bookkeeping (no secrets)
//!   backups/                 default local backup location
//!   backup.toml              backup targets and schedule (no secrets)

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub fn home() -> PathBuf {
    if let Ok(h) = std::env::var("PIT_HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".the-pit")
}

pub fn vault_dir() -> PathBuf {
    home().join("vault")
}
pub fn header_path() -> PathBuf {
    vault_dir().join("header.json")
}
pub fn library_path() -> PathBuf {
    vault_dir().join("library.sealed")
}
pub fn history_dir() -> PathBuf {
    vault_dir().join("history")
}
pub fn log_path() -> PathBuf {
    home().join("log").join("audit.log")
}
/// Unix socket paths are limited to ~104 bytes. A deep `$PIT_HOME` uses a short
/// private directory instead, which must be owned by us and mode 0700.
pub fn socket_path() -> PathBuf {
    let p = home().join("run").join("agent.sock");
    if p.as_os_str().len() < 100 {
        return p;
    }
    let uid = unsafe { libc::getuid() };
    let tag = &crate::crypto::sha256_hex(home().as_os_str().as_encoded_bytes())[..12];
    PathBuf::from(format!("/tmp/the-pit-{uid}-{tag}")).join("agent.sock")
}

/// Before talking to a socket, make sure it and its folder belong to us and
/// nobody else can write to the folder (a socket placed by someone else would
/// receive our password).
pub fn verify_socket(sock: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = unsafe { libc::getuid() };
    let refuse = |what: &str| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{what} is not private to you; refusing to use it"),
        ))
    };
    if let Some(dir) = sock.parent() {
        if let Ok(md) = fs::symlink_metadata(dir) {
            if !md.is_dir() || md.uid() != uid || md.mode() & 0o022 != 0 {
                return refuse(&dir.display().to_string());
            }
        }
    }
    if let Ok(md) = fs::symlink_metadata(sock) {
        if md.uid() != uid || md.file_type().is_symlink() {
            return refuse(&sock.display().to_string());
        }
    }
    Ok(())
}

fn check_socket_dir() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let sock = socket_path();
    let dir = sock
        .parent()
        .ok_or_else(|| Error::Invalid("socket path".into()))?;
    match fs::symlink_metadata(dir) {
        Ok(md) => {
            let uid = unsafe { libc::getuid() };
            if !md.is_dir() || md.uid() != uid || md.mode() & 0o077 != 0 {
                return Err(Error::Refused(format!(
                    "{} is not a private directory owned by you",
                    dir.display()
                )));
            }
        }
        Err(_) => {
            fs::create_dir(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}
pub fn state_dir() -> PathBuf {
    home().join("state")
}
pub fn backups_dir() -> PathBuf {
    home().join("backups")
}
pub fn backup_config() -> PathBuf {
    home().join("backup.toml")
}

/// Create a directory (and parents) with mode 0700, and tighten it if it exists.
pub fn private_dir(p: &Path) -> Result<()> {
    fs::create_dir_all(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn ensure_layout() -> Result<()> {
    for d in [
        home(),
        vault_dir(),
        history_dir(),
        home().join("log"),
        home().join("run"),
        state_dir(),
        backups_dir(),
    ] {
        private_dir(&d)?;
    }
    check_socket_dir()
}

/// Write a file atomically with mode 0600: temp file, fsync, rename, fsync dir.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::Invalid("path has no parent".into()))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        crate::crypto::random_id()
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Append one line to a 0600 file.
pub fn append_private(path: &Path, line: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line)?;
    f.write_all(b"\n")?;
    f.sync_data()?;
    Ok(())
}

/// Refuse to operate if The Pit's home is group/world accessible or not ours.
pub fn check_home_permissions() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let h = home();
    if !h.exists() {
        return Ok(());
    }
    let md = fs::metadata(&h)?;
    let uid = unsafe { libc::getuid() };
    if md.uid() != uid {
        return Err(Error::Refused(format!(
            "{} is not owned by you",
            h.display()
        )));
    }
    if md.mode() & 0o077 != 0 {
        fs::set_permissions(&h, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// True when `p` sits inside a git work tree.
pub fn in_git_tree(p: &Path) -> Option<PathBuf> {
    let mut cur = if p.is_dir() { Some(p) } else { p.parent() };
    while let Some(d) = cur {
        if d.join(".git").exists() {
            return Some(d.to_path_buf());
        }
        cur = d.parent();
    }
    None
}

/// True if git says `p` is ignored in its repository.
pub fn git_ignored(repo: &Path, p: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["check-ignore", "-q", "--no-index"])
        .arg(p)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(h) = dirs::home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(s)
}

/// The executable's own path, for launchd and MCP configuration.
pub fn self_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("pit"))
}

/// PATH used when The Pit runs vendor CLIs from the agent (launchd gives a minimal PATH).
pub fn tool_path() -> String {
    let mut parts: Vec<String> = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(String::from)
        .collect();
    for extra in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        if !parts.iter().any(|p| p == extra) {
            parts.push(extra.into());
        }
    }
    if let Some(h) = dirs::home_dir() {
        for extra in [".fly/bin", ".cargo/bin", ".local/bin"] {
            let p = h.join(extra).display().to_string();
            if !parts.contains(&p) {
                parts.push(p);
            }
        }
    }
    parts.join(":")
}
