//! The agent: the only process that ever holds the vault key.
//!
//! It listens on a Unix socket in a 0700 directory, accepts connections only
//! from its own uid, keeps an unlocked session for a bounded time, and asks a
//! human for approval before anything sensitive.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::model::{now, Library};
use crate::protocol::{Auth, Request, Response};
use crate::vault::{self, Header, Keys, Unlocker};
use crate::{audit, crypto, harden, ops, paths, presence, totp};

pub struct Session {
    pub header: Header,
    pub keys: Keys,
    pub lib: Library,
    pub generation: u64,
    pub opened: Instant,
    pub last: Instant,
    pub expires: Instant,
    pub elevated_until: Option<Instant>,
    pub elevated_ai: bool,
    /// Approvals a person gave recently, each covering one scope from one terminal.
    pub windows: Vec<Window>,
    /// Open receive windows for shared secrets. Their keys exist only here, so
    /// a window that closes — or a session that ends — takes its key with it.
    pub inbox: Vec<Inbox>,
}

/// One receive window (see `share`): a key pair for one incoming secret.
pub struct Inbox {
    pub key: crypto_box::SecretKey,
    pub until: Instant,
    pub expires: i64,
}

impl Inbox {
    pub fn id(&self) -> String {
        hex::encode(&self.key.public_key().as_bytes()[..4])
    }
}

/// After a person approves a change, more changes to the same scope from the
/// same terminal (or the same app) go ahead without asking again until `until`.
pub struct Window {
    pub origin: Origin,
    pub scope: String,
    pub until: Instant,
}

/// The program a request came through: pid and start time.
pub type Origin = (i32, u64);

impl Session {
    pub fn save(&mut self) -> Result<()> {
        self.lib.log_seq = self.lib.log_seq.max(audit::last_seq());
        self.generation =
            vault::save_library(&self.header, &self.keys, &self.lib, self.generation)?;
        Ok(())
    }

    pub fn audit(&self, event: &str, actor: &str, data: Value) {
        let _ = audit::record(&self.keys, event, actor, data);
    }

    /// For operations that hand out values: no log entry, no value.
    pub fn audit_strict(&self, event: &str, actor: &str, data: Value) -> Result<()> {
        audit::record(&self.keys, event, actor, data)
            .map(|_| ())
            .map_err(|e| {
                Error::Invalid(format!(
                    "could not write the audit log ({e}); nothing was handed out"
                ))
            })
    }

    fn expired(&self) -> bool {
        let now = Instant::now();
        now >= self.expires
            || now.duration_since(self.last) >= Duration::from_secs(self.lib.settings.idle_secs)
    }

    pub fn elevated(&self, client: &str) -> bool {
        match self.elevated_until {
            Some(t) if Instant::now() < t => client != "mcp" || self.elevated_ai,
            _ => false,
        }
    }

    fn in_window(&self, origin: Origin, scope: &str) -> bool {
        let now = Instant::now();
        self.lib.settings.approval_window_secs > 0
            && self
                .windows
                .iter()
                .any(|w| w.origin == origin && w.scope == scope && now < w.until)
    }
}

struct Pending {
    reason: String,
    digest: String,
    created: Instant,
    approved: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Throttle {
    failures: u32,
    last: i64,
}

pub struct State {
    pub session: Option<Session>,
    pending: HashMap<String, Pending>,
}

pub type Shared = Arc<Mutex<State>>;

/// The identity of whoever is on the other end of a request.
#[derive(Clone)]
pub struct Caller {
    pub client: String,
    pub actor: String,
    pub origin: Option<Origin>,
}

/// Wrong answers at the approval gate after which the session is closed.
const LOCK_AFTER_FAILURES: u32 = 6;

fn throttle_path() -> std::path::PathBuf {
    paths::state_dir().join("throttle.json")
}

/// The failure count is kept in three places — a file, the OS keychain and this
/// process — and the highest one counts, so clearing one does not clear it.
static THROTTLE: Mutex<Throttle> = Mutex::new(Throttle {
    failures: 0,
    last: 0,
});

fn throttle_account() -> String {
    let home = paths::home();
    format!(
        "throttle-{}",
        &crypto::sha256_hex(home.to_string_lossy().as_bytes())[..16]
    )
}

fn throttle_load() -> Throttle {
    let file: Throttle = std::fs::read(throttle_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let kc: Throttle = crate::keychain::get(&throttle_account())
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mem = THROTTLE.lock().unwrap_or_else(|p| p.into_inner());
    [
        file,
        kc,
        Throttle {
            failures: mem.failures,
            last: mem.last,
        },
    ]
    .into_iter()
    .max_by_key(|t| (t.failures, t.last))
    .unwrap_or_default()
}

fn throttle_check() -> Result<()> {
    let t = throttle_load();
    if t.failures < 3 {
        return Ok(());
    }
    let wait = (1i64 << (t.failures - 3).min(12)).min(3600);
    let left = t.last + wait - now();
    if left > 0 {
        Err(Error::Throttled(left as u64))
    } else {
        Ok(())
    }
}

fn throttle_fail() {
    let mut t = throttle_load();
    t.failures += 1;
    t.last = now();
    let bytes = serde_json::to_vec(&t).unwrap_or_default();
    let _ = paths::write_private(&throttle_path(), &bytes);
    let _ = crate::keychain::set(&throttle_account(), &bytes);
    *THROTTLE.lock().unwrap_or_else(|p| p.into_inner()) = t;
}

fn throttle_reset() -> u32 {
    let t = throttle_load();
    let _ = std::fs::remove_file(throttle_path());
    let _ = crate::keychain::delete(&throttle_account());
    *THROTTLE.lock().unwrap_or_else(|p| p.into_inner()) = Throttle::default();
    t.failures
}

pub fn run(foreground: bool) -> Result<()> {
    harden::agent();
    paths::check_home_permissions()?;
    paths::ensure_layout()?;
    let sock = paths::socket_path();
    if UnixStream::connect(&sock).is_ok() {
        return Err(Error::Exists("an agent is already running".into()));
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    if foreground {
        eprintln!("the pit agent listening on {}", sock.display());
    }
    let state: Shared = Arc::new(Mutex::new(State {
        session: None,
        pending: HashMap::new(),
    }));

    // Reaper: drop expired sessions from memory even when nobody is asking.
    {
        let st = state.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
            if g.session.as_ref().map(|s| s.expired()).unwrap_or(false) {
                if let Some(s) = g.session.take() {
                    s.audit("lock", "agent", json!({"reason": "timeout"}));
                }
            }
            if let Some(s) = g.session.as_mut() {
                let now = Instant::now();
                s.inbox.retain(|w| now < w.until);
            }
            g.pending
                .retain(|_, p| p.created.elapsed() < Duration::from_secs(300));
            if !paths::socket_path().exists() {
                std::process::exit(0);
            }
        });
    }

    std::thread::spawn(backup_watch);

    let me = unsafe { libc::getuid() };
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Some((uid, pid)) = harden::peer(stream.as_raw_fd()) else {
            continue;
        };
        if uid != me {
            continue;
        }
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let st = state.clone();
        std::thread::spawn(move || {
            let _ = serve(stream, st, pid);
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Connections served at once; more are closed until one finishes.
const MAX_CONNECTIONS: usize = 64;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Largest request accepted on the socket (file secrets and bundles included).
const MAX_REQUEST: u64 = 64 * 1024 * 1024;

fn serve(stream: UnixStream, state: Shared, pid: i32) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.ends_with('\n') && line.len() as u64 >= MAX_REQUEST {
        line.zeroize();
        return Err(Error::Invalid("request too large".into()));
    }
    let req: std::result::Result<Request, _> = serde_json::from_str(&line);
    line.zeroize();
    let resp = match req {
        Ok(req) => {
            let caller = Caller {
                client: if req.client.is_empty() {
                    "cli".into()
                } else {
                    req.client.clone()
                },
                actor: describe_peer(pid, &req.client),
                origin: origin(pid),
            };
            let shutdown = req.op == "shutdown";
            let r = Response::from_result(handle(&state, &caller, req));
            if shutdown {
                let _ = std::fs::remove_file(paths::socket_path());
                let mut s = stream;
                let _ = s.write_all(&serde_json::to_vec(&r).unwrap_or_default());
                let _ = s.write_all(b"\n");
                std::process::exit(0);
            }
            r
        }
        Err(_) => Response::from_result(Err(Error::Invalid("malformed request".into()))),
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    let mut s = stream;
    s.write_all(&out)?;
    out.zeroize();
    Ok(())
}

fn describe_peer(pid: i32, client: &str) -> String {
    let exe = harden::process_path(pid);
    let ppid = harden::parent_pid(pid);
    let parent = if ppid > 0 {
        harden::process_path(ppid)
    } else {
        String::new()
    };
    let short = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    if parent.is_empty() {
        format!("{} ({})", client, short(&exe))
    } else {
        format!("{} ({} ← {})", client, short(&exe), short(&parent))
    }
}

/// Where a request comes from, for approval windows: the nearest program above
/// `pit` that is not a shell — a terminal tab's login process, or the app that
/// ran the command. A different tab or app has to be approved on its own.
fn origin(pid: i32) -> Option<Origin> {
    const SHELLS: &[&str] = &[
        "sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "nu",
    ];
    let mut p = harden::parent_pid(pid);
    for _ in 0..16 {
        if p <= 1 {
            return None;
        }
        let path = harden::process_path(p);
        let name = path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_start_matches('-');
        if !SHELLS.contains(&name) {
            return harden::start_time(p).map(|t| (p, t));
        }
        p = harden::parent_pid(p);
    }
    None
}

fn digest(req: &Request) -> String {
    crypto::sha256_hex(format!("{}|{}", req.op, req.args).as_bytes())
}

/// Ops that run without an unlocked session.
const OPEN_OPS: &[&str] = &[
    "ping",
    "status",
    "init",
    "unlock",
    "lock",
    "shutdown",
    "approvals",
];

/// What shell and console completion may ask for: names, never values.
const COMPLETE_OPS: &[&str] = &[
    "ping",
    "status",
    "tree",
    "approvals",
    "contact.list",
    "share.pending",
    "settings.get",
];

fn handle(state: &Shared, caller: &Caller, req: Request) -> Result<Value> {
    let completing = caller.client == "complete";
    if completing && !COMPLETE_OPS.contains(&req.op.as_str()) {
        return Err(Error::Refused(format!(
            "`{}` is not available to completion",
            req.op
        )));
    }
    if !OPEN_OPS.contains(&req.op.as_str()) {
        let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
        match g.session.as_mut() {
            // Pressing Tab is not using the pit: it does not hold off the idle lock.
            Some(s) if !s.expired() => {
                if !completing {
                    s.last = Instant::now()
                }
            }
            Some(_) => {
                if let Some(s) = g.session.take() {
                    s.audit("lock", "agent", json!({"reason": "timeout"}));
                }
                return Err(Error::Locked);
            }
            None => return Err(Error::Locked),
        }
    }
    match req.op.as_str() {
        "ping" => Ok(json!({"pong": true})),
        "status" => status(state),
        "init" => init(state, caller, &req),
        "unlock" => unlock(state, caller, &req),
        "lock" | "shutdown" => {
            let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(s) = g.session.take() {
                s.audit("lock", &caller.actor, json!({"reason": req.op}));
            }
            g.pending.clear();
            Ok(json!({"locked": true}))
        }
        "approvals" => {
            let g = state.lock().unwrap_or_else(|p| p.into_inner());
            let list: Vec<Value> = g
                .pending
                .iter()
                .filter(|(_, p)| !p.approved)
                .map(|(t, p)| json!({"ticket": t, "reason": p.reason, "age_secs": p.created.elapsed().as_secs()}))
                .collect();
            Ok(json!({"pending": list}))
        }
        "approve" => {
            let ticket = req
                .args
                .get("ticket")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let reason = {
                let g = state.lock().unwrap_or_else(|p| p.into_inner());
                g.pending
                    .get(&ticket)
                    .map(|p| p.reason.clone())
                    .ok_or_else(|| Error::NotFound(format!("ticket {ticket}")))?
            };
            if caller.client == "mcp" {
                return Err(Error::Refused(
                    "approvals are given by a person, not by an AI client".into(),
                ));
            }
            gate(state, caller, &req, &format!("Approve: {reason}"), true)?;
            let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(p) = g.pending.get_mut(&ticket) {
                p.approved = true;
            }
            if let Some(s) = g.session.as_ref() {
                s.audit(
                    "approve",
                    &caller.actor,
                    json!({"ticket": ticket, "reason": reason}),
                );
            }
            Ok(json!({"approved": ticket}))
        }
        _ => {
            if let Some(reason) = ops::needs_approval(state, caller, &req)? {
                gate(state, caller, &req, &reason, false)?;
            }
            let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
            let s = g.session.as_mut().ok_or(Error::Locked)?;
            // A failed operation leaves the in-memory library exactly as it was.
            let before = s.lib.clone();
            let r = ops::dispatch(s, caller, &req);
            if r.is_err() {
                s.lib = before;
            }
            r
        }
    }
}

fn status(state: &Shared) -> Result<Value> {
    let initialized = vault::exists();
    let header = Header::load().ok();
    let g = state.lock().unwrap_or_else(|p| p.into_inner());
    let mut v = json!({
        "initialized": initialized,
        "unlocked": false,
        "home": paths::home().display().to_string(),
        "touch_id_hardware": presence::available(),
        "pending_approvals": g.pending.values().filter(|p| !p.approved).count(),
    });
    if let Some(h) = &header {
        v["vault_id"] = json!(h.vault_id);
        v["quick_unlock"] = json!(h.has("device"));
    }
    if let Some(s) = g.session.as_ref().filter(|s| !s.expired()) {
        let now = Instant::now();
        v["unlocked"] = json!(true);
        v["owner"] = json!(s.lib.owner.name);
        v["expires_in"] = json!(s.expires.saturating_duration_since(now).as_secs());
        v["idle_in"] = json!(Duration::from_secs(s.lib.settings.idle_secs)
            .saturating_sub(now.duration_since(s.last))
            .as_secs());
        v["elevated_in"] = json!(s
            .elevated_until
            .map(|t| t.saturating_duration_since(now).as_secs())
            .unwrap_or(0));
        v["mfa"] = json!({"touch_id": s.lib.mfa.touch_id, "totp": s.lib.mfa.totp_secret.is_some()});
        v["projects"] = json!(s.lib.projects.len());
    }
    Ok(v)
}

fn arg_str<'a>(req: &'a Request, k: &str) -> Option<&'a str> {
    req.args.get(k).and_then(|v| v.as_str())
}

fn init(state: &Shared, caller: &Caller, req: &Request) -> Result<Value> {
    if caller.client == "mcp" {
        return Err(Error::Refused(
            "a vault is created by a person at a terminal".into(),
        ));
    }
    let password = req
        .auth
        .as_ref()
        .and_then(|a| a.password.as_deref())
        .ok_or_else(|| Error::Invalid("a password is required".into()))?;
    let name = arg_str(req, "name").unwrap_or("owner").to_string();
    let touch_id = req
        .args
        .get("touch_id")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && presence::available();
    let quick = req
        .args
        .get("quick_unlock")
        .and_then(|v| v.as_bool())
        .unwrap_or(touch_id);

    let id_secret = crypto_box::SecretKey::generate(&mut rand_core::OsRng);
    let lib = Library {
        version: crate::model::LIBRARY_VERSION,
        owner: crate::model::Owner {
            name,
            identity_public: id_secret.public_key().as_bytes().to_vec(),
            identity_secret: id_secret.to_bytes().to_vec(),
            created: now(),
        },
        settings: Default::default(),
        globals: Default::default(),
        projects: Default::default(),
        connections: Default::default(),
        contacts: Default::default(),
        mfa: crate::model::Mfa {
            touch_id,
            totp_secret: None,
            totp_last_step: 0,
        },
        last_password_unlock: now(),
        log_seq: 0,
    };
    let (mut header, keys, rk, generation) = vault::create(password.as_bytes(), &lib)?;
    if quick {
        header.enable_device(&keys.vmk)?;
        header.save()?;
    }
    let code = crate::codes::encode("R", &rk);
    let session = new_session(header, keys, lib, generation);
    session.audit(
        "init",
        &caller.actor,
        json!({"touch_id": touch_id, "quick_unlock": quick}),
    );
    let vault_id = session.header.vault_id.clone();
    let identity = crate::codes::encode("ID", &session.lib.owner.identity_public);
    state.lock().unwrap_or_else(|p| p.into_inner()).session = Some(session);
    Ok(
        json!({"recovery_code": code, "vault_id": vault_id, "identity": identity, "touch_id": touch_id, "quick_unlock": quick}),
    )
}

fn new_session(header: Header, keys: Keys, lib: Library, generation: u64) -> Session {
    let now = Instant::now();
    let secs = lib.settings.session_secs;
    Session {
        header,
        keys,
        lib,
        generation,
        opened: now,
        last: now,
        expires: now + Duration::from_secs(secs),
        elevated_until: None,
        elevated_ai: false,
        windows: vec![],
        inbox: vec![],
    }
}

fn unlock(state: &Shared, caller: &Caller, req: &Request) -> Result<Value> {
    if caller.client == "mcp" {
        return Err(Error::Refused(
            "the pit is unlocked by a person: run `pit unlock` in a terminal".into(),
        ));
    }
    throttle_check()?;
    let header = Header::load()?;
    let method = arg_str(req, "method").unwrap_or("password");
    let auth = req.auth.as_ref();

    let vmk = match method {
        "password" => {
            let pw = auth
                .and_then(|a| a.password.as_deref())
                .ok_or_else(|| Error::Invalid("password required".into()))?;
            header.unwrap(Unlocker::Password(pw.as_bytes()))
        }
        "recovery" => {
            let code = arg_str(req, "code")
                .ok_or_else(|| Error::Invalid("recovery code required".into()))?;
            let rk = if code.trim_start().to_uppercase().starts_with("PIT-S-") {
                let shares: Vec<Vec<u8>> = code
                    .split([',', '\n'])
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| crate::codes::decode("S", s).map(|z| z.to_vec()))
                    .collect::<Result<_>>()?;
                crate::shamir::combine(&shares)?
            } else {
                crate::codes::decode("R", code)?
            };
            header.unwrap(Unlocker::Recovery(&rk))
        }
        "touchid" => {
            if !header.has("device") {
                return Err(Error::Invalid(
                    "quick unlock is not enabled — unlock with your password".into(),
                ));
            }
            presence::confirm("unlock The Pit")?;
            header.unwrap(Unlocker::Device)
        }
        _ => return Err(Error::Invalid(format!("unknown unlock method {method}"))),
    };
    let vmk = match vmk {
        Ok(k) => k,
        Err(e) => {
            throttle_fail();
            return Err(e);
        }
    };
    let keys = Keys::from(vmk);
    let (mut lib, generation) = vault::load_library(&header, &keys)?;

    match method {
        "touchid" => {
            let max = lib.settings.password_recheck_days as i64 * 86400;
            if now() - lib.last_password_unlock > max {
                return Err(Error::Refused(format!(
                    "your password has not been used for over {} days — unlock with it",
                    lib.settings.password_recheck_days
                )));
            }
        }
        "password" if lib.mfa.any() => {
            second_factor(&mut lib, auth)?;
        }
        _ => {}
    }
    let failures = throttle_reset();
    if method == "password" {
        lib.last_password_unlock = now();
    }
    let mut session = new_session(header, keys, lib, generation);
    if let Some(secs) = req.args.get("ttl_secs").and_then(|v| v.as_u64()) {
        let secs = secs.clamp(60, session.lib.settings.session_secs.max(60));
        session.expires = session.opened + Duration::from_secs(secs);
    }
    if method == "recovery" {
        // The recovery code is the master factor: it may reset everything else
        // (password, second factors) without the factors it is replacing.
        session.elevated_until = Some(Instant::now() + Duration::from_secs(600));
    }
    if method == "password" || session.lib.mfa.totp_last_step > 0 {
        session.save()?;
    }
    session.audit(
        "unlock",
        &caller.actor,
        json!({"method": method, "failed_attempts_before": failures}),
    );
    let expires_in = session
        .expires
        .saturating_duration_since(Instant::now())
        .as_secs();
    let recovery = method == "recovery";
    state.lock().unwrap_or_else(|p| p.into_inner()).session = Some(session);
    Ok(json!({"unlocked": true, "expires_in": expires_in, "must_reset_password": recovery}))
}

/// The second factor after a password: Touch ID if enabled, else (or if Touch
/// ID is cancelled) an authenticator code.
fn second_factor(lib: &mut Library, auth: Option<&Auth>) -> Result<()> {
    if let (Some(code), Some(secret)) = (
        auth.and_then(|a| a.totp.as_deref()),
        lib.mfa.totp_secret.as_ref(),
    ) {
        return match totp::verify(secret, code, now() as u64, lib.mfa.totp_last_step) {
            Some(step) => {
                lib.mfa.totp_last_step = step;
                Ok(())
            }
            None => {
                throttle_fail();
                Err(Error::Denied)
            }
        };
    }
    if lib.mfa.touch_id
        && presence::available()
        && presence::confirm("finish unlocking The Pit").is_ok()
    {
        return Ok(());
    }
    if lib.mfa.totp_secret.is_some() {
        return Err(Error::ApprovalRequired {
            ticket: String::new(),
            reason: "enter the code from your authenticator app".into(),
            methods: vec!["totp".into()],
        });
    }
    Err(Error::Denied)
}

/// Ask a human. Order: an open elevation window, an approved ticket, an
/// authenticator code or password sent with the request, Touch ID. Otherwise a
/// ticket is issued for `pit approve`.
pub fn gate(
    state: &Shared,
    caller: &Caller,
    req: &Request,
    reason: &str,
    is_approve: bool,
) -> Result<()> {
    let d = digest(req);
    {
        let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
        if !is_approve {
            if g.session
                .as_ref()
                .map(|s| s.elevated(&caller.client))
                .unwrap_or(false)
            {
                return Ok(());
            }
            if let (Some(o), Some(sc), Some(s)) =
                (caller.origin, window_scope(caller, req), g.session.as_ref())
            {
                if s.in_window(o, &sc) {
                    return Ok(());
                }
            }
            if let Some(t) = req.auth.as_ref().and_then(|a| a.ticket.as_ref()) {
                if let Some(p) = g.pending.get(t) {
                    if p.approved && p.digest == d {
                        g.pending.remove(t);
                        return Ok(());
                    }
                }
            }
        }
        if caller.client != "mcp" {
            if let Some(auth) = req
                .auth
                .as_ref()
                .filter(|a| a.totp.is_some() || a.password.is_some())
            {
                // Every guess at a factor counts against the same persistent throttle,
                // and too many wrong answers close the session outright.
                throttle_check()?;
                let s = g.session.as_mut().ok_or(Error::Locked)?;
                let ok = if let (Some(code), Some(secret)) =
                    (auth.totp.as_deref(), s.lib.mfa.totp_secret.clone())
                {
                    match totp::verify(&secret, code, now() as u64, s.lib.mfa.totp_last_step) {
                        Some(step) => {
                            s.lib.mfa.totp_last_step = step;
                            let _ = s.save();
                            true
                        }
                        None => false,
                    }
                } else if let Some(pw) = auth.password.as_deref() {
                    s.header.unwrap(Unlocker::Password(pw.as_bytes())).is_ok()
                } else {
                    false
                };
                if ok {
                    throttle_reset();
                    if !is_approve {
                        open_window(s, caller, req);
                    }
                    return Ok(());
                }
                throttle_fail();
                if throttle_load().failures >= LOCK_AFTER_FAILURES {
                    if let Some(s) = g.session.take() {
                        s.audit(
                            "lock",
                            "agent",
                            json!({"reason": "too many failed approvals"}),
                        );
                    }
                    g.pending.clear();
                    return Err(Error::Locked);
                }
                return Err(Error::Denied);
            }
        }
    }
    let touch = {
        let g = state.lock().unwrap_or_else(|p| p.into_inner());
        g.session
            .as_ref()
            .map(|s| s.lib.mfa.touch_id)
            .unwrap_or(false)
    } && presence::available();
    if touch {
        let who = if caller.client == "mcp" {
            "An AI assistant asks: "
        } else {
            ""
        };
        if presence::confirm(&format!("{who}{reason}")).is_ok() {
            if !is_approve {
                let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(s) = g.session.as_mut() {
                    open_window(s, caller, req);
                }
            }
            return Ok(());
        }
    }
    let mut g = state.lock().unwrap_or_else(|p| p.into_inner());
    let ticket = crypto::random_id()[..10].to_string();
    g.pending.insert(
        ticket.clone(),
        Pending {
            reason: reason.into(),
            digest: d,
            created: Instant::now(),
            approved: false,
        },
    );
    let mut methods = vec![];
    if caller.client == "mcp" {
        methods.push("pit approve".to_string());
    } else {
        if g.session
            .as_ref()
            .map(|s| s.lib.mfa.totp_secret.is_some())
            .unwrap_or(false)
        {
            methods.push("totp".into());
        }
        methods.push("password".into());
    }
    Err(Error::ApprovalRequired {
        ticket,
        reason: reason.into(),
        methods,
    })
}

/// The scope an approval window would cover for this request, if any. AI
/// clients never get one, and neither do requests that hand values back
/// (reveal, `pit run`) or the always-asked actions (removals, exports,
/// settings): each of those is approved on its own.
fn window_scope(caller: &Caller, req: &Request) -> Option<String> {
    if caller.client == "mcp" {
        return None;
    }
    ops::window_scope(req)
}

fn open_window(s: &mut Session, caller: &Caller, req: &Request) {
    let secs = s.lib.settings.approval_window_secs;
    let (Some(origin), Some(scope)) = (caller.origin, window_scope(caller, req)) else {
        return;
    };
    if secs == 0 {
        return;
    }
    let now = Instant::now();
    s.windows
        .retain(|w| now < w.until && !(w.origin == origin && w.scope == scope));
    s.windows.push(Window {
        origin,
        scope: scope.clone(),
        until: now + Duration::from_secs(secs),
    });
    s.audit(
        "approval.window",
        &caller.actor,
        json!({"scope": scope, "secs": secs}),
    );
}

/// Back up after every change. The vault files are watched rather than hooked
/// into each operation, so nothing that writes them can be missed. A failed
/// send is retried with growing gaps (30s up to 15 min), and once at start-up
/// to catch up on anything that changed while this computer was off.
fn backup_watch() {
    const SETTLE: Duration = Duration::from_secs(3);
    const BACKOFF: [u64; 6] = [30, 60, 120, 300, 600, 900];
    let stamp = || {
        ["vault/header.json", "vault/library.sealed"]
            .iter()
            .map(|r| {
                std::fs::metadata(paths::home().join(r))
                    .map(|m| (m.len(), m.modified().ok()))
                    .ok()
            })
            .collect::<Vec<_>>()
    };
    let mut seen = stamp();
    let mut changed_at: Option<Instant> = None;
    let mut retry_at: Option<Instant> = Some(Instant::now() + Duration::from_secs(10));
    let mut failures = 0usize;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let now_stamp = stamp();
        if now_stamp != seen {
            seen = now_stamp;
            changed_at = Some(Instant::now());
        }
        let settled = changed_at.map(|t| t.elapsed() >= SETTLE).unwrap_or(false);
        let retry = retry_at.map(|t| Instant::now() >= t).unwrap_or(false);
        if !settled && !retry {
            continue;
        }
        changed_at = None;
        retry_at = None;
        if !crate::backup::Config::load()
            .map(|c| c.auto)
            .unwrap_or(true)
            || !crate::vault::exists()
        {
            continue;
        }
        // A separate process does the sending, so slow networks and outside
        // tools (ssh, rclone) never run inside the agent.
        let ok = std::process::Command::new(paths::self_exe())
            .args(["backup", "sync", "--quiet"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            failures = 0;
        } else {
            retry_at = Some(
                Instant::now() + Duration::from_secs(BACKOFF[failures.min(BACKOFF.len() - 1)]),
            );
            failures += 1;
        }
    }
}
