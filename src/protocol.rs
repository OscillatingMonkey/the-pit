//! Client ↔ agent protocol: one JSON request and one JSON response per line,
//! over a Unix socket that only the owning user can open. The agent also
//! checks the peer's uid on every connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::paths;

#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

impl Auth {
    pub fn with_password(p: impl Into<String>) -> Auth {
        Auth {
            password: Some(p.into()),
            totp: None,
            ticket: None,
        }
    }
    pub fn with_totp(c: impl Into<String>) -> Auth {
        Auth {
            password: None,
            totp: Some(c.into()),
            ticket: None,
        }
    }
    pub fn with_ticket(t: impl Into<String>) -> Auth {
        Auth {
            password: None,
            totp: None,
            ticket: Some(t.into()),
        }
    }
}

impl Drop for Auth {
    fn drop(&mut self) {
        if let Some(p) = self.password.as_mut() {
            p.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub op: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub auth: Option<Auth>,
    /// cli | console | mcp | service
    #[serde(default)]
    pub client: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub ticket: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn from_result(r: Result<Value>) -> Response {
        match r {
            Ok(data) => Response {
                ok: true,
                data,
                error: None,
            },
            Err(e) => {
                let (ticket, methods) = match &e {
                    Error::ApprovalRequired {
                        ticket, methods, ..
                    } => (Some(ticket.clone()), methods.clone()),
                    _ => (None, vec![]),
                };
                let message = match &e {
                    Error::ApprovalRequired { reason, .. } => reason.clone(),
                    other => other.to_string(),
                };
                Response {
                    ok: false,
                    data: Value::Null,
                    error: Some(ErrorBody {
                        code: e.code().into(),
                        message,
                        ticket,
                        methods,
                    }),
                }
            }
        }
    }
}

pub fn error_from(body: ErrorBody) -> Error {
    match body.code.as_str() {
        "denied" => Error::Denied,
        "locked" => Error::Locked,
        "approval_required" => Error::ApprovalRequired {
            ticket: body.ticket.unwrap_or_default(),
            reason: body.message,
            methods: body.methods,
        },
        "not_found" => Error::NotFound(body.message.trim_start_matches("not found: ").to_string()),
        "exists" => Error::Exists(
            body.message
                .trim_start_matches("already exists: ")
                .to_string(),
        ),
        "refused" => Error::Refused(body.message.trim_start_matches("refused: ").to_string()),
        "remote" => Error::Remote(body.message),
        "confirm" => Error::Confirm(body.message),
        "throttled" => Error::Throttled(
            body.message
                .split_whitespace()
                .find_map(|w| w.trim_end_matches('s').parse().ok())
                .unwrap_or(60),
        ),
        _ => Error::Invalid(body.message),
    }
}

fn connect() -> std::io::Result<UnixStream> {
    let sock = paths::socket_path();
    paths::verify_socket(&sock)?;
    UnixStream::connect(sock)
}

pub fn agent_running() -> bool {
    connect().is_ok()
}

/// A read-only listing for completion: never starts the agent, never waits
/// long, and never keeps a session awake (the agent treats the `complete`
/// client that way).
pub fn peek(op: &str) -> Option<Value> {
    let mut s = connect().ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let req = Request {
        op: op.into(),
        args: serde_json::json!({}),
        auth: None,
        client: "complete".into(),
    };
    let mut line = serde_json::to_vec(&req).ok()?;
    line.push(b'\n');
    s.write_all(&line).ok()?;
    let mut buf = String::new();
    BufReader::new(s).read_line(&mut buf).ok()?;
    let resp: Response = serde_json::from_str(&buf).ok()?;
    resp.ok.then_some(resp.data)
}

/// Start the agent in the background if it is not already running.
pub fn ensure_agent() -> Result<()> {
    if agent_running() {
        return Ok(());
    }
    paths::ensure_layout()?;
    let exe = paths::self_exe();
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("agent")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn()?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if agent_running() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(Error::Invalid(
        "the agent did not start — try `pit agent` in another terminal to see why".into(),
    ))
}

pub fn call(client: &str, op: &str, args: Value, auth: Option<Auth>) -> Result<Value> {
    ensure_agent()?;
    let mut s = connect().map_err(|_| Error::Invalid("cannot reach the agent".into()))?;
    s.set_read_timeout(Some(Duration::from_secs(600)))?;
    let req = Request {
        op: op.into(),
        args,
        auth,
        client: client.into(),
    };
    let mut line = serde_json::to_vec(&req)?;
    line.push(b'\n');
    s.write_all(&line)?;
    line.zeroize();
    let mut r = BufReader::new(s);
    let mut buf = String::new();
    r.read_line(&mut buf)?;
    let resp: Response = serde_json::from_str(&buf)
        .map_err(|_| Error::Invalid("the agent sent an unreadable reply".into()))?;
    buf.zeroize();
    if resp.ok {
        Ok(resp.data)
    } else {
        Err(error_from(resp.error.unwrap_or(ErrorBody {
            code: "invalid".into(),
            message: "unknown error".into(),
            ticket: None,
            methods: vec![],
        })))
    }
}
