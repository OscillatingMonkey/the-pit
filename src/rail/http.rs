//! HTTPS client. TLS via rustls with the Mozilla root store; plain http is refused.

use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("the-pit/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .redirects(0)
        .build()
}

pub struct Resp {
    pub status: u16,
    pub body: Value,
    pub headers: Vec<(String, String)>,
}

pub fn send(req: ureq::Request, body: Option<&Value>) -> Result<Resp> {
    let r = match body {
        Some(b) => req.send_json(b.clone()),
        None => req.call(),
    };
    let resp = match r {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(t)) => {
            return Err(Error::Remote(format!("network: {}", t.kind())))
        }
    };
    let status = resp.status();
    let headers = resp
        .headers_names()
        .into_iter()
        .filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string())))
        .collect();
    let text = resp.into_string().unwrap_or_default();
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(Resp {
        status,
        body,
        headers,
    })
}

/// A short, value-free description of an API error.
pub fn api_error(service: &str, r: &Resp) -> Error {
    let msg = r
        .body
        .pointer("/error/message")
        .or_else(|| r.body.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Error::Remote(format!(
        "{service} answered HTTP {}{}",
        r.status,
        if msg.is_empty() {
            String::new()
        } else {
            format!(": {msg}")
        }
    ))
}
