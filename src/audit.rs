//! The audit log: every push, reveal, unlock and change, with where it went.
//!
//! One line per event. Each line is encrypted with the log key and chained to
//! the previous line by SHA-256, so an edited, removed or reordered line is
//! detected by `pit log`. A sealed anchor records the newest entry, and the
//! library records a lower bound, so entries cut from the end are detected too.

use std::fs;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::{self, Sealed};
use crate::error::{Error, Result};
use crate::model::now;
use crate::paths;
use crate::vault::Keys;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize)]
struct Line {
    seq: u64,
    prev: String,
    sealed: Sealed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub time: i64,
    pub event: String,
    pub actor: String,
    #[serde(default)]
    pub data: Value,
}

fn aad(seq: u64, prev: &str) -> Vec<u8> {
    format!("the-pit/log|{seq}|{prev}").into_bytes()
}

fn anchor_path() -> std::path::PathBuf {
    paths::log_path().with_file_name("anchor.sealed")
}

#[derive(Serialize, Deserialize)]
struct Anchor {
    seq: u64,
    hash: String,
}

fn write_anchor(keys: &Keys, seq: u64, hash: &str) {
    let a = Anchor {
        seq,
        hash: hash.to_string(),
    };
    if let Ok(pt) = serde_json::to_vec(&a) {
        let sealed = crypto::seal(&keys.log, &pt, b"the-pit/log-anchor");
        if let Ok(b) = serde_json::to_vec(&sealed) {
            let _ = paths::write_private(&anchor_path(), &b);
        }
    }
}

fn read_anchor(keys: &Keys) -> Option<Anchor> {
    let b = fs::read(anchor_path()).ok()?;
    let sealed: Sealed = serde_json::from_slice(&b).ok()?;
    let pt = crypto::open(&keys.log, &sealed, b"the-pit/log-anchor").ok()?;
    serde_json::from_slice(&pt).ok()
}

/// The sequence number of the newest entry.
pub fn last_seq() -> u64 {
    tail().0
}

fn line_hash(raw: &str) -> String {
    crypto::sha256_hex(raw.as_bytes())
}

fn tail() -> (u64, String) {
    let Ok(text) = fs::read_to_string(paths::log_path()) else {
        return (0, GENESIS.into());
    };
    match text.lines().rev().find(|l| !l.trim().is_empty()) {
        Some(last) => {
            let seq = serde_json::from_str::<Line>(last)
                .map(|l| l.seq)
                .unwrap_or(0);
            (seq, line_hash(last))
        }
        None => (0, GENESIS.into()),
    }
}

pub fn record(keys: &Keys, event: &str, actor: &str, data: Value) -> Result<u64> {
    let (seq, prev) = tail();
    let seq = seq + 1;
    let ev = Event {
        seq,
        time: now(),
        event: event.into(),
        actor: actor.into(),
        data,
    };
    let sealed = crypto::seal(&keys.log, &serde_json::to_vec(&ev)?, &aad(seq, &prev));
    let line = serde_json::to_string(&Line { seq, prev, sealed })?;
    paths::append_private(&paths::log_path(), line.as_bytes())?;
    write_anchor(keys, seq, &line_hash(&line));
    Ok(seq)
}

pub struct Verified {
    pub events: Vec<Event>,
    pub broken_at: Option<u64>,
}

/// Read and verify the whole log. `at_least` is the newest sequence number the
/// library has seen; a log shorter than that, or than its anchor, was cut.
pub fn read(keys: &Keys, at_least: u64) -> Result<Verified> {
    let text = match fs::read_to_string(paths::log_path()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut prev = GENESIS.to_string();
    let mut expect = 1u64;
    let mut events = vec![];
    let mut broken_at = None;
    for raw in text.lines().filter(|l| !l.trim().is_empty()) {
        let line: Line = match serde_json::from_str(raw) {
            Ok(l) => l,
            Err(_) => {
                broken_at.get_or_insert(expect);
                break;
            }
        };
        if line.seq != expect || line.prev != prev {
            broken_at.get_or_insert(expect);
        }
        match crypto::open(&keys.log, &line.sealed, &aad(line.seq, &line.prev)) {
            Ok(pt) => events
                .push(serde_json::from_slice(&pt).map_err(|_| Error::Invalid("log entry".into()))?),
            Err(_) => {
                broken_at.get_or_insert(line.seq);
            }
        }
        prev = line_hash(raw);
        expect = line.seq + 1;
    }
    let last = expect - 1;
    match read_anchor(keys) {
        Some(a) => {
            let anchored = text.lines().filter(|l| !l.trim().is_empty()).find(|l| {
                serde_json::from_str::<Line>(l)
                    .map(|x| x.seq == a.seq)
                    .unwrap_or(false)
            });
            if a.seq > last || anchored.map(line_hash).as_deref() != Some(a.hash.as_str()) {
                broken_at.get_or_insert(a.seq.min(last + 1));
            }
        }
        None if last > 0 || at_least > 0 => {
            broken_at.get_or_insert(last + 1);
        }
        None => {}
    }
    if last < at_least {
        broken_at.get_or_insert(last + 1);
    }
    Ok(Verified { events, broken_at })
}
