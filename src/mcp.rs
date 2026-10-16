//! MCP server (JSON-RPC 2.0 over stdio) for AI assistants.
//!
//! An AI client can see what exists (names, descriptions, fingerprints),
//! declare secrets, fill empty ones with generated values, and ask for pushes.
//! It can never read a value: there is no tool for it, and the agent refuses
//! value-returning operations from MCP clients regardless. Pushes from an AI
//! wait for a person's Touch ID or `pit approve`.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::protocol;

const INSTRUCTIONS: &str = "The Pit holds this developer's secrets, encrypted. You can list projects, channels and secret names (never values), declare secrets that are needed, generate random values for empty secrets, and request pushes to configured destinations. Every push you request is shown to the person for approval (Touch ID or `pit approve <ticket>`). Never ask the person to paste a secret value into the chat: ask them to run `pit set PROJECT/CHANNEL NAME` in their terminal. If the pit is locked, ask them to run `pit unlock`. Services such as Vercel, Fly and GitHub need the real value, so a secret that a destination pushes must stay `sealed` (two-way); `hashed` (one-way) secrets can never be pushed. To find secrets already sitting in a project (.env files, hard-coded keys), use pit_scan, then ask the person to run `pit scan <folder>` in their terminal to choose what to copy in; it never edits the project.";

fn tools() -> Value {
    let pc = json!({
        "project": {"type": "string", "description": "Project name"},
        "channel": {"type": "string", "description": "Channel name, e.g. production, development"}
    });
    json!([
        {"name": "pit_status", "description": "Whether The Pit is unlocked, and what is waiting for approval.", "inputSchema": {"type": "object", "properties": {}}},
        {"name": "pit_list", "description": "Projects, channels, secret names, descriptions, protection, set/empty state and fingerprints, plus destinations. Never values.",
         "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}}}},
        {"name": "pit_needs", "description": "Secrets that are declared but still have no value.", "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}}}},
        {"name": "pit_declare", "description": "Declare a secret a project needs, with a description, and no value. The person fills it in with `pit set`.",
         "inputSchema": {"type": "object", "required": ["scope", "name"], "properties": {
            "scope": {"type": "string", "description": "global, PROJECT, or PROJECT/CHANNEL"},
            "name": {"type": "string"}, "description": {"type": "string"},
            "protection": {"type": "string", "enum": ["sealed", "hashed", "plain"]}}}},
        {"name": "pit_generate", "description": "Fill an EMPTY secret with a random value (e.g. a session secret). Refused if it already has a value.",
         "inputSchema": {"type": "object", "required": ["scope", "name"], "properties": {
            "scope": {"type": "string"}, "name": {"type": "string"},
            "length": {"type": "integer", "minimum": 16, "maximum": 4096},
            "charset": {"type": "string", "enum": ["base64url", "alnum", "hex", "symbols"]}}}},
        {"name": "pit_push", "description": "Push a channel's secrets to its destinations (Fly, Vercel, GitHub, local .env files…). A person approves each push. Use dry_run first to see what would be sent.",
         "inputSchema": {"type": "object", "required": ["project", "channel"], "properties": {
            "project": pc["project"], "channel": pc["channel"],
            "destinations": {"type": "array", "items": {"type": "string"}},
            "dry_run": {"type": "boolean"}, "ticket": {"type": "string", "description": "An approved ticket from `pit approve`, when retrying"}}}},
        {"name": "pit_diff", "description": "Compare a channel with what each destination currently holds (names only).",
         "inputSchema": {"type": "object", "required": ["project", "channel"], "properties": pc}},
        {"name": "pit_scan", "description": "Look through a project folder for secrets that should live in The Pit (.env files, hard-coded keys, key files). Returns names, file:line places and whether each is committed to git. Never values, and never changes anything; the person imports with `pit scan <folder>`.",
         "inputSchema": {"type": "object", "required": ["folder"], "properties": {"folder": {"type": "string"}, "all": {"type": "boolean", "description": "Include ordinary settings too"}}}},
        {"name": "pit_log", "description": "Recent audit log entries: pushes and where they went, reveals, unlocks.",
         "inputSchema": {"type": "object", "properties": {"project": {"type": "string"}, "event": {"type": "string"}, "limit": {"type": "integer"}}}}
    ])
}

fn call_tool(name: &str, args: &Value) -> Result<Value> {
    let a = |k: &str| args.get(k).cloned().unwrap_or(Value::Null);
    let ticket = args
        .get("ticket")
        .and_then(|v| v.as_str())
        .map(protocol::Auth::with_ticket);
    let mcp = |op: &str, v: Value, auth: Option<protocol::Auth>| protocol::call("mcp", op, v, auth);
    match name {
        "pit_status" => mcp("status", json!({}), None),
        "pit_list" => mcp("tree", json!({"project": a("project")}), None),
        "pit_needs" => mcp("needs", json!({"project": a("project")}), None),
        "pit_declare" => mcp(
            "secret.declare",
            json!({"scope": a("scope"), "name": a("name"), "description": a("description"), "protection": a("protection")}),
            None,
        ),
        "pit_generate" => mcp(
            "secret.generate",
            json!({"scope": a("scope"), "name": a("name"), "length": a("length"), "charset": a("charset")}),
            None,
        ),
        "pit_push" => {
            let dests = args.get("destinations").cloned().unwrap_or(json!([]));
            mcp(
                "push",
                json!({"project": a("project"), "channel": a("channel"), "destinations": dests, "dry_run": a("dry_run").as_bool().unwrap_or(false)}),
                ticket,
            )
        }
        "pit_scan" => {
            let folder = args.get("folder").and_then(|v| v.as_str()).unwrap_or(".");
            let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
            let found =
                crate::scan::scan(std::path::Path::new(&crate::paths::expand_tilde(folder)))?;
            let findings: Vec<Value> = found
                .iter()
                .filter(|f| all || f.confidence > crate::scan::Confidence::Low)
                .map(|f| {
                    json!({
                        "suggested_name": f.name, "what": f.what, "places": f.places,
                        "committed_to_git": f.committed,
                    })
                })
                .collect();
            Ok(json!({"folder": folder, "findings": findings,
                "next": "Ask the person to run `pit scan <folder>` in their terminal to choose which to copy in."}))
        }
        "pit_diff" => mcp(
            "remote",
            json!({"project": a("project"), "channel": a("channel")}),
            None,
        ),
        "pit_log" => mcp(
            "log",
            json!({"project": a("project"), "event": a("event"), "limit": a("limit").as_u64().unwrap_or(30)}),
            None,
        ),
        _ => Err(Error::Invalid(format!("unknown tool {name}"))),
    }
}

fn explain(e: &Error) -> String {
    match e {
        Error::Locked => "The Pit is locked. Ask the person to run `pit unlock` in their terminal, then try again.".into(),
        Error::ApprovalRequired { ticket, reason, .. } => format!(
            "Waiting for the person's approval to {reason}. They were asked with Touch ID; if they did not see it, ask them to run `pit approve {ticket}` in their terminal, then call this tool again with ticket=\"{ticket}\"."
        ),
        Error::Denied => "The person declined.".into(),
        Error::Confirm(m) => format!("{m}\nNot changed. Use protection \"sealed\" for anything a destination pushes; only the person can choose one-way here, from their terminal."),
        other => other.to_string(),
    }
}

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let result: Option<Value> = match method {
            "initialize" => Some(json!({
                "protocolVersion": msg.pointer("/params/protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "the-pit", "version": env!("CARGO_PKG_VERSION")},
                "instructions": INSTRUCTIONS,
            })),
            "ping" => Some(json!({})),
            "tools/list" => Some(json!({"tools": tools()})),
            "tools/call" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let args = msg
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                Some(match call_tool(name, &args) {
                    Ok(v) => {
                        json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}]})
                    }
                    Err(e) => {
                        json!({"content": [{"type": "text", "text": explain(&e)}], "isError": true})
                    }
                })
            }
            m if m.starts_with("notifications/") => None,
            _ => {
                if let Some(id) = id {
                    let resp = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}});
                    writeln!(out, "{resp}")?;
                    out.flush()?;
                }
                continue;
            }
        };
        if let (Some(id), Some(r)) = (id, result) {
            writeln!(out, "{}", json!({"jsonrpc": "2.0", "id": id, "result": r}))?;
            out.flush()?;
        }
    }
    Ok(())
}
