//! Everything the agent can do once unlocked, and which of it needs a person
//! to approve first.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::agent::{Caller, Session, Shared};
use crate::error::{invalid, Error, Result};
use crate::model::{
    fmt_time, now, valid_name, valid_slug, Channel, Connection, Destination, Kind, Library,
    Project, Protection, Scope, Secret,
};
use crate::protocol::Request;
use crate::rail::{self, Item};
use crate::{backup, codes, crypto, importer, resolve, totp, values, vault};

// ---------------------------------------------------------------------------
// arguments

fn arg<'a>(req: &'a Request, k: &str) -> Result<&'a str> {
    req.args
        .get(k)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Invalid(format!("missing `{k}`")))
}
fn o<'a>(req: &'a Request, k: &str) -> Option<&'a str> {
    req.args.get(k).and_then(|v| v.as_str())
}
fn b(req: &Request, k: &str) -> Option<bool> {
    req.args.get(k).and_then(|v| v.as_bool())
}
fn u(req: &Request, k: &str) -> Option<u64> {
    req.args.get(k).and_then(|v| v.as_u64())
}
fn strings(req: &Request, k: &str) -> Vec<String> {
    req.args
        .get(k)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
fn map(req: &Request, k: &str) -> BTreeMap<String, String> {
    req.args
        .get(k)
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str()
                            .map(String::from)
                            .unwrap_or_else(|| v.to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}
fn scope(req: &Request) -> Result<Scope> {
    Scope::parse(arg(req, "scope")?)
}

// ---------------------------------------------------------------------------
// policy

const AI_REFUSED: &[&str] = &[
    "secret.reveal",
    "run.env",
    "bundle.export",
    "bundle.import",
    "emergency.export",
    "password.change",
    "recovery.rotate",
    "mfa.touchid",
    "mfa.totp.begin",
    "mfa.totp.confirm",
    "mfa.totp.disable",
    "device.set",
    "settings.set",
    "history.restore",
    "conn.add",
    "conn.rm",
    "elevate",
    "import.secretpit",
    "secret.import",
    "backup.diff",
    "secret.verify",
    "secret.rollback",
    "project.rm",
    "channel.rm",
    "secret.rm",
];

const ALWAYS_APPROVE: &[&str] = &[
    "secret.reveal",
    "bundle.export",
    "bundle.import",
    "emergency.export",
    "password.change",
    "recovery.rotate",
    "mfa.touchid",
    "mfa.totp.confirm",
    "mfa.totp.disable",
    "device.set",
    "settings.set",
    "history.restore",
    "conn.add",
    "conn.rm",
    "elevate",
    "project.rm",
    "channel.rm",
    "secret.rm",
    "secret.rollback",
];

/// A scope is protected if a protected channel can see what is in it: the
/// channel itself, a project inherited by a protected channel, or the global
/// scope when any protected channel exists.
pub fn scope_protected(lib: &Library, sc: &Scope) -> bool {
    match sc {
        Scope::Channel(p, c) => lib.channel(p, c).map(|c| c.protected).unwrap_or(false),
        Scope::Project(p) => lib
            .project(p)
            .map(|p| p.channels.values().any(|c| c.protected && c.inherit))
            .unwrap_or(false),
        Scope::Global => lib
            .projects
            .values()
            .any(|p| p.channels.values().any(|c| c.protected)),
    }
}

fn channel_protected(lib: &Library, req: &Request) -> bool {
    let scoped = ["scope", "to"].iter().any(|k| {
        o(req, k)
            .and_then(|sc| Scope::parse(sc).ok())
            .map(|sc| scope_protected(lib, &sc))
            .unwrap_or(false)
    });
    let from_pc = match (o(req, "project"), o(req, "channel")) {
        (Some(p), Some(c)) => lib.channel(p, c).map(|c| c.protected).unwrap_or(false),
        _ => false,
    };
    scoped || from_pc
}

/// The scope one approval covers for a while (see `agent::Window`): the
/// channel, project or global scope the request changes. `None` for requests
/// that are asked about every time.
pub fn window_scope(req: &Request) -> Option<String> {
    let op = req.op.as_str();
    if ALWAYS_APPROVE.contains(&op) || AI_REFUSED.contains(&op) || op == "approve" {
        return None;
    }
    let sc = match (o(req, "project"), o(req, "channel")) {
        (Some(p), Some(c)) => format!("{p}/{c}"),
        _ => o(req, "scope").unwrap_or("").to_string(),
    };
    Some(match o(req, "to") {
        Some(to) => format!("{sc} → {to}"),
        None => sc,
    })
}

fn describe(req: &Request) -> String {
    let pc = match (o(req, "project"), o(req, "channel")) {
        (Some(p), Some(c)) => format!("{p}/{c}"),
        _ => o(req, "scope").unwrap_or("").to_string(),
    };
    let name = o(req, "name").map(|n| format!(" {n}")).unwrap_or_default();
    match req.op.as_str() {
        "push" => {
            let d = strings(req, "destinations");
            let to = if d.is_empty() {
                "all destinations".to_string()
            } else {
                d.join(", ")
            };
            format!("push {pc} to {to}")
        }
        "secret.reveal" => format!("reveal{name} from {pc}"),
        "run.env" => format!("load {pc} into a program's environment"),
        "absorb" => format!(
            "absorb values from {pc} {}",
            o(req, "destination").unwrap_or("")
        ),
        "bundle.export" => "export an encrypted bundle".into(),
        "bundle.import" => {
            if b(req, "with_destinations").unwrap_or(false) {
                "import a bundle INCLUDING its destinations and connections (where secrets get pushed)".into()
            } else {
                "import a bundle (secrets only)".into()
            }
        }
        "emergency.export" => "EXPORT EVERY SECRET (emergency dump)".into(),
        "secret.import" => format!(
            "import {} secret(s) into {pc}{}",
            req.args
                .get("items")
                .and_then(|i| i.as_array())
                .map(|a| a.len())
                .unwrap_or(0),
            if b(req, "overwrite").unwrap_or(false) {
                ", replacing values that differ"
            } else {
                ""
            }
        ),
        "elevate" => format!(
            "keep sensitive actions open for {} min",
            u(req, "secs").unwrap_or(300) / 60
        ),
        op => format!("{op}{name} {pc}").trim().to_string(),
    }
}

/// `Some(reason)` if this request needs a person's approval first.
pub fn needs_approval(state: &Shared, caller: &Caller, req: &Request) -> Result<Option<String>> {
    let ai = caller.client == "mcp";
    if ai && AI_REFUSED.contains(&req.op.as_str()) {
        return Err(Error::Refused(format!(
            "`{}` is not available to AI clients; a person runs it with the pit CLI",
            req.op
        )));
    }
    let g = state.lock().unwrap_or_else(|p| p.into_inner());
    let sess = g.session.as_ref().ok_or(Error::Locked)?;
    let lib = &sess.lib;
    let op = req.op.as_str();
    let reason = describe(req);
    if ALWAYS_APPROVE.contains(&op) {
        return Ok(Some(reason));
    }
    let protected = channel_protected(lib, req);
    let need = match op {
        // A dry run sends nothing and shows only names, so it never asks.
        "push" => {
            !b(req, "dry_run").unwrap_or(false)
                && (protected || (ai && lib.settings.ai_push_needs_approval))
        }
        "absorb" => (protected || ai) && !b(req, "dry_run").unwrap_or(false),
        "run.env" => protected || lib.settings.run_needs_approval,
        "secret.declare" | "secret.generate" => protected,
        "secret.set" | "secret.edit" | "secret.move" => protected || ai,
        // Where values go is always the owner's call, protected channel or not.
        "dest.add" | "dest.edit" => true,
        "dest.rm" => protected || ai,
        "channel.edit" => protected || ai,
        "import.secretpit" => !b(req, "dry_run").unwrap_or(false),
        // Adding new values is like `pit set`; replacing existing ones is not.
        "secret.import" => {
            !b(req, "dry_run").unwrap_or(false)
                && (protected || b(req, "overwrite").unwrap_or(false))
        }
        _ => false,
    };
    Ok(if need { Some(reason) } else { None })
}

// ---------------------------------------------------------------------------
// dispatch

pub fn dispatch(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    match req.op.as_str() {
        "tree" => Ok(tree(&s.lib, o(req, "project"))),
        "needs" => Ok(needs(&s.lib, o(req, "project"))),
        "identity" => Ok(
            json!({"identity": codes::encode("ID", &s.lib.owner.identity_public), "owner": s.lib.owner.name}),
        ),
        "elevate" => {
            let secs = u(req, "secs")
                .unwrap_or(s.lib.settings.elevate_secs)
                .clamp(30, 3600);
            s.elevated_until = Some(Instant::now() + Duration::from_secs(secs));
            s.elevated_ai = b(req, "ai").unwrap_or(false);
            s.audit(
                "elevate",
                &caller.actor,
                json!({"secs": secs, "ai": s.elevated_ai}),
            );
            Ok(json!({"elevated_for": secs}))
        }
        "unelevate" => {
            s.elevated_until = None;
            Ok(json!({"elevated": false}))
        }

        "project.add" => {
            let name = s_(req, "name")?;
            valid_slug("project", &name)?;
            if s.lib.projects.contains_key(&name) {
                return Err(Error::Exists(format!("project {name}")));
            }
            let mut p = Project {
                name: name.clone(),
                description: o(req, "description").unwrap_or("").into(),
                created: now(),
                secrets: BTreeMap::new(),
                channels: BTreeMap::new(),
            };
            for c in strings(req, "channels") {
                valid_slug("channel", &c)?;
                p.channels
                    .insert(c.clone(), new_channel(&c, "", c == "production"));
            }
            s.lib.projects.insert(name.clone(), p);
            s.save()?;
            s.audit("project.add", &caller.actor, json!({"project": name}));
            Ok(json!({"project": name}))
        }
        "project.edit" => {
            let name = s_(req, "name")?;
            let mut p = s
                .lib
                .projects
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("project {name}")))?;
            if let Some(d) = o(req, "description") {
                p.description = d.into();
            }
            let new = o(req, "rename").map(String::from).unwrap_or(name.clone());
            valid_slug("project", &new)?;
            if new != name && s.lib.projects.contains_key(&new) {
                s.lib.projects.insert(name, p);
                return Err(Error::Exists(format!("project {new}")));
            }
            p.name = new.clone();
            s.lib.projects.insert(new.clone(), p);
            s.save()?;
            s.audit(
                "project.edit",
                &caller.actor,
                json!({"project": name, "now": new}),
            );
            Ok(json!({"project": new}))
        }
        "project.rm" => {
            let name = s_(req, "name")?;
            s.lib
                .projects
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("project {name}")))?;
            s.save()?;
            s.audit("project.rm", &caller.actor, json!({"project": name}));
            Ok(json!({"removed": name}))
        }

        "channel.add" => {
            let p = s_(req, "project")?;
            let c = s_(req, "name")?;
            valid_slug("channel", &c)?;
            let protected = b(req, "protected").unwrap_or(c == "production");
            let project = s.lib.project_mut(&p)?;
            if project.channels.contains_key(&c) {
                return Err(Error::Exists(format!("channel {p}/{c}")));
            }
            let mut ch = new_channel(&c, o(req, "description").unwrap_or(""), protected);
            if let Some(i) = b(req, "inherit") {
                ch.inherit = i;
            }
            project.channels.insert(c.clone(), ch);
            s.save()?;
            s.audit(
                "channel.add",
                &caller.actor,
                json!({"project": p, "channel": c, "protected": protected}),
            );
            Ok(json!({"channel": format!("{p}/{c}"), "protected": protected}))
        }
        "channel.edit" => {
            let p = s_(req, "project")?;
            let c = s_(req, "channel")?;
            let ch = s.lib.channel_mut(&p, &c)?;
            if let Some(d) = o(req, "description") {
                ch.description = d.into();
            }
            if let Some(i) = b(req, "inherit") {
                ch.inherit = i;
            }
            if let Some(pr) = b(req, "protected") {
                ch.protected = pr;
            }
            let state = json!({"inherit": ch.inherit, "protected": ch.protected});
            if let Some(new) = o(req, "rename") {
                valid_slug("channel", new)?;
                let project = s.lib.project_mut(&p)?;
                if project.channels.contains_key(new) {
                    return Err(Error::Exists(format!("channel {p}/{new}")));
                }
                let mut ch = project.channels.remove(&c).expect("checked above");
                ch.name = new.into();
                project.channels.insert(new.into(), ch);
            }
            s.save()?;
            s.audit(
                "channel.edit",
                &caller.actor,
                json!({"project": p, "channel": c, "state": state}),
            );
            Ok(state)
        }
        "channel.rm" => {
            let p = s_(req, "project")?;
            let c = s_(req, "channel")?;
            s.lib
                .project_mut(&p)?
                .channels
                .remove(&c)
                .ok_or_else(|| Error::NotFound(format!("channel {p}/{c}")))?;
            s.save()?;
            s.audit(
                "channel.rm",
                &caller.actor,
                json!({"project": p, "channel": c}),
            );
            Ok(json!({"removed": format!("{p}/{c}")}))
        }

        "secret.declare" | "secret.set" | "secret.generate" => secret_set(s, caller, req),
        "secret.edit" => secret_edit(s, caller, req),
        "secret.rm" => {
            let sc = scope(req)?;
            let name = s_(req, "name")?;
            s.lib
                .secrets_mut(&sc)?
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("{name} in {sc}")))?;
            s.save()?;
            s.audit(
                "secret.rm",
                &caller.actor,
                json!({"scope": sc.to_string(), "name": name}),
            );
            Ok(json!({"removed": name}))
        }
        "secret.move" => {
            let from = scope(req)?;
            let to = Scope::parse(arg(req, "to")?)?;
            let name = s_(req, "name")?;
            let sec = s
                .lib
                .secrets_mut(&from)?
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("{name} in {from}")))?;
            let dest = s.lib.secrets_mut(&to)?;
            if dest.contains_key(&name) {
                s.lib.secrets_mut(&from)?.insert(name.clone(), sec);
                return Err(Error::Exists(format!("{name} in {to}")));
            }
            dest.insert(name.clone(), sec);
            guard_one_way(s, caller, &to, &name, req)?;
            s.save()?;
            s.audit(
                "secret.move",
                &caller.actor,
                json!({"name": name, "from": from.to_string(), "to": to.to_string()}),
            );
            Ok(json!({"moved": name, "to": to.to_string()}))
        }
        "secret.reveal" => {
            let sc = scope(req)?;
            let name = s_(req, "name")?;
            let sec = s
                .lib
                .secrets(&sc)?
                .get(&name)
                .ok_or_else(|| Error::NotFound(format!("{name} in {sc}")))?;
            let v = values::open(&s.keys, sec)?
                .ok_or_else(|| Error::Invalid(format!("{name} is empty")))?;
            let out = json!({
                "name": name,
                "value_b64": crypto::b64e(&v),
                "is_text": std::str::from_utf8(&v).is_ok() && matches!(sec.kind, Kind::Text),
                "filename": match &sec.kind { Kind::File { filename } => Some(filename.clone()), _ => None },
                "fp": sec.fingerprint(),
                "clipboard_secs": s.lib.settings.clipboard_secs,
            });
            s.audit_strict(
                "reveal",
                &caller.actor,
                json!({"scope": sc.to_string(), "name": name, "fp": sec.fingerprint()}),
            )?;
            Ok(out)
        }
        "secret.verify" => {
            let sc = scope(req)?;
            let name = s_(req, "name")?;
            let cand = Zeroizing::new(crypto::b64d(arg(req, "value_b64")?)?);
            let sec = s
                .lib
                .secrets(&sc)?
                .get(&name)
                .ok_or_else(|| Error::NotFound(format!("{name} in {sc}")))?;
            let ok = values::verify(sec, &cand, &s.keys)?;
            s.audit(
                "verify",
                &caller.actor,
                json!({"scope": sc.to_string(), "name": name, "match": ok}),
            );
            Ok(json!({"match": ok}))
        }
        "secret.rollback" => {
            let sc = scope(req)?;
            let name = s_(req, "name")?;
            let sec = s
                .lib
                .secrets_mut(&sc)?
                .get_mut(&name)
                .ok_or_else(|| Error::NotFound(format!("{name} in {sc}")))?;
            if sec.history.is_empty() {
                return Err(Error::Invalid(format!("{name} has no earlier value")));
            }
            let prev = sec.history.remove(0);
            let cur = sec.value.replace(prev);
            if let Some(c) = cur {
                sec.history.insert(0, c);
            }
            sec.updated = now();
            let fp = sec.fingerprint().map(String::from);
            s.save()?;
            s.audit(
                "secret.rollback",
                &caller.actor,
                json!({"scope": sc.to_string(), "name": name, "fp": fp}),
            );
            Ok(json!({"name": name, "fp": fp}))
        }

        "dest.add" | "dest.edit" => dest_upsert(s, caller, req),
        "dest.rm" => {
            let p = s_(req, "project")?;
            let c = s_(req, "channel")?;
            let name = s_(req, "name")?;
            s.lib
                .channel_mut(&p, &c)?
                .destinations
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("destination {name}")))?;
            s.save()?;
            s.audit(
                "dest.rm",
                &caller.actor,
                json!({"project": p, "channel": c, "destination": name}),
            );
            Ok(json!({"removed": name}))
        }

        "conn.add" => conn_add(s, caller, req),
        "conn.verify" => {
            let name = s_(req, "name")?;
            let conn = s
                .lib
                .connections
                .get(&name)
                .cloned()
                .ok_or_else(|| Error::NotFound(format!("connection {name}")))?;
            let token = conn_token(s, &conn)?;
            let account = rail::verify_connection(
                &conn.kind,
                token.as_deref().map(|t| t.as_str()),
                &conn.config,
            )?;
            if let Some(c) = s.lib.connections.get_mut(&name) {
                c.account = account.clone();
                c.verified_at = now();
            }
            s.save()?;
            Ok(json!({"name": name, "account": account}))
        }
        "conn.rm" => {
            let name = s_(req, "name")?;
            s.lib
                .connections
                .remove(&name)
                .ok_or_else(|| Error::NotFound(format!("connection {name}")))?;
            s.save()?;
            s.audit("conn.rm", &caller.actor, json!({"connection": name}));
            Ok(
                json!({"removed": name, "note": "revoke the token at the service too — The Pit no longer holds it, but the service still honours it"}),
            )
        }

        "push" => push(s, caller, req),
        "remote" => remote(s, req),
        "absorb" => absorb(s, caller, req),
        "run.env" => run_env(s, caller, req),
        "log" => log(s, req),

        "bundle.export" => {
            let projects = strings(req, "projects");
            let pass = o(req, "passphrase").map(|p| Zeroizing::new(p.to_string()));
            let recipient = o(req, "recipient").map(String::from);
            let data = backup::export_bundle(
                s,
                &projects,
                pass.as_deref().map(|p| p.as_str()),
                recipient.as_deref(),
                b(req, "connections").unwrap_or(false),
            )?;
            s.audit_strict("bundle.export", &caller.actor, json!({"projects": projects, "passphrase": pass.is_some(), "recipient": recipient.is_some()}))?;
            Ok(json!({"bundle_b64": crypto::b64e(&data)}))
        }
        "bundle.import" => {
            let data = crypto::b64d(arg(req, "bundle_b64")?)?;
            let pass = o(req, "passphrase").map(|p| Zeroizing::new(p.to_string()));
            let report = backup::import_bundle(
                s,
                &data,
                pass.as_deref().map(|p| p.as_str()),
                b(req, "replace").unwrap_or(false),
                b(req, "with_destinations").unwrap_or(false),
            )?;
            s.save()?;
            s.audit("bundle.import", &caller.actor, report.clone());
            Ok(report)
        }
        "emergency.export" => {
            let pass = o(req, "passphrase").map(|p| Zeroizing::new(p.to_string()));
            let data = backup::emergency_export(s, pass.as_deref().map(|p| p.as_str()))?;
            s.audit_strict(
                "emergency.export",
                &caller.actor,
                json!({"encrypted": pass.is_some()}),
            )?;
            Ok(json!({"export_b64": crypto::b64e(&data), "encrypted": pass.is_some()}))
        }

        "password.change" => {
            let new = Zeroizing::new(arg(req, "new_password")?.to_string());
            crate::cli::password_policy(&new, &s.lib.owner.name)?;
            s.header.set_password(&s.keys.vmk, new.as_bytes())?;
            s.header.save()?;
            s.lib.last_password_unlock = now();
            s.save()?;
            s.audit("password.change", &caller.actor, json!({}));
            Ok(json!({"changed": true}))
        }
        "recovery.rotate" => {
            let rk = s.header.new_recovery(&s.keys.vmk)?;
            s.header.save()?;
            let out = match (u(req, "threshold"), u(req, "shares")) {
                (Some(k), Some(n)) => {
                    if !(2..=16).contains(&k) || n < k || n > 16 {
                        return invalid("shares must satisfy 2 <= threshold <= shares <= 16");
                    }
                    let shares = crate::shamir::split(&rk, k as u8, n as u8)?;
                    let codes: Vec<String> =
                        shares.iter().map(|sh| codes::encode("S", sh)).collect();
                    json!({"shares": codes, "threshold": k})
                }
                _ => json!({"recovery_code": codes::encode("R", &rk)}),
            };
            s.audit(
                "recovery.rotate",
                &caller.actor,
                json!({"split": u(req, "shares")}),
            );
            Ok(out)
        }
        "mfa.touchid" => {
            let on = b(req, "enable").unwrap_or(true);
            if on && !crate::presence::available() {
                return invalid("Touch ID is not available on this Mac");
            }
            s.lib.mfa.touch_id = on;
            s.save()?;
            s.audit("mfa.touchid", &caller.actor, json!({"enabled": on}));
            Ok(json!({"touch_id": on}))
        }
        "mfa.totp.begin" => {
            let secret = totp::new_secret();
            Ok(
                json!({"secret": totp::base32(&secret), "uri": totp::uri(&secret, &s.lib.owner.name)}),
            )
        }
        "mfa.totp.confirm" => {
            let secret = data_encoding::BASE32_NOPAD
                .decode(arg(req, "secret")?.as_bytes())
                .map_err(|_| Error::Invalid("secret is not base32".into()))?;
            let step =
                totp::verify(&secret, arg(req, "code")?, now() as u64, 0).ok_or(Error::Denied)?;
            s.lib.mfa.totp_secret = Some(secret);
            s.lib.mfa.totp_last_step = step;
            s.save()?;
            s.audit("mfa.totp", &caller.actor, json!({"enabled": true}));
            Ok(json!({"totp": true}))
        }
        "mfa.totp.disable" => {
            s.lib.mfa.totp_secret = None;
            s.save()?;
            s.audit("mfa.totp", &caller.actor, json!({"enabled": false}));
            Ok(json!({"totp": false}))
        }
        "device.set" => {
            let on = b(req, "enable").unwrap_or(true);
            if on {
                s.header.enable_device(&s.keys.vmk)?;
            } else {
                s.header.disable_device()?;
            }
            s.header.save()?;
            s.audit("device.set", &caller.actor, json!({"quick_unlock": on}));
            Ok(json!({"quick_unlock": on}))
        }
        "settings.get" => Ok(serde_json::to_value(&s.lib.settings)?),
        "settings.set" => {
            let key = arg(req, "key")?;
            let val = arg(req, "value")?;
            let st = &mut s.lib.settings;
            let num = || {
                val.parse::<u64>()
                    .map_err(|_| Error::Invalid(format!("{key} takes a number")))
            };
            match key {
                "session_secs" => st.session_secs = num()?.clamp(60, 7 * 86400),
                "idle_secs" => st.idle_secs = num()?.clamp(60, 24 * 3600),
                "elevate_secs" => st.elevate_secs = num()?.clamp(30, 3600),
                "password_recheck_days" => st.password_recheck_days = num()?.clamp(1, 90),
                "clipboard_secs" => st.clipboard_secs = num()?.clamp(5, 600),
                "ai_push_needs_approval" => st.ai_push_needs_approval = val == "true",
                "run_needs_approval" => st.run_needs_approval = val == "true",
                "approval_window_secs" => st.approval_window_secs = num()?.min(30 * 60),
                _ => return invalid(format!("unknown setting {key}")),
            }
            s.save()?;
            s.audit(
                "settings.set",
                &caller.actor,
                json!({"key": key, "value": val}),
            );
            Ok(serde_json::to_value(&s.lib.settings)?)
        }
        "history.list" => Ok(json!({
            "current": s.generation,
            "generations": vault::history().iter().map(|(g, p)| json!({"generation": g, "saved": std::fs::metadata(p).ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| fmt_time(d.as_secs() as i64))})).collect::<Vec<_>>()
        })),
        "history.restore" => {
            let g = u(req, "generation")
                .ok_or_else(|| Error::Invalid("missing `generation`".into()))?;
            let (_, path) = vault::history()
                .into_iter()
                .find(|(x, _)| *x == g)
                .ok_or_else(|| Error::NotFound(format!("generation {g}")))?;
            let mut old = vault::load_generation(&s.header, &s.keys, &path)?;
            old.mfa = s.lib.mfa.clone();
            old.last_password_unlock = s.lib.last_password_unlock;
            s.lib = old;
            s.save()?;
            s.audit("history.restore", &caller.actor, json!({"generation": g}));
            Ok(json!({"restored": g, "now": s.generation}))
        }
        "secret.import" => secret_import(s, caller, req),
        "backup.diff" => {
            let a = crypto::b64d(arg(req, "a_b64")?)?;
            let pw = o(req, "password");
            let (la, sa) = backup::open_snapshot(s, &a, pw)?;
            let (lb, b_label, b_gen) = match o(req, "b_b64") {
                Some(b) => {
                    let (lb, sb) = backup::open_snapshot(s, &crypto::b64d(b)?, pw)?;
                    (lb, fmt_time(sb.created), sb.generation)
                }
                None => (s.lib.clone(), "now".to_string(), s.generation),
            };
            Ok(json!({
                "a": {"taken": fmt_time(sa.created), "generation": sa.generation, "vault": &sa.vault_id[..8]},
                "b": {"taken": b_label, "generation": b_gen},
                "changes": backup::diff(&la, &lb),
            }))
        }
        "import.secretpit" => {
            let dir = arg(req, "dir")?.to_string();
            let map = o(req, "map").unwrap_or("").to_string();
            let dry = b(req, "dry_run").unwrap_or(true);
            let report = importer::import(s, &dir, &map, dry)?;
            if !dry {
                s.save()?;
                s.audit(
                    "import",
                    &caller.actor,
                    json!({"from": dir, "summary": report.get("summary")}),
                );
            }
            Ok(report)
        }
        op => Err(Error::Invalid(format!("unknown operation {op}"))),
    }
}

fn s_(req: &Request, k: &str) -> Result<String> {
    arg(req, k).map(String::from)
}

pub fn new_channel(name: &str, description: &str, protected: bool) -> Channel {
    Channel {
        name: name.into(),
        description: description.into(),
        inherit: true,
        protected,
        secrets: BTreeMap::new(),
        destinations: BTreeMap::new(),
    }
}

pub fn new_secret(name: &str, protection: Protection, kind: Kind) -> Secret {
    Secret {
        id: crypto::random_id(),
        name: name.into(),
        description: String::new(),
        protection,
        kind,
        tags: vec![],
        value: None,
        history: vec![],
        created: now(),
        updated: now(),
    }
}

// ---------------------------------------------------------------------------
// listing

pub fn secret_meta(sec: &Secret) -> Value {
    json!({
        "name": sec.name,
        "description": sec.description,
        "protection": sec.protection.to_string(),
        "kind": match &sec.kind { Kind::Text => "text", Kind::File { .. } => "file" },
        "filename": match &sec.kind { Kind::File { filename } => Some(filename.clone()), _ => None },
        "tags": sec.tags,
        "set": sec.is_set(),
        "fp": sec.fingerprint(),
        "updated": fmt_time(sec.updated),
        "versions": sec.history.len() + sec.value.is_some() as usize,
    })
}

fn tree(lib: &Library, only: Option<&str>) -> Value {
    // A one-way secret that a destination expects is flagged wherever it is listed.
    let secret_meta = |sec: &Secret| {
        let mut m = secret_meta(sec);
        if sec.protection == Protection::Hashed {
            m["unpushable_to"] = json!(resolve::receivers(lib, &sec.id));
        }
        m
    };
    let projects: Vec<Value> = lib
        .projects
        .values()
        .filter(|p| only.map(|o| o == p.name).unwrap_or(true))
        .map(|p| {
            json!({
                "name": p.name,
                "description": p.description,
                "secrets": p.secrets.values().map(&secret_meta).collect::<Vec<_>>(),
                "channels": p.channels.values().map(|c| json!({
                    "name": c.name,
                    "description": c.description,
                    "inherit": c.inherit,
                    "protected": c.protected,
                    "secrets": c.secrets.values().map(&secret_meta).collect::<Vec<_>>(),
                    "destinations": c.destinations.values().map(|d| json!({
                        "name": d.name,
                        "kind": d.kind,
                        "description": d.description,
                        "address": rail::address(&d.kind, &d.config),
                        "select": d.select,
                        "config": d.config,
                        "connection": d.connection,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "projects": projects,
        "globals": lib.globals.values().map(&secret_meta).collect::<Vec<_>>(),
        "connections": lib.connections.values().map(|c| json!({
            "name": c.name, "kind": c.kind, "mode": c.mode, "account": c.account,
            "description": c.description, "verified": fmt_time(c.verified_at), "config": c.config,
        })).collect::<Vec<_>>(),
    })
}

fn needs(lib: &Library, only: Option<&str>) -> Value {
    let mut out = vec![];
    for (n, sec) in &lib.globals {
        if !sec.is_set() && only.is_none() {
            out.push(json!({"scope": "global", "name": n, "description": sec.description}));
        }
    }
    for p in lib
        .projects
        .values()
        .filter(|p| only.map(|o| o == p.name).unwrap_or(true))
    {
        for (n, sec) in &p.secrets {
            if !sec.is_set() {
                out.push(json!({"scope": p.name, "name": n, "description": sec.description}));
            }
        }
        for c in p.channels.values() {
            for (n, sec) in &c.secrets {
                if !sec.is_set() {
                    out.push(json!({"scope": format!("{}/{}", p.name, c.name), "name": n, "description": sec.description}));
                }
            }
        }
    }
    json!({"empty": out})
}

// ---------------------------------------------------------------------------
// secrets

fn generate(len: usize, charset: &str) -> Zeroizing<Vec<u8>> {
    let alphabet: &[u8] = match charset {
        "hex" => b"0123456789abcdef",
        "alnum" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "base64url" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        _ => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+-.:=@^_~",
    };
    // rejection sampling: no modulo bias
    let limit = 256 - (256 % alphabet.len());
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    while out.len() < len {
        let mut buf = [0u8; 64];
        crypto::fill_random(&mut buf);
        for &x in buf.iter() {
            if (x as usize) < limit && out.len() < len {
                out.push(alphabet[x as usize % alphabet.len()]);
            }
        }
    }
    out
}

/// A service such as Vercel or Fly stores the real value, so the pit decrypts a
/// secret at push time. A one-way secret has no value left to decrypt; putting
/// one where a destination expects it needs the person's explicit say-so.
fn guard_one_way(
    s: &Session,
    caller: &Caller,
    sc: &Scope,
    name: &str,
    req: &Request,
) -> Result<()> {
    let Some(sec) = s.lib.secrets(sc)?.get(name) else {
        return Ok(());
    };
    // Only a person at a terminal can confirm; an AI client is always told no.
    let confirmed = caller.client != "mcp" && b(req, "confirmed").unwrap_or(false);
    if sec.protection != Protection::Hashed || confirmed {
        return Ok(());
    }
    let to = resolve::receivers(&s.lib, &sec.id);
    if to.is_empty() {
        return Ok(());
    }
    Err(Error::Confirm(format!(
        "{name} is stored one-way, but it is pushed to:\n  {}\n\
         Services need the real value, and a one-way secret can never be pushed — these \
         destinations would go without it. Keep it sealed (encrypted here, decrypted only \
         when pushed) unless the value is only ever checked, never sent.",
        to.join("\n  ")
    )))
}

fn secret_set(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let sc = scope(req)?;
    let name = s_(req, "name")?;
    valid_name("secret", &name)?;
    let declare_only = req.op == "secret.declare";
    let protection: Option<Protection> = o(req, "protection").map(|p| p.parse()).transpose()?;
    let filename = o(req, "filename").map(String::from);
    if let Some(f) = &filename {
        if !crate::model::safe_relative(f) {
            return invalid(format!("{f} is not a safe file name"));
        }
    }

    let value: Option<Zeroizing<Vec<u8>>> = if declare_only {
        None
    } else if req.op == "secret.generate" {
        let len = u(req, "length").unwrap_or(48).clamp(16, 4096) as usize;
        Some(generate(len, o(req, "charset").unwrap_or("base64url")))
    } else {
        Some(Zeroizing::new(crypto::b64d(arg(req, "value_b64")?)?))
    };

    let keys = &s.keys;
    let map = s.lib.secrets_mut(&sc)?;
    let existed = map.contains_key(&name);
    if declare_only && existed {
        return Err(Error::Exists(format!(
            "{name} in {sc} — use `pit edit` or `pit describe` to change an existing secret"
        )));
    }
    if req.op == "secret.generate" && caller.client == "mcp" {
        if let Some(sec) = map.get(&name) {
            if sec.is_set() {
                return Err(Error::Refused(format!(
                    "{name} already has a value; an AI client may only fill empty secrets"
                )));
            }
        }
    }
    let sec = map.entry(name.clone()).or_insert_with(|| {
        let kind = match &filename {
            Some(f) => Kind::File {
                filename: f.clone(),
            },
            None => Kind::Text,
        };
        new_secret(&name, protection.unwrap_or(Protection::Sealed), kind)
    });
    if let Some(p) = protection {
        if existed && p != sec.protection {
            values::reprotect(keys, sec, p)?;
        }
    }
    if let Some(d) = o(req, "description") {
        sec.description = d.into();
    }
    let tags = strings(req, "tags");
    if !tags.is_empty() {
        sec.tags = tags;
    }
    if let Some(f) = filename {
        sec.kind = Kind::File { filename: f };
    }
    if let Some(v) = value.as_ref() {
        if let Kind::Text = sec.kind {
            if std::str::from_utf8(v).is_err() {
                return invalid(format!("{name} is binary — store it as a file (--file)"));
            }
        }
        values::set(keys, sec, v)?;
    }
    sec.updated = now();
    let meta = secret_meta(sec);
    guard_one_way(s, caller, &sc, &name, req)?;
    s.save()?;
    s.audit(
        if value.is_some() { "secret.set" } else { "secret.declare" },
        &caller.actor,
        json!({"scope": sc.to_string(), "name": name, "fp": meta.get("fp"), "protection": meta.get("protection")}),
    );
    Ok(meta)
}

/// Bring many values in at once (from a .env file, a JSON file or a scan).
/// Unchanged values are left alone; values that differ are only replaced with
/// `overwrite`, and their old value stays in history.
fn secret_import(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let sc = scope(req)?;
    let dry = b(req, "dry_run").unwrap_or(false);
    let overwrite = b(req, "overwrite").unwrap_or(false);
    let protection: Protection = o(req, "protection").unwrap_or("sealed").parse()?;
    let tags = strings(req, "tags");
    let items = req
        .args
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let (mut added, mut unchanged, mut differs, mut replaced, mut rejected) =
        (vec![], vec![], vec![], vec![], vec![]);
    let keys = &s.keys;
    let map = s.lib.secrets_mut(&sc)?;
    for it in &items {
        let name = it["name"].as_str().unwrap_or("").to_string();
        if let Err(e) = valid_name("secret", &name) {
            rejected.push(json!({"name": name, "why": e.to_string()}));
            continue;
        }
        let value = Zeroizing::new(crypto::b64d(it["value_b64"].as_str().unwrap_or(""))?);
        let filename = it["filename"].as_str().filter(|f| !f.is_empty());
        if let Some(f) = filename {
            if !crate::model::safe_relative(f) {
                rejected.push(json!({"name": name, "why": "unsafe file name"}));
                continue;
            }
        } else if std::str::from_utf8(&value).is_err() {
            rejected.push(json!({"name": name, "why": "binary — import it as a file"}));
            continue;
        }
        if value.is_empty() {
            rejected.push(json!({"name": name, "why": "empty — use `pit declare`"}));
            continue;
        }
        let desc = it["description"].as_str().unwrap_or("");
        match map.get_mut(&name) {
            Some(sec)
                if sec.fingerprint() == Some(crypto::fingerprint(&keys.fp, &value).as_str()) =>
            {
                unchanged.push(name)
            }
            Some(sec) if sec.is_set() && !overwrite => differs.push(name),
            Some(sec) => {
                if !dry {
                    values::set(keys, sec, &value)?;
                    if sec.description.is_empty() {
                        sec.description = desc.into();
                    }
                }
                replaced.push(name);
            }
            None => {
                if !dry {
                    let kind = match filename {
                        Some(f) => Kind::File { filename: f.into() },
                        None => Kind::Text,
                    };
                    let mut sec = new_secret(&name, protection, kind);
                    sec.description = desc.into();
                    sec.tags = tags.clone();
                    values::set(keys, &mut sec, &value)?;
                    map.insert(name.clone(), sec);
                }
                added.push(name);
            }
        }
    }
    if !dry {
        for n in added.iter().chain(replaced.iter()) {
            guard_one_way(s, caller, &sc, n, req)?;
        }
        if !added.is_empty() || !replaced.is_empty() {
            s.save()?;
            s.audit(
                "secret.import",
                &caller.actor,
                json!({"scope": sc.to_string(), "added": added, "replaced": replaced, "source": o(req, "source")}),
            );
        }
    }
    Ok(json!({
        "scope": sc.to_string(), "dry_run": dry, "added": added, "unchanged": unchanged,
        "differs": differs, "replaced": replaced, "rejected": rejected,
    }))
}

fn secret_edit(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let sc = scope(req)?;
    let name = s_(req, "name")?;
    let keys = &s.keys;
    let map = s.lib.secrets_mut(&sc)?;
    let mut sec = map
        .remove(&name)
        .ok_or_else(|| Error::NotFound(format!("{name} in {sc}")))?;
    let r = (|| -> Result<()> {
        if let Some(d) = o(req, "description") {
            sec.description = d.into();
        }
        if let Some(p) = o(req, "protection") {
            values::reprotect(keys, &mut sec, p.parse()?)?;
        }
        if req.args.get("tags").is_some() {
            sec.tags = strings(req, "tags");
        }
        if let Some(f) = o(req, "filename") {
            if !f.is_empty() && !crate::model::safe_relative(f) {
                return invalid(format!("{f} is not a safe file name"));
            }
            sec.kind = if f.is_empty() {
                Kind::Text
            } else {
                Kind::File { filename: f.into() }
            };
        }
        if let Some(n) = o(req, "rename") {
            valid_name("secret", n)?;
            sec.name = n.into();
        }
        Ok(())
    })();
    let key = sec.name.clone();
    if r.is_err() || map.contains_key(&key) && key != name {
        sec.name = name.clone();
        map.insert(name.clone(), sec);
        r?;
        return Err(Error::Exists(format!("{key} in {sc}")));
    }
    let meta = secret_meta(&sec);
    map.insert(key.clone(), sec);
    guard_one_way(s, caller, &sc, &key, req)?;
    s.save()?;
    s.audit(
        "secret.edit",
        &caller.actor,
        json!({"scope": sc.to_string(), "name": name}),
    );
    Ok(meta)
}

// ---------------------------------------------------------------------------
// destinations and connections

fn dest_upsert(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let p = s_(req, "project")?;
    let c = s_(req, "channel")?;
    let name = s_(req, "name")?;
    valid_slug("destination", &name)?;
    let ch = s.lib.channel_mut(&p, &c)?;
    let existing = ch.destinations.get(&name).cloned();
    if req.op == "dest.add" && existing.is_some() {
        return Err(Error::Exists(format!("destination {name}")));
    }
    let mut d = existing.unwrap_or(Destination {
        name: name.clone(),
        kind: o(req, "kind").unwrap_or("").into(),
        description: String::new(),
        select: vec![],
        config: BTreeMap::new(),
        connection: None,
    });
    if let Some(k) = o(req, "kind") {
        d.kind = k.into();
    }
    let info = rail::kind_info(&d.kind)?;
    if let Some(desc) = o(req, "description") {
        d.description = desc.into();
    }
    if req.args.get("select").is_some() {
        d.select = strings(req, "select");
    }
    for (k, v) in map(req, "config") {
        if !info.config.iter().any(|(ck, _)| *ck == k) && k != "token_from" {
            return invalid(format!(
                "{} destinations have no setting `{k}` (they take: {})",
                d.kind,
                info.config
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if v.is_empty() {
            d.config.remove(&k);
        } else {
            d.config.insert(k, v);
        }
    }
    if let Some(cn) = o(req, "connection") {
        d.connection = if cn.is_empty() { None } else { Some(cn.into()) };
    }
    let one_way = resolve::one_way_selected(&s.lib, &p, &c, &d);
    let out = json!({"name": d.name, "kind": d.kind, "address": rail::address(&d.kind, &d.config), "one_way": one_way});
    s.lib
        .channel_mut(&p, &c)?
        .destinations
        .insert(name.clone(), d);
    s.save()?;
    s.audit(
        &req.op,
        &caller.actor,
        json!({"project": p, "channel": c, "destination": name, "address": out["address"]}),
    );
    Ok(out)
}

fn conn_add(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let name = s_(req, "name")?;
    valid_slug("connection", &name)?;
    let kind = s_(req, "kind")?;
    let mode = o(req, "mode").unwrap_or("token").to_string();
    let config = map(req, "config");
    let token = o(req, "token").map(|t| Zeroizing::new(t.trim().to_string()));
    let account = match mode.as_str() {
        "token" => {
            let t = token
                .as_ref()
                .ok_or_else(|| Error::Invalid("a token is required".into()))?;
            if b(req, "skip_verify").unwrap_or(false) {
                "unverified".to_string()
            } else {
                rail::verify_connection(&kind, Some(t), &config)?
            }
        }
        "cli" => {
            let t = rail::cli_token(&kind)?;
            rail::verify_connection(&kind, t.as_deref().map(|x| x.as_str()), &config)?
        }
        _ => return invalid("mode must be token or cli"),
    };
    let stored = match (&mode[..], token) {
        ("token", Some(t)) => Some(values::store(
            &s.keys,
            &format!("connection:{name}"),
            Protection::Sealed,
            t.as_bytes(),
        )?),
        _ => None,
    };
    let conn = Connection {
        name: name.clone(),
        kind: kind.clone(),
        description: o(req, "description").unwrap_or("").into(),
        mode: mode.clone(),
        account: account.clone(),
        token: stored,
        config,
        created: now(),
        verified_at: now(),
    };
    s.lib.connections.insert(name.clone(), conn);
    s.save()?;
    s.audit(
        "conn.add",
        &caller.actor,
        json!({"connection": name, "kind": kind, "mode": mode, "account": account}),
    );
    Ok(json!({"name": name, "kind": kind, "mode": mode, "account": account}))
}

fn conn_token(s: &Session, conn: &Connection) -> Result<Option<Zeroizing<String>>> {
    match conn.mode.as_str() {
        "cli" => rail::cli_token(&conn.kind),
        _ => match &conn.token {
            Some(st) => {
                let v = values::open_stored(&s.keys, &format!("connection:{}", conn.name), st)?;
                Ok(Some(Zeroizing::new(
                    String::from_utf8_lossy(&v).into_owned(),
                )))
            }
            None => Ok(None),
        },
    }
}

// ---------------------------------------------------------------------------
// push

struct Prepared {
    ctx_config: BTreeMap<String, String>,
    token: Option<Zeroizing<String>>,
    conn_mode: String,
    conn_name: String,
}

fn lookup_value(s: &Session, project: &str, channel: &str, name: &str) -> Result<Option<String>> {
    let view = resolve::channel_view(&s.lib, project, channel)?;
    let sec = match name.strip_prefix("global:") {
        Some(g) => s.lib.globals.get(g),
        None => view.get(name).map(|v| v.secret),
    };
    match sec {
        None => Err(Error::NotFound(format!(
            "{name} (referenced by a destination setting)"
        ))),
        Some(sec) => {
            Ok(values::open(&s.keys, sec)?.map(|v| String::from_utf8_lossy(&v).into_owned()))
        }
    }
}

/// Destination settings are addresses, shown in logs and to AI clients, so
/// they may only be filled from `plain` secrets.
fn template_value(s: &Session, project: &str, channel: &str, name: &str) -> Result<Option<String>> {
    let view = resolve::channel_view(&s.lib, project, channel)?;
    let sec = match name.strip_prefix("global:") {
        Some(g) => s.lib.globals.get(g),
        None => view.get(name).map(|v| v.secret),
    };
    if let Some(sec) = sec {
        if sec.protection != Protection::Plain {
            return Err(Error::Refused(format!(
                "destination settings may only use plain secrets, and {name} is {} — store the address as plain, or pass credentials with token_from",
                sec.protection
            )));
        }
    }
    lookup_value(s, project, channel, name)
}

fn prepare(s: &Session, project: &str, channel: &str, d: &Destination) -> Result<Prepared> {
    let mut cfg = BTreeMap::new();
    for (k, v) in &d.config {
        if k == "token_from" {
            continue;
        }
        let r = resolve::template(v, &mut |n| template_value(s, project, channel, n))?;
        cfg.insert(k.clone(), r);
    }
    let info = rail::kind_info(&d.kind)?;
    let mut token = None;
    let mut conn_mode = String::new();
    let mut conn_name = String::new();
    if info.needs_connection {
        if let Some(from) = d.config.get("token_from") {
            if let Some(v) = lookup_value(s, project, channel, from)? {
                if !v.is_empty() {
                    token = Some(Zeroizing::new(v));
                    conn_mode = "token".into();
                    conn_name = format!("secret:{from}");
                }
            }
        }
        if token.is_none() {
            let name = d.connection.clone().unwrap_or_else(|| d.kind.clone());
            match s.lib.connections.get(&name) {
                Some(conn) => {
                    token = conn_token(s, conn)?;
                    conn_mode = conn.mode.clone();
                    conn_name = name;
                }
                None if d.kind == "fly" => {
                    conn_mode = "cli".into();
                    conn_name = "flyctl session".into();
                }
                None => {
                    return Err(Error::Invalid(format!(
                        "destination {} needs a {} connection — run `pit connect {}`",
                        d.name, d.kind, d.kind
                    )))
                }
            }
        }
    }
    Ok(Prepared {
        ctx_config: cfg,
        token,
        conn_mode,
        conn_name,
    })
}

/// A channel that is not protected must not reach an address a protected
/// channel of the same project pushes to.
fn guard_collisions(
    s: &Session,
    project: &str,
    channel: &str,
    kind: &str,
    address: &str,
) -> Result<()> {
    let ch = s.lib.channel(project, channel)?;
    if ch.protected {
        return Ok(());
    }
    for other in s
        .lib
        .project(project)?
        .channels
        .values()
        .filter(|c| c.protected)
    {
        for d in other.destinations.values().filter(|d| d.kind == kind) {
            if let Ok(p) = prepare(s, project, &other.name, d) {
                if rail::address(kind, &p.ctx_config) == address {
                    return Err(Error::Refused(format!(
                        "{project}/{channel} is not protected but {address} belongs to the protected channel {project}/{}",
                        other.name
                    )));
                }
            }
        }
    }
    Ok(())
}

fn push(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let project = s_(req, "project")?;
    let channel = s_(req, "channel")?;
    let dry = b(req, "dry_run").unwrap_or(false);
    let force = b(req, "force").unwrap_or(false);
    let ch = s.lib.channel(&project, &channel)?;
    let protected = ch.protected;
    let wanted = strings(req, "destinations");
    let dests: Vec<Destination> = if wanted.is_empty() {
        ch.destinations.values().cloned().collect()
    } else {
        wanted
            .iter()
            .map(|n| {
                ch.destinations.get(n).cloned().ok_or_else(|| {
                    Error::NotFound(format!("destination {n} in {project}/{channel}"))
                })
            })
            .collect::<Result<_>>()?
    };
    if dests.is_empty() {
        return invalid(format!(
            "{project}/{channel} has no destinations — add one with `pit dest add`"
        ));
    }
    let mut results = vec![];
    for d in dests {
        // Logged before anything is sent: if the log cannot be written, nothing goes out.
        if !dry {
            s.audit_strict(
                "push.start",
                &caller.actor,
                json!({"project": project, "channel": channel, "destination": d.name, "kind": d.kind,
                       "address": rail::address(&d.kind, &d.config)}),
            )?;
        }
        let r = push_one(s, &project, &channel, protected, &d, dry, force);
        let (ok, value) = match r {
            Ok((v, keys, skipped, address, via)) => {
                s.audit(
                    "push",
                    &caller.actor,
                    json!({"project": project, "channel": channel, "destination": d.name, "kind": d.kind,
                           "address": address, "via": via, "keys": keys, "skipped": skipped, "dry_run": dry, "result": "ok"}),
                );
                (true, v)
            }
            Err(e) => {
                s.audit(
                    "push",
                    &caller.actor,
                    json!({"project": project, "channel": channel, "destination": d.name, "kind": d.kind,
                           "address": rail::address(&d.kind, &d.config), "dry_run": dry, "result": "error", "error": e.to_string()}),
                );
                (
                    false,
                    json!({"destination": d.name, "error": e.to_string()}),
                )
            }
        };
        results.push(json!({"ok": ok, "result": value}));
    }
    Ok(json!({"project": project, "channel": channel, "dry_run": dry, "results": results}))
}

type PushOut = (Value, Vec<Value>, Vec<Value>, String, String);

fn push_one(
    s: &Session,
    project: &str,
    channel: &str,
    protected: bool,
    d: &Destination,
    dry: bool,
    force: bool,
) -> Result<PushOut> {
    let prep = prepare(s, project, channel, d)?;
    let address = rail::address(&d.kind, &prep.ctx_config);
    guard_collisions(s, project, channel, &d.kind, &address)?;
    let selected = resolve::select(&s.lib, project, channel, d)?;
    let mut items = vec![];
    let mut keys = vec![];
    let mut skipped = vec![];
    for sel in selected {
        if let Err(why) = resolve::pushable(sel.secret) {
            skipped.push(json!({"name": sel.deliver_as, "why": why}));
            continue;
        }
        let v = values::open(&s.keys, sel.secret)?.expect("pushable implies set");
        keys.push(json!({"name": sel.deliver_as, "fp": sel.secret.fingerprint()}));
        items.push(Item {
            name: sel.deliver_as.clone(),
            value: v,
            filename: match &sel.secret.kind {
                Kind::File { filename } => Some(filename.clone()),
                Kind::Text => None,
            },
        });
    }
    if items.is_empty() {
        return Err(Error::Invalid(format!(
            "nothing to push to {} — every selected secret is empty",
            d.name
        )));
    }
    let ctx = rail::Ctx {
        project,
        channel,
        protected,
        dest_name: &d.name,
        config: prep.ctx_config,
        token: prep.token,
        dry_run: dry,
        force,
    };
    let rep = rail::push(&d.kind, &ctx, &items)?;
    let via = if prep.conn_name.is_empty() {
        "local".to_string()
    } else {
        format!("{} ({})", prep.conn_name, prep.conn_mode)
    };
    Ok((
        json!({"destination": d.name, "kind": d.kind, "address": rep.address, "sent": rep.sent, "skipped": skipped, "notes": rep.notes, "via": via}),
        keys,
        skipped,
        rep.address,
        via,
    ))
}

fn remote(s: &Session, req: &Request) -> Result<Value> {
    let project = s_(req, "project")?;
    let channel = s_(req, "channel")?;
    let ch = s.lib.channel(&project, &channel)?;
    let mut out = vec![];
    for d in ch.destinations.values() {
        let only = strings(req, "destinations");
        if !only.is_empty() && !only.contains(&d.name) {
            continue;
        }
        let entry = (|| -> Result<Value> {
            let prep = prepare(s, &project, &channel, d)?;
            let selected = resolve::select(&s.lib, &project, &channel, d)?;
            let local: Vec<String> = selected
                .iter()
                .filter(|x| x.secret.is_set())
                .map(|x| x.deliver_as.clone())
                .collect();
            let ctx = rail::Ctx {
                project: &project,
                channel: &channel,
                protected: ch.protected,
                dest_name: &d.name,
                config: prep.ctx_config,
                token: prep.token,
                dry_run: true,
                force: false,
            };
            let remote = rail::remote_names(&d.kind, &ctx)?;
            Ok(match remote {
                Some(r) => json!({
                    "destination": d.name,
                    "address": rail::address(&d.kind, &ctx.config),
                    "missing_there": local.iter().filter(|n| !r.contains(n)).collect::<Vec<_>>(),
                    "only_there": r.iter().filter(|n| !local.contains(n)).collect::<Vec<_>>(),
                    "in_both": local.iter().filter(|n| r.contains(n)).count(),
                }),
                None => {
                    json!({"destination": d.name, "address": rail::address(&d.kind, &ctx.config), "note": "this kind cannot be listed"})
                }
            })
        })();
        out.push(entry.unwrap_or_else(|e| json!({"destination": d.name, "error": e.to_string()})));
    }
    Ok(json!({"project": project, "channel": channel, "destinations": out}))
}

fn absorb(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let project = s_(req, "project")?;
    let channel = s_(req, "channel")?;
    let dest = s_(req, "destination")?;
    let dry = b(req, "dry_run").unwrap_or(false);
    let ch = s.lib.channel(&project, &channel)?;
    let d = ch
        .destinations
        .get(&dest)
        .cloned()
        .ok_or_else(|| Error::NotFound(format!("destination {dest}")))?;
    let prep = prepare(s, &project, &channel, &d)?;
    let selected: Vec<(String, String, Option<String>, String)> =
        resolve::select(&s.lib, &project, &channel, &d)?
            .into_iter()
            .map(|x| {
                let stored = x.secret.name.clone();
                let file = match &x.secret.kind {
                    Kind::File { filename } => Some(filename.clone()),
                    _ => None,
                };
                (x.deliver_as, stored, file, x.secret.id.clone())
            })
            .collect();
    let ctx = rail::Ctx {
        project: &project,
        channel: &channel,
        protected: ch.protected,
        dest_name: &d.name,
        config: prep.ctx_config,
        token: None,
        dry_run: true,
        force: false,
    };
    let names: Vec<(String, Option<String>)> = selected
        .iter()
        .map(|(a, _, f, _)| (a.clone(), f.clone()))
        .collect();
    let found = rail::local::read_back(&d.kind, &ctx, &names)?;
    let mut changed = vec![];
    let mut unknown = vec![];
    let mut inherited = vec![];
    let mut updates: Vec<(String, Zeroizing<Vec<u8>>)> = vec![];
    for (name, value) in found {
        match selected.iter().find(|(a, _, _, _)| *a == name) {
            Some((_, stored, _, _)) => {
                // Absorb only writes the channel's own secrets; a value inherited
                // from the project may also feed other channels.
                let Some(sec) = s.lib.channel(&project, &channel)?.secrets.get(stored) else {
                    inherited.push(stored.clone());
                    continue;
                };
                let same = match sec.fingerprint() {
                    Some(fp) => crypto::fingerprint(&s.keys.fp, &value) == fp,
                    None => value.is_empty(),
                };
                if !same {
                    changed.push(stored.clone());
                    updates.push((stored.clone(), value));
                }
            }
            None => unknown.push(name),
        }
    }
    if !dry {
        for (stored, value) in &updates {
            let scope = Scope::Channel(project.clone(), channel.clone());
            let keys = &s.keys;
            let sec = s
                .lib
                .secrets_mut(&scope)?
                .get_mut(stored)
                .ok_or_else(|| Error::NotFound(stored.clone()))?;
            values::set(keys, sec, value)?;
        }
        if !updates.is_empty() {
            s.save()?;
        }
        s.audit("absorb", &caller.actor, json!({"project": project, "channel": channel, "destination": dest, "changed": changed}));
    }
    Ok(
        json!({"changed": changed, "not_in_pit": unknown, "project_level": inherited, "dry_run": dry}),
    )
}

fn run_env(s: &mut Session, caller: &Caller, req: &Request) -> Result<Value> {
    let project = s_(req, "project")?;
    let channel = s_(req, "channel")?;
    let select = strings(req, "select");
    let d = match o(req, "destination") {
        Some(name) => s
            .lib
            .channel(&project, &channel)?
            .destinations
            .get(name)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("destination {name}")))?,
        None => Destination {
            name: "run".into(),
            // `files` so that wildcards include file secrets, which `pit run` materializes.
            kind: "files".into(),
            description: String::new(),
            select: if select.is_empty() {
                vec!["*".into()]
            } else {
                select
            },
            config: BTreeMap::new(),
            connection: None,
        },
    };
    let mut env = serde_json::Map::new();
    let mut files = vec![];
    let mut names = vec![];
    for sel in resolve::select(&s.lib, &project, &channel, &d)? {
        if resolve::pushable(sel.secret).is_err() {
            continue;
        }
        let v = values::open(&s.keys, sel.secret)?.expect("set");
        names.push(sel.deliver_as.clone());
        match &sel.secret.kind {
            Kind::File { filename } => files.push(
                json!({"name": sel.deliver_as, "filename": filename, "b64": crypto::b64e(&v)}),
            ),
            Kind::Text => {
                env.insert(
                    sel.deliver_as.clone(),
                    Value::String(String::from_utf8_lossy(&v).into_owned()),
                );
            }
        }
    }
    s.audit_strict(
        "run",
        &caller.actor,
        json!({"project": project, "channel": channel, "keys": names}),
    )?;
    Ok(json!({"env": env, "files": files}))
}

fn log(s: &Session, req: &Request) -> Result<Value> {
    let v = crate::audit::read(&s.keys, s.lib.log_seq)?;
    let limit = u(req, "limit").unwrap_or(50) as usize;
    let project = o(req, "project");
    let event = o(req, "event");
    let mut events: Vec<Value> = v
        .events
        .iter()
        .rev()
        .filter(|e| event.map(|x| e.event == x).unwrap_or(true))
        .filter(|e| project.map(|p| e.data.get("project").and_then(|x| x.as_str()) == Some(p)).unwrap_or(true))
        .take(limit)
        .map(|e| json!({"seq": e.seq, "time": fmt_time(e.time), "event": e.event, "actor": e.actor, "data": e.data}))
        .collect();
    events.reverse();
    Ok(
        json!({"events": events, "total": v.events.len(), "intact": v.broken_at.is_none(), "broken_at": v.broken_at}),
    )
}
