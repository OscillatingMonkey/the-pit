//! The interactive console: `pit` with no arguments. Every CLI command works
//! here without the `pit` prefix, plus `use PROJECT/CHANNEL` to set a context.
//! Console history is kept in memory only. Tab completes commands, flags, and
//! project, channel, secret and destination names (never values).

use std::cell::RefCell;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use serde_json::{json, Value};

use crate::cli::{self, Cli};
use crate::error::Result;
use crate::{protocol, ui};

const CONSOLE_WORDS: [&str; 4] = ["use", "help", "exit", "quit"];

fn prompt(context: &Option<String>) -> String {
    let open = protocol::call("console", "status", json!({}), None)
        .map(|r| r["unlocked"] == json!(true))
        .unwrap_or(false);
    let lock = if open { "" } else { " (locked)" };
    match context {
        Some(c) => format!("pit {c}{lock}> "),
        None => format!("pit{lock}> "),
    }
}

pub fn run() -> Result<()> {
    protocol::ensure_agent()?;
    println!("{}", ui::bold("The Pit console"));
    println!("Type any pit command without `pit` (ls, set, push, log…). `use PROJECT/CHANNEL` sets a context.");
    println!("`help` lists commands, `help COMMAND` explains one, Tab completes, `exit` leaves. History is not saved.\n");
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut rl: Editor<PitHelper, DefaultHistory> =
        Editor::with_config(config).map_err(|e| crate::error::Error::Invalid(e.to_string()))?;
    rl.set_helper(Some(PitHelper::default()));
    let mut context: Option<String> = None;
    loop {
        if let Some(h) = rl.helper_mut() {
            h.context = context.clone();
        }
        let line = match rl.readline(&prompt(&context)) {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                ui::error(&e.to_string());
                break;
            }
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(mut words) = shell_words::split(line) else {
            ui::error("could not parse that line (unbalanced quotes?)");
            continue;
        };
        match words[0].as_str() {
            "exit" | "quit" | "q" => break,
            "help" | "?" => {
                let mut argv = vec!["pit".to_string()];
                argv.extend(words[1..].iter().cloned());
                argv.push("--help".into());
                match Cli::try_parse_from(&argv) {
                    Err(e) if e.kind() == clap::error::ErrorKind::InvalidSubcommand => {
                        println!("{}", cli::unknown_command_help(&words[1], ""));
                    }
                    Err(e) => {
                        let _ = e.print();
                    }
                    Ok(_) => {}
                }
                if words.len() == 1 {
                    println!(
                        "\nconsole only: use PROJECT/CHANNEL · use (clear) · help COMMAND · exit"
                    );
                }
                continue;
            }
            "use" => {
                context = words.get(1).cloned();
                match &context {
                    Some(c) => ui::ok(&format!("context {c} — commands that take PROJECT/CHANNEL use it when you leave it out")),
                    None => ui::ok("context cleared"),
                }
                continue;
            }
            "console" => continue,
            _ => {}
        }
        if let Some(ctx) = &context {
            apply_context(&mut words, ctx);
        }
        let mut argv = vec!["pit".to_string()];
        argv.extend(words.iter().cloned());
        match Cli::try_parse_from(&argv) {
            Ok(c) => {
                if let Err(e) = cli::run(c) {
                    ui::error(&e.to_string());
                }
            }
            Err(e) => match e.kind() {
                clap::error::ErrorKind::InvalidSubcommand => {
                    println!("{}", cli::unknown_command_help(&words[0], ""));
                }
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    let _ = e.print();
                }
                _ => {
                    let _ = e.print();
                    println!("`help {}` shows how to use it.", words[0]);
                }
            },
        }
    }
    Ok(())
}

/// Insert the context where a command expects PROJECT/CHANNEL and it was left out.
fn apply_context(words: &mut Vec<String>, ctx: &str) {
    let takes_target = ["push", "diff", "ls", "list"];
    let takes_scope = [
        "set", "declare", "reveal", "view", "show", "get", "rm", "delete", "remove", "verify",
        "rollback", "edit",
    ];
    let cmd = words[0].clone();
    let positional: Vec<&String> = words
        .iter()
        .skip(1)
        .filter(|w| !w.starts_with('-'))
        .collect();
    if (takes_target.contains(&cmd.as_str())
        && positional.first().map(|p| !p.contains('/')).unwrap_or(true))
        || (takes_scope.contains(&cmd.as_str()) && positional.len() == 1)
    {
        words.insert(1, ctx.to_string());
    } else if cmd == "run" && !words.iter().any(|w| w == "-c" || w == "--channel") {
        words.insert(1, ctx.to_string());
        words.insert(1, "-c".into());
    }
}

// ---------------------------------------------------------------------------
// completion

/// Names from the vault, fetched from the agent (names only) and kept briefly.
#[derive(Default, Clone)]
struct Names {
    /// "global", "PROJECT" and "PROJECT/CHANNEL"
    scopes: Vec<String>,
    /// (scope, secret name) — scope as in `scopes`
    secrets: Vec<(String, String)>,
    /// (PROJECT/CHANNEL, destination name)
    destinations: Vec<(String, String)>,
    connections: Vec<String>,
}

fn names_from(tree: &Value) -> Names {
    let mut n = Names {
        scopes: vec!["global".into()],
        ..Default::default()
    };
    let list = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x["name"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    for s in list(&tree["globals"]) {
        n.secrets.push(("global".into(), s));
    }
    for c in list(&tree["connections"]) {
        n.connections.push(c);
    }
    for p in tree["projects"].as_array().into_iter().flatten() {
        let pname = p["name"].as_str().unwrap_or_default().to_string();
        n.scopes.push(pname.clone());
        for s in list(&p["secrets"]) {
            n.secrets.push((pname.clone(), s));
        }
        for c in p["channels"].as_array().into_iter().flatten() {
            let scope = format!("{pname}/{}", c["name"].as_str().unwrap_or_default());
            n.scopes.push(scope.clone());
            for s in list(&c["secrets"]) {
                n.secrets.push((scope.clone(), s));
            }
            for d in list(&c["destinations"]) {
                n.destinations.push((scope.clone(), d));
            }
        }
    }
    n
}

#[derive(Default)]
struct PitHelper {
    context: Option<String>,
    cache: RefCell<Option<(Instant, Names)>>,
}

impl PitHelper {
    fn names(&self) -> Names {
        let mut c = self.cache.borrow_mut();
        if let Some((at, n)) = c.as_ref() {
            if at.elapsed() < Duration::from_secs(5) {
                return n.clone();
            }
        }
        let n = protocol::call("console", "tree", json!({}), None)
            .map(|t| names_from(&t))
            .unwrap_or_default();
        *c = Some((Instant::now(), n.clone()));
        n
    }

    /// Secret names visible from `scope`: its own, its project's (for a channel), and globals.
    fn secrets_in(&self, names: &Names, scope: &str) -> Vec<String> {
        let project = scope.split('/').next().unwrap_or(scope);
        let mut out: Vec<String> = names
            .secrets
            .iter()
            .filter(|(s, _)| s == scope || s == project || s == "global")
            .map(|(_, n)| n.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn candidates(&self, before: &[&str], partial: &str) -> Vec<String> {
        if before.is_empty() {
            let mut all = cli::command_names();
            all.extend(CONSOLE_WORDS.iter().map(|s| s.to_string()));
            return all;
        }
        if before[0] == "help" || before[0] == "?" {
            return if before.len() == 1 {
                cli::command_names()
            } else {
                subcommands_at(&before[1..])
            };
        }
        if before[0] == "use" {
            return if before.len() == 1 {
                self.names().scopes
            } else {
                vec![]
            };
        }
        // Walk down the command tree as far as the typed words go.
        let mut cmd = Cli::command();
        let mut depth = 0;
        while depth < before.len() {
            let w = before[depth];
            let next = cmd
                .get_subcommands()
                .find(|c| c.get_name() == w || c.get_all_aliases().any(|a| a == w))
                .cloned();
            match next {
                Some(sub) => {
                    cmd = sub;
                    depth += 1;
                }
                None => break,
            }
        }
        if depth == 0 {
            return vec![];
        }
        if partial.starts_with('-') {
            return cmd
                .get_arguments()
                .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
                .chain(["--help".to_string()])
                .collect();
        }
        if cmd.has_subcommands() && depth == before.len() {
            return cmd
                .get_subcommands()
                .map(|c| c.get_name().to_string())
                .collect();
        }
        // Positional values: a scope first, then names within it.
        let names = self.names();
        let typed: Vec<&str> = before[depth..]
            .iter()
            .copied()
            .filter(|w| !w.starts_with('-'))
            .collect();
        let top = before[0];
        if top == "connect" || top == "disconnect" {
            return names.connections;
        }
        let scope = typed
            .iter()
            .find(|w| names.scopes.iter().any(|s| s == *w))
            .map(|s| s.to_string())
            .or_else(|| self.context.clone());
        match (typed.len(), scope) {
            (0, Some(ctx)) if self.context.is_some() => {
                // With a context set, the scope may be left out.
                let mut v = names.scopes.clone();
                v.extend(self.secrets_in(&names, &ctx));
                if top == "dest" {
                    v.extend(
                        names
                            .destinations
                            .iter()
                            .filter(|(s, _)| *s == ctx)
                            .map(|(_, d)| d.clone()),
                    );
                }
                v
            }
            (0, _) => names.scopes,
            (_, Some(scope)) if top == "dest" => names
                .destinations
                .iter()
                .filter(|(s, _)| *s == scope)
                .map(|(_, d)| d.clone())
                .collect(),
            (_, Some(scope)) => {
                let mut v = self.secrets_in(&names, &scope);
                if top == "push" {
                    v = names
                        .destinations
                        .iter()
                        .filter(|(s, _)| *s == scope)
                        .map(|(_, d)| d.clone())
                        .collect();
                }
                v
            }
            _ => vec![],
        }
    }
}

/// Subcommand names under a path of command words (for `help backup <Tab>`).
fn subcommands_at(path: &[&str]) -> Vec<String> {
    let mut cmd = Cli::command();
    for w in path {
        let next = cmd
            .get_subcommands()
            .find(|c| c.get_name() == *w || c.get_all_aliases().any(|a| a == *w))
            .cloned();
        match next {
            Some(sub) => cmd = sub,
            None => return vec![],
        }
    }
    cmd.get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect()
}

impl Completer for PitHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let head = &line[..pos];
        let start = head.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
        let partial = &head[start..];
        let before: Vec<&str> = head[..start].split_whitespace().collect();
        let mut matches: Vec<String> = self
            .candidates(&before, partial)
            .into_iter()
            .filter(|c| c.starts_with(partial))
            .collect();
        matches.sort();
        matches.dedup();
        Ok((
            start,
            matches
                .into_iter()
                .map(|m| Pair {
                    display: m.clone(),
                    replacement: if m.ends_with('/') { m } else { format!("{m} ") },
                })
                .collect(),
        ))
    }
}

impl Hinter for PitHelper {
    type Hint = String;
}
impl Highlighter for PitHelper {}
impl Validator for PitHelper {}
impl Helper for PitHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    fn helper() -> PitHelper {
        let tree = json!({
            "globals": [{"name": "SHARED_TOKEN"}],
            "connections": [{"name": "vercel-main"}],
            "projects": [{
                "name": "myapp",
                "secrets": [{"name": "PROJECT_KEY"}],
                "channels": [
                    {"name": "production", "secrets": [{"name": "STRIPE_KEY"}], "destinations": [{"name": "web"}]},
                    {"name": "development", "secrets": [{"name": "DEV_ONLY"}], "destinations": []}
                ]
            }]
        });
        let h = PitHelper::default();
        *h.cache.borrow_mut() = Some((Instant::now(), names_from(&tree)));
        h
    }

    fn complete(h: &PitHelper, line: &str) -> Vec<String> {
        let before: Vec<&str> = line[..line.rfind(' ').map(|i| i + 1).unwrap_or(0)]
            .split_whitespace()
            .collect();
        let partial = &line[line.rfind(' ').map(|i| i + 1).unwrap_or(0)..];
        let mut v: Vec<String> = h
            .candidates(&before, partial)
            .into_iter()
            .filter(|c| c.starts_with(partial))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn completes_commands_aliases_and_console_words() {
        let h = helper();
        assert!(complete(&h, "rev").contains(&"reveal".to_string()));
        assert!(complete(&h, "vi").contains(&"view".to_string()));
        assert!(complete(&h, "us").contains(&"use".to_string()));
        assert_eq!(complete(&h, "backup li"), vec!["list"]);
    }

    #[test]
    fn completes_scopes_then_secrets_in_scope() {
        let h = helper();
        assert_eq!(complete(&h, "reveal myapp/p"), vec!["myapp/production"]);
        assert_eq!(
            complete(&h, "reveal myapp/production "),
            vec!["PROJECT_KEY", "SHARED_TOKEN", "STRIPE_KEY"]
        );
        assert!(!complete(&h, "reveal myapp/production ").contains(&"DEV_ONLY".to_string()));
        assert_eq!(complete(&h, "push myapp/production "), vec!["web"]);
        assert_eq!(
            complete(&h, "use my"),
            vec!["myapp", "myapp/development", "myapp/production"]
        );
    }

    #[test]
    fn completes_flags_and_uses_context() {
        let mut h = helper();
        assert!(complete(&h, "reveal --").contains(&"--copy".to_string()));
        h.context = Some("myapp/development".into());
        let v = complete(&h, "reveal D");
        assert_eq!(v, vec!["DEV_ONLY"]);
    }

    #[test]
    fn unknown_command_help_points_to_reveal() {
        let s = cli::unknown_command_help("veiw", "");
        assert!(s.contains("`view`") || s.contains("`reveal`"), "{s}");
        let s = cli::unknown_command_help("display", "");
        assert!(s.contains("Did you mean `reveal`"), "{s}");
        assert!(s.contains("reveal PROJECT/CHANNEL NAME"));
    }
}
