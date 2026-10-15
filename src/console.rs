//! The interactive console: `pit` with no arguments. Every CLI command works
//! here without the `pit` prefix, plus `use PROJECT/CHANNEL` to set a context.
//! Console history is kept in memory only.

use clap::Parser;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use serde_json::json;

use crate::cli::{self, Cli};
use crate::error::Result;
use crate::{protocol, ui};

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
    println!("`help` lists commands, `exit` leaves. History is not saved.\n");
    let mut rl = DefaultEditor::new().map_err(|e| crate::error::Error::Invalid(e.to_string()))?;
    let mut context: Option<String> = None;
    loop {
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
                let _ = Cli::try_parse_from(["pit", "--help"]).map_err(|e| e.print());
                println!("\nconsole only: use PROJECT/CHANNEL · use (clear) · exit");
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
        argv.extend(words);
        match Cli::try_parse_from(&argv) {
            Ok(c) => {
                if let Err(e) = cli::run(c) {
                    ui::error(&e.to_string());
                }
            }
            Err(e) => {
                let _ = e.print();
            }
        }
    }
    Ok(())
}

/// Insert the context where a command expects PROJECT/CHANNEL and it was left out.
fn apply_context(words: &mut Vec<String>, ctx: &str) {
    let takes_target = ["push", "diff", "ls"];
    let takes_scope = [
        "set", "declare", "reveal", "rm", "verify", "rollback", "edit",
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
