//! The interactive console: `pit` with no arguments. Every CLI command works
//! here without the `pit` prefix, plus `use PROJECT/CHANNEL` to set a context.
//! Console history is kept in memory only. Tab completes commands, flags, flag
//! values and names from the vault (never values), and a greyed hint shows the
//! rest of the word or what the command expects next (→ accepts it).

use clap::Parser;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use serde_json::json;

use crate::cli::{self, Cli};
use crate::complete::{Engine, FILES};
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
    println!("`help` lists commands, `help COMMAND` explains one, Tab completes, `exit` leaves. History is not saved.\n");
    let config = Config::builder()
        .completion_type(CompletionType::List)
        .auto_add_history(true)
        .build();
    let mut rl: Editor<PitHelper, DefaultHistory> =
        Editor::with_config(config).map_err(|e| crate::error::Error::Invalid(e.to_string()))?;
    rl.set_helper(Some(PitHelper::new()));
    let mut context: Option<String> = None;
    loop {
        if let Some(h) = rl.helper_mut() {
            h.engine.context = context.clone();
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
// completion and hints (see `complete`)

#[derive(Default)]
struct PitHelper {
    engine: Engine,
}

impl PitHelper {
    fn new() -> Self {
        PitHelper {
            engine: Engine::console(),
        }
    }
}

/// File names in the folder being typed, for arguments that take a path.
fn files(partial: &str) -> Vec<String> {
    let (dir, prefix) = match partial.rfind('/') {
        Some(i) => (&partial[..=i], &partial[i + 1..]),
        None => ("", partial),
    };
    let read = if dir.is_empty() { "." } else { dir };
    let mut out = vec![];
    if let Ok(entries) = std::fs::read_dir(read) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(prefix) || (name.starts_with('.') && !prefix.starts_with('.')) {
                continue;
            }
            let slash = if e.path().is_dir() { "/" } else { "" };
            out.push(format!("{dir}{name}{slash}"));
        }
    }
    out
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
        let mut pairs = vec![];
        for c in self.engine.candidates(&before, partial) {
            if c.value == FILES {
                for f in files(partial) {
                    let replacement = if f.ends_with('/') {
                        f.clone()
                    } else {
                        format!("{f} ")
                    };
                    pairs.push(Pair {
                        display: f,
                        replacement,
                    });
                }
                continue;
            }
            let display = if c.help.is_empty() {
                c.value.clone()
            } else {
                format!("{:<28} {}", c.value, c.help)
            };
            let replacement = if c.value.ends_with('/') {
                c.value
            } else {
                format!("{} ", c.value)
            };
            pairs.push(Pair {
                display,
                replacement,
            });
        }
        Ok((start, pairs))
    }
}

/// Shown greyed after the cursor; → or End accepts the part that completes the word.
pub struct Hint {
    shown: String,
    insert: String,
}

impl rustyline::hint::Hint for Hint {
    fn display(&self) -> &str {
        &self.shown
    }
    fn completion(&self) -> Option<&str> {
        (!self.insert.is_empty()).then_some(self.insert.as_str())
    }
}

impl Hinter for PitHelper {
    type Hint = Hint;

    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<Hint> {
        if pos < line.len() {
            return None;
        }
        let (shown, insert) = self.engine.hint(line)?;
        let shown = if insert.is_empty() {
            format!("  {shown}")
        } else {
            shown
        };
        Some(Hint { shown, insert })
    }
}

impl Highlighter for PitHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        std::borrow::Cow::Owned(ui::dim(hint))
    }
}
impl Validator for PitHelper {}
impl Helper for PitHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_command_help_points_to_reveal() {
        let s = cli::unknown_command_help("veiw", "");
        assert!(s.contains("`view`") || s.contains("`reveal`"), "{s}");
        let s = cli::unknown_command_help("display", "");
        assert!(s.contains("Did you mean `reveal`"), "{s}");
        assert!(s.contains("reveal PROJECT/CHANNEL NAME"));
    }

    #[test]
    fn context_fills_in_the_scope() {
        let mut w: Vec<String> = ["reveal", "KEY"].iter().map(|s| s.to_string()).collect();
        apply_context(&mut w, "myapp/production/eu");
        assert_eq!(w, vec!["reveal", "myapp/production/eu", "KEY"]);
    }
}
