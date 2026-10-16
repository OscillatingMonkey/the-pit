//! The `pit` command.

use clap::Parser;
use the_pit::{cli, error, harden, ui};

fn main() {
    harden::process();
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) if e.kind() == clap::error::ErrorKind::InvalidSubcommand => {
            let word = match e.get(clap::error::ContextKind::InvalidSubcommand) {
                Some(clap::error::ContextValue::String(w)) => w.clone(),
                _ => String::new(),
            };
            eprintln!("{}", cli::unknown_command_help(&word, "pit "));
            std::process::exit(2);
        }
        Err(e) => e.exit(),
    };
    let code = match cli::run(cli) {
        Ok(code) => code,
        Err(e) => {
            ui::error(&e.to_string());
            match e {
                error::Error::ApprovalRequired { ticket, .. } if !ticket.is_empty() => {
                    ui::note(&format!("approve it with: pit approve {ticket}"));
                }
                error::Error::Locked => ui::note("run `pit unlock`"),
                error::Error::Confirm(_) => ui::note("run this in a terminal to confirm it"),
                _ => {}
            }
            1
        }
    };
    std::process::exit(code);
}
