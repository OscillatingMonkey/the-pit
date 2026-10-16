//! The `pit` command.

use clap::Parser;
use the_pit::{cli, error, harden, ui};

fn main() {
    harden::process();
    let cli = cli::Cli::parse();
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
