//! The Pit — an encrypted, local secrets vault for developers.

mod agent;
mod audit;
mod backup;
mod cli;
mod codes;
mod console;
mod crypto;
mod error;
mod harden;
mod importer;
mod keychain;
mod mcp;
mod model;
mod ops;
mod paths;
mod presence;
mod protocol;
mod rail;
mod resolve;
mod s3;
mod scan;
mod service;
mod shamir;
mod totp;
mod ui;
mod values;
mod vault;

use clap::Parser;

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
