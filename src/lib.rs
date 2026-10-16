//! The Pit — an encrypted, local secrets vault for developers.
//!
//! The `pit` binary is a thin wrapper around this library; the library exists so the
//! fuzz targets and tests can reach the parsers directly.

pub mod agent;
pub mod audit;
pub mod backup;
pub mod cli;
pub mod codes;
pub mod console;
pub mod crypto;
pub mod error;
pub mod harden;
pub mod importer;
pub mod keychain;
pub mod mcp;
pub mod model;
pub mod ops;
pub mod paths;
pub mod presence;
pub mod protocol;
pub mod rail;
pub mod resolve;
pub mod s3;
pub mod scan;
pub mod service;
pub mod shamir;
pub mod totp;
pub mod ui;
pub mod values;
pub mod vault;
