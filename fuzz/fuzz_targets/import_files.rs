//! .env, JSON and YAML import must never panic, whatever the file holds.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let name = match kind % 4 {
        0 => ".env",
        1 => "secrets.json",
        2 => "config.yaml",
        _ => "settings.env.local",
    };
    let _ = the_pit::scan::read_source(Path::new(name), text);
    let _ = the_pit::scan::read_env(text);
    let _ = the_pit::scan::env_name(text);
    let _ = the_pit::scan::name_is_sensitive(text);
});
