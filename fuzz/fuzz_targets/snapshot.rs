//! Backup snapshots come from other machines and cloud storage: reading one must
//! never panic, and file names from a listing must parse safely.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = the_pit::backup::inspect_snapshot(data);
    if let Ok(name) = std::str::from_utf8(data) {
        let _ = the_pit::backup::parse_name(name);
    }
});
