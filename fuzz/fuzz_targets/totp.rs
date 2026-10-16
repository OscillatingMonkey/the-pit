//! Authenticator codes: any input is checked without panicking, and a code is
//! never accepted twice for the same step.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let now = u64::from_le_bytes(data[..8].try_into().unwrap()) % 4_000_000_000;
    let secret = [3u8; 20];
    if let Ok(code) = std::str::from_utf8(&data[8..]) {
        if let Some(step) = the_pit::totp::verify(&secret, code, now, 0) {
            assert!(the_pit::totp::verify(&secret, code, now, step).is_none(), "replay accepted");
        }
    }
});
