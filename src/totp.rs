//! RFC 6238 time-based one-time passwords (HMAC-SHA1, 6 digits, 30 s), the
//! format every authenticator app understands.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::{ct_eq, random_bytes};

pub const STEP: u64 = 30;

pub fn new_secret() -> Vec<u8> {
    random_bytes(20)
}

pub fn base32(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub fn uri(secret: &[u8], account: &str) -> String {
    format!(
        "otpauth://totp/The%20Pit:{}?secret={}&issuer=The%20Pit&algorithm=SHA1&digits=6&period=30",
        account.replace(' ', "%20"),
        base32(secret)
    )
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let bin = ((h[o] as u32 & 0x7f) << 24)
        | ((h[o + 1] as u32) << 16)
        | ((h[o + 2] as u32) << 8)
        | h[o + 3] as u32;
    bin % 1_000_000
}

/// Verify a code within ±1 step. Returns the matched step so a code cannot be
/// replayed (the caller stores it and rejects steps <= the last one used).
pub fn verify(secret: &[u8], code: &str, now: u64, last_step: u64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let step = now / STEP;
    let mut found = None;
    for s in [step.saturating_sub(1), step, step + 1] {
        let expect = format!("{:06}", hotp(secret, s));
        if ct_eq(expect.as_bytes(), code.as_bytes()) && s > last_step {
            found = Some(s);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B, SHA1, T = 59 → 94287082 (8 digits) → 287082 (6 digits)
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 59 / 30), 287082);
        assert_eq!(verify(secret, "287082", 59, 0), Some(1));
        assert_eq!(verify(secret, "287082", 59, 1), None, "replay is rejected");
    }
}
