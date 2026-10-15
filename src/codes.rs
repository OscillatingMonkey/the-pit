//! Human-transcribable encodings for recovery keys and recovery shares.
//!
//! Crockford base32 (no I, L, O, U; case-insensitive), grouped in fives, with a
//! 4-character checksum so a mistyped character is caught before any key
//! derivation is attempted.
//!
//!   recovery key:   PIT-R-XXXXX-XXXXX-...-CCCC
//!   recovery share: PIT-S-XXXXX-...-CCCC

use data_encoding::{Encoding, Specification};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{invalid, Result};

fn crockford() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzOoIiLl");
    spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ001111");
    spec.encoding().expect("valid base32 specification")
}

fn checksum(kind: &str, payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(payload);
    crockford().encode(&h.finalize()[..3])[..4].to_string()
}

pub fn encode(kind: &str, payload: &[u8]) -> String {
    let body = crockford().encode(payload);
    let groups: Vec<String> = body
        .as_bytes()
        .chunks(5)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!(
        "PIT-{}-{}-{}",
        kind,
        groups.join("-"),
        checksum(kind, payload)
    )
}

pub fn decode(kind: &str, text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let prefix = format!("PIT-{kind}-");
    let rest = cleaned.strip_prefix(&prefix).ok_or_else(|| {
        crate::error::Error::Invalid("that is not a code of the expected kind".into())
    })?;
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() < 2 {
        return invalid("code is too short");
    }
    let (body, sum) = parts.split_at(parts.len() - 1);
    let body = body.concat();
    let payload =
        Zeroizing::new(crockford().decode(body.as_bytes()).map_err(|_| {
            crate::error::Error::Invalid("code contains an invalid character".into())
        })?);
    if checksum(kind, &payload) != sum[0] {
        return invalid("checksum mismatch — check the code for a typo");
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_typo_detection() {
        let k: Vec<u8> = (0..32).collect();
        let s = encode("R", &k);
        assert_eq!(&decode("R", &s.to_lowercase()).unwrap()[..], &k[..]);
        let mut bad = s.clone().into_bytes();
        let i = 10;
        bad[i] = if bad[i] == b'A' { b'B' } else { b'A' };
        assert!(decode("R", &String::from_utf8(bad).unwrap()).is_err());
        assert!(decode("S", &s).is_err());
    }
}
