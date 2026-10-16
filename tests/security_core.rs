//! Edge cases of the security core (crypto helpers, recovery codes, Shamir sharing, TOTP),
//! written so mutation testing (`cargo mutants`) can tell when a check is weakened.

use the_pit::crypto::{self, KdfParams, Key};
use the_pit::{codes, shamir, totp};

// --- crypto helpers ---------------------------------------------------------------------------

#[test]
fn key_debug_never_prints_key_material() {
    let k = Key::from_bytes(&[0xAB; 32]).unwrap();
    let s = format!("{k:?}");
    assert_eq!(s, "Key(<redacted>)");
    assert!(!s.to_lowercase().contains("ab"));
}

#[test]
fn random_ids_are_128_bit_hex_and_unique() {
    let a = crypto::random_id();
    let b = crypto::random_id();
    assert_eq!(a.len(), 32);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

#[test]
fn sha256_hex_known_answer() {
    assert_eq!(
        crypto::sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn base64_round_trip_and_known_answer() {
    assert_eq!(crypto::b64e(b"the pit"), "dGhlIHBpdA==");
    assert_eq!(crypto::b64d("dGhlIHBpdA==").unwrap(), b"the pit");
    assert!(crypto::b64d("not base64!").is_err());
    // The serde form used for every sealed record round-trips exactly.
    let k = Key::from_bytes(&[5u8; 32]).unwrap();
    let s = crypto::seal(&k, b"value", b"ctx");
    let json = serde_json::to_string(&s).unwrap();
    let back: crypto::Sealed = serde_json::from_str(&json).unwrap();
    assert_eq!((back.n.clone(), back.c.clone()), (s.n.clone(), s.c.clone()));
    assert_eq!(&crypto::open(&k, &back, b"ctx").unwrap()[..], b"value");
}

#[test]
fn one_way_hash_verifies_only_the_right_value() {
    let (params, digest) = crypto::hash_secret(b"hunter2-but-longer").unwrap();
    assert_eq!(params.m_kib, 64 * 1024, "one-way hashes use 64 MiB");
    assert!(crypto::verify_hashed(&params, &digest, b"hunter2-but-longer").unwrap());
    assert!(!crypto::verify_hashed(&params, &digest, b"hunter2-but-longeR").unwrap());
}

#[test]
fn kdf_floor_is_exact() {
    let ok = KdfParams {
        alg: "argon2id".into(),
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
        salt: vec![1; 16],
    };
    assert!(ok.derive(b"pw").is_ok(), "exactly at the floor is accepted");
    for weak in [
        KdfParams {
            m_kib: 19 * 1024 - 1,
            ..ok.clone()
        },
        KdfParams {
            m_kib: 4096,
            ..ok.clone()
        },
        KdfParams { t: 1, ..ok.clone() },
        KdfParams {
            salt: vec![1; 15],
            ..ok.clone()
        },
    ] {
        assert!(weak.derive(b"pw").is_err(), "{weak:?} accepted");
    }
}

// --- recovery codes ---------------------------------------------------------------------------

#[test]
fn codes_round_trip_at_every_length() {
    for n in 1..=40 {
        let payload: Vec<u8> = (0..n as u8).collect();
        let code = codes::encode("R", &payload);
        assert_eq!(
            &codes::decode("R", &code).unwrap()[..],
            &payload[..],
            "{code}"
        );
        // Typing is forgiving: case and spaces do not matter.
        assert_eq!(
            &codes::decode("R", &code.to_lowercase().replace('-', " - ")).unwrap()[..],
            &payload[..]
        );
    }
}

#[test]
fn codes_reject_wrong_kind_typos_and_truncation() {
    let code = codes::encode("R", &[7u8; 32]);
    assert!(codes::decode("S", &code).is_err(), "kind is checked");
    assert!(
        codes::decode("R", "PIT-R-ABCD").is_err(),
        "no checksum group"
    );
    assert!(codes::decode("R", "PIT-R-").is_err());
    let parts: Vec<&str> = code.split('-').collect();
    let truncated = parts[..parts.len() - 2].join("-") + "-" + parts[parts.len() - 1];
    assert!(codes::decode("R", &truncated).is_err(), "dropped group");
    let mut typo = code.clone().into_bytes();
    let i = typo.iter().position(|&c| c == b'-').unwrap() + 5;
    typo[i] = if typo[i] == b'A' { b'B' } else { b'A' };
    assert!(
        codes::decode("R", &String::from_utf8(typo).unwrap()).is_err(),
        "typo caught by checksum"
    );
}

// --- Shamir secret sharing --------------------------------------------------------------------

#[test]
fn shamir_threshold_bounds() {
    let s = b"recovery key bytes";
    assert!(
        shamir::split(s, 1, 3).is_err(),
        "threshold 1 would be no sharing at all"
    );
    assert!(shamir::split(s, 0, 3).is_err());
    assert!(shamir::split(s, 3, 2).is_err(), "more needed than exist");
    let one = shamir::split(b"x", 2, 2).unwrap();
    assert_eq!(
        &shamir::combine(&one).unwrap()[..],
        b"x",
        "a one-byte secret works"
    );
    for (k, n) in [(2, 2), (2, 3), (3, 3), (3, 5)] {
        let shares = shamir::split(s, k, n).unwrap();
        assert_eq!(shares.len(), n as usize);
        assert_eq!(&shamir::combine(&shares[..k as usize]).unwrap()[..], s);
        assert_eq!(
            &shamir::combine(&shares[n as usize - k as usize..]).unwrap()[..],
            s
        );
    }
}

#[test]
fn shamir_fewer_than_threshold_reveals_nothing_useful() {
    let s = [0x42u8; 16];
    let shares = shamir::split(&s, 3, 5).unwrap();
    // Two shares of a 3-of-5 split combine to something, but not the secret.
    assert_ne!(&shamir::combine(&shares[..2]).unwrap()[..], &s[..]);
}

#[test]
fn shamir_rejects_malformed_shares() {
    let shares = shamir::split(b"abcd", 2, 3).unwrap();
    assert!(shamir::combine(&shares[..1]).is_err(), "one share");
    assert!(shamir::combine(&[]).is_err());
    assert!(
        shamir::combine(&[vec![1], vec![2]]).is_err(),
        "no data bytes"
    );
    let mut short = shares[1].clone();
    short.pop();
    assert!(
        shamir::combine(&[shares[0].clone(), short]).is_err(),
        "different lengths"
    );
    assert!(
        shamir::combine(&[shares[0].clone(), shares[0].clone()]).is_err(),
        "duplicate share"
    );
    let mut zero = shares[1].clone();
    zero[0] = 0;
    assert!(
        shamir::combine(&[shares[0].clone(), zero]).is_err(),
        "x = 0 would be the secret itself"
    );
}

// --- TOTP (RFC 6238) --------------------------------------------------------------------------

const RFC_SECRET: &[u8] = b"12345678901234567890";

/// RFC 6238 Appendix B (SHA-1), last six digits.
#[test]
fn totp_rfc6238_vectors() {
    for (t, code) in [
        (59u64, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ] {
        assert_eq!(
            totp::verify(RFC_SECRET, code, t, 0),
            Some(t / totp::STEP),
            "t={t}"
        );
    }
}

#[test]
fn totp_window_is_one_step_each_way_and_no_replay() {
    let t = 1111111111u64; // code 050471 belongs to step t/30
    let step = t / totp::STEP;
    assert_eq!(
        totp::verify(RFC_SECRET, "050471", t + 30, 0),
        Some(step),
        "previous step accepted"
    );
    assert_eq!(
        totp::verify(RFC_SECRET, "050471", t - 30, 0),
        Some(step),
        "next step accepted"
    );
    assert_eq!(
        totp::verify(RFC_SECRET, "050471", t + 60, 0),
        None,
        "two steps late refused"
    );
    assert_eq!(
        totp::verify(RFC_SECRET, "050471", t - 60, 0),
        None,
        "two steps early refused"
    );
    assert_eq!(
        totp::verify(RFC_SECRET, "050471", t, step),
        None,
        "replay refused"
    );
    assert_eq!(
        totp::verify(RFC_SECRET, " 050 471 ", t, 0),
        Some(step),
        "spaces allowed"
    );
    for bad in ["05047", "0504711", "05047a", ""] {
        assert_eq!(totp::verify(RFC_SECRET, bad, t, 0), None, "{bad:?}");
    }
}

#[test]
fn totp_enrolment_data() {
    let a = totp::new_secret();
    assert_eq!(a.len(), 20, "160-bit secret, as RFC 4226 recommends");
    assert_ne!(a, totp::new_secret());
    assert_eq!(
        totp::base32(b"12345678901234567890"),
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
    let uri = totp::uri(RFC_SECRET, "me at work");
    assert!(uri.starts_with(
        "otpauth://totp/The%20Pit:me%20at%20work?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"
    ));
    assert!(uri.contains("digits=6") && uri.contains("period=30"));
}
