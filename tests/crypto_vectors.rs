//! Known-answer tests: The Pit's cryptography checked against published test vectors.
//!
//! * Project Wycheproof (C2SP/wycheproof, Apache-2.0) — XChaCha20-Poly1305, HKDF-SHA256 and
//!   HMAC-SHA256, including the "invalid" cases that must be rejected. Files in tests/vectors/.
//! * RFC 9106 §5.3 — the Argon2id test vector.
//!
//! Where The Pit wraps a primitive (`crypto::open`, `crypto::fingerprint`, `Key::derive`,
//! `KdfParams::derive`) the wrapper itself is tested, not just the library underneath.

use serde_json::Value;
use the_pit::crypto::{self, KdfParams, Key, Sealed};

fn vectors(file: &str) -> Value {
    let path = format!("{}/tests/vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn tests(doc: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

#[test]
fn xchacha20_poly1305_wycheproof() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let doc = vectors("xchacha20_poly1305_test.json");
    let (mut valid, mut invalid) = (0, 0);
    for (g, t) in tests(&doc) {
        let (key, iv, aad, msg) = (hx(&t["key"]), hx(&t["iv"]), hx(&t["aad"]), hx(&t["msg"]));
        let mut ct = hx(&t["ct"]);
        ct.extend(hx(&t["tag"]));
        let id = t["tcId"].as_u64().unwrap();
        let ok = t["result"] == "valid";
        if g["ivSize"] != 192 || key.len() != 32 {
            // The Pit only ever uses 256-bit keys and 192-bit nonces; other sizes must be refused.
            if let Ok(k) = Key::from_bytes(&key) {
                assert!(
                    crypto::open(&k, &Sealed { n: iv, c: ct }, &aad).is_err(),
                    "tc {id}"
                );
            }
            continue;
        }
        let k = Key::from_bytes(&key).unwrap();
        let opened = crypto::open(
            &k,
            &Sealed {
                n: iv.clone(),
                c: ct.clone(),
            },
            &aad,
        );
        if ok {
            assert_eq!(
                &opened.expect("valid vector opens")[..],
                &msg[..],
                "tc {id}"
            );
            let enc = XChaCha20Poly1305::new(key.as_slice().into())
                .encrypt(
                    XNonce::from_slice(&iv),
                    Payload {
                        msg: &msg,
                        aad: &aad,
                    },
                )
                .unwrap();
            assert_eq!(enc, ct, "tc {id} encrypt");
            valid += 1;
        } else {
            assert!(opened.is_err(), "tc {id}: invalid vector must be rejected");
            invalid += 1;
        }
    }
    assert!(
        valid > 0 && invalid > 0,
        "{valid} valid / {invalid} invalid"
    );
}

#[test]
fn hkdf_sha256_wycheproof() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let doc = vectors("hkdf_sha256_test.json");
    let mut n = 0;
    for (_, t) in tests(&doc) {
        let (ikm, salt, info, okm) = (hx(&t["ikm"]), hx(&t["salt"]), hx(&t["info"]), hx(&t["okm"]));
        let size = t["size"].as_u64().unwrap() as usize;
        let id = t["tcId"].as_u64().unwrap();
        let mut out = vec![0u8; size];
        let r = Hkdf::<Sha256>::new(Some(&salt), &ikm).expand(&info, &mut out);
        if t["result"] == "valid" {
            r.unwrap();
            assert_eq!(out, okm, "tc {id}");
        } else {
            assert!(r.is_err(), "tc {id}: invalid vector must be rejected");
        }
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn hmac_sha256_wycheproof_and_fingerprints() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let doc = vectors("hmac_sha256_test.json");
    let mut fingerprints = 0;
    for (g, t) in tests(&doc) {
        let (key, msg, tag) = (hx(&t["key"]), hx(&t["msg"]), hx(&t["tag"]));
        let id = t["tcId"].as_u64().unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(&msg);
        let full = mac.finalize().into_bytes();
        let matches = full[..tag.len()] == tag[..];
        assert_eq!(matches, t["result"] == "valid", "tc {id}");
        // crypto::fingerprint is HMAC-SHA256 under a 256-bit key, cut to 48 bits.
        if t["result"] == "valid" && key.len() == 32 && g["tagSize"].as_u64().unwrap() >= 48 {
            let k = Key::from_bytes(&key).unwrap();
            assert_eq!(
                crypto::fingerprint(&k, &msg),
                hex::encode(&tag[..6]),
                "tc {id}"
            );
            fingerprints += 1;
        }
    }
    assert!(fingerprints > 0);
}

/// `Key::derive` must be RFC 5869 HKDF-SHA256 (salt "the-pit/v1", info = purpose),
/// checked here against an independent extract-and-expand written from the RFC.
#[test]
fn key_derive_is_rfc5869_hkdf() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let hmac = |k: &[u8], d: &[&[u8]]| {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).unwrap();
        for part in d {
            m.update(part);
        }
        m.finalize().into_bytes().to_vec()
    };
    let master = [0x42u8; 32];
    let k = Key::from_bytes(&master).unwrap();
    for purpose in ["library", "values", "log", "fingerprint"] {
        let prk = hmac(b"the-pit/v1", &[&master]);
        let okm = hmac(&prk, &[purpose.as_bytes(), &[1u8]]);
        assert_eq!(k.derive(purpose).as_bytes()[..], okm[..32], "{purpose}");
    }
}

/// RFC 9106 §5.3: Argon2id, version 0x13, with secret and associated data.
#[test]
fn argon2id_rfc9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&[4u8; 12]).unwrap())
        .build()
        .unwrap();
    let a =
        Argon2::new_with_secret(&[3u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
        .unwrap();
    assert_eq!(
        hex::encode(out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

/// The Pit's own Argon2id wrapper gives the same answer as the reference
/// implementation, refuses weak parameters, and its defaults meet RFC 9106 / OWASP guidance.
#[test]
fn kdf_params_derive_matches_argon2id() {
    use argon2::{Algorithm, Argon2, Params, Version};
    let p = KdfParams {
        alg: "argon2id".into(),
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
        salt: vec![9u8; 32],
    };
    let ours = p.derive(b"correct horse battery staple").unwrap();
    let mut reference = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, Some(32)).unwrap(),
    )
    .hash_password_into(b"correct horse battery staple", &[9u8; 32], &mut reference)
    .unwrap();
    assert_eq!(ours.as_bytes(), &reference);

    // Anything below OWASP's floor (19 MiB, 2 passes, 16-byte salt) is refused, so a
    // tampered header cannot weaken key derivation.
    for weak in [
        KdfParams {
            m_kib: 1024,
            ..p.clone()
        },
        KdfParams { t: 1, ..p.clone() },
        KdfParams {
            salt: vec![9u8; 8],
            ..p.clone()
        },
        KdfParams {
            alg: "pbkdf2".into(),
            ..p.clone()
        },
    ] {
        assert!(weak.derive(b"x").is_err(), "{weak:?} accepted");
    }

    let pw = KdfParams::new_password();
    assert_eq!(pw.alg, "argon2id");
    assert!(
        pw.m_kib >= 46 * 1024 && pw.t >= 1,
        "OWASP minimum for Argon2id"
    );
    assert!(
        pw.m_kib >= 64 * 1024 && pw.t >= 3,
        "RFC 9106 second recommended option"
    );
    assert_eq!(pw.salt.len(), 32);
}

/// Sealing uses a fresh random nonce every time and binds the context (AAD).
#[test]
fn seal_nonces_are_unique_and_context_bound() {
    let k = Key::from_bytes(&[1u8; 32]).unwrap();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        let s = crypto::seal(&k, b"value", b"secret:a");
        assert_eq!(s.n.len(), 24);
        assert!(seen.insert(s.n.clone()), "nonce reused");
        assert!(crypto::open(&k, &s, b"secret:b").is_err());
    }
}
