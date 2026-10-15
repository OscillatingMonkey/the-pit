//! Cryptographic primitives. Everything here is a thin, typed wrapper over
//! audited RustCrypto implementations:
//!
//! * Argon2id (RFC 9106) for password-based key derivation
//! * XChaCha20-Poly1305 (RFC 8439 + XChaCha extension) for authenticated encryption
//! * HKDF-SHA256 (RFC 5869) for key separation
//! * HMAC-SHA256 (RFC 2104) for keyed fingerprints
//!
//! Key material lives in `Key` values that are zeroized on drop.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 32;

/// A 256-bit symmetric key. Zeroized on drop, never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k);
        Key(k)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != KEY_LEN {
            return Err(Error::Crypto("key length".into()));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(b);
        Ok(Key(k))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive an independent subkey for one purpose (HKDF-SHA256).
    pub fn derive(&self, purpose: &str) -> Key {
        let hk = Hkdf::<Sha256>::new(Some(b"the-pit/v1"), &self.0);
        let mut out = [0u8; KEY_LEN];
        hk.expand(purpose.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Key(out)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("the operating system random source is unavailable");
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill_random(&mut v);
    v
}

pub fn random_id() -> String {
    hex::encode(random_bytes(16))
}

/// Argon2id parameters. Stored beside every derived key so they can be raised
/// later without breaking existing vaults.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Above the OWASP and RFC 9106 recommendations: 128 MiB, 3 passes, 4 lanes.
    pub fn new_password() -> Self {
        KdfParams {
            alg: "argon2id".into(),
            m_kib: 128 * 1024,
            t: 3,
            p: 4,
            salt: random_bytes(SALT_LEN),
        }
    }

    /// Used for one-way stored secrets, which are verified more often.
    pub fn new_hash() -> Self {
        KdfParams {
            alg: "argon2id".into(),
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
            salt: random_bytes(SALT_LEN),
        }
    }

    pub fn derive(&self, secret: &[u8]) -> Result<Key> {
        if self.alg != "argon2id" {
            return Err(Error::Crypto(format!("unsupported kdf {}", self.alg)));
        }
        if self.m_kib < 19 * 1024 || self.t < 2 || self.salt.len() < 16 {
            return Err(Error::Crypto("kdf parameters below the minimum".into()));
        }
        let params = Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        a.hash_password_into(secret, &self.salt, out.as_mut())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Key::from_bytes(out.as_ref())
    }
}

/// An authenticated ciphertext. The nonce is random per message (XChaCha's
/// 192-bit nonce makes random nonces safe).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "b64")]
    pub n: Vec<u8>,
    #[serde(with = "b64")]
    pub c: Vec<u8>,
}

pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Sealed {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = random_bytes(NONCE_LEN);
    let c = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption with a valid key cannot fail");
    Sealed { n: nonce, c }
}

pub fn open(key: &Key, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.n.len() != NONCE_LEN {
        return Err(Error::Crypto("nonce length".into()));
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.n),
            Payload {
                msg: &sealed.c,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Denied)
}

/// Keyed fingerprint: identifies a value across pushes and logs without
/// revealing it, and without letting anyone outside the vault test guesses.
pub fn fingerprint(key: &Key, value: &[u8]) -> String {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("hmac accepts any key length");
    mac.update(value);
    hex::encode(&mac.finalize().into_bytes()[..6])
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// One-way storage: Argon2id hash. The value can be verified, never recovered.
pub fn hash_secret(value: &[u8]) -> Result<(KdfParams, Vec<u8>)> {
    let p = KdfParams::new_hash();
    let k = p.derive(value)?;
    Ok((p, k.as_bytes().to_vec()))
}

pub fn verify_hashed(params: &KdfParams, digest: &[u8], candidate: &[u8]) -> Result<bool> {
    let k = params.derive(candidate)?;
    Ok(ct_eq(k.as_bytes(), digest))
}

pub mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub fn b64e(v: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(v)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(s.trim())
        .map_err(|_| Error::Invalid("base64".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_and_aad_binding() {
        let k = Key::generate();
        let s = seal(&k, b"hello", b"ctx");
        assert_eq!(&open(&k, &s, b"ctx").unwrap()[..], b"hello");
        assert!(open(&k, &s, b"other").is_err());
        assert!(open(&Key::generate(), &s, b"ctx").is_err());
    }

    #[test]
    fn derive_separates_purposes() {
        let k = Key::generate();
        assert_ne!(k.derive("a").as_bytes(), k.derive("b").as_bytes());
        assert_eq!(k.derive("a").as_bytes(), k.derive("a").as_bytes());
    }

    #[test]
    fn kdf_rejects_weak_params() {
        let mut p = KdfParams::new_hash();
        p.m_kib = 1024;
        assert!(p.derive(b"x").is_err());
    }
}
