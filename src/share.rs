//! Sharing one secret with another person's vault.
//!
//! The recipient opens a receive window: their agent makes an X25519 key pair
//! that exists only in its memory, and gives out a request code carrying the
//! public half, their identity key and when the window closes.
//!
//! The sender's agent encrypts the value to the window key, authenticated with
//! the sender's identity (crypto_box), then seals that to the recipient's
//! identity (sealed box). Opening a share takes both the recipient's identity
//! and the window key, so:
//!
//! * the value travels encrypted end to end, and never leaves either agent in
//!   the clear — neither person sees it while it moves;
//! * the outer layer is sealed to the identity the sender confirmed for that
//!   person, so only that person's vault can open it, whatever window key the
//!   request carried;
//! * once the window closes — used, timed out, cancelled, or the pit locked —
//!   its key is gone, and the share cannot be opened by anyone, ever.
//!
//! Context (who it is from, which window it is for, when it was sent) is
//! inside the authenticated plaintext and checked against the envelope after
//! opening.
//!
//!   request: PIT-RQ-…  version | identity(32) | window(32) | expires(i64 BE) | name
//!   share:   PIT-SH-…  sealed-box(identity, from(32) | window(32) | nonce(24) | box)

use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::codes;
use crate::crypto::b64;
use crate::error::{invalid, Error, Result};

pub const REQUEST_KIND: &str = "RQ";
pub const SHARE_KIND: &str = "SH";
const VERSION: u8 = 1;
const KEY: usize = 32;
const NONCE: usize = 24;
const MAX_NAME: usize = 64;

/// What a recipient hands the sender: where to encrypt to, and until when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; KEY],
    pub window: [u8; KEY],
    pub expires: i64,
    pub name: String,
}

impl Request {
    pub fn encode(&self) -> String {
        let mut b = vec![VERSION];
        b.extend_from_slice(&self.identity);
        b.extend_from_slice(&self.window);
        b.extend_from_slice(&self.expires.to_be_bytes());
        b.extend_from_slice(truncate(&self.name, MAX_NAME).as_bytes());
        codes::encode(REQUEST_KIND, &b)
    }

    pub fn decode(code: &str) -> Result<Request> {
        let b = codes::decode(REQUEST_KIND, code)?;
        if b.len() < 1 + 2 * KEY + 8 || b[0] != VERSION {
            return invalid("that is not a receive request this version of The Pit understands");
        }
        let name = String::from_utf8(b[1 + 2 * KEY + 8..].to_vec())
            .map_err(|_| Error::Invalid("request name".into()))?;
        Ok(Request {
            identity: b[1..1 + KEY].try_into().expect("length checked"),
            window: b[1 + KEY..1 + 2 * KEY].try_into().expect("length checked"),
            expires: i64::from_be_bytes(b[1 + 2 * KEY..1 + 2 * KEY + 8].try_into().expect("8")),
            name,
        })
    }
}

fn truncate(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The secret being shared: its name, how to store it, and its value.
#[derive(Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

impl Drop for Item {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct Inner {
    v: u8,
    #[serde(with = "b64")]
    from: Vec<u8>,
    from_name: String,
    #[serde(with = "b64")]
    window: Vec<u8>,
    sent: i64,
    item: Item,
}

/// The first layer of a share, opened with the recipient's identity.
pub struct Envelope {
    pub from: [u8; KEY],
    pub window: [u8; KEY],
    nonce: [u8; NONCE],
    boxed: Vec<u8>,
}

/// A share opened all the way.
pub struct Opened {
    pub from: [u8; KEY],
    pub from_name: String,
    pub sent: i64,
    pub item: Item,
}

fn secret_key(b: &[u8]) -> Result<SecretKey> {
    SecretKey::from_slice(b).map_err(|_| Error::Crypto("identity has the wrong length".into()))
}

pub fn public_of(secret: &[u8]) -> Result<[u8; KEY]> {
    Ok(secret_key(secret)?.public_key().to_bytes())
}

/// Encrypt `item` for the window in `req`, from the identity `from_secret`.
pub fn seal(
    from_secret: &[u8],
    from_name: &str,
    req: &Request,
    item: Item,
    sent: i64,
) -> Result<String> {
    let sk = secret_key(from_secret)?;
    let from = sk.public_key().to_bytes();
    let inner = Inner {
        v: VERSION,
        from: from.to_vec(),
        from_name: truncate(from_name, MAX_NAME).to_string(),
        window: req.window.to_vec(),
        sent,
        item,
    };
    let pt = Zeroizing::new(serde_json::to_vec(&inner)?);
    let cipher = SalsaBox::new(&PublicKey::from(req.window), &sk);
    let nonce = SalsaBox::generate_nonce(&mut rand_core::OsRng);
    let boxed = cipher
        .encrypt(&nonce, pt.as_slice())
        .map_err(|_| Error::Crypto("box".into()))?;
    let mut outer = Vec::with_capacity(2 * KEY + NONCE + boxed.len());
    outer.extend_from_slice(&from);
    outer.extend_from_slice(&req.window);
    outer.extend_from_slice(&nonce);
    outer.extend_from_slice(&boxed);
    let sealed = PublicKey::from(req.identity)
        .seal(&mut rand_core::OsRng, &outer)
        .map_err(|_| Error::Crypto("sealed box".into()))?;
    let mut b = vec![VERSION];
    b.extend_from_slice(&sealed);
    Ok(codes::encode(SHARE_KIND, &b))
}

/// Open the outer layer with this vault's identity: who sent it, and which
/// receive window it is for.
pub fn peel(identity_secret: &[u8], code: &str) -> Result<Envelope> {
    let b = codes::decode(SHARE_KIND, code)?;
    if b.first() != Some(&VERSION) {
        return invalid("that is not a share this version of The Pit understands");
    }
    let outer = secret_key(identity_secret)?
        .unseal(&b[1..])
        .map_err(|_| Error::Refused("this share was not made for this vault's identity".into()))?;
    if outer.len() < 2 * KEY + NONCE {
        return invalid("share is too short");
    }
    Ok(Envelope {
        from: outer[..KEY].try_into().expect("length checked"),
        window: outer[KEY..2 * KEY].try_into().expect("length checked"),
        nonce: outer[2 * KEY..2 * KEY + NONCE]
            .try_into()
            .expect("length checked"),
        boxed: outer[2 * KEY + NONCE..].to_vec(),
    })
}

impl Envelope {
    /// Open the inner layer with the receive window's key.
    pub fn open(&self, window: &SecretKey) -> Result<Opened> {
        if window.public_key().to_bytes() != self.window {
            return Err(Error::Denied);
        }
        let cipher = SalsaBox::new(&PublicKey::from(self.from), window);
        let pt = Zeroizing::new(
            cipher
                .decrypt(&self.nonce.into(), self.boxed.as_slice())
                .map_err(|_| Error::Denied)?,
        );
        let inner: Inner = serde_json::from_slice(&pt)?;
        if inner.v != VERSION || inner.from != self.from || inner.window != self.window {
            return Err(Error::Denied);
        }
        Ok(Opened {
            from: self.from,
            from_name: inner.from_name.clone(),
            sent: inner.sent,
            item: inner.item,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item() -> Item {
        Item {
            name: "API_KEY".into(),
            description: "d".into(),
            filename: None,
            value: b"sk_live_123".to_vec(),
        }
    }

    #[test]
    fn request_roundtrip() {
        let r = Request {
            identity: [7; 32],
            window: [9; 32],
            expires: 1_800_000_000,
            name: "sam".into(),
        };
        assert_eq!(Request::decode(&r.encode()).unwrap(), r);
        assert!(Request::decode(&codes::encode("ID", &[0; 32])).is_err());
    }

    #[test]
    fn share_needs_identity_and_window() {
        let alice = SecretKey::generate(&mut rand_core::OsRng);
        let bob = SecretKey::generate(&mut rand_core::OsRng);
        let win = SecretKey::generate(&mut rand_core::OsRng);
        let req = Request {
            identity: bob.public_key().to_bytes(),
            window: win.public_key().to_bytes(),
            expires: 0,
            name: "bob".into(),
        };
        let code = seal(&alice.to_bytes(), "alice", &req, item(), 5).unwrap();
        assert!(!code.contains("sk_live"));

        let env = peel(&bob.to_bytes(), &code).unwrap();
        assert_eq!(env.from, alice.public_key().to_bytes());
        let o = env.open(&win).unwrap();
        assert_eq!(o.item.value, b"sk_live_123");
        assert_eq!(o.from_name, "alice");

        // someone else's identity cannot peel it; another window cannot open it
        assert!(peel(&alice.to_bytes(), &code).is_err());
        let other = SecretKey::generate(&mut rand_core::OsRng);
        assert!(env.open(&other).is_err());
    }

    #[test]
    fn swapped_window_key_is_useless_without_the_identity() {
        let alice = SecretKey::generate(&mut rand_core::OsRng);
        let bob = SecretKey::generate(&mut rand_core::OsRng);
        let mallory = SecretKey::generate(&mut rand_core::OsRng);
        // the request's window was replaced, but its identity is bob's
        let req = Request {
            identity: bob.public_key().to_bytes(),
            window: mallory.public_key().to_bytes(),
            expires: 0,
            name: "bob".into(),
        };
        let code = seal(&alice.to_bytes(), "alice", &req, item(), 5).unwrap();
        assert!(peel(&mallory.to_bytes(), &code).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let alice = SecretKey::generate(&mut rand_core::OsRng);
        let bob = SecretKey::generate(&mut rand_core::OsRng);
        let win = SecretKey::generate(&mut rand_core::OsRng);
        let req = Request {
            identity: bob.public_key().to_bytes(),
            window: win.public_key().to_bytes(),
            expires: 0,
            name: "bob".into(),
        };
        let code = seal(&alice.to_bytes(), "alice", &req, item(), 5).unwrap();
        let mut env = peel(&bob.to_bytes(), &code).unwrap();
        env.boxed[0] ^= 1;
        assert!(env.open(&win).is_err());
        // a different sender claimed on the envelope fails authentication
        let mut env = peel(&bob.to_bytes(), &code).unwrap();
        env.from = SecretKey::generate(&mut rand_core::OsRng)
            .public_key()
            .to_bytes();
        assert!(env.open(&win).is_err());
    }
}
