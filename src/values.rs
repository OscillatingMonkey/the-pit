//! Storing and opening individual secret values.

use zeroize::Zeroizing;

use crate::crypto::{self};
use crate::error::{Error, Result};
use crate::model::{now, Protection, Secret, Stored, StoredData};
use crate::vault::Keys;

fn aad(secret_id: &str) -> Vec<u8> {
    format!("the-pit/value|{secret_id}").into_bytes()
}

pub fn store(keys: &Keys, secret_id: &str, protection: Protection, value: &[u8]) -> Result<Stored> {
    let fp = crypto::fingerprint(&keys.fp, value);
    let data = match protection {
        Protection::Sealed => StoredData::Sealed {
            sealed: crypto::seal(&keys.value, value, &aad(secret_id)),
        },
        Protection::Plain => StoredData::Plain {
            bytes: value.to_vec(),
        },
        Protection::Hashed => {
            let (params, digest) = crypto::hash_secret(value)?;
            StoredData::Hashed { params, digest }
        }
    };
    Ok(Stored {
        fp,
        set_at: now(),
        len: value.len(),
        data,
    })
}

pub fn open_stored(keys: &Keys, secret_id: &str, s: &Stored) -> Result<Zeroizing<Vec<u8>>> {
    match &s.data {
        StoredData::Plain { bytes } => Ok(Zeroizing::new(bytes.clone())),
        StoredData::Sealed { sealed } => crypto::open(&keys.value, sealed, &aad(secret_id)),
        StoredData::Hashed { .. } => Err(Error::Refused(
            "this secret is stored one-way and cannot be read back".into(),
        )),
    }
}

pub fn open(keys: &Keys, secret: &Secret) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match &secret.value {
        None => Ok(None),
        Some(s) => open_stored(keys, &secret.id, s).map(Some),
    }
}

pub fn verify(secret: &Secret, candidate: &[u8], keys: &Keys) -> Result<bool> {
    match &secret.value {
        None => Ok(false),
        Some(Stored {
            data: StoredData::Hashed { params, digest },
            ..
        }) => crypto::verify_hashed(params, digest, candidate),
        Some(s) => {
            let v = open_stored(keys, &secret.id, s)?;
            Ok(crypto::ct_eq(&v, candidate))
        }
    }
}

/// Set a new value, keeping the previous one in the secret's history.
pub fn set(keys: &Keys, secret: &mut Secret, value: &[u8]) -> Result<()> {
    let stored = store(keys, &secret.id, secret.protection, value)?;
    if let Some(old) = secret.value.take() {
        secret.history.insert(0, old);
        secret.history.truncate(5);
    }
    secret.value = Some(stored);
    secret.updated = now();
    Ok(())
}

/// Change how a secret is protected. Going to `hashed` is one-way; coming back
/// from `hashed` requires the value to be supplied again.
pub fn reprotect(keys: &Keys, secret: &mut Secret, to: Protection) -> Result<()> {
    if secret.protection == to {
        return Ok(());
    }
    if secret.protection == Protection::Hashed && secret.value.is_some() {
        return Err(Error::Refused(
            "a one-way secret cannot be converted back; set its value again instead".into(),
        ));
    }
    let current = open(keys, secret)?;
    secret.protection = to;
    secret.history.clear();
    if let Some(v) = current {
        secret.value = Some(store(keys, &secret.id, to, &v)?);
    }
    secret.updated = now();
    Ok(())
}
