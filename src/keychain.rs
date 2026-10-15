//! The operating system's credential store. On macOS, the login Keychain.
//! Holds only the device unlock key and backup-target credentials.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const SERVICE: &str = "dev.thepit";

#[cfg(target_os = "macos")]
pub fn set(account: &str, secret: &[u8]) -> Result<()> {
    use security_framework::passwords::{delete_generic_password, set_generic_password};
    let _ = delete_generic_password(SERVICE, account);
    set_generic_password(SERVICE, account, secret)
        .map_err(|e| Error::Crypto(format!("keychain: {e}")))
}

#[cfg(target_os = "macos")]
pub fn get(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, account) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(e) if e.code() == -25300 => Ok(None),
        Err(e) => Err(Error::Crypto(format!("keychain: {e}"))),
    }
}

#[cfg(target_os = "macos")]
pub fn delete(account: &str) -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, account) {
        Ok(()) => Ok(()),
        Err(e) if e.code() == -25300 => Ok(()),
        Err(e) => Err(Error::Crypto(format!("keychain: {e}"))),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set(_account: &str, _secret: &[u8]) -> Result<()> {
    Err(Error::Invalid("no OS keychain on this platform yet".into()))
}
#[cfg(not(target_os = "macos"))]
pub fn get(_account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(None)
}
#[cfg(not(target_os = "macos"))]
pub fn delete(_account: &str) -> Result<()> {
    Ok(())
}
