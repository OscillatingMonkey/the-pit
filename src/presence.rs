//! Proof that a human is present: Touch ID or Apple Watch, through the system's
//! LocalAuthentication dialog. Software cannot answer that dialog.

use crate::error::{Error, Result};

#[cfg(target_os = "macos")]
mod mac {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometricsOrCompanion;

    pub fn available() -> bool {
        unsafe {
            let ctx = LAContext::new();
            ctx.canEvaluatePolicy_error(POLICY).is_ok()
        }
    }

    pub fn confirm(reason: &str) -> Result<bool, String> {
        let (tx, rx) = mpsc::channel::<bool>();
        unsafe {
            let ctx = LAContext::new();
            if let Err(e) = ctx.canEvaluatePolicy_error(POLICY) {
                return Err(e.localizedDescription().to_string());
            }
            let block = RcBlock::new(move |ok: Bool, _err: *mut NSError| {
                let _ = tx.send(ok.as_bool());
            });
            ctx.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &block);
            let r = rx.recv_timeout(Duration::from_secs(90)).unwrap_or(false);
            if !r {
                ctx.invalidate();
            }
            Ok(r)
        }
    }
}

pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    {
        mac::available()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Show the system presence dialog. `reason` is shown to the person.
pub fn confirm(reason: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        match mac::confirm(reason) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Denied),
            Err(e) => Err(Error::Invalid(format!("Touch ID unavailable: {e}"))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        Err(Error::Invalid(
            "Touch ID is not available on this platform".into(),
        ))
    }
}
