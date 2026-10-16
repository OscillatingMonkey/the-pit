//! Encrypted records: tampered or random ciphertext must be rejected (never
//! panic, never "succeed"), and seal/open must round-trip with the right context.
#![no_main]
use libfuzzer_sys::fuzz_target;
use the_pit::crypto::{self, Key, Sealed};

fuzz_target!(|data: &[u8]| {
    let key = Key::from_bytes(&[7u8; 32]).unwrap();
    let split = data.first().map(|b| *b as usize).unwrap_or(0).min(data.len());
    let (aad, body) = data.split_at(split);
    let sealed = crypto::seal(&key, body, aad);
    assert_eq!(&crypto::open(&key, &sealed, aad).unwrap()[..], body);
    if !aad.is_empty() {
        assert!(crypto::open(&key, &sealed, &aad[1..]).is_err(), "wrong context must fail");
    }
    let forged = Sealed { n: data.iter().copied().cycle().take(24).collect(), c: body.to_vec() };
    if forged.n.len() == 24 {
        assert!(crypto::open(&key, &forged, aad).is_err(), "unauthenticated data must fail");
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = crypto::b64d(text);
    }
});
