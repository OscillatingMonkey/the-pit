//! Recovery codes, shares and identity codes are typed by people: decoding must
//! reject anything malformed without panicking, and split/combine must round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for kind in ["R", "S", "ID"] {
            let _ = the_pit::codes::decode(kind, text);
        }
    }
    if data.len() >= 3 {
        let k = 2 + data[0] % 3;
        let n = k + data[1] % 3;
        let secret = &data[2..];
        if !secret.is_empty() {
            if let Ok(shares) = the_pit::shamir::split(secret, k, n) {
                let back = the_pit::shamir::combine(&shares[..k as usize]).expect("k shares combine");
                assert_eq!(&back[..], secret);
            }
        }
        let shares: Vec<Vec<u8>> = data.chunks(17).map(|c| c.to_vec()).collect();
        let _ = the_pit::shamir::combine(&shares);
    }
});
