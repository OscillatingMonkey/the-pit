//! Shamir secret sharing over GF(2^8) (the AES field, polynomial 0x11b).
//!
//! Used to split the recovery key into N shares so that any K of them restore
//! it and fewer than K reveal nothing. Arithmetic is table-free and branch-free
//! so timing does not depend on secret bytes.

use crate::crypto::fill_random;
use crate::error::{invalid, Result};
use zeroize::Zeroizing;

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & 0u8.wrapping_sub(b & 1);
        let hi = a >> 7;
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(hi));
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    // a^254 = a^-1 in GF(2^8)
    let mut r = 1u8;
    let mut base = a;
    let mut e = 254u8;
    for _ in 0..8 {
        let m = 0u8.wrapping_sub(e & 1);
        r = (gf_mul(r, base) & m) | (r & !m);
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
/// Each share is `[x, y0, y1, ...]` with x in 1..=n.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>> {
    if k < 2 || n < k {
        return invalid("need 2 <= threshold <= shares");
    }
    let mut shares: Vec<Vec<u8>> = (1..=n).map(|x| vec![x]).collect();
    let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
    for &s in secret {
        coeffs[0] = s;
        fill_random(&mut coeffs[1..]);
        for share in shares.iter_mut() {
            let x = share[0];
            // Horner evaluation
            let mut y = 0u8;
            for &c in coeffs.iter().rev() {
                y = gf_mul(y, x) ^ c;
            }
            share.push(y);
        }
    }
    Ok(shares)
}

/// Reconstruct from at least `k` distinct shares (Lagrange interpolation at 0).
pub fn combine(shares: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>> {
    if shares.len() < 2 {
        return invalid("at least two shares are needed");
    }
    let len = shares[0].len();
    if len < 2 || shares.iter().any(|s| s.len() != len) {
        return invalid("shares are not from the same split");
    }
    let xs: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    for (i, &a) in xs.iter().enumerate() {
        if a == 0 || xs[i + 1..].contains(&a) {
            return invalid("duplicate or malformed share");
        }
    }
    let mut out = Zeroizing::new(vec![0u8; len - 1]);
    for (i, si) in shares.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;
        for (j, &xj) in xs.iter().enumerate() {
            if i != j {
                num = gf_mul(num, xj);
                den = gf_mul(den, xs[i] ^ xj);
            }
        }
        let l = gf_mul(num, gf_inv(den));
        for b in 0..len - 1 {
            out[b] ^= gf_mul(si[b + 1], l);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_subset_recovers() {
        let secret: Vec<u8> = (0..32).collect();
        let shares = split(&secret, 3, 5).unwrap();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let got = combine(&[shares[a].clone(), shares[b].clone(), shares[c].clone()])
                        .unwrap();
                    assert_eq!(&got[..], &secret[..]);
                }
            }
        }
        let two = combine(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(&two[..], &secret[..]);
    }

    #[test]
    fn inverse_is_correct() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }
}
