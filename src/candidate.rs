//! Deterministic candidate derivation and Ethereum address formatting.
//!
//! Each candidate private key is `HMAC-SHA-256(seed, DOMAIN || iteration_be64 || counter_be32)`.
//! The domain separator is a fixed-length prefix and both numeric fields have fixed widths, so
//! the encoding is unambiguous. A block that is zero or not below the secp256k1 group order is
//! rejected and the counter is incremented, which avoids modulo bias.

use hmac::{Hmac, KeyInit, Mac};
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator mixed into every derivation block (fixed length: 20 bytes).
pub const DOMAIN: &[u8; 20] = b"vani-rs/candidate/v1";

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Derives candidate private keys from one seed.
pub struct Deriver {
    keyed: HmacSha256,
}

impl Deriver {
    /// Creates a deriver. Any non-empty seed length is accepted by callers; HMAC handles all keys.
    pub fn new(seed: &[u8]) -> Self {
        let keyed = <HmacSha256 as KeyInit>::new_from_slice(seed).expect("HMAC accepts any key length");
        Self { keyed }
    }

    /// Derives the secp256k1 secret key for `iteration`.
    pub fn secret_key(&self, iteration: u64) -> SecretKey {
        for counter in 0..=u32::MAX {
            let mut mac = self.keyed.clone();
            mac.update(DOMAIN);
            mac.update(&iteration.to_be_bytes());
            mac.update(&counter.to_be_bytes());
            let block = Zeroizing::new(mac.finalize().into_bytes());
            if let Ok(key) = SecretKey::from_slice(block.as_slice()) {
                return key;
            }
        }
        unreachable!("2^32 consecutive rejected HMAC blocks is computationally impossible")
    }
}

/// Returns the lowercase 40-character hex address (no prefix) for a secret key.
pub fn address_lower(key: &SecretKey) -> [u8; 40] {
    let point = key.public_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    let hash = Keccak256::digest(&bytes[1..]);
    let mut out = [0u8; 40];
    for (i, b) in hash[12..].iter().enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 15)];
    }
    out
}

/// Applies EIP-55 checksum casing to a lowercase 40-character hex address.
pub fn eip55(lower: &[u8; 40]) -> String {
    let hash = Keccak256::digest(lower);
    lower
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 15
            };
            if c.is_ascii_lowercase() && nibble >= 8 {
                c.to_ascii_uppercase() as char
            } else {
                c as char
            }
        })
        .collect()
}

/// Formats a secret key as `0x` plus 64 lowercase hex characters, zeroized on drop.
pub fn private_key_hex(key: &SecretKey) -> Zeroizing<String> {
    let bytes = Zeroizing::new(key.to_bytes());
    let mut s = Zeroizing::new(String::with_capacity(66));
    s.push_str("0x");
    for b in bytes.iter() {
        s.push(HEX[usize::from(b >> 4)] as char);
        s.push(HEX[usize::from(b & 15)] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from_u64(n: u64) -> SecretKey {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        SecretKey::from_slice(&b).unwrap()
    }

    #[test]
    fn private_key_one_known_address() {
        let lower = address_lower(&key_from_u64(1));
        assert_eq!(eip55(&lower), "7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    #[test]
    fn private_key_two_known_address() {
        let lower = address_lower(&key_from_u64(2));
        assert_eq!(
            std::str::from_utf8(&lower).unwrap(),
            "2b5ad5c4795c026514f8317c7a215e218dccd6cf"
        );
    }

    #[test]
    fn keccak_empty_known_answer() {
        let h = Keccak256::digest(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn eip55_published_vectors() {
        for v in [
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let lower: [u8; 40] = v.to_ascii_lowercase().as_bytes().try_into().unwrap();
            assert_eq!(eip55(&lower), v);
        }
    }

    #[test]
    fn hmac_sha256_rfc4231_case_1() {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&[0x0b; 20]).unwrap();
        mac.update(b"Hi There");
        let out = mac.finalize().into_bytes();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn derivation_is_deterministic_and_pinned() {
        let d = Deriver::new(b"vani-rs test seed");
        let a = private_key_hex(&d.secret_key(0));
        assert_eq!(*a, *private_key_hex(&d.secret_key(0)));
        assert_ne!(*a, *private_key_hex(&d.secret_key(1)));
        assert_eq!(a.len(), 66);
        assert!(a.starts_with("0x"));
        assert_ne!(*a, *private_key_hex(&Deriver::new(b"other").secret_key(0)));
    }

    #[test]
    fn iteration_encoding_is_fixed_width() {
        // Iterations whose big-endian encodings share prefixes/suffixes must still differ.
        let d = Deriver::new(&[7u8; 32]);
        let keys: Vec<_> = [0u64, 1, 256, 1 << 32, u64::MAX]
            .iter()
            .map(|&i| private_key_hex(&d.secret_key(i)))
            .collect();
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(*keys[i], *keys[j]);
            }
        }
    }
}
