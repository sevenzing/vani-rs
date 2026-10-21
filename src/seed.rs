//! Seed handling: parsing, generation, and masked previews.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fmt;
use zeroize::Zeroizing;

/// Recommended minimum seed length in bytes.
pub const RECOMMENDED_LEN: usize = 32;

/// Seed errors. Messages never contain seed material.
#[derive(Debug)]
pub enum SeedError {
    Empty,
    Base64,
    Random(String),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "seed is empty"),
            Self::Base64 => write!(f, "seed is not valid Base64"),
            Self::Random(e) => write!(f, "operating system randomness failed: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

/// Secret seed bytes, zeroized on drop. `Debug` never prints contents.
pub struct Seed(Zeroizing<Vec<u8>>);

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed(<{} bytes>)", self.0.len())
    }
}

impl Seed {
    /// Generates 32 bytes from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, SeedError> {
        let mut bytes = Zeroizing::new(vec![0u8; RECOMMENDED_LEN]);
        getrandom::fill(&mut bytes).map_err(|e| SeedError::Random(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// Parses Base64 text (surrounding whitespace ignored). Any non-empty length is accepted.
    pub fn from_base64(text: &str) -> Result<Self, SeedError> {
        let bytes = Zeroizing::new(STANDARD.decode(text.trim()).map_err(|_| SeedError::Base64)?);
        if bytes.is_empty() {
            return Err(SeedError::Empty);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// True when shorter than the recommended length.
    pub fn is_short(&self) -> bool {
        self.0.len() < RECOMMENDED_LEN
    }

    /// Base64 encoding, zeroized on drop.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(&*self.0))
    }

    /// Masked preview of the Base64 form.
    pub fn masked(&self) -> String {
        mask(&self.to_base64())
    }
}

/// Reveals the first and last four characters and replaces the middle with `*`.
/// Values of eight or fewer characters are fully masked.
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_reveals_only_edges() {
        assert_eq!(mask("abcdefghijkl"), "abcd****ijkl");
        assert_eq!(mask("abcdefgh"), "********");
        assert_eq!(mask(""), "");
    }

    #[test]
    fn base64_round_trip_and_validation() {
        let s = Seed::from_base64(" AQIDBA== \n").unwrap();
        assert_eq!(s.as_bytes(), &[1, 2, 3, 4]);
        assert!(s.is_short());
        assert_eq!(&*s.to_base64(), "AQIDBA==");
        assert!(matches!(Seed::from_base64("!!"), Err(SeedError::Base64)));
        assert!(matches!(Seed::from_base64(" "), Err(SeedError::Empty)));
    }

    #[test]
    fn generated_seed_is_32_bytes_and_debug_is_redacted() {
        let s = Seed::generate().unwrap();
        assert_eq!(s.as_bytes().len(), 32);
        assert!(!s.is_short());
        assert_eq!(format!("{s:?}"), "Seed(<32 bytes>)");
        let t = Seed::generate().unwrap();
        assert_ne!(s.as_bytes(), t.as_bytes());
    }
}
