//! Pattern normalization, matching, and conservative probability estimation.

use regex::Regex;
use std::fmt;

/// Error raised for an invalid pattern.
#[derive(Debug)]
pub struct PatternError(String);

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid pattern: {}", self.0)
    }
}

impl std::error::Error for PatternError {}

/// A compiled address pattern.
#[derive(Debug)]
pub struct Pattern {
    regex: Regex,
    case_insensitive: bool,
    /// Per-candidate match probability when the pattern is a simple hex prefix.
    probability: Option<f64>,
}

impl Pattern {
    /// Normalizes and compiles `raw`.
    ///
    /// One optional leading `0x` is removed, a missing `^`/`$` is added, and the body is wrapped
    /// as `^(?:body)$`. Case-insensitive mode uses the regex engine's `(?i)` flag; the pattern
    /// text itself is never modified.
    pub fn new(raw: &str, case_insensitive: bool) -> Result<Self, PatternError> {
        let body = raw.strip_prefix('^').unwrap_or(raw);
        let body = body
            .strip_prefix("0x")
            .or_else(|| body.strip_prefix("0X"))
            .unwrap_or(body);
        let body = strip_unescaped_dollar(body);
        let flags = if case_insensitive { "(?i)" } else { "" };
        let regex = Regex::new(&format!("{flags}^(?:{body})$")).map_err(|e| PatternError(e.to_string()))?;
        let probability = prefix_probability(body, case_insensitive);
        Ok(Self {
            regex,
            case_insensitive,
            probability,
        })
    }

    /// Whether this pattern ignores case.
    pub fn case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Tests an address of 40 hex characters (no `0x`).
    ///
    /// In case-insensitive mode any casing gives the same result, so callers may pass the
    /// lowercase form and skip the EIP-55 computation.
    pub fn is_match(&self, address: &str) -> bool {
        self.regex.is_match(address)
    }

    /// Probability that one random candidate matches, if the pattern is a recognized hex prefix.
    pub fn match_probability(&self) -> Option<f64> {
        self.probability
    }
}

fn strip_unescaped_dollar(s: &str) -> &str {
    match s.strip_suffix('$') {
        Some(rest) => {
            let backslashes = rest.bytes().rev().take_while(|&b| b == b'\\').count();
            if backslashes % 2 == 0 { rest } else { s }
        }
        None => s,
    }
}

/// Recognizes `hexdigits` followed by `.*`, `.+`, or nothing (exactly 40 digits), and returns the
/// per-address probability. `.+` is valid only below 40 digits, where at least one more
/// character always exists, so it matches exactly the same addresses as `.*`. Letter digits in
/// case-sensitive mode have probability 1/32 (1/16 for the hex value times 1/2 for the EIP-55
/// casing), which is an approximation.
fn prefix_probability(body: &str, case_insensitive: bool) -> Option<f64> {
    let (digits, suffix) = match body.strip_suffix(".*") {
        Some(d) => (d, Suffix::Any),
        None => match body.strip_suffix(".+") {
            Some(d) => (d, Suffix::AtLeastOne),
            None => (body, Suffix::None),
        },
    };
    let n = digits.len();
    let length_ok = match suffix {
        Suffix::Any => n <= 40,
        Suffix::AtLeastOne => n < 40,
        Suffix::None => n == 40,
    };
    if n == 0 || !length_ok || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        digits
            .bytes()
            .map(|b| {
                if b.is_ascii_alphabetic() && !case_insensitive {
                    1.0 / 32.0
                } else {
                    1.0 / 16.0
                }
            })
            .product(),
    )
}

enum Suffix {
    Any,
    AtLeastOne,
    None,
}

/// Probability of at least one match after `n` independent candidates, each with probability `p`.
pub fn probability_by(p: f64, n: f64) -> f64 {
    -(n * (-p).ln_1p()).exp_m1()
}

/// Number of candidates for a 50% chance of at least one match.
pub fn iterations_for_half(p: f64) -> f64 {
    std::f64::consts::LN_2 / -(-p).ln_1p()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "012345aBcdEF0123456789abcdef0123456789Ab";

    fn m(p: &str, ci: bool, a: &str) -> bool {
        Pattern::new(p, ci).unwrap().is_match(a)
    }

    #[test]
    fn optional_0x_and_implicit_anchors() {
        assert!(m("0x012345.*", false, ADDR));
        assert!(m("012345.*", false, ADDR));
        assert!(!m("012345", false, ADDR));
        assert!(!m("2345.*", false, ADDR));
        assert!(m(".*89Ab", false, ADDR));
    }

    #[test]
    fn explicit_anchors() {
        assert!(m("^012345.*$", false, ADDR));
        assert!(m("^0x012345.*", false, ADDR));
        assert!(m(".*89Ab$", false, ADDR));
        assert!(!m("^012345$", false, ADDR));
    }

    #[test]
    fn alternation_is_fully_anchored() {
        assert!(!m("012|345", false, ADDR));
        assert!(m("012345.*|zzz", false, ADDR));
    }

    #[test]
    fn escaped_dollar_is_not_an_anchor() {
        assert!(Pattern::new(r"a\$", false).is_ok());
        assert!(!m(r"012345.*\$", false, ADDR));
    }

    #[test]
    fn case_sensitivity() {
        assert!(!m("012345abcdef.*", false, ADDR));
        assert!(m("012345abcdef.*", true, ADDR));
        assert!(m("012345ABCDEF.*", true, ADDR));
    }

    #[test]
    fn case_insensitive_does_not_rewrite_metacharacters() {
        // Lowercasing the raw pattern would turn \S into \s and break this.
        assert!(m(r"\S+", true, ADDR));
        assert!(!m(r"\s+", true, ADDR));
        assert!(m(r"\D\D.*", true, "ab0000000000000000000000000000000000000000"));
    }

    #[test]
    fn invalid_pattern_rejected() {
        assert!(Pattern::new("(", false).is_err());
    }

    #[test]
    fn probability_recognition() {
        let p = |s: &str, ci| Pattern::new(s, ci).unwrap().match_probability();
        assert_eq!(p("0x012345.*", false), Some(1.0 / 16f64.powi(6)));
        assert_eq!(p("^012345.*$", false), Some(1.0 / 16f64.powi(6)));
        assert_eq!(p("0x012345.+", false), Some(1.0 / 16f64.powi(6)));
        assert_eq!(p("ab.+", true), Some(1.0 / 256.0));
        assert_eq!(p(&format!("{}.+", "1".repeat(40)), false), None);
        assert_eq!(p(&format!("{}.+", "1".repeat(39)), false), Some(16f64.powi(-39)));
        assert_eq!(p("ab.*", false), Some(1.0 / 1024.0));
        assert_eq!(p("ab.*", true), Some(1.0 / 256.0));
        assert_eq!(p("012345", false), None);
        assert_eq!(p("0[0-9].*", false), None);
        assert_eq!(p(".*abc", false), None);
        assert_eq!(p(&"1".repeat(40), false), Some(16f64.powi(-40)));
    }

    #[test]
    fn estimate_math() {
        let p = 1.0 / 16.0;
        assert!((probability_by(p, 1.0) - p).abs() < 1e-12);
        assert!((probability_by(p, iterations_for_half(p)) - 0.5).abs() < 1e-9);
    }
}
