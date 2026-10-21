//! Command-line interface definition.

use clap::Parser;
use std::path::PathBuf;

fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// Searches deterministic Ethereum key candidates for an address matching a regex.
///
/// The pattern is matched against the 40 hex characters of the EIP-55 address (no `0x`).
/// A leading `0x` is stripped; `^` and `$` anchors are added when absent.
///
/// Seed source precedence: --seed, --seed-file, or --stdin (mutually exclusive); if none is
/// given and the current directory is a result directory containing `seed.secret`, that seed and
/// directory are reused; otherwise a fresh seed is generated. A `seed.secret` inside a result
/// directory (via --seed-file or the current directory) resumes that directory; any other seed
/// source is copied into a new result directory.
#[derive(Parser, Debug)]
#[command(name = "vani-rs", version, about, long_about)]
pub struct Cli {
    /// Regex for the address, e.g. `0x012345.*` (case-sensitive unless -c)
    #[arg(short = 'n', long)]
    pub pattern: String,

    /// Base64 seed
    #[arg(short = 's', long, conflicts_with_all = ["seed_file", "stdin"])]
    pub seed: Option<String>,

    /// File containing a Base64 seed; `seed.secret` inside a result directory resumes that run
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "stdin")]
    pub seed_file: Option<PathBuf>,

    /// Read the Base64 seed from standard input
    #[arg(long)]
    pub stdin: bool,

    /// Number of worker threads (default: all logical CPUs)
    #[arg(short = 't', long, value_parser = clap::value_parser!(u64).range(1..=4096))]
    pub threads: Option<u64>,

    /// First iteration to examine
    #[arg(short = 'i', long, default_value_t = 0)]
    pub iter: u64,

    /// Match case-insensitively using the regex engine's Unicode case folding
    #[arg(short = 'c', long)]
    pub case_insensitive: bool,

    /// Directory for result directories
    #[arg(long, default_value = "data", value_name = "DIR")]
    pub data_dir: PathBuf,
}

impl Cli {
    pub fn thread_count(&self) -> usize {
        self.threads.map_or_else(default_threads, |t| t as usize)
    }

    pub fn threads_is_default(&self) -> bool {
        self.threads.is_none_or(|t| t as usize == default_threads())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_parse() {
        let c =
            Cli::try_parse_from(["vani-rs", "-n", "ab.*", "-f", "p", "-t", "2", "-i", "7", "-c"]).unwrap();
        assert_eq!(
            (c.pattern.as_str(), c.threads, c.iter, c.case_insensitive),
            ("ab.*", Some(2), 7, true)
        );
        let c =
            Cli::try_parse_from(["vani-rs", "--pattern", "a", "--seed", "AQID", "--threads", "1"]).unwrap();
        assert_eq!(c.seed.as_deref(), Some("AQID"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Cli::try_parse_from(["vani-rs"]).is_err(), "pattern is required");
        assert!(Cli::try_parse_from(["vani-rs", "-n", "a", "-t", "0"]).is_err());
        assert!(Cli::try_parse_from(["vani-rs", "-n", "a", "-s", "AQID", "-f", "x"]).is_err());
        assert!(Cli::try_parse_from(["vani-rs", "-n", "a", "-f", "x", "--stdin"]).is_err());
    }
}
