//! CLI orchestration. All output goes through the supplied writers so it can be inspected;
//! full seed and private key values are never written to them.

use crate::candidate::{Deriver, private_key_hex};
use crate::cli::Cli;
use crate::pattern::Pattern;
use crate::progress::{final_stats, status_line};
use crate::search::{self, Snapshot};
use crate::seed::{Seed, mask};
use crate::storage::{ResultDir, read_secret_file};
use std::error::Error;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use zeroize::Zeroizing;

/// How a run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Found,
    Interrupted,
    Exhausted,
}

type Res<T> = Result<T, Box<dyn Error>>;

/// Quotes a string for POSIX shells when needed.
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Builds the command that restarts a stopped run at `resume_point`.
pub fn resume_command(cli: &Cli, seed_path: &Path, resume_point: u64) -> String {
    let mut parts = vec![
        "vani-rs".to_string(),
        "--seed-file".into(),
        shell_quote(&seed_path.display().to_string()),
        "--iter".into(),
        resume_point.to_string(),
        "--pattern".into(),
        shell_quote(&cli.pattern),
    ];
    if cli.case_insensitive {
        parts.push("--case-insensitive".into());
    }
    if !cli.threads_is_default() {
        parts.push("--threads".into());
        parts.push(cli.thread_count().to_string());
    }
    if cli.data_dir != Path::new("data") {
        parts.push("--data-dir".into());
        parts.push(shell_quote(&cli.data_dir.display().to_string()));
    }
    parts.join(" ")
}

/// Runs the whole program. `cwd` is used only to detect an enclosing result directory when no
/// seed source was given. `progress` receives the once-per-second status line when present.
pub fn execute(
    cli: &Cli,
    cwd: &Path,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    mut progress: Option<&mut dyn Write>,
    stop: &AtomicBool,
) -> Res<Status> {
    let pattern = Pattern::new(&cli.pattern, cli.case_insensitive)?;
    let threads = cli.thread_count();

    // Seed source precedence: explicit --seed, --seed-file, or --stdin; otherwise a result
    // directory that is the current directory; otherwise a fresh random seed. Only a seed file
    // (explicit or detected) inside a result directory reuses that directory; explicit seeds
    // always get a new directory so an unrelated working directory is never touched.
    let (seed, existing) = if let Some(text) = &cli.seed {
        (Seed::from_base64(text)?, None)
    } else if let Some(path) = &cli.seed_file {
        let text = read_secret_file(path)?;
        (Seed::from_base64(&text)?, ResultDir::adopt(path)?)
    } else if cli.stdin {
        let mut text = Zeroizing::new(String::new());
        stdin.take(1 << 20).read_to_string(&mut text)?;
        (Seed::from_base64(&text)?, None)
    } else if let Some(dir) = ResultDir::detect(cwd)? {
        let text = read_secret_file(&dir.seed_path())?;
        (Seed::from_base64(&text)?, Some(dir))
    } else {
        (Seed::generate()?, None)
    };
    if seed.is_short() {
        writeln!(
            out,
            "warning: seed is shorter than 32 bytes; its length does not prove its entropy"
        )?;
    }
    let dir = match existing {
        Some(dir) => {
            writeln!(out, "Resuming in existing result directory (seed unchanged)")?;
            dir
        }
        None => {
            let dir = ResultDir::create(&cli.data_dir)?;
            dir.write_seed(&seed)?;
            dir
        }
    };

    let first_key = private_key_hex(&Deriver::new(seed.as_bytes()).secret_key(cli.iter));
    writeln!(out, "Result directory: {}", dir.path().display())?;
    writeln!(out, "Seed (masked): {}", seed.masked())?;
    writeln!(out, "First candidate key (masked): {}", mask(&first_key))?;
    drop(first_key);
    writeln!(
        out,
        "Pattern: {} | threads: {threads} | first iteration: {}",
        cli.pattern, cli.iter
    )?;
    out.flush()?;

    let p = pattern.match_probability();
    let mut prev = (0u64, Duration::ZERO);
    let outcome = search::run(
        seed.as_bytes(),
        &pattern,
        cli.iter,
        threads,
        stop,
        Duration::from_secs(1),
        |snap: &Snapshot| {
            if let Some(w) = progress.as_mut() {
                // Best effort: a failed status write must not abort the search.
                let _ = write!(w, "\r\x1b[K{}", status_line(snap, prev, p));
                let _ = w.flush();
            }
            prev = (snap.completed, snap.elapsed);
        },
    );
    if let Some(w) = progress.as_mut() {
        let _ = writeln!(w);
    }

    if let Some(found) = &outcome.found {
        writeln!(out, "Match at iteration {}: 0x{}", found.iteration, found.address)?;
        let key_hex = private_key_hex(&found.key);
        match dir.write_private_key(&key_hex) {
            Ok(path) => {
                writeln!(out, "Private key (masked): {}", mask(&key_hex))?;
                writeln!(out, "Private key saved to: {}", path.display())?;
            }
            Err(e) => {
                writeln!(
                    out,
                    "Could not save the private key ({e}). It can be re-derived from the saved seed at iteration {}.",
                    found.iteration
                )?;
                return Err(e.into());
            }
        }
        writeln!(out, "{}", final_stats(outcome.completed, outcome.elapsed, p))?;
        return Ok(Status::Found);
    }

    writeln!(out, "{}", final_stats(outcome.completed, outcome.elapsed, p))?;
    match (outcome.interrupted, outcome.resume_point) {
        (true, Some(resume_point)) => {
            writeln!(
                out,
                "Interrupted. Resume (may repeat some already examined iterations) with:"
            )?;
            writeln!(out, "  {}", resume_command(cli, &dir.seed_path(), resume_point))?;
            Ok(Status::Interrupted)
        }
        _ => {
            writeln!(out, "Search space exhausted.")?;
            Ok(Status::Exhausted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    const SEED: &str = "dGVzdC1zZWVkLWZvci12YW5pLXJzLXRlc3RzLTAwMQ=="; // not a real secret

    fn run(args: &[&str], stdin: &str, stop: bool) -> (Res<Status>, String) {
        run_in(Path::new("/nonexistent-cwd"), args, stdin, stop)
    }

    fn run_in(cwd: &Path, args: &[&str], stdin: &str, stop: bool) -> (Res<Status>, String) {
        let cli = Cli::try_parse_from(args).unwrap();
        let mut out = Vec::new();
        let stop = AtomicBool::new(stop);
        let r = execute(&cli, cwd, &mut stdin.as_bytes(), &mut out, None, &stop);
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn end_to_end_match_never_prints_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let d = data.to_str().unwrap();
        let (r, out) = run(
            &["vani-rs", "-n", "0x00.*", "-s", SEED, "-t", "2", "--data-dir", d],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        let rd = std::fs::read_dir(&data).unwrap().next().unwrap().unwrap().path();
        let key = std::fs::read_to_string(rd.join("private-key.secret")).unwrap();
        assert!(key.starts_with("0x") && key.len() == 66);
        let seed_file = std::fs::read_to_string(rd.join("seed.secret")).unwrap();
        assert_eq!(seed_file, SEED);
        assert!(!out.contains(SEED), "full seed leaked");
        assert!(!out.contains(&key[2..]) && !out.contains(&key), "full key leaked");
        assert!(out.contains(&mask(SEED)), "masked seed preview expected: {out}");
        assert!(out.contains("Match at iteration"));
    }

    #[test]
    fn resume_in_existing_dir_keeps_seed_and_adds_unique_key_file() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let d = data.to_str().unwrap();
        let (r, _) = run(&["vani-rs", "-n", "00.*", "-s", SEED, "--data-dir", d], "", false);
        assert_eq!(r.unwrap(), Status::Found);
        let rd = std::fs::read_dir(&data).unwrap().next().unwrap().unwrap().path();
        let sf = rd.join("seed.secret");
        let (r, out) = run(
            &[
                "vani-rs",
                "-n",
                "00.*",
                "-f",
                sf.to_str().unwrap(),
                "-i",
                "0",
                "--data-dir",
                d,
            ],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        assert!(out.contains("Resuming in existing"));
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1, "no new directory");
        assert_eq!(std::fs::read_to_string(&sf).unwrap(), SEED);
        let keys = std::fs::read_dir(&rd)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("private-key")
            })
            .count();
        assert_eq!(keys, 2);
    }

    fn only_dir(data: &Path) -> std::path::PathBuf {
        std::fs::read_dir(data).unwrap().next().unwrap().unwrap().path()
    }

    #[test]
    fn launching_from_a_result_dir_reuses_its_seed_and_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let d = data.to_str().unwrap();
        let (r, _) = run(&["vani-rs", "-n", "00.*", "-s", SEED, "--data-dir", d], "", false);
        assert_eq!(r.unwrap(), Status::Found);
        let rd = only_dir(&data);
        let (r, out) = run_in(&rd, &["vani-rs", "-n", "00.*", "--data-dir", d], "", false);
        assert_eq!(r.unwrap(), Status::Found);
        assert!(out.contains("Resuming in existing"), "{out}");
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1, "no new directory");
        assert_eq!(std::fs::read_to_string(rd.join("seed.secret")).unwrap(), SEED);
        assert!(out.contains(&mask(SEED)) && !out.contains(SEED));
    }

    #[test]
    fn explicit_seed_sources_take_precedence_over_cwd_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let d = data.to_str().unwrap();
        let (r, _) = run(&["vani-rs", "-n", "00.*", "-s", SEED, "--data-dir", d], "", false);
        assert_eq!(r.unwrap(), Status::Found);
        let rd = only_dir(&data);
        let other = "b3RoZXItc2VlZC1mb3ItcHJlY2VkZW5jZS10ZXN0LTAwMDE="; // not a real secret
        // --seed and --stdin run inside a result dir must create a new directory and not
        // touch the enclosing one.
        let (r, _) = run_in(
            &rd,
            &["vani-rs", "-n", "00.*", "-s", other, "--data-dir", d],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        let (r, _) = run_in(
            &rd,
            &["vani-rs", "-n", "00.*", "--stdin", "--data-dir", d],
            &format!("{other}\n"),
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 3);
        assert_eq!(std::fs::read_to_string(rd.join("seed.secret")).unwrap(), SEED);
        assert_eq!(std::fs::read_dir(&rd).unwrap().count(), 2, "seed + one key only");
    }

    #[test]
    fn cwd_without_result_dir_generates_fresh_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        std::fs::write(tmp.path().join("seed.secret"), SEED).unwrap();
        let (r, out) = run_in(
            tmp.path(),
            &["vani-rs", "-n", "00.*", "--data-dir", data.to_str().unwrap()],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        assert!(!out.contains(&mask(SEED)));
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);
    }

    #[test]
    fn iteration_u64_max_is_accepted_and_exhausts() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("data");
        let max = u64::MAX.to_string();
        let (r, out) = run(
            &[
                "vani-rs",
                "-n",
                "ffffffffffffffffffffffffffffffffffffffff",
                "-s",
                SEED,
                "-i",
                &max,
                "--data-dir",
                d.to_str().unwrap(),
            ],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Exhausted);
        assert!(out.contains("Candidates examined: 1"), "{out}");
    }

    #[test]
    fn external_seed_file_and_stdin_create_new_dirs_with_copied_seed() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let d = data.to_str().unwrap();
        let ext = tmp.path().join("seed.secret");
        std::fs::write(&ext, SEED).unwrap();
        let (r, _) = run(
            &[
                "vani-rs",
                "-n",
                "00.*",
                "-f",
                ext.to_str().unwrap(),
                "--data-dir",
                d,
            ],
            "",
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        let (r, _) = run(
            &["vani-rs", "-n", "00.*", "--stdin", "--data-dir", d],
            &format!("{SEED}\n"),
            false,
        );
        assert_eq!(r.unwrap(), Status::Found);
        assert_eq!(std::fs::read_dir(&data).unwrap().count(), 2);
    }

    #[test]
    fn interrupt_prints_resume_command_without_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("data");
        let (r, out) = run(
            &[
                "vani-rs",
                "-n",
                "it's.*",
                "-s",
                SEED,
                "-c",
                "-t",
                "3",
                "-i",
                "5",
                "--data-dir",
                d.to_str().unwrap(),
            ],
            "",
            true,
        );
        // "it's.*" is a valid regex that cannot match hex addresses.
        assert_eq!(r.unwrap(), Status::Interrupted);
        assert!(out.contains("--seed-file") && out.contains("--iter 5"), "{out}");
        assert!(out.contains("--case-insensitive") && out.contains("--threads 3"));
        assert!(out.contains(r"'it'\''s.*'"));
        assert!(!out.contains(SEED));
    }

    #[test]
    fn invalid_pattern_and_seed_errors_are_clear() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("data");
        let d = d.to_str().unwrap();
        let (r, _) = run(&["vani-rs", "-n", "(", "--data-dir", d], "", false);
        assert!(r.unwrap_err().to_string().contains("invalid pattern"));
        let (r, out) = run(
            &["vani-rs", "-n", "a", "-s", "not base64!!", "--data-dir", d],
            "",
            false,
        );
        let e = r.unwrap_err().to_string();
        assert!(e.contains("Base64") && !e.contains("not base64") && !out.contains("not base64"));
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("a/b-c.d"), "a/b-c.d");
        assert_eq!(shell_quote("^0x.*$"), "'^0x.*$'");
        assert_eq!(shell_quote(""), "''");
    }
}
