//! Private result storage. Unix only: fails closed where permissions cannot be enforced.

#[cfg(not(unix))]
compile_error!("vani-rs requires Unix file permissions (0700/0600) for secret storage");

use crate::seed::Seed;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use zeroize::Zeroizing;

pub const SEED_FILE: &str = "seed.secret";
pub const KEY_FILE: &str = "private-key.secret";
const MAX_SEED_FILE: u64 = 1 << 20;

/// A private result directory (mode 0700).
#[derive(Debug)]
pub struct ResultDir {
    path: PathBuf,
}

fn random_suffix() -> io::Result<String> {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn check_private_dir(path: &Path) -> io::Result<()> {
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must not be accessible by group/others (mode {:o}); run chmod 700",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

/// Creates a new file (never overwriting) with mode 0600 and writes `contents` to it.
fn create_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // The creation mode is subject to the umask, which can only remove bits; enforce 0600 anyway
    // and verify before any secret byte is written.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
        return Err(io::Error::other("could not enforce 0600 on secret file"));
    }
    file.write_all(contents)?;
    file.sync_all()
}

impl ResultDir {
    /// Creates a new timestamped `0700` directory under `data_dir` (itself created `0700`).
    pub fn create(data_dir: &Path) -> io::Result<Self> {
        Self::create_at(data_dir, OffsetDateTime::now_utc())
    }

    fn create_at(data_dir: &Path, now: OffsetDateTime) -> io::Result<Self> {
        if data_dir.exists() {
            check_private_dir(data_dir)?;
        } else {
            DirBuilder::new().recursive(true).mode(0o700).create(data_dir)?;
            fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;
        }
        let base = format!(
            "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}Z-result",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        let mut name = base.clone();
        for _ in 0..16 {
            let path = data_dir.join(&name);
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    name = format!("{base}-{}", random_suffix()?);
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find an unused result directory name",
        ))
    }

    /// If `seed_file` is an existing `seed.secret` directly inside a result directory (named like
    /// `YYYY-MM-DDTHH-MM-SSZ-result[-xxxxxxxx]`), returns that directory after checking that it is
    /// private. Any other file is an external seed and yields `None`.
    pub fn adopt(seed_file: &Path) -> io::Result<Option<Self>> {
        if seed_file.file_name().is_none_or(|n| n != SEED_FILE) {
            return Ok(None);
        }
        let parent = match seed_file.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let Ok(parent) = parent.canonicalize() else {
            return Ok(None);
        };
        if !parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_result_dir_name)
        {
            return Ok(None);
        }
        check_private_dir(&parent)?;
        Ok(Some(Self { path: parent }))
    }

    /// Detects whether `dir` itself is a result directory containing `seed.secret`.
    pub fn detect(dir: &Path) -> io::Result<Option<Self>> {
        let seed_file = dir.join(SEED_FILE);
        if seed_file.is_file() {
            Self::adopt(&seed_file)
        } else {
            Ok(None)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn seed_path(&self) -> PathBuf {
        self.path.join(SEED_FILE)
    }

    /// Stores the seed as Base64 in `seed.secret`; fails if the file exists.
    pub fn write_seed(&self, seed: &Seed) -> io::Result<()> {
        create_private_file(&self.seed_path(), seed.to_base64().as_bytes())
    }

    /// Stores the `0x`-prefixed private key hex, choosing a unique name on collision.
    pub fn write_private_key(&self, key_hex: &str) -> io::Result<PathBuf> {
        let mut name = KEY_FILE.to_string();
        for _ in 0..16 {
            let path = self.path.join(&name);
            match create_private_file(&path, key_hex.as_bytes()) {
                Ok(()) => return Ok(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    name = format!("private-key-{}.secret", random_suffix()?);
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find an unused key file name",
        ))
    }
}

/// True for `YYYY-MM-DDTHH-MM-SSZ-result` optionally followed by `-` and 8 lowercase hex digits.
fn is_result_dir_name(name: &str) -> bool {
    const SHAPE: &[u8; 19] = b"dddd-dd-ddTdd-dd-dd";
    let Some((stamp, tail)) = name.split_once("Z-result") else {
        return false;
    };
    let stamp_ok = stamp.len() == SHAPE.len()
        && stamp
            .bytes()
            .zip(SHAPE)
            .all(|(c, &m)| if m == b'd' { c.is_ascii_digit() } else { c == m });
    let tail_ok = tail.is_empty()
        || tail
            .strip_prefix('-')
            .is_some_and(|t| t.len() == 8 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    stamp_ok && tail_ok
}

/// Reads a text secret from a file with a size limit, zeroizing the buffer on drop.
pub fn read_secret_file(path: &Path) -> io::Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    File::open(path)?.take(MAX_SEED_FILE).read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_private_dir_and_files_without_clobbering() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let dir = ResultDir::create(&data).unwrap();
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(dir.path()), 0o700);
        assert!(
            dir.path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("Z-result")
        );

        let seed = Seed::from_base64("AQIDBA==").unwrap();
        dir.write_seed(&seed).unwrap();
        assert_eq!(mode(&dir.seed_path()), 0o600);
        assert!(dir.write_seed(&seed).is_err(), "seed must never be overwritten");
        assert_eq!(fs::read_to_string(dir.seed_path()).unwrap(), "AQIDBA==");

        let key = format!("0x{}", "ab".repeat(32));
        let k1 = dir.write_private_key(&key).unwrap();
        let k2 = dir.write_private_key(&key).unwrap();
        assert_eq!(k1.file_name().unwrap(), KEY_FILE);
        assert_ne!(k1, k2);
        assert_eq!(mode(&k1), 0o600);
        assert_eq!(mode(&k2), 0o600);
        assert_eq!(fs::read_to_string(&k1).unwrap(), key);
    }

    #[test]
    fn same_second_collision_gets_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let a = ResultDir::create_at(tmp.path(), now).unwrap();
        let b = ResultDir::create_at(tmp.path(), now).unwrap();
        assert_eq!(a.path().file_name().unwrap(), "2023-11-14T22-13-20Z-result");
        assert_ne!(a.path(), b.path());
        assert_eq!(mode(b.path()), 0o700);
    }

    #[test]
    fn rejects_loose_existing_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ResultDir::create(tmp.path()).is_err());
    }

    #[test]
    fn adopts_only_seed_files_inside_result_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let dir = ResultDir::create(&data).unwrap();
        dir.write_seed(&Seed::generate().unwrap()).unwrap();
        let adopted = ResultDir::adopt(&dir.seed_path()).unwrap().unwrap();
        assert_eq!(adopted.path(), dir.path().canonicalize().unwrap());
        let detected = ResultDir::detect(dir.path()).unwrap().unwrap();
        assert_eq!(detected.path(), adopted.path());

        let outside = tmp.path().join("seed.secret");
        fs::write(&outside, "AQID").unwrap();
        assert!(ResultDir::adopt(&outside).unwrap().is_none());
        assert!(ResultDir::detect(&data).unwrap().is_none());
        let renamed = dir.path().join("other.txt");
        fs::write(&renamed, "AQID").unwrap();
        assert!(ResultDir::adopt(&renamed).unwrap().is_none());
    }

    #[test]
    fn result_dir_names() {
        assert!(is_result_dir_name("2026-10-21T12-00-00Z-result"));
        assert!(is_result_dir_name("2026-10-21T12-00-00Z-result-0a1b2c3d"));
        assert!(!is_result_dir_name("2026-10-21T12-00-00Z-result-xyz"));
        assert!(!is_result_dir_name("2026-10-21T12-00-00Z-results"));
        assert!(!is_result_dir_name("data"));
        assert!(!is_result_dir_name("abcd-ef-ghTij-kl-mnZ-result"));
    }

    #[test]
    fn rejects_loose_result_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = ResultDir::create(tmp.path().join("data").as_path()).unwrap();
        dir.write_seed(&Seed::generate().unwrap()).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ResultDir::detect(dir.path()).is_err());
    }
}
