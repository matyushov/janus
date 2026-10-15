//! SMB user credentials of the share. There is no guest access: without a
//! login/password pair `janus-smbd` does not accept SESSION_SETUP.
//!
//! Sources (by priority):
//! 1. dev: `JANUS_SMB_USER` + `JANUS_SMB_PASSWORD` (in the daemon's environment; never written to disk);
//! 2. the file `JANUS_SMB_CREDS_FILE` or `~/.config/janus/smb-credentials`,
//!    format `user:password`, mode 0600. If there is no pair, `janus-cli client configure`
//!    generates a random one and saves it here (Keychain later).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub const USER_ENV: &str = "JANUS_SMB_USER";
pub const PASSWORD_ENV: &str = "JANUS_SMB_PASSWORD";
pub const FILE_ENV: &str = "JANUS_SMB_CREDS_FILE";
/// User name in the generated pair.
pub const GENERATED_USER: &str = "janus";

#[derive(Clone, PartialEq, Eq)]
pub struct SmbCredentials {
    pub user: String,
    pub password: String,
}

impl std::fmt::Debug for SmbCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbCredentials")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// Default file path (`FILE_ENV` or `~/.config/janus/smb-credentials`).
pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(FILE_ENV) {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/janus/smb-credentials"))
}

/// Shared store: read by the SMB daemon, written by control on `configure`.
pub struct CredentialStore {
    current: RwLock<Option<SmbCredentials>>,
    path: Option<PathBuf>,
}

impl CredentialStore {
    /// Load from the environment, then from the file. A missing pair is not an error:
    /// the daemon lives but rejects every logon until `ensure_generated`.
    pub fn load(
        env_user: Option<String>,
        env_password: Option<String>,
        path: Option<PathBuf>,
    ) -> Self {
        let from_env = match (env_user, env_password) {
            (Some(user), Some(password)) if !user.is_empty() && !password.is_empty() => {
                Some(SmbCredentials { user, password })
            }
            _ => None,
        };
        let creds = from_env.or_else(|| path.as_deref().and_then(|p| read_file(p).ok().flatten()));
        CredentialStore {
            current: RwLock::new(creds),
            path,
        }
    }

    /// `load` from the real process environment.
    pub fn from_process_env() -> Self {
        Self::load(
            std::env::var(USER_ENV).ok(),
            std::env::var(PASSWORD_ENV).ok(),
            default_path(),
        )
    }

    pub fn get(&self) -> Option<SmbCredentials> {
        self.current
            .read()
            .expect("credentials lock poisoned")
            .clone()
    }

    /// If there is no pair, generate a random one and save it to the file (0600).
    /// `Ok(true)` means a new one was created, `Ok(false)` that it already existed.
    pub fn ensure_generated(&self) -> std::io::Result<bool> {
        if self.get().is_some() {
            return Ok(false);
        }
        let path = self.path.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "путь файла учётных данных неизвестен",
            )
        })?;
        let creds = SmbCredentials {
            user: GENERATED_USER.to_owned(),
            password: random_password()?,
        };
        write_file(path, &creds)?;
        *self.current.write().expect("credentials lock poisoned") = Some(creds);
        Ok(true)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

/// 128 bits of randomness in hex (32 characters).
fn random_password() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn read_file(path: &Path) -> std::io::Result<Option<SmbCredentials>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let line = text.lines().next().unwrap_or("").trim_end();
    Ok(line.split_once(':').and_then(|(u, p)| {
        (!u.is_empty() && !p.is_empty()).then(|| SmbCredentials {
            user: u.to_owned(),
            password: p.to_owned(),
        })
    }))
}

/// Atomic write: a tmp file with mode 0600 + rename.
fn write_file(path: &Path, c: &SmbCredentials) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    writeln!(f, "{}:{}", c.user, c.password)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("janus-cred-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn env_pair_wins_over_file_and_needs_both_parts() {
        let dir = tmpdir("env");
        let file = dir.join("c");
        std::fs::write(&file, "filuser:filepw\n").unwrap();
        let s = CredentialStore::load(Some("u".into()), Some("p".into()), Some(file.clone()));
        assert_eq!(s.get().unwrap().user, "u");
        // half of a pair from env is ignored → the file
        let s = CredentialStore::load(Some("u".into()), None, Some(file.clone()));
        assert_eq!(s.get().unwrap().user, "filuser");
        let s = CredentialStore::load(Some(String::new()), Some("p".into()), None);
        assert!(s.get().is_none());
    }

    #[test]
    fn no_credentials_means_none() {
        let dir = tmpdir("none");
        let s = CredentialStore::load(None, None, Some(dir.join("missing")));
        assert!(s.get().is_none());
    }

    #[test]
    fn generation_writes_0600_file_and_is_idempotent() {
        let dir = tmpdir("gen");
        let file = dir.join("sub/creds");
        let s = CredentialStore::load(None, None, Some(file.clone()));
        assert!(s.ensure_generated().unwrap());
        let c = s.get().unwrap();
        assert_eq!(c.user, GENERATED_USER);
        assert_eq!(c.password.len(), 32);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // a repeated call changes nothing
        assert!(!s.ensure_generated().unwrap());
        assert_eq!(s.get().unwrap(), c);
        // a new process picks up the same pair from the file
        let s2 = CredentialStore::load(None, None, Some(file));
        assert_eq!(s2.get().unwrap(), c);
    }

    #[test]
    fn two_generations_differ() {
        let a = random_password().unwrap();
        let b = random_password().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_file_is_ignored() {
        let dir = tmpdir("bad");
        for body in ["", "nocolon\n", ":pw\n", "user:\n"] {
            let f = dir.join("c");
            std::fs::write(&f, body).unwrap();
            assert!(
                CredentialStore::load(None, None, Some(f)).get().is_none(),
                "{body:?}"
            );
        }
    }

    #[test]
    fn debug_does_not_leak_password() {
        let c = SmbCredentials {
            user: "u".into(),
            password: "secret".into(),
        };
        assert!(!format!("{c:?}").contains("secret"));
    }
}
