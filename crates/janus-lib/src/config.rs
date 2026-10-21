//! Configuration: a persistent file + a push from the agent (`Configure`).
//! The agent is the source of truth; the file exists so that socket activation does not depend
//! on a live agent. Secrets are references only (Keychain), not values.
//!
//! File format: JSON (`serde_json`), one object `{"version":1,"share":{..}}`. JSON over TOML
//! because the same data already travels as protobuf/JSON-shaped fields, the dependency is
//! tiny and pure Rust, and the file is machine-written (never hand-edited). Unknown fields are
//! ignored, missing ones default, so older and newer daemons can read each other's files.
//! Location: `JANUS_CONFIG`, else `<state-dir>/config` (`~/.config/janus/config`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

/// Override of the config file path.
pub const FILE_ENV: &str = "JANUS_CONFIG";
const FORMAT_VERSION: u32 = 1;

/// Default file path (`FILE_ENV` or `<state-dir>/config`).
pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(FILE_ENV).filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".config/janus/config"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FlushPolicy {
    #[default]
    Unspecified,
    /// F_FULLFSYNC waits for the remote Fsync on the appliance (an honest end-to-end).
    SyncThrough,
    /// F_FULLFSYNC = fsync of the WAL on the Mac; the network catches up.
    LocalJournal,
}

/// Default size of the unuploaded backlog the journal may hold (1 GiB).
pub const DEFAULT_MAX_BACKLOG: u64 = 1 << 30;

/// The directory holding the config and the journal (`~/.config/janus`).
pub fn state_dir() -> Option<PathBuf> {
    default_path().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// Write-ahead journal settings. `enabled = false` is the J3a behaviour: every operation
/// goes to the receiver synchronously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct JournalConfig {
    pub enabled: bool,
    /// Empty = `<state-dir>/journal`.
    pub dir: String,
    /// Unuploaded data the journal may hold; writes wait (then fail) when it is reached.
    /// 0 = `DEFAULT_MAX_BACKLOG`.
    pub max_backlog_bytes: u64,
}

impl Default for JournalConfig {
    fn default() -> Self {
        JournalConfig {
            enabled: true,
            dir: String::new(),
            max_backlog_bytes: 0,
        }
    }
}

impl JournalConfig {
    pub fn max_backlog(&self) -> u64 {
        if self.max_backlog_bytes == 0 {
            DEFAULT_MAX_BACKLOG
        } else {
            self.max_backlog_bytes
        }
    }

    pub fn resolve_dir(&self) -> Option<PathBuf> {
        self.resolve_dir_in(state_dir().as_deref())
    }

    /// Like `resolve_dir`, with an explicit state directory instead of the environment's
    /// (the embedding SDK never reads `HOME`).
    pub fn resolve_dir_in(&self, state_dir: Option<&Path>) -> Option<PathBuf> {
        if !self.dir.is_empty() {
            return Some(PathBuf::from(&self.dir));
        }
        state_dir.map(|d| d.join("journal"))
    }
}

/// How long the SMB layer keeps a client waiting for FLUSH / CLOSE / SET_INFO that depend on
/// the receiver. `0` means the built-in default for each field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SmbWaitConfig {
    /// After this long a still-running operation gets an interim STATUS_PENDING (default 1500).
    pub interim_after_ms: u32,
    /// The ceiling: the client is then answered with an error (default 300).
    pub max_wait_sec: u32,
    /// A receiver failing continuously this long ends the wait early with an error (default 120).
    pub down_after_sec: u32,
}

impl SmbWaitConfig {
    pub fn interim_after(&self) -> Option<std::time::Duration> {
        (self.interim_after_ms > 0)
            .then(|| std::time::Duration::from_millis(self.interim_after_ms.into()))
    }
    pub fn max_wait(&self) -> Option<std::time::Duration> {
        (self.max_wait_sec > 0).then(|| std::time::Duration::from_secs(self.max_wait_sec.into()))
    }
    pub fn down_after(&self) -> Option<std::time::Duration> {
        (self.down_after_sec > 0)
            .then(|| std::time::Duration::from_secs(self.down_after_sec.into()))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareConfig {
    pub appliance_endpoint: String,
    /// mTLS identity. Production: `tls_identity_ref` (Keychain). Dev/file
    /// mode: PEM paths (the daemon reads them itself). One of the two is set.
    pub tls_identity_ref: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    /// CA certificate(s) that sign the receiver's server certificate (PEM; public, not a secret).
    #[serde(with = "pem_text")]
    pub ca_pem: Vec<u8>,
    pub share_name: String,
    /// SMB listener port of the share; 0 = daemon default.
    pub mount_port: u32,
    pub smb_user: String,
    pub smb_password_ref: String,
    /// Ceiling → the "volume size" for backupd (TM thinning decisions).
    pub quota_bytes: u64,
    pub flush_policy: FlushPolicy,
    pub advertise_bonjour: bool,
    /// The share's client profile (TM / Windows / POSIX) sets case semantics,
    /// AAPL, POSIX-ext and so on. See profile::ClientProfile.
    pub profile: crate::profile::ClientProfile,
    pub journal: JournalConfig,
    pub smb_wait: SmbWaitConfig,
}

mod pem_text {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&String::from_utf8_lossy(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Ok(String::deserialize(d)?.into_bytes())
    }
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    share: ShareConfig,
}

fn invalid(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

impl ShareConfig {
    /// Semantic validation shared by `apply` and `load`.
    pub fn validate(&self) -> std::io::Result<()> {
        if self.appliance_endpoint.trim().is_empty() {
            return Err(invalid("appliance_endpoint is required"));
        }
        if self.flush_policy == FlushPolicy::LocalJournal && !self.journal.enabled {
            return Err(invalid("flush policy LOCAL_JOURNAL needs the journal"));
        }
        if self.client_cert_path.is_empty() != self.client_key_path.is_empty() {
            return Err(invalid(
                "client_cert_path and client_key_path must be set together",
            ));
        }
        if self.mount_port > u16::MAX as u32 {
            return Err(invalid("mount_port out of range"));
        }
        Ok(())
    }
}

/// Config store. `Configure` is the only writer; hot-path readers
/// get an Arc without waiting for a write (TODO: replace RwLock with arc-swap).
#[derive(Debug, Default)]
pub struct ConfigStore {
    current: RwLock<Arc<ShareConfig>>,
    /// Where `apply` persists; `None` = in-memory only.
    path: Option<PathBuf>,
    /// Whether any configuration was ever loaded/applied.
    configured: std::sync::atomic::AtomicBool,
    /// Serializes writers (tmp file + rename).
    write_lock: Mutex<()>,
}

impl ConfigStore {
    /// In-memory store (tests, dev).
    pub fn in_memory() -> ConfigStore {
        ConfigStore::default()
    }

    /// Load the persistent file at startup. A missing file is NOT an error
    /// (first start before the agent): the daemon lives without a share and waits for Configure.
    pub fn load(path: &Path) -> std::io::Result<ConfigStore> {
        let store = ConfigStore {
            path: Some(path.to_path_buf()),
            ..Default::default()
        };
        match std::fs::read(path) {
            Ok(bytes) => {
                let f: FileFormat = serde_json::from_slice(&bytes)
                    .map_err(|e| invalid(format!("{}: {e}", path.display())))?;
                if f.version > FORMAT_VERSION {
                    return Err(invalid(format!(
                        "{}: unsupported config version {}",
                        path.display(),
                        f.version
                    )));
                }
                f.share.validate()?;
                *store.current.write().expect("config lock poisoned") = Arc::new(f.share);
                store
                    .configured
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(store)
    }

    /// Validation → atomic persist (tmp+rename, 0600) → publication.
    pub fn apply(&self, new: ShareConfig) -> std::io::Result<()> {
        new.validate()?;
        let _w = self.write_lock.lock().expect("config write lock poisoned");
        if let Some(path) = &self.path {
            let body = serde_json::to_vec_pretty(&FileFormat {
                version: FORMAT_VERSION,
                share: new.clone(),
            })
            .map_err(std::io::Error::other)?;
            write_atomic(path, &body)?;
        }
        *self.current.write().expect("config lock poisoned") = Arc::new(new);
        self.configured
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub fn current(&self) -> Arc<ShareConfig> {
        self.current.read().expect("config lock poisoned").clone()
    }

    /// `true` once a configuration was loaded from disk or applied.
    pub fn is_configured(&self) -> bool {
        self.configured.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// tmp file in the same directory → fsync → rename → fsync of the directory (unix).
fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(d) = dir {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    #[cfg(unix)]
    if let Some(d) = dir {
        // Make the rename durable; failure here does not undo it.
        let _ = std::fs::File::open(d).and_then(|d| d.sync_all());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("janus-cfg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> ShareConfig {
        ShareConfig {
            appliance_endpoint: "vault:7443".into(),
            client_cert_path: "/c.pem".into(),
            client_key_path: "/k.pem".into(),
            ca_pem: b"-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n".to_vec(),
            share_name: "tm".into(),
            mount_port: 4445,
            smb_user: "u".into(),
            smb_password_ref: "keychain:x".into(),
            quota_bytes: 123,
            flush_policy: FlushPolicy::SyncThrough,
            advertise_bonjour: true,
            profile: crate::profile::ClientProfile::WindowsGeneric,
            ..Default::default()
        }
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let d = tmpdir("missing");
        let s = ConfigStore::load(&d.join("config")).unwrap();
        assert!(!s.is_configured());
        assert!(s.current().appliance_endpoint.is_empty());
    }

    #[test]
    fn apply_persists_and_load_restores_everything() {
        let d = tmpdir("roundtrip");
        let path = d.join("sub/config");
        let s = ConfigStore::load(&path).unwrap();
        s.apply(sample()).unwrap();
        assert!(s.is_configured());

        let r = ConfigStore::load(&path).unwrap();
        assert!(r.is_configured());
        let (a, b) = (s.current(), r.current());
        assert_eq!(a.appliance_endpoint, b.appliance_endpoint);
        assert_eq!(b.ca_pem, sample().ca_pem);
        assert_eq!(b.mount_port, 4445);
        assert_eq!(b.quota_bytes, 123);
        assert_eq!(b.flush_policy, FlushPolicy::SyncThrough);
        assert_eq!(b.profile, crate::profile::ClientProfile::WindowsGeneric);
        assert_eq!(b.smb_password_ref, "keychain:x");
        // no leftovers of the tmp file
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[cfg(unix)]
    #[test]
    fn file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        let path = d.join("config");
        ConfigStore::load(&path).unwrap().apply(sample()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn invalid_config_is_rejected_and_not_published() {
        let d = tmpdir("invalid");
        let path = d.join("config");
        let s = ConfigStore::load(&path).unwrap();
        s.apply(sample()).unwrap();

        let mut bad = sample();
        bad.appliance_endpoint.clear();
        assert!(s.apply(bad).is_err());
        let mut bad = sample();
        bad.flush_policy = FlushPolicy::LocalJournal;
        bad.journal.enabled = false;
        let e = s.apply(bad).unwrap_err();
        assert!(e.to_string().contains("needs the journal"));
        let mut bad = sample();
        bad.client_key_path.clear();
        assert!(s.apply(bad).is_err());

        // old config intact in memory and on disk
        assert_eq!(s.current().share_name, "tm");
        assert_eq!(ConfigStore::load(&path).unwrap().current().share_name, "tm");
    }

    #[test]
    fn corrupt_file_is_an_error_not_silently_empty() {
        let d = tmpdir("corrupt");
        let path = d.join("config");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(ConfigStore::load(&path).is_err());
    }

    #[test]
    fn unknown_fields_ignored_and_newer_version_refused() {
        let d = tmpdir("compat");
        let path = d.join("config");
        std::fs::write(
            &path,
            br#"{"version":1,"future":1,"share":{"appliance_endpoint":"h:1","extra":2}}"#,
        )
        .unwrap();
        assert_eq!(
            ConfigStore::load(&path)
                .unwrap()
                .current()
                .appliance_endpoint,
            "h:1"
        );
        std::fs::write(&path, br#"{"version":99,"share":{}}"#).unwrap();
        assert!(ConfigStore::load(&path).is_err());
    }

    #[test]
    fn journal_settings_default_on_roundtrip_and_old_files_load() {
        let d = tmpdir("journal");
        let path = d.join("config");
        // a file written before J3b has no journal section: the journal is on
        std::fs::write(
            &path,
            br#"{"version":1,"share":{"appliance_endpoint":"h:1"}}"#,
        )
        .unwrap();
        let c = ConfigStore::load(&path).unwrap().current();
        assert!(c.journal.enabled);
        assert_eq!(c.journal.max_backlog(), DEFAULT_MAX_BACKLOG);

        let mut cfg = sample();
        cfg.journal = JournalConfig {
            enabled: false,
            dir: "/x/j".into(),
            max_backlog_bytes: 5,
        };
        let s = ConfigStore::load(&path).unwrap();
        s.apply(cfg.clone()).unwrap();
        let back = ConfigStore::load(&path).unwrap().current();
        assert_eq!(back.journal, cfg.journal);
        assert_eq!(back.journal.resolve_dir().unwrap(), PathBuf::from("/x/j"));
        assert_eq!(back.journal.max_backlog(), 5);
    }

    #[test]
    fn secret_values_are_not_a_field() {
        // The persisted file contains only references/paths.
        let d = tmpdir("nosecret");
        let path = d.join("config");
        ConfigStore::load(&path).unwrap().apply(sample()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("smb_password_ref"));
        assert!(!text.contains("PRIVATE KEY"));
    }
}
