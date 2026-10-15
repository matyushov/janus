//! Configuration: a persistent file + a push from the agent (`Configure`).
//! The agent is the source of truth; the file exists so that socket activation does not depend
//! on a live agent. Secrets are references only (Keychain), not values.

use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlushPolicy {
    #[default]
    Unspecified,
    /// F_FULLFSYNC waits for the remote Fsync on the appliance (an honest end-to-end).
    SyncThrough,
    /// F_FULLFSYNC = fsync of the WAL on the Mac; the network catches up.
    LocalJournal,
}

#[derive(Debug, Clone, Default)]
pub struct ShareConfig {
    pub appliance_endpoint: String,
    /// mTLS identity. Production: `tls_identity_ref` (Keychain). Dev/file
    /// mode: PEM paths (the daemon reads them itself). One of the two is set.
    pub tls_identity_ref: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub share_name: String,
    pub smb_user: String,
    pub smb_password_ref: String,
    /// Ceiling → the "volume size" for backupd (TM thinning decisions).
    pub quota_bytes: u64,
    pub flush_policy: FlushPolicy,
    pub advertise_bonjour: bool,
    /// The share's client profile (TM / Windows / POSIX) sets case semantics,
    /// AAPL, POSIX-ext and so on. See profile::ClientProfile.
    pub profile: crate::profile::ClientProfile,
}

/// Config store. `Configure` is the only writer; hot-path readers
/// get an Arc without waiting for a write (TODO: replace RwLock with arc-swap).
#[derive(Debug, Default)]
pub struct ConfigStore {
    current: RwLock<Arc<ShareConfig>>,
}

impl ConfigStore {
    /// Load the persistent file at startup. A missing file is NOT an error
    /// (first start before the agent): the daemon lives without a share and waits for Configure.
    pub fn load(_path: &std::path::Path) -> std::io::Result<ConfigStore> {
        todo!("чтение + валидация")
    }

    /// Validation → atomic persist (tmp+rename, 0600) → publication.
    pub fn apply(&self, _new: ShareConfig) -> std::io::Result<()> {
        todo!("persist + swap; перестройка зависимых — у вызывающего (control)")
    }

    pub fn current(&self) -> Arc<ShareConfig> {
        self.current.read().expect("config lock poisoned").clone()
    }
}
