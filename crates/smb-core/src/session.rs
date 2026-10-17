//! Sessions and tree connect (states follow the README model: Authenticating → Active).
//!
//! MILESTONE 1 (J1): sessions live in `ConnState` (per connection). UPGRADE: move to
//! `ServerShared` (shared table, multichannel/binding, surviving the connection).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use janus_lib::journal::ParkedRecord;
use janus_lib::vfs::{BackendError, BackendHandle};
use smb_wire::fileinfo::DirEntry;
use smb_wire::ntlm::NtlmServer;

use crate::shared::Shared;

/// Unfinished authentication (between the first SESSION_SETUP and AUTHENTICATE).
pub struct PendingAuth {
    /// NTLM exchange; `None` until the client has sent NEGOTIATE_MESSAGE
    /// (for example, it first offered another SPNEGO mechanism).
    pub ntlm: Option<NtlmServer>,
    /// Session.PreauthIntegrityHashValue: starts from the connection hash after NEGOTIATE.
    pub preauth_hash: [u8; 64],
    pub started: Instant,
}

pub enum SessionState {
    /// NTLM exchange in progress: no signature yet.
    Authenticating(Box<PendingAuth>),
    /// Exchange complete, signing key derived, signing ON.
    Active { user: String, signing_key: [u8; 16] },
}

/// An open made durable by DH2Q: it survives a dropped connection for `timeout`.
#[derive(Debug, Clone, Copy)]
pub struct DurableInfo {
    pub create_guid: [u8; 16],
    pub timeout: Duration,
}

pub struct Session {
    pub session_id: u64,
    pub state: SessionState,
    pub trees: HashMap<u32, TreeConnect>,
    /// Open objects keyed by the volatile part of the FileId.
    pub opens: HashMap<u64, Open>,
    next_tree_id: u32,
    next_file_id: u64,
    /// Where leases are released when an open goes away.
    shared: Option<Arc<Shared>>,
}

/// An open file or directory (the SMB side of a backend handle).
pub struct Open {
    pub tree_id: u32,
    /// Path relative to the share root, `/`-separated (empty for the root).
    pub rel_path: String,
    pub handle: BackendHandle,
    pub directory: bool,
    /// Granted access with generic bits expanded.
    pub access: u32,
    /// Delete-on-close is set (CREATE option or FileDispositionInformation).
    pub delete_pending: bool,
    /// Directory enumeration state (QUERY_DIRECTORY).
    pub scan: Option<DirScan>,
    /// Sequential-read prefetch state.
    pub readahead: Readahead,
    /// The lease key this open uses (its lease is released with the open).
    pub lease: Option<[u8; 16]>,
    pub durable: Option<DurableInfo>,
}

/// A read started ahead of the client asking for it.
pub struct Prefetch {
    pub offset: u64,
    pub length: u32,
    /// `ConnState::io_epoch` when it was started; any later write makes it stale.
    pub epoch: u64,
    /// `None` once the task has been handed to the READ that consumes it.
    pub task: Option<tokio::task::JoinHandle<Result<Vec<u8>, BackendError>>>,
}

impl Drop for Prefetch {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

/// Per-open readahead: prefetched ranges in offset order, and where the last read ended
/// (the next read is "sequential" when it starts there).
#[derive(Default)]
pub struct Readahead {
    pub queue: VecDeque<Prefetch>,
    pub next_offset: u64,
}

/// A directory listing snapshotted when the enumeration starts: the client sees a stable
/// view even while files are created, and the backend is asked once per scan.
pub struct DirScan {
    pub entries: Vec<DirEntry>,
    pub pos: usize,
    /// At least one entry has been returned in this scan (decides NO_SUCH_FILE vs NO_MORE_FILES).
    pub returned: bool,
}

impl Session {
    pub fn new(session_id: u64, state: SessionState) -> Self {
        Session {
            session_id,
            state,
            trees: HashMap::new(),
            opens: HashMap::new(),
            next_tree_id: 1,
            next_file_id: 1,
            shared: None,
        }
    }

    /// Lets the session release the leases of the opens it loses.
    pub fn with_shared(mut self, shared: Arc<Shared>) -> Self {
        self.shared = Some(shared);
        self
    }

    /// The authenticated user, once the session is active.
    pub fn user(&self) -> Option<&str> {
        match &self.state {
            SessionState::Active { user, .. } => Some(user),
            SessionState::Authenticating(_) => None,
        }
    }

    /// An open is going away for good: its lease and its durable record go with it.
    fn release_lease(&self, open: &Open) {
        let Some(shared) = &self.shared else { return };
        if let Some(key) = &open.lease {
            shared.release_lease(key);
        }
        if let Some(d) = &open.durable {
            shared.forget_durable(&d.create_guid);
        }
    }

    /// Signing key of an active session.
    pub fn signing_key(&self) -> Option<[u8; 16]> {
        match &self.state {
            SessionState::Active { signing_key, .. } => Some(*signing_key),
            SessionState::Authenticating(_) => None,
        }
    }

    pub fn add_tree(&mut self, share: &str) -> u32 {
        let tree_id = self.next_tree_id;
        self.next_tree_id += 1;
        self.trees.insert(
            tree_id,
            TreeConnect {
                tree_id,
                share: share.to_owned(),
                aapl_negotiated: false,
            },
        );
        tree_id
    }
}

impl Session {
    /// Register an open; FileId = (persistent, volatile) with the same number.
    pub fn add_open(&mut self, open: Open) -> [u8; 16] {
        let id = self.next_file_id;
        self.next_file_id += 1;
        self.opens.insert(id, open);
        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&id.to_le_bytes());
        file_id[8..].copy_from_slice(&id.to_le_bytes());
        file_id
    }

    fn open_key(file_id: &[u8; 16]) -> Option<u64> {
        let persistent = u64::from_le_bytes(file_id[..8].try_into().expect("8 bytes"));
        let volatile = u64::from_le_bytes(file_id[8..].try_into().expect("8 bytes"));
        (persistent == volatile).then_some(volatile)
    }

    /// Find an open object by FileId on the given tree.
    pub fn open_mut(&mut self, file_id: &[u8; 16], tree_id: u32) -> Option<&mut Open> {
        let key = Self::open_key(file_id)?;
        self.opens.get_mut(&key).filter(|o| o.tree_id == tree_id)
    }

    /// Remove an open from the table (the caller closes the backend handle).
    pub fn take_open(&mut self, file_id: &[u8; 16], tree_id: u32) -> Option<Open> {
        let key = Self::open_key(file_id)?;
        if self.opens.get(&key)?.tree_id != tree_id {
            return None;
        }
        let open = self.opens.remove(&key)?;
        self.release_lease(&open);
        Some(open)
    }

    /// Remove all opens of a tree (TREE_DISCONNECT).
    pub fn take_tree_opens(&mut self, tree_id: u32) -> Vec<Open> {
        let keys: Vec<u64> = self
            .opens
            .iter()
            .filter(|(_, o)| o.tree_id == tree_id)
            .map(|(k, _)| *k)
            .collect();
        let opens: Vec<Open> = keys
            .into_iter()
            .filter_map(|k| self.opens.remove(&k))
            .collect();
        opens.iter().for_each(|o| self.release_lease(o));
        opens
    }

    /// Remove every open (LOGOFF, connection drop).
    pub fn take_all_opens(&mut self) -> Vec<Open> {
        let opens: Vec<Open> = self.opens.drain().map(|(_, o)| o).collect();
        opens.iter().for_each(|o| self.release_lease(o));
        opens
    }

    /// The connection dropped: durable files are handed back for parking (their leases stay),
    /// every other open is returned to be closed.
    pub fn drain_for_drop(
        &mut self,
        client_guid: [u8; 16],
    ) -> (Vec<(ParkedRecord, BackendHandle, Duration)>, Vec<Open>) {
        let owner = self.user().unwrap_or_default().to_owned();
        let ids: Vec<u64> = self.opens.keys().copied().collect();
        let (mut parked, mut closed) = (Vec::new(), Vec::new());
        for id in ids {
            let Some(open) = self.opens.remove(&id) else {
                continue;
            };
            match open.durable {
                Some(d) if !open.directory => {
                    let mut file_id = [0u8; 16];
                    file_id[..8].copy_from_slice(&id.to_le_bytes());
                    file_id[8..].copy_from_slice(&id.to_le_bytes());
                    parked.push((
                        ParkedRecord {
                            create_guid: d.create_guid,
                            file_id,
                            client_guid,
                            owner: owner.clone(),
                            rel_path: open.rel_path,
                            access: open.access,
                            delete_pending: open.delete_pending,
                            lease_key: open.lease,
                            lease_state: 0,
                            timeout_ms: d.timeout.as_millis() as u32,
                            expires_unix_ms: 0,
                        },
                        open.handle,
                        d.timeout,
                    ));
                }
                _ => {
                    self.release_lease(&open);
                    closed.push(open);
                }
            }
        }
        (parked, closed)
    }
}

pub struct TreeConnect {
    pub tree_id: u32,
    pub share: String,
    /// AAPL is negotiated on the FIRST tree connect, globally for the server.
    pub aapl_negotiated: bool,
}

/// Debug without key material or NTLM state.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.state {
            SessionState::Authenticating(_) => "Authenticating",
            SessionState::Active { .. } => "Active",
        };
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("state", &state)
            .field("trees", &self.trees.len())
            .field("opens", &self.opens.len())
            .finish()
    }
}
