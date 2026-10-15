//! Sessions and tree connect (states follow the README model: Authenticating → Active).
//!
//! MILESTONE 1 (J1): sessions live in `ConnState` (per connection). UPGRADE: move to
//! `ServerShared` (shared table, multichannel/binding, surviving the connection).

use std::collections::HashMap;
use std::time::Instant;

use janus_lib::vfs::BackendHandle;
use smb_wire::fileinfo::DirEntry;
use smb_wire::ntlm::NtlmServer;

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

pub struct Session {
    pub session_id: u64,
    pub state: SessionState,
    pub trees: HashMap<u32, TreeConnect>,
    /// Open objects keyed by the volatile part of the FileId.
    pub opens: HashMap<u64, Open>,
    next_tree_id: u32,
    next_file_id: u64,
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
        self.opens.remove(&key)
    }

    /// Remove all opens of a tree (TREE_DISCONNECT).
    pub fn take_tree_opens(&mut self, tree_id: u32) -> Vec<Open> {
        let keys: Vec<u64> = self
            .opens
            .iter()
            .filter(|(_, o)| o.tree_id == tree_id)
            .map(|(k, _)| *k)
            .collect();
        keys.into_iter()
            .filter_map(|k| self.opens.remove(&k))
            .collect()
    }

    /// Remove every open (LOGOFF, connection drop).
    pub fn take_all_opens(&mut self) -> Vec<Open> {
        self.opens.drain().map(|(_, o)| o).collect()
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
