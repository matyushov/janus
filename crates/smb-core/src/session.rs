//! Sessions and tree connect (states follow the README model: Authenticating → Active).
//!
//! MILESTONE 1 (J1): sessions live in `ConnState` (per connection). UPGRADE: move to
//! `ServerShared` (shared table, multichannel/binding, surviving the connection).

use std::collections::HashMap;
use std::time::Instant;

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
    /// Open objects keyed by the volatile part of the FileId. Only the share root for now.
    pub opens: HashMap<u64, OpenRoot>,
    next_tree_id: u32,
    next_file_id: u64,
}

/// The open share root directory (virtual and empty until there is a file model, J2).
pub struct OpenRoot {
    pub tree_id: u32,
    /// The (empty) listing has already been returned; afterwards `STATUS_NO_MORE_FILES`.
    pub enumerated: bool,
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
    /// Open the share root on tree `tree_id`; FileId = (persistent, volatile) with the same number.
    pub fn open_root(&mut self, tree_id: u32) -> [u8; 16] {
        let id = self.next_file_id;
        self.next_file_id += 1;
        self.opens.insert(
            id,
            OpenRoot {
                tree_id,
                enumerated: false,
            },
        );
        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&id.to_le_bytes());
        file_id[8..].copy_from_slice(&id.to_le_bytes());
        file_id
    }

    /// Find an open object by FileId on the given tree.
    pub fn open_mut(&mut self, file_id: &[u8; 16], tree_id: u32) -> Option<&mut OpenRoot> {
        let persistent = u64::from_le_bytes(file_id[..8].try_into().expect("8 байт"));
        let volatile = u64::from_le_bytes(file_id[8..].try_into().expect("8 байт"));
        if persistent != volatile {
            return None;
        }
        self.opens
            .get_mut(&volatile)
            .filter(|o| o.tree_id == tree_id)
    }

    pub fn close(&mut self, file_id: &[u8; 16], tree_id: u32) -> bool {
        if self.open_mut(file_id, tree_id).is_none() {
            return false;
        }
        let volatile = u64::from_le_bytes(file_id[8..].try_into().expect("8 байт"));
        self.opens.remove(&volatile).is_some()
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
