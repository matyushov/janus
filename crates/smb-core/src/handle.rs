//! Open handle and durable semantics: the heart of the Apple requirements.
//! State machine: Opening → Active ⇄ Parked → Expired | Closed (internals §2.3).

use std::time::{Duration, Instant};

use janus_lib::vfs::BackendHandle;

use crate::lease::LeaseKey;
use crate::server::ConnId;

/// SMB2 FileId (16 bytes): issued by us, the server owns the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub [u8; 16]);

#[derive(Debug)]
pub struct OpenHandle {
    pub file_id: FileId,
    pub rel_path: String,
    pub backend_file: BackendHandle,
    pub lease: Option<LeaseKey>,
    pub durable: Option<DurableConfig>,
    pub state: HandleState,
}

/// Durable V2 parameters. Timeout is the server's ANSWER: TM validation sends 0
/// (discovering the default), then 30 s, and compares it with our answer.
#[derive(Debug, Clone)]
pub struct DurableConfig {
    pub create_guid: [u8; 16],
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum HandleState {
    /// Owned by a live connection.
    Active(ConnId),
    /// The connection died; waiting for RECONNECT_V2 until the deadline.
    Parked {
        expires_at: Instant,
    },
    Closing,
}
