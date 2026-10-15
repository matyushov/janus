//! ServerShared: everything that outlives a connection: sessions, handles, leases,
//! durable parking, backend, events. The connection actor holds only the link.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use janus_lib::config::ShareConfig;
use janus_lib::observability::{EventBus, Metrics};
use janus_lib::vfs::StorageBackend;

use crate::handle::{FileId, OpenHandle};
use crate::lease::{Lease, LeaseKey};
use crate::session::Session;

/// NB: generic rather than Arc<dyn StorageBackend>: async fn in a trait is not
/// dyn-compatible; we will wrap it later if needed (boxed futures).
pub struct ServerShared<B: StorageBackend> {
    pub sessions: Mutex<HashMap<u64, Session>>,
    pub opens: OpenTable,
    pub leases: LeaseTable,
    pub parked: DurableParkRegistry,
    pub backend: Arc<B>,
    pub metrics: Arc<Metrics>,
    pub events: Arc<EventBus>,
    pub config: Arc<ShareConfig>, // TODO: a live reference to ConfigStore
}

/// Table of open handles. A connection's death does NOT remove a handle;
/// it moves Active(conn) → Parked(expires_at).
#[derive(Default)]
pub struct OpenTable {
    by_id: Mutex<HashMap<FileId, OpenHandle>>,
}

impl OpenTable {
    pub fn park_all_for_conn(&self, _conn: crate::server::ConnId) {
        todo!("Active(conn) → Parked + таймер DurableConfig.timeout")
    }

    pub fn reconnect(
        &self,
        _create_guid: [u8; 16],
        _new_conn: crate::server::ConnId,
    ) -> Option<FileId> {
        todo!("DURABLE_HANDLE_RECONNECT_V2: Parked → Active(new_conn), тот же FileId")
    }
}

#[derive(Default)]
pub struct LeaseTable {
    by_key: Mutex<HashMap<LeaseKey, Lease>>,
}

impl LeaseTable {
    /// Server-initiated break: puts LeaseBreakNotify into the owning
    /// connection's write queue and arms the ack timer.
    pub fn request_break(&self, _key: LeaseKey) {
        todo!("Granted → BreakPending; таймаут ack → принудительный даунгрейд")
    }
}

/// Parked durable handles waiting for RECONNECT_V2 (persisted next to the WAL:
/// janus_lib::journal::ParkedHandleStore, to survive a daemon restart).
#[derive(Default)]
pub struct DurableParkRegistry;
