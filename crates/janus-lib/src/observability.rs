//! Metrics (atomics, lock-free reads from Status), the event bus, diagnostics.
//! Layers 1–2 write here directly (injected at assembly) and know nothing about control.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64};

/// All counters are atomics: Status never slows down the hot path (§8.4).
#[derive(Debug, Default)]
pub struct Metrics {
    pub smb_sessions: AtomicU32,
    pub open_handles: AtomicU32,
    pub durable_handles_parked: AtomicU32,
    pub journal_backlog_bytes: AtomicU64,
    pub uploaded_bytes_total: AtomicU64,
    pub upload_errors: AtomicU32,
    pub last_appliance_ack_unix_ms: AtomicI64,
}

/// SMB operations that were answered with an interim STATUS_PENDING and are still waiting for
/// the backend, across all connections. The SMB layer writes, `status` reads.
#[derive(Debug, Default)]
pub struct PendingOps {
    next: std::sync::atomic::AtomicU64,
    since: std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>,
}

impl PendingOps {
    /// An operation went asynchronous (`started` is when the request was taken). The token ends it.
    pub fn begin(&self, started: std::time::Instant) -> u64 {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.since
            .lock()
            .expect("pending ops poisoned")
            .insert(id, started);
        id
    }

    pub fn end(&self, token: u64) {
        self.since
            .lock()
            .expect("pending ops poisoned")
            .remove(&token);
    }

    /// (number of operations, age of the oldest).
    pub fn snapshot(&self) -> (usize, Option<std::time::Duration>) {
        let m = self.since.lock().expect("pending ops poisoned");
        (m.len(), m.values().map(|t| t.elapsed()).max())
    }
}

/// Events for the agent's WatchEvents stream and the diagnostics ring.
#[derive(Debug, Clone)]
pub enum Event {
    SessionUp(String),
    SessionDown(String),
    ValidationPassed,
    ValidationFailed(String),
    UploadError(String),
    /// The WAL is approaching its limit; backpressure is coming soon.
    JournalHighWater(u64),
}

/// TODO: tokio::sync::broadcast; for now a stub of the interface.
#[derive(Debug, Default)]
pub struct EventBus;

impl EventBus {
    pub fn emit(&self, _e: Event) {
        todo!("broadcast to subscribers + DiagRing")
    }
}

/// A ring buffer of the latest events/errors for GetDiagnostics.
#[derive(Debug, Default)]
pub struct DiagRing {
    ring: VecDeque<(i64, Event)>,
}

/// Assembling a diagnostics bundle: the ring + a log tail + a metrics snapshot.
/// Secrets do not get into the bundle by design (password values are never logged anywhere).
pub struct DiagnosticsCollector;
