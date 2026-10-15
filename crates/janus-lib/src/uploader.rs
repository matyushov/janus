//! Uploader: asynchronous delivery WAL → janus-receiverd (gRPC).
//!
//! Outside the barriers it does not affect SMB reply latency. The only
//! synchronization points:
//! - `flush_barrier(file)` is an honest F_FULLFSYNC under SYNC_THROUGH;
//! - `drain_barrier()` is the Drain command: a guarantee that "everything reached the appliance"
//!   before the point is fixed on the receiving side (a backend snapshot is outside janus).

use crate::journal::{PathId, Seq};

/// A handle for GrpcBackend/ControlService (the task itself lives in tokio, TODO).
#[derive(Debug, Clone)]
pub struct UploaderHandle;

impl UploaderHandle {
    /// Wait for the acks of all dirty ranges of the file + Fsync(file) on the receiver.
    pub async fn flush_barrier(&self, _file: PathId) -> Result<(), UploadError> {
        todo!("барьер per-file")
    }

    /// The same for the whole bundle + Fsync(all_bundle). Drain stands on this.
    pub async fn drain_barrier(&self) -> Result<(), UploadError> {
        todo!("барьер bundle")
    }

    pub fn backlog_bytes(&self) -> u64 {
        todo!("для Status")
    }
}

#[derive(Debug)]
pub enum UploadError {
    RemoteUnavailable,
    Timeout,
}

/// Batch scheduler: reads dirty ranges from the checkpoint, coalesces
/// adjacent ones, cuts at ≤ 1 MiB (the WriteRange limit).
#[derive(Debug, Default)]
pub struct BatchPlanner;

/// Parallelism window (a semaphore of N in-flight WriteRange; start with 4).
/// Order between non-overlapping ranges does not matter (later-wins in the WAL).
#[derive(Debug, Default)]
pub struct InflightWindow;

/// Retries: exponential backoff + jitter. WriteRange is idempotent → a repeat is safe.
/// RemoteUnavailable → pause, the WAL accumulates (up to the limit → Busy upward).
#[derive(Debug, Default)]
pub struct RetryPolicy;

/// Watermark of acknowledged seq: journal.mark_uploaded(W) + backlog metrics.
#[derive(Debug, Default)]
pub struct AckTracker {
    pub watermark: Option<Seq>,
}
