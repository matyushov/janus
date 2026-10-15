//! `GrpcBackend`: the production `StorageBackend`, J3a flavour = **sync-through**.
//!
//! Every operation goes to `janus-receiverd` immediately (no local journal, no read overlay),
//! so the latency of an SMB reply equals the RTT to the receiver; `flush` is an honest
//! end-to-end `Fsync`. The journal-backed mode arrives in J3b.
//!
//! Handles live on the client: `BackendHandle → (current rel path, kind, flags)`. The server
//! never sees them, every RPC carries a path, which keeps all writes idempotent (by offset).
//! `LocalFsBackend` is the behavioural reference; `tests/backend_contract.rs` runs one
//! set of assertions against both.
//!
//! Retries: only calls that are idempotent by construction (reads, stat, list, `WriteRange`,
//! `Fsync`, truncate, set-times) are retried, and only on `UNAVAILABLE`. Exclusive create,
//! rename and delete are NOT retried: a lost reply would turn success into a spurious
//! `AlreadyExists`/`NotFound`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use janus_proto::v1 as pb;
use janus_proto::v1::band_transport_client::BandTransportClient;
use pb::{bundle_op_reply, bundle_op_request, fsync_request};
use tonic::transport::Channel;
use tonic::{Code, Status};

use crate::remote::{RemoteClient, Timeouts, is_transport_failure};
use crate::vfs::{
    BackendError, BackendHandle, Disposition, FileStat, FsStats, Kind, OpenRequest, Opened, Result,
    SetTimes, StorageBackend,
};

/// Contract limit of one `WriteRange`/`ReadRange` payload.
pub const MAX_CHUNK: usize = 1 << 20;
/// Volume size reported when neither the receiver nor the configuration gives a quota (1 TiB).
const DEFAULT_QUOTA: u64 = 1 << 40;

/// Retry policy for idempotent calls.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts (1 = no retry).
    pub attempts: u32,
    /// Delay before the second attempt; doubles each time.
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            attempts: 3,
            base_delay: Duration::from_millis(150),
        }
    }
}

struct HandleEntry {
    /// Current path (updated by `rename`).
    path: Mutex<String>,
    directory: bool,
    writable: bool,
    delete_on_close: AtomicBool,
}

impl HandleEntry {
    fn path(&self) -> String {
        self.path.lock().expect("path poisoned").clone()
    }
}

pub struct GrpcBackend {
    client: BandTransportClient<Channel>,
    retry: RetryPolicy,
    timeouts: Timeouts,
    /// When a call last timed out (a silent peer); cleared by the next success. Errors the receiver
    /// or the network report promptly (refused connection, `UNAVAILABLE`) do not set it.
    degraded: Mutex<Option<Instant>>,
    /// Used when the receiver reports "no quota" (0).
    fallback_quota: u64,
    next_handle: AtomicU64,
    next_write_id: AtomicU64,
    handles: Mutex<HashMap<u64, Arc<HandleEntry>>>,
}

impl GrpcBackend {
    pub fn new(client: BandTransportClient<Channel>, fallback_quota: u64) -> GrpcBackend {
        GrpcBackend {
            client,
            retry: RetryPolicy::default(),
            timeouts: Timeouts::default(),
            degraded: Mutex::new(None),
            fallback_quota: if fallback_quota == 0 {
                DEFAULT_QUOTA
            } else {
                fallback_quota
            },
            next_handle: AtomicU64::new(1),
            next_write_id: AtomicU64::new(1),
            handles: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_remote(remote: &RemoteClient, fallback_quota: u64) -> GrpcBackend {
        GrpcBackend::new(remote.transport(), fallback_quota).with_timeouts(remote.timeouts())
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    fn mark_degraded(&self) {
        *self.degraded.lock().expect("degraded poisoned") = Some(Instant::now());
    }

    /// Bound a whole backend operation (possibly several RPCs) by the time budget.
    async fn within<T>(&self, op: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.timeouts.budget, op)
            .await
            .unwrap_or(Err(BackendError::RemoteUnavailable))
    }

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    // ---- RPC plumbing -------------------------------------------------------------

    /// One RPC with retries under a shared deadline: every attempt is limited by `request`
    /// (or `bulk_request`) and by what is left of the budget, and a retry starts only if
    /// the backoff plus a minimal attempt still fit. A silent peer is a timeout, which counts
    /// as a transport failure (retried only when `idempotent`).
    async fn rpc<T, F, Fut>(&self, idempotent: bool, bulk: bool, call: F) -> Result<T>
    where
        F: Fn(BandTransportClient<Channel>) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, Status>>,
    {
        /// A retry with less than this left is pointless.
        const MIN_ATTEMPT: Duration = Duration::from_millis(500);
        let last_failure = *self.degraded.lock().expect("degraded poisoned");
        if last_failure.is_some_and(|t| t.elapsed() < self.timeouts.fail_fast) {
            return Err(BackendError::RemoteUnavailable);
        }
        let degraded = last_failure.is_some();
        let attempts = if idempotent && !degraded {
            self.retry.attempts.max(1)
        } else {
            1
        };
        let mut per_attempt = if bulk {
            self.timeouts.bulk_request
        } else {
            self.timeouts.request
        };
        if degraded {
            per_attempt = per_attempt.min(self.timeouts.degraded_probe);
        }
        let deadline = Instant::now() + self.timeouts.budget;
        let mut delay = self.retry.base_delay;
        let mut attempt = 1;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let outcome = match tokio::time::timeout(
                per_attempt.min(left),
                call(self.client.clone()),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    // A silent peer: later calls must not each wait a full budget.
                    self.mark_degraded();
                    Err(Status::unavailable("transport error: request timed out"))
                }
            };
            match outcome {
                Ok(r) => {
                    *self.degraded.lock().expect("degraded poisoned") = None;
                    return Ok(r.into_inner());
                }
                Err(s) if attempt < attempts && is_transport_failure(&s) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left < delay + MIN_ATTEMPT {
                        return Err(map_status(&s));
                    }
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                    attempt += 1;
                }
                Err(s) => return Err(map_status(&s)),
            }
        }
    }

    async fn bundle(
        &self,
        idempotent: bool,
        op: bundle_op_request::Op,
    ) -> Result<bundle_op_reply::Result> {
        let reply = self
            .rpc(idempotent, false, |mut c| {
                let op = op.clone();
                async move { c.bundle_op(pb::BundleOpRequest { op: Some(op) }).await }
            })
            .await?;
        reply
            .result
            .ok_or_else(|| BackendError::Io(std::io::Error::other("empty BundleOp reply")))
    }

    async fn bundle_ok(&self, idempotent: bool, op: bundle_op_request::Op) -> Result<()> {
        match self.bundle(idempotent, op).await? {
            bundle_op_reply::Result::Ok(_) => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    async fn stat_path(&self, rel: &str) -> Result<FileStat> {
        match self
            .bundle(
                true,
                bundle_op_request::Op::Stat(pb::StatOp {
                    file: file_ref(rel),
                }),
            )
            .await?
        {
            bundle_op_reply::Result::Stat(s) => Ok(stat_from_proto(s)),
            other => Err(unexpected(other)),
        }
    }

    // ---- handle table -------------------------------------------------------------

    fn entry(&self, h: BackendHandle) -> Result<Arc<HandleEntry>> {
        self.handles
            .lock()
            .expect("handle table poisoned")
            .get(&h.0)
            .cloned()
            .ok_or(BackendError::BadHandle)
    }

    fn insert(&self, entry: HandleEntry) -> BackendHandle {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .expect("handle table poisoned")
            .insert(id, Arc::new(entry));
        BackendHandle(id)
    }

    /// Number of open handles (diagnostics/tests).
    pub fn open_handles(&self) -> usize {
        self.handles.lock().expect("handle table poisoned").len()
    }
}

// ---- helpers ------------------------------------------------------------------------

fn file_ref(rel: &str) -> Option<pb::FileRef> {
    Some(pb::FileRef {
        rel_path: rel.to_owned(),
    })
}

fn unexpected(r: bundle_op_reply::Result) -> BackendError {
    BackendError::Io(std::io::Error::other(format!(
        "unexpected BundleOp reply: {r:?}"
    )))
}

/// Same rules as `LocalFsBackend::resolve`, applied before anything reaches the wire:
/// `.`/`..`/NUL/`\` → `AccessDenied`; `:` (alternate data streams) → `NotFound`.
/// Returns the normalized `/`-joined path ("" = root).
fn normalize(rel: &str) -> Result<String> {
    let mut parts = Vec::new();
    for part in rel.split('/').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." || part.contains('\0') || part.contains('\\') {
            return Err(BackendError::AccessDenied);
        }
        if part.contains(':') {
            return Err(BackendError::NotFound);
        }
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn stat_from_proto(s: pb::FileStat) -> FileStat {
    let name = s.rel_path.rsplit('/').next().unwrap_or("").to_owned();
    FileStat {
        name,
        size: if s.directory { 0 } else { s.size },
        directory: s.directory,
        read_only: s.read_only,
        mtime_unix_ns: s.mtime_unix_ns,
        atime_unix_ns: s.atime_unix_ns.unwrap_or(s.mtime_unix_ns),
        ctime_unix_ns: s.ctime_unix_ns.unwrap_or(s.mtime_unix_ns),
        btime_unix_ns: s.btime_unix_ns.unwrap_or(s.mtime_unix_ns),
        file_id: s.file_id,
        rel_path: s.rel_path,
    }
}

/// gRPC status → `BackendError`. The `janus-error` trailer refines the code; unknown or
/// missing classes fall back to the plain code. A transport failure is `RemoteUnavailable`,
/// never `NotFound`.
pub fn map_status(s: &Status) -> BackendError {
    let class = s
        .metadata()
        .get("janus-error")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match class {
        "path-not-found" => return BackendError::PathNotFound,
        "not-a-directory" => return BackendError::NotADirectory,
        "is-a-directory" => return BackendError::IsADirectory,
        "not-empty" => return BackendError::DirectoryNotEmpty,
        _ => {}
    }
    if is_transport_failure(s) {
        return BackendError::RemoteUnavailable;
    }
    match s.code() {
        Code::NotFound => BackendError::NotFound,
        Code::AlreadyExists => BackendError::AlreadyExists,
        Code::PermissionDenied | Code::Unauthenticated => BackendError::AccessDenied,
        Code::ResourceExhausted => BackendError::NoSpace,
        Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled | Code::Aborted => {
            BackendError::RemoteUnavailable
        }
        Code::InvalidArgument | Code::OutOfRange => BackendError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            s.message().to_owned(),
        )),
        _ => BackendError::Io(std::io::Error::other(format!(
            "receiver error {:?}: {}",
            s.code(),
            s.message()
        ))),
    }
}

fn is_under(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

impl GrpcBackend {
    async fn open_inner(&self, rel_path: &str, req: OpenRequest) -> Result<Opened> {
        let rel = normalize(rel_path)?;
        let truncating = matches!(
            req.disposition,
            Disposition::Overwrite | Disposition::OverwriteOrCreate | Disposition::Supersede
        );

        // Two rounds: a concurrent creator can win the race between our stat and our create.
        for round in 0..2 {
            let existing = if rel.is_empty() {
                Some(self.stat_path("").await?)
            } else {
                match self.stat_path(&rel).await {
                    Ok(s) => Some(s),
                    Err(BackendError::NotFound) => None,
                    Err(e) => return Err(e),
                }
            };

            let (stat, created, overwritten) = match existing {
                Some(m) => {
                    if req.disposition == Disposition::Create {
                        return Err(BackendError::AlreadyExists);
                    }
                    match (m.directory, req.kind) {
                        (true, Kind::File) => return Err(BackendError::IsADirectory),
                        (false, Kind::Directory) => return Err(BackendError::NotADirectory),
                        _ => {}
                    }
                    if m.directory && truncating {
                        return Err(BackendError::IsADirectory);
                    }
                    if truncating {
                        self.bundle_ok(
                            true,
                            bundle_op_request::Op::Truncate(pb::TruncateOp {
                                file: file_ref(&rel),
                                new_length: 0,
                            }),
                        )
                        .await?;
                        (self.stat_path(&rel).await?, false, true)
                    } else {
                        (m, false, false)
                    }
                }
                None => {
                    if matches!(req.disposition, Disposition::Open | Disposition::Overwrite) {
                        return Err(BackendError::NotFound);
                    }
                    let directory = req.kind == Kind::Directory;
                    let r = self
                        .bundle_ok(
                            false,
                            bundle_op_request::Op::Create(pb::CreateOp {
                                file: file_ref(&rel),
                                directory,
                                exclusive: true,
                                no_create_parents: true,
                            }),
                        )
                        .await;
                    match r {
                        Ok(()) => {}
                        Err(BackendError::AlreadyExists)
                            if round == 0 && req.disposition != Disposition::Create =>
                        {
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    (self.stat_path(&rel).await?, true, false)
                }
            };

            let handle = self.insert(HandleEntry {
                path: Mutex::new(rel.clone()),
                directory: stat.directory,
                writable: req.write || truncating || created,
                delete_on_close: req.delete_on_close.into(),
            });
            return Ok(Opened {
                handle,
                stat,
                created,
                overwritten,
            });
        }
        Err(BackendError::AlreadyExists)
    }

    async fn read_inner(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let e = self.entry(h)?;
        if e.directory {
            return Err(BackendError::IsADirectory);
        }
        let path = e.path();
        // Never let offset+len pass u64::MAX: such a read is simply short.
        let want = (len as u64).min(u64::MAX - offset) as usize;
        let mut out = Vec::with_capacity(want.min(4 * MAX_CHUNK));
        while out.len() < want {
            let chunk = (want - out.len()).min(MAX_CHUNK);
            let pos = offset + out.len() as u64;
            let reply = self
                .rpc(true, true, |mut c| {
                    let req = pb::ReadRangeRequest {
                        file: file_ref(&path),
                        offset: pos,
                        length: chunk as u32,
                    };
                    async move { c.read_range(req).await }
                })
                .await?;
            let got = reply.data.len();
            out.extend_from_slice(&reply.data);
            if reply.eof || got < chunk {
                break; // short reads happen only at end of file
            }
        }
        Ok(out)
    }

    async fn write_inner(&self, h: BackendHandle, offset: u64, data: &[u8]) -> Result<()> {
        let e = self.entry(h)?;
        if e.directory {
            return Err(BackendError::IsADirectory);
        }
        if !e.writable {
            return Err(BackendError::AccessDenied);
        }
        if data.is_empty() {
            return Ok(());
        }
        if offset.checked_add(data.len() as u64).is_none() {
            return Err(BackendError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "write range exceeds u64",
            )));
        }
        let path = e.path();
        for (i, chunk) in data.chunks(MAX_CHUNK).enumerate() {
            let pos = offset + (i * MAX_CHUNK) as u64;
            let write_id = self.next_write_id.fetch_add(1, Ordering::Relaxed);
            // Repeating a WriteRange is safe (same offset, same bytes).
            self.rpc(true, true, |mut c| {
                let req = pb::WriteRangeRequest {
                    file: file_ref(&path),
                    offset: pos,
                    data: chunk.to_vec(),
                    write_id,
                };
                async move { c.write_range(req).await }
            })
            .await?;
        }
        Ok(())
    }
}

impl StorageBackend for GrpcBackend {
    async fn open(&self, rel_path: &str, req: OpenRequest) -> Result<Opened> {
        self.within(self.open_inner(rel_path, req)).await
    }

    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        let e = self.entry(h)?;
        self.stat_path(&e.path()).await
    }

    async fn read(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        self.within(self.read_inner(h, offset, len)).await
    }

    async fn write(&self, h: BackendHandle, offset: u64, data: &[u8]) -> Result<()> {
        self.within(self.write_inner(h, offset, data)).await
    }

    async fn flush(&self, h: BackendHandle, _fullfsync: bool) -> Result<()> {
        let e = self.entry(h)?;
        if e.directory {
            return Ok(());
        }
        let path = e.path();
        // Sync-through: F_FULLFSYNC and plain flush both wait for the receiver's fsync.
        self.rpc(true, false, |mut c| {
            let req = pb::FsyncRequest {
                scope: Some(fsync_request::Scope::File(pb::FileRef {
                    rel_path: path.clone(),
                })),
            };
            async move { c.fsync(req).await }
        })
        .await?;
        Ok(())
    }

    async fn close(&self, h: BackendHandle) -> Result<()> {
        let e = self
            .handles
            .lock()
            .expect("handle table poisoned")
            .remove(&h.0)
            .ok_or(BackendError::BadHandle)?;
        if e.delete_on_close.load(Ordering::Relaxed) {
            // The handle is gone either way; if the receiver is unreachable the delete is
            // reported as failed and not retried (J3b's journal will own such retries).
            self.bundle_ok(
                false,
                bundle_op_request::Op::Delete(pb::DeleteOp {
                    file: file_ref(&e.path()),
                    non_recursive: true,
                }),
            )
            .await?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        let (src, dst) = (normalize(from)?, normalize(to)?);
        self.bundle_ok(
            false,
            bundle_op_request::Op::Rename(pb::RenameOp {
                from: file_ref(&src),
                to: file_ref(&dst),
                replace,
                no_create_parents: true,
            }),
        )
        .await?;
        // Open handles under the renamed path follow it.
        for e in self.handles.lock().expect("handle table poisoned").values() {
            let mut p = e.path.lock().expect("path poisoned");
            if is_under(&p, &src) {
                let tail = p[src.len()..].to_owned();
                *p = format!("{dst}{tail}");
            }
        }
        Ok(())
    }

    async fn set_delete_on_close(&self, h: BackendHandle, on: bool) -> Result<()> {
        let e = self.entry(h)?;
        if on && e.directory {
            let empty = match self
                .bundle(
                    true,
                    bundle_op_request::Op::List(pb::ListOp { rel_dir: e.path() }),
                )
                .await?
            {
                bundle_op_reply::Result::Listing(l) => l.entries.is_empty(),
                other => return Err(unexpected(other)),
            };
            if !empty {
                return Err(BackendError::DirectoryNotEmpty);
            }
        }
        e.delete_on_close.store(on, Ordering::Relaxed);
        Ok(())
    }

    async fn truncate(&self, h: BackendHandle, new_len: u64) -> Result<()> {
        let e = self.entry(h)?;
        if e.directory {
            return Err(BackendError::IsADirectory);
        }
        if !e.writable {
            return Err(BackendError::AccessDenied);
        }
        self.bundle_ok(
            true,
            bundle_op_request::Op::Truncate(pb::TruncateOp {
                file: file_ref(&e.path()),
                new_length: new_len,
            }),
        )
        .await
    }

    async fn set_times(&self, h: BackendHandle, times: SetTimes) -> Result<()> {
        let e = self.entry(h)?;
        if e.directory {
            return Ok(()); // best effort, like the reference backend
        }
        self.bundle_ok(
            true,
            bundle_op_request::Op::SetTimes(pb::SetTimesOp {
                file: file_ref(&e.path()),
                atime_unix_ns: times.atime_unix_ns,
                mtime_unix_ns: times.mtime_unix_ns,
            }),
        )
        .await
    }

    async fn list(&self, rel_dir: &str) -> Result<Vec<FileStat>> {
        let dir = normalize(rel_dir)?;
        match self
            .bundle(
                true,
                bundle_op_request::Op::List(pb::ListOp { rel_dir: dir }),
            )
            .await?
        {
            bundle_op_reply::Result::Listing(l) => {
                let mut out: Vec<FileStat> = l.entries.into_iter().map(stat_from_proto).collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
            other => Err(unexpected(other)),
        }
    }

    async fn stat(&self, rel_path: &str) -> Result<FileStat> {
        self.stat_path(&normalize(rel_path)?).await
    }

    async fn statfs(&self) -> Result<FsStats> {
        let r = self
            .rpc(true, false, |mut c| async move {
                c.stat_fs(pb::StatFsRequest {}).await
            })
            .await?;
        Ok(FsStats {
            quota_bytes: if r.quota_bytes == 0 {
                self.fallback_quota
            } else {
                r.quota_bytes
            },
            used_bytes: r.used_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_the_reference_rules() {
        assert_eq!(normalize("").unwrap(), "");
        assert_eq!(normalize("/a//b/").unwrap(), "a/b");
        for bad in ["..", "a/../b", "./a", "a\\b", "a\0b"] {
            assert!(
                matches!(normalize(bad), Err(BackendError::AccessDenied)),
                "{bad}"
            );
        }
        assert!(matches!(normalize("f:stream"), Err(BackendError::NotFound)));
    }

    #[test]
    fn status_mapping() {
        use BackendError as E;
        assert!(matches!(
            map_status(&Status::resource_exhausted("q")),
            E::NoSpace
        ));
        assert!(matches!(
            map_status(&Status::unavailable("down")),
            E::RemoteUnavailable
        ));
        assert!(matches!(
            map_status(&Status::deadline_exceeded("t")),
            E::RemoteUnavailable
        ));
        assert!(matches!(map_status(&Status::not_found("x")), E::NotFound));
        assert!(matches!(
            map_status(&Status::permission_denied("x")),
            E::AccessDenied
        ));
        assert!(matches!(
            map_status(&Status::already_exists("x")),
            E::AlreadyExists
        ));
        let mut st = Status::not_found("x");
        st.metadata_mut()
            .insert("janus-error", "path-not-found".parse().unwrap());
        assert!(matches!(map_status(&st), E::PathNotFound));
        let mut st = Status::failed_precondition("x");
        st.metadata_mut()
            .insert("janus-error", "not-empty".parse().unwrap());
        assert!(matches!(map_status(&st), E::DirectoryNotEmpty));
    }

    #[test]
    fn rename_prefix_is_component_aware() {
        assert!(is_under("a/b", "a"));
        assert!(is_under("a", "a"));
        assert!(!is_under("ab/c", "a"));
    }
}
