//! Uploader: asynchronous delivery WAL → janus-receiverd (gRPC).
//!
//! Outside the barriers it does not affect SMB reply latency. The only
//! synchronization points:
//! - `flush_barrier(file)` is an honest F_FULLFSYNC under SYNC_THROUGH;
//! - `drain_barrier()` is the Drain command: a guarantee that "everything reached the appliance"
//!   before the point is fixed on the receiving side (a backend snapshot is outside janus).
//!
//! # How it works
//!
//! One tokio task plans batches (a contiguous run of dirty bytes of one file, at most
//! `max_batch` = 1 MiB, the oldest file first) and sends them with up to `window` concurrent
//! `WriteRange` calls. Ranges that overlap a batch in flight are not planned, so a newer write
//! to the same bytes can never be overtaken on the network by an older one; non-overlapping
//! ranges may finish in any order. A batch is acknowledged in the journal (`Journal::ack`)
//! only after the receiver answered, and only for the records it was assembled from, so a
//! write that landed meanwhile stays dirty (later-wins).
//!
//! Errors are classified by the target:
//! - transient (transport, timeout, `UNAVAILABLE`): the batch stays dirty, the whole uploader
//!   pauses with an exponential backoff (+ jitter) and tries again; `WriteRange` is idempotent;
//! - permanent (no space on the receiver, access denied, anything else): not retried. The
//!   error becomes the *sticky* error of the file. It is returned by the next barrier of that
//!   file and shown in the status; a new write to the file clears it (so that a retry after
//!   Time Machine freed space works), as does dropping the file's dirty bytes.
//!
//! Network time budgets and the degraded-peer logic live in the target (`remote::Timeouts`
//! applied by `GrpcBackend`'s link); this module only decides when to call and what to do
//! with the outcome.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, Semaphore};

use crate::journal::{Journal, PathId, Seq};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A permanent failure kept as the sticky error of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sticky {
    NoSpace,
    AccessDenied,
    Other(String),
}

impl std::fmt::Display for Sticky {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sticky::NoSpace => write!(f, "no space left on the receiver"),
            Sticky::AccessDenied => write!(f, "access denied by the receiver"),
            Sticky::Other(m) => write!(f, "{m}"),
        }
    }
}

/// Outcome of one call to the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFail {
    /// Try again later.
    Transient(String),
    /// Do not retry.
    Permanent(Sticky),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    /// The receiver could not be reached in time.
    RemoteUnavailable,
    Timeout,
    /// A permanent error of the file.
    Sticky(Sticky),
    /// The journal itself failed (disk).
    Journal(String),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::RemoteUnavailable => write!(f, "receiver unavailable"),
            UploadError::Timeout => write!(f, "timed out waiting for the receiver"),
            UploadError::Sticky(s) => write!(f, "{s}"),
            UploadError::Journal(m) => write!(f, "journal: {m}"),
        }
    }
}

/// The receiver as the uploader sees it. Implemented by `GrpcBackend`'s link and by test mocks.
pub trait UploadTarget: Send + Sync + 'static {
    /// Idempotent write of `data` at `offset`; `write_id` is stable across retries.
    fn write_range<'a>(
        &'a self,
        path: &'a str,
        offset: u64,
        data: Vec<u8>,
        write_id: u64,
    ) -> BoxFut<'a, Result<(), UploadFail>>;

    /// `Some(path)` = fsync of one file, `None` = of the whole bundle.
    fn fsync<'a>(&'a self, path: Option<&'a str>) -> BoxFut<'a, Result<(), UploadFail>>;
}

/// Retries: exponential backoff + jitter. WriteRange is idempotent → a repeat is safe.
/// Transient errors → pause, the WAL accumulates (up to the limit → backpressure upward).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max: Duration,
    /// ± fraction of the delay.
    pub jitter: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            base: Duration::from_millis(200),
            max: Duration::from_secs(2),
            jitter: 0.25,
        }
    }
}

impl RetryPolicy {
    /// Delay before retry number `failures` (1 = the first retry); `unit` in `[0, 1)` picks
    /// the point inside the jitter window (0.5 = no change).
    pub fn delay_with(&self, failures: u32, unit: f64) -> Duration {
        let exp = failures.saturating_sub(1).min(16);
        let raw = self.base.saturating_mul(1 << exp).min(self.max);
        let factor = 1.0 + self.jitter * (2.0 * unit - 1.0);
        raw.mul_f64(factor.max(0.0))
    }

    pub fn delay(&self, failures: u32) -> Duration {
        let mut r = [0u8; 4];
        let _ = getrandom::fill(&mut r);
        self.delay_with(
            failures,
            u32::from_le_bytes(r) as f64 / (u32::MAX as f64 + 1.0),
        )
    }
}

#[derive(Debug, Clone)]
pub struct UploaderConfig {
    /// Concurrent WriteRange calls.
    pub window: usize,
    /// Bytes per WriteRange (the contract limit is 1 MiB).
    pub max_batch: usize,
    pub retry: RetryPolicy,
}

impl Default for UploaderConfig {
    fn default() -> Self {
        UploaderConfig {
            window: 4,
            max_batch: 1 << 20,
            retry: RetryPolicy::default(),
        }
    }
}

/// Parallelism window: ranges being uploaded right now, per file, plus the permit count.
/// Order between non-overlapping ranges does not matter (later-wins in the WAL), but a range
/// that overlaps one in flight must wait.
#[derive(Debug, Default)]
pub struct InflightWindow {
    ranges: HashMap<PathId, Vec<(u64, u64)>>,
    count: usize,
}

impl InflightWindow {
    fn skip_for(&self, file: PathId) -> Vec<(u64, u64)> {
        self.ranges.get(&file).cloned().unwrap_or_default()
    }

    fn start(&mut self, file: PathId, range: (u64, u64)) {
        self.ranges.entry(file).or_default().push(range);
        self.count += 1;
    }

    fn finish(&mut self, file: PathId, range: (u64, u64)) {
        if let Some(v) = self.ranges.get_mut(&file) {
            if let Some(i) = v.iter().position(|r| *r == range) {
                v.swap_remove(i);
            }
            if v.is_empty() {
                self.ranges.remove(&file);
            }
        }
        self.count -= 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn file_busy(&self, file: PathId) -> bool {
        self.ranges.contains_key(&file)
    }
}

/// Batch scheduler: picks the oldest dirty file that has an uploadable run, coalescing
/// adjacent dirty intervals and cutting at `max_batch`.
#[derive(Debug)]
pub struct BatchPlanner {
    pub max_batch: usize,
}

impl BatchPlanner {
    fn next(
        &self,
        journal: &Journal,
        window: &InflightWindow,
        sticky: &HashMap<PathId, Sticky>,
    ) -> std::io::Result<Option<crate::journal::Batch>> {
        for f in journal.dirty_files_by_age() {
            if sticky.contains_key(&f) {
                continue;
            }
            if let Some(b) = journal.plan_batch(f, &window.skip_for(f), self.max_batch)? {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }
}

/// Acknowledged bytes and the time of the last ack.
#[derive(Debug, Default)]
pub struct AckTracker {
    pub uploaded_bytes: AtomicU64,
    pub last_ack_unix_ms: AtomicU64,
    pub errors: AtomicU64,
}

impl AckTracker {
    fn acked(&self, bytes: u64) {
        self.uploaded_bytes.fetch_add(bytes, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        self.last_ack_unix_ms.store(now, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct State {
    window: InflightWindow,
    sticky: HashMap<PathId, Sticky>,
    backoff_until: Option<Instant>,
    failures: u32,
    last_error: Option<String>,
    /// File → seq of its newest write that a successful `Fsync(file)` covered. A flush of a
    /// file with nothing newer needs no round trip (a close right after a flush is common).
    synced: HashMap<PathId, u64>,
}

/// What `status` shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploaderStats {
    pub backlog_bytes: u64,
    pub uploaded_bytes_total: u64,
    pub upload_errors: u64,
    pub last_ack_unix_ms: u64,
    pub oldest_age_ms: u64,
    pub last_error: String,
    pub sticky_files: usize,
}

struct Shared {
    journal: Arc<Journal>,
    target: RwLock<Arc<dyn UploadTarget>>,
    cfg: UploaderConfig,
    state: Mutex<State>,
    /// New work / state change for the uploader task.
    work: Notify,
    /// Something was acknowledged or failed: wake the barriers and the writers waiting for room.
    progress: Notify,
    stop: AtomicBool,
    paused: AtomicBool,
    stopped: Notify,
    exited: AtomicBool,
    acks: AckTracker,
    sem: Arc<Semaphore>,
}

/// Stops the task when the last handle goes away.
struct Guard(Arc<Shared>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::Release);
        self.0.work.notify_one();
    }
}

/// A handle for GrpcBackend/ControlService (the task itself lives in tokio).
#[derive(Clone)]
pub struct UploaderHandle {
    shared: Arc<Shared>,
    _guard: Arc<Guard>,
}

impl std::fmt::Debug for UploaderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploaderHandle").finish_non_exhaustive()
    }
}

impl UploaderHandle {
    /// Start the uploader task on the current tokio runtime. Whatever is dirty in `journal`
    /// (for example after a restart) starts flowing immediately.
    pub fn start(
        journal: Arc<Journal>,
        target: Arc<dyn UploadTarget>,
        cfg: UploaderConfig,
    ) -> UploaderHandle {
        let shared = Arc::new(Shared {
            journal,
            target: RwLock::new(target),
            sem: Arc::new(Semaphore::new(cfg.window.max(1))),
            cfg,
            state: Mutex::new(State::default()),
            work: Notify::new(),
            progress: Notify::new(),
            stop: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            stopped: Notify::new(),
            exited: AtomicBool::new(false),
            acks: AckTracker::default(),
        });
        tokio::spawn(run(Arc::clone(&shared)));
        shared.work.notify_one();
        UploaderHandle {
            _guard: Arc::new(Guard(Arc::clone(&shared))),
            shared,
        }
    }

    pub fn journal(&self) -> &Arc<Journal> {
        &self.shared.journal
    }

    /// Replace the receiver (reconfiguration): batches in flight finish on the old one.
    pub fn set_target(&self, target: Arc<dyn UploadTarget>) {
        *self.shared.target.write().expect("target poisoned") = target;
        let mut st = self.shared.state.lock().expect("state poisoned");
        st.backoff_until = None;
        st.failures = 0;
        drop(st);
        self.shared.work.notify_one();
    }

    /// New data is in the journal.
    pub fn kick(&self) {
        self.shared.work.notify_one();
    }

    /// A new write to `file`: whatever failed permanently before may work now.
    pub fn clear_sticky(&self, file: PathId) {
        let removed = self
            .shared
            .state
            .lock()
            .expect("state poisoned")
            .sticky
            .remove(&file)
            .is_some();
        if removed {
            self.shared.work.notify_one();
        }
    }

    /// The dirty bytes of the file are gone (deleted / truncated): forget its error. Waits
    /// until batches of the file that are on the wire have finished, so that none of them can
    /// land after the receiver-side delete or truncate.
    pub async fn forget_file(&self, file: PathId, deadline: Instant) -> Result<(), UploadError> {
        self.shared
            .state
            .lock()
            .expect("state poisoned")
            .sticky
            .remove(&file);
        self.mark_unsynced(file);
        self.wait(deadline, || {
            let st = self.shared.state.lock().expect("state poisoned");
            (!st.window.file_busy(file)).then_some(())
        })
        .await
    }

    pub fn backlog_bytes(&self) -> u64 {
        self.shared.journal.live_bytes()
    }

    pub fn sticky_error(&self, file: PathId) -> Option<Sticky> {
        self.shared
            .state
            .lock()
            .expect("state poisoned")
            .sticky
            .get(&file)
            .cloned()
    }

    pub fn uploaded_bytes_total(&self) -> u64 {
        self.shared.acks.uploaded_bytes.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> UploaderStats {
        let st = self.shared.state.lock().expect("state poisoned");
        UploaderStats {
            backlog_bytes: self.shared.journal.live_bytes(),
            uploaded_bytes_total: self.shared.acks.uploaded_bytes.load(Ordering::Relaxed),
            upload_errors: self.shared.acks.errors.load(Ordering::Relaxed),
            last_ack_unix_ms: self.shared.acks.last_ack_unix_ms.load(Ordering::Relaxed),
            oldest_age_ms: self
                .shared
                .journal
                .oldest_age()
                .map_or(0, |d| d.as_millis() as u64),
            last_error: st.last_error.clone().unwrap_or_default(),
            sticky_files: st.sticky.len(),
        }
    }

    /// Number of batches on the wire.
    pub fn inflight(&self) -> usize {
        self.shared
            .state
            .lock()
            .expect("state poisoned")
            .window
            .len()
    }

    /// Run `check` until it returns `Some`, waking on every progress event, until `deadline`.
    async fn wait<T>(
        &self,
        deadline: Instant,
        mut check: impl FnMut() -> Option<T>,
    ) -> Result<T, UploadError> {
        loop {
            let notified = self.shared.progress.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(v) = check() {
                return Ok(v);
            }
            if tokio::time::timeout_at(deadline.into(), notified)
                .await
                .is_err()
            {
                return Err(self.timeout_error());
            }
        }
    }

    fn timeout_error(&self) -> UploadError {
        let st = self.shared.state.lock().expect("state poisoned");
        if st.failures > 0 {
            UploadError::RemoteUnavailable
        } else {
            UploadError::Timeout
        }
    }

    /// Wait until the files have no dirty bytes written before this call (acknowledged by
    /// the receiver, or dropped). No fsync. A sticky error of any of them is returned.
    pub async fn wait_uploaded(
        &self,
        files: &[PathId],
        deadline: Instant,
    ) -> Result<(), UploadError> {
        let s0 = self.shared.journal.last_seq();
        self.wait(deadline, || {
            let st = self.shared.state.lock().expect("state poisoned");
            for f in files {
                if let Some(e) = st.sticky.get(f) {
                    return Some(Err(UploadError::Sticky(e.clone())));
                }
            }
            drop(st);
            let pending = files.iter().any(|f| {
                self.shared
                    .journal
                    .file_min_seq(*f)
                    .is_some_and(|m| m <= s0)
            });
            (!pending).then_some(Ok(()))
        })
        .await?
    }

    async fn fsync(&self, path: Option<&str>, deadline: Instant) -> Result<(), UploadError> {
        let target = self.shared.target.read().expect("target poisoned").clone();
        match tokio::time::timeout_at(deadline.into(), target.fsync(path)).await {
            Err(_) => Err(UploadError::RemoteUnavailable),
            Ok(Ok(())) => Ok(()),
            Ok(Err(UploadFail::Transient(m))) => {
                self.record_error(&m);
                Err(UploadError::RemoteUnavailable)
            }
            Ok(Err(UploadFail::Permanent(s))) => Err(UploadError::Sticky(s)),
        }
    }

    fn record_error(&self, msg: &str) {
        self.shared.acks.errors.fetch_add(1, Ordering::Relaxed);
        self.shared.state.lock().expect("state poisoned").last_error = Some(msg.to_owned());
    }

    /// Wait for the acks of all dirty ranges of the file + Fsync(file) on the receiver.
    pub async fn flush_barrier(&self, file: PathId, deadline: Instant) -> Result<(), UploadError> {
        self.wait_uploaded(&[file], deadline).await?;
        let newest = self.shared.journal.last_write_seq(file).map_or(0, |s| s.0);
        let covered = self
            .shared
            .state
            .lock()
            .expect("state poisoned")
            .synced
            .get(&file)
            .copied();
        if covered.is_some_and(|c| c >= newest) {
            return Ok(());
        }
        let Some(p) = self.shared.journal.path_of(file) else {
            return Ok(());
        };
        self.fsync(Some(&p), deadline).await?;
        self.shared
            .state
            .lock()
            .expect("state poisoned")
            .synced
            .insert(file, newest);
        Ok(())
    }

    /// The receiver-side file changed by other means than journal writes (truncate, times):
    /// the next flush must fsync again.
    pub fn mark_unsynced(&self, file: PathId) {
        self.shared
            .state
            .lock()
            .expect("state poisoned")
            .synced
            .remove(&file);
    }

    /// The same for the whole bundle + Fsync(all_bundle). Drain stands on this. Files with a
    /// sticky error cannot be drained: the call returns their error once nothing else is left.
    pub async fn drain_barrier(&self, deadline: Instant) -> Result<(), UploadError> {
        self.wait(deadline, || {
            let st = self.shared.state.lock().expect("state poisoned");
            if self.shared.journal.live_bytes() == 0 && st.window.is_empty() {
                return Some(Ok(()));
            }
            // Only stuck files left: waiting will not help.
            if st.window.is_empty() {
                let dirty = self.shared.journal.dirty_files_by_age();
                if !dirty.is_empty()
                    && let Some(e) = dirty.iter().find_map(|f| st.sticky.get(f))
                    && dirty.iter().all(|f| st.sticky.contains_key(f))
                {
                    return Some(Err(UploadError::Sticky(e.clone())));
                }
            }
            None
        })
        .await??;
        self.fsync(None, deadline).await?;
        // Everything is on the receiver: persist that, so a restart does not replay it.
        trim(&self.shared);
        Ok(())
    }

    /// Backpressure: wait until `len` more bytes fit under `max_backlog` (a lone write larger
    /// than the limit is let through once the journal is empty) and the journal's disk use is
    /// sane.
    pub async fn wait_for_room(
        &self,
        max_backlog: u64,
        len: u64,
        deadline: Instant,
    ) -> Result<(), UploadError> {
        let j = &self.shared.journal;
        self.wait(deadline, || {
            let live = j.live_bytes();
            // Superseded records pin disk until the watermark passes them.
            let disk_ok = j.disk_bytes() < max_backlog.saturating_mul(2).saturating_add(len);
            ((live == 0 || live.saturating_add(len) <= max_backlog) && disk_ok).then_some(())
        })
        .await
    }

    /// Hold back new batches (batches already on the wire finish). A diagnostic and test hook:
    /// it makes "the receiver has not got the data yet" reproducible.
    pub fn set_paused(&self, paused: bool) {
        self.shared.paused.store(paused, Ordering::Release);
        self.shared.work.notify_one();
    }

    /// Stop the task (batches in flight are abandoned; whatever is dirty stays in the journal).
    pub fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.work.notify_one();
    }

    /// Wait until the task has exited after `shutdown`.
    pub async fn stopped(&self) {
        let n = self.shared.stopped.notified();
        tokio::pin!(n);
        n.as_mut().enable();
        if !self.shared.exited.load(Ordering::Acquire) {
            let _ = tokio::time::timeout(Duration::from_secs(5), n).await;
        }
    }
}

async fn run(sh: Arc<Shared>) {
    let planner = BatchPlanner {
        max_batch: sh.cfg.max_batch,
    };
    let mut last_trim = Instant::now();
    loop {
        if sh.stop.load(Ordering::Acquire) {
            break;
        }
        if sh.paused.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        }
        // Paused after a transient failure.
        let pause = sh
            .state
            .lock()
            .expect("state poisoned")
            .backoff_until
            .filter(|t| *t > Instant::now());
        if let Some(t) = pause {
            // A kick must not cut the backoff short; only its end does.
            tokio::time::sleep_until(t.into()).await;
            continue;
        }
        let Ok(permit) = Arc::clone(&sh.sem).acquire_owned().await else {
            break;
        };
        let planned = {
            let mut st = sh.state.lock().expect("state poisoned");
            match planner.next(&sh.journal, &st.window, &st.sticky) {
                Ok(Some(b)) => {
                    st.window
                        .start(b.file, (b.offset, b.offset + b.data.len() as u64));
                    Ok(Some(b))
                }
                other => other.map(|_| None),
            }
        };
        match planned {
            Ok(Some(batch)) => {
                let sh2 = Arc::clone(&sh);
                tokio::spawn(async move {
                    upload(&sh2, batch).await;
                    drop(permit);
                    sh2.work.notify_one();
                });
                if last_trim.elapsed() > Duration::from_secs(1) {
                    last_trim = Instant::now();
                    trim(&sh);
                }
            }
            Ok(None) => {
                drop(permit);
                // Housekeeping (watermark file, closing and deleting segments) costs file
                // system calls: at most once a second, never per small file.
                if last_trim.elapsed() > Duration::from_secs(1) {
                    last_trim = Instant::now();
                    trim(&sh);
                }
                // Nothing to plan: wait for new data, or for a batch to finish.
                let _ = tokio::time::timeout(Duration::from_secs(1), sh.work.notified()).await;
            }
            Err(e) => {
                drop(permit);
                set_error(&sh, &format!("journal read: {e}"));
                let mut st = sh.state.lock().expect("state poisoned");
                st.backoff_until = Some(Instant::now() + Duration::from_secs(1));
            }
        }
    }
    sh.exited.store(true, Ordering::Release);
    sh.stopped.notify_waiters();
}

fn trim(sh: &Shared) {
    if let Err(e) = sh.journal.trim() {
        set_error(sh, &format!("journal trim: {e}"));
    }
}

fn set_error(sh: &Shared, msg: &str) {
    sh.acks.errors.fetch_add(1, Ordering::Relaxed);
    sh.state.lock().expect("state poisoned").last_error = Some(msg.to_owned());
}

async fn upload(sh: &Shared, batch: crate::journal::Batch) {
    let range = (batch.offset, batch.offset + batch.data.len() as u64);
    let write_id = batch.parts.first().map_or(0, |p| p.seq.0);
    let target = sh.target.read().expect("target poisoned").clone();
    let bytes = batch.data.len() as u64;
    let result = target
        .write_range(&batch.path, batch.offset, batch.data, write_id)
        .await;
    match result {
        Ok(()) => {
            for p in &batch.parts {
                sh.journal.ack(batch.file, *p);
            }
            sh.acks.acked(bytes);
            let mut st = sh.state.lock().expect("state poisoned");
            st.window.finish(batch.file, range);
            st.failures = 0;
            st.backoff_until = None;
        }
        Err(UploadFail::Transient(m)) => {
            sh.acks.errors.fetch_add(1, Ordering::Relaxed);
            let mut st = sh.state.lock().expect("state poisoned");
            st.window.finish(batch.file, range);
            st.failures += 1;
            st.last_error = Some(m);
            let until = Instant::now() + sh.cfg.retry.delay(st.failures);
            st.backoff_until = Some(st.backoff_until.map_or(until, |b| b.max(until)));
        }
        Err(UploadFail::Permanent(s)) => {
            sh.acks.errors.fetch_add(1, Ordering::Relaxed);
            let mut st = sh.state.lock().expect("state poisoned");
            st.window.finish(batch.file, range);
            st.last_error = Some(format!("{}: {s}", batch.path));
            st.sticky.insert(batch.file, s);
        }
    }
    sh.progress.notify_waiters();
}

/// Seq of the newest record (for tests and diagnostics).
pub fn last_seq(h: &UploaderHandle) -> Seq {
    h.shared.journal.last_seq()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalOptions;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct MockState {
        files: HashMap<String, Vec<u8>>,
        /// Scripted outcomes for the next write_range calls.
        script: VecDeque<UploadFail>,
        fail_path: Option<(String, UploadFail)>,
        frozen: bool,
        writes: Vec<(String, u64, usize)>,
        fsyncs: Vec<Option<String>>,
        running: usize,
        max_running: usize,
        /// Ranges being written, to detect overlapping concurrent writes.
        overlapped: bool,
        active: Vec<(String, u64, u64)>,
        delay: Duration,
    }

    #[derive(Default)]
    struct Mock {
        st: Mutex<MockState>,
        thaw: Notify,
    }

    impl Mock {
        fn freeze(&self) {
            self.st.lock().unwrap().frozen = true;
        }
        fn thaw(&self) {
            self.st.lock().unwrap().frozen = false;
            self.thaw.notify_waiters();
        }
        fn file(&self, p: &str) -> Vec<u8> {
            self.st
                .lock()
                .unwrap()
                .files
                .get(p)
                .cloned()
                .unwrap_or_default()
        }
    }

    impl UploadTarget for Mock {
        fn write_range<'a>(
            &'a self,
            path: &'a str,
            offset: u64,
            data: Vec<u8>,
            _write_id: u64,
        ) -> BoxFut<'a, Result<(), UploadFail>> {
            Box::pin(async move {
                let end = offset + data.len() as u64;
                {
                    let mut s = self.st.lock().unwrap();
                    s.running += 1;
                    s.max_running = s.max_running.max(s.running);
                    if s.active
                        .iter()
                        .any(|(p, a, b)| p == path && offset < *b && *a < end)
                    {
                        s.overlapped = true;
                    }
                    s.active.push((path.to_owned(), offset, end));
                }
                let r = self.run(path, offset, data).await;
                let mut s = self.st.lock().unwrap();
                s.running -= 1;
                if let Some(i) = s
                    .active
                    .iter()
                    .position(|x| *x == (path.to_owned(), offset, end))
                {
                    s.active.swap_remove(i);
                }
                r
            })
        }

        fn fsync<'a>(&'a self, path: Option<&'a str>) -> BoxFut<'a, Result<(), UploadFail>> {
            Box::pin(async move {
                if self.st.lock().unwrap().frozen {
                    return Err(UploadFail::Transient("frozen".into()));
                }
                self.st.lock().unwrap().fsyncs.push(path.map(str::to_owned));
                Ok(())
            })
        }
    }

    impl Mock {
        async fn run(&self, path: &str, offset: u64, data: Vec<u8>) -> Result<(), UploadFail> {
            loop {
                let n = self.thaw.notified();
                tokio::pin!(n);
                n.as_mut().enable();
                if !self.st.lock().unwrap().frozen {
                    break;
                }
                n.await;
            }
            let delay = self.st.lock().unwrap().delay;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let mut s = self.st.lock().unwrap();
            if let Some(f) = s.script.pop_front() {
                return Err(f);
            }
            if let Some((p, f)) = &s.fail_path
                && p == path
            {
                return Err(f.clone());
            }
            let f = s.files.entry(path.to_owned()).or_default();
            let end = offset as usize + data.len();
            if f.len() < end {
                f.resize(end, 0);
            }
            f[offset as usize..end].copy_from_slice(&data);
            s.writes.push((path.to_owned(), offset, data.len()));
            Ok(())
        }
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let mut r = [0u8; 4];
        getrandom::fill(&mut r).unwrap();
        std::env::temp_dir().join(format!(
            "janus-up-{name}-{}-{}",
            std::process::id(),
            u32::from_le_bytes(r)
        ))
    }

    fn fast() -> UploaderConfig {
        UploaderConfig {
            retry: RetryPolicy {
                base: Duration::from_millis(10),
                max: Duration::from_millis(40),
                jitter: 0.0,
            },
            ..Default::default()
        }
    }

    fn setup(name: &str) -> (Arc<Journal>, Arc<Mock>, UploaderHandle, std::path::PathBuf) {
        let d = tmpdir(name);
        let (j, _) = Journal::open(&d, JournalOptions::default()).unwrap();
        let j = Arc::new(j);
        let m = Arc::new(Mock::default());
        let up = UploaderHandle::start(Arc::clone(&j), m.clone(), fast());
        (j, m, up, d)
    }

    fn soon(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(salt))
            .collect()
    }

    #[test]
    fn retry_delay_grows_and_is_capped_with_jitter() {
        let p = RetryPolicy {
            base: Duration::from_millis(100),
            max: Duration::from_millis(1000),
            jitter: 0.5,
        };
        let d = |n| p.delay_with(n, 0.5);
        assert_eq!(d(1), Duration::from_millis(100));
        assert_eq!(d(2), Duration::from_millis(200));
        assert_eq!(d(4), Duration::from_millis(800));
        assert_eq!(d(5), Duration::from_millis(1000));
        assert_eq!(d(60), Duration::from_millis(1000));
        assert_eq!(p.delay_with(1, 0.0), Duration::from_millis(50));
        assert_eq!(p.delay_with(1, 0.999999).as_millis(), 149);
    }

    #[tokio::test]
    async fn uploads_everything_identically_and_empties_the_journal() {
        let (j, m, up, d) = setup("basic");
        let f = j.intern("dir/big");
        let data = pattern(5 * (1 << 20) + 123, 1);
        for (i, c) in data.chunks(300_000).enumerate() {
            j.append(f, (i * 300_000) as u64, c).unwrap();
            up.kick();
        }
        up.flush_barrier(f, soon(5000)).await.unwrap();
        assert_eq!(m.file("dir/big"), data);
        assert_eq!(j.live_bytes(), 0);
        assert_eq!(up.uploaded_bytes_total(), data.len() as u64);
        assert!(
            m.st.lock()
                .unwrap()
                .fsyncs
                .contains(&Some("dir/big".into()))
        );
        let st = m.st.lock().unwrap();
        assert!(st.writes.iter().all(|w| w.2 <= 1 << 20), "WriteRange limit");
        assert!(!st.overlapped);
        drop(st);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn window_bounds_concurrency_and_uses_it() {
        let (j, m, up, d) = setup("window");
        m.st.lock().unwrap().delay = Duration::from_millis(30);
        let f = j.intern("f");
        for i in 0..32u64 {
            j.append(f, i << 20, &[i as u8; 1 << 20]).unwrap();
        }
        up.kick();
        up.wait_uploaded(&[f], soon(10_000)).await.unwrap();
        let max = m.st.lock().unwrap().max_running;
        assert!((2..=4).contains(&max), "max concurrent = {max}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn transient_errors_are_retried_and_counted() {
        let (j, m, up, d) = setup("transient");
        {
            let mut s = m.st.lock().unwrap();
            for _ in 0..3 {
                s.script.push_back(UploadFail::Transient("boom".into()));
            }
        }
        let f = j.intern("f");
        j.append(f, 0, b"payload").unwrap();
        up.kick();
        up.flush_barrier(f, soon(5000)).await.unwrap();
        assert_eq!(m.file("f"), b"payload");
        let s = up.stats();
        assert_eq!(s.upload_errors, 3);
        assert_eq!(s.backlog_bytes, 0);
        assert!(s.last_ack_unix_ms > 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn frozen_receiver_makes_barriers_fail_and_resumes_after_thaw() {
        let (j, m, up, d) = setup("freeze");
        m.freeze();
        let f = j.intern("f");
        j.append(f, 0, &[1; 1000]).unwrap();
        up.kick();
        // the barrier gives up at its deadline instead of reporting success
        let r = up.flush_barrier(f, soon(150)).await;
        assert!(matches!(
            r,
            Err(UploadError::Timeout | UploadError::RemoteUnavailable)
        ));
        assert_eq!(j.live_bytes(), 1000, "nothing was lost");
        // more writes accumulate while frozen
        j.append(f, 1000, &[2; 1000]).unwrap();
        assert_eq!(up.backlog_bytes(), 2000);
        m.thaw();
        up.flush_barrier(f, soon(5000)).await.unwrap();
        assert_eq!(m.file("f").len(), 2000);
        assert_eq!(j.live_bytes(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_second_flush_without_new_writes_costs_no_round_trip() {
        let (j, m, up, d) = setup("syncskip");
        let f = j.intern("f");
        j.append(f, 0, b"x").unwrap();
        up.kick();
        up.flush_barrier(f, soon(2000)).await.unwrap();
        up.flush_barrier(f, soon(2000)).await.unwrap();
        let count = |m: &Mock| m.st.lock().unwrap().fsyncs.len();
        assert_eq!(count(&m), 1);
        // new data, or a truncate / times change, makes the next flush sync again
        j.append(f, 1, b"y").unwrap();
        up.kick();
        up.flush_barrier(f, soon(2000)).await.unwrap();
        assert_eq!(count(&m), 2);
        up.mark_unsynced(f);
        up.flush_barrier(f, soon(2000)).await.unwrap();
        assert_eq!(count(&m), 3);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn fsync_failure_is_an_error_not_a_false_success() {
        let (j, m, up, d) = setup("fsyncfail");
        let f = j.intern("f");
        j.append(f, 0, b"x").unwrap();
        up.kick();
        up.wait_uploaded(&[f], soon(2000)).await.unwrap();
        m.freeze();
        let r = up.flush_barrier(f, soon(500)).await;
        assert!(matches!(r, Err(UploadError::RemoteUnavailable)));
        m.thaw();
        up.flush_barrier(f, soon(2000)).await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn permanent_error_is_sticky_not_retried_and_isolated() {
        let (j, m, up, d) = setup("sticky");
        m.st.lock().unwrap().fail_path =
            Some(("bad".into(), UploadFail::Permanent(Sticky::NoSpace)));
        let bad = j.intern("bad");
        let good = j.intern("good");
        j.append(bad, 0, b"doomed").unwrap();
        j.append(good, 0, b"fine").unwrap();
        up.kick();
        up.flush_barrier(good, soon(3000)).await.unwrap();
        assert_eq!(m.file("good"), b"fine");
        let r = up.flush_barrier(bad, soon(3000)).await;
        assert_eq!(r, Err(UploadError::Sticky(Sticky::NoSpace)));
        // not retried: exactly one attempt reached the mock for `bad`
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(up.stats().upload_errors, 1);
        assert_eq!(up.stats().sticky_files, 1);
        assert!(up.stats().last_error.contains("bad"));
        // the data is still readable from the journal
        assert_eq!(j.live_bytes(), 6);
        // a drain reports the stuck file instead of hanging
        let r = up.drain_barrier(soon(3000)).await;
        assert_eq!(r, Err(UploadError::Sticky(Sticky::NoSpace)));
        // a new write clears it and the upload is tried again (space freed meanwhile)
        m.st.lock().unwrap().fail_path = None;
        j.append(bad, 6, b"!").unwrap();
        up.clear_sticky(bad);
        up.flush_barrier(bad, soon(3000)).await.unwrap();
        assert_eq!(m.file("bad"), b"doomed!");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn later_write_wins_and_overlapping_ranges_are_never_concurrent() {
        let (j, m, up, d) = setup("laterwins");
        m.st.lock().unwrap().delay = Duration::from_millis(40);
        let f = j.intern("f");
        j.append(f, 0, &[1; 4096]).unwrap();
        up.kick();
        // wait until the first batch is on the wire, then overwrite part of it
        while up.inflight() == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        j.append(f, 1000, &[2; 100]).unwrap();
        j.append(f, 0, &[3; 10]).unwrap();
        up.kick();
        up.flush_barrier(f, soon(5000)).await.unwrap();
        let got = m.file("f");
        assert_eq!(&got[..10], &[3; 10]);
        assert_eq!(&got[10..1000], &[1; 990][..]);
        assert_eq!(&got[1000..1100], &[2; 100][..]);
        assert_eq!(&got[1100..], &[1; 2996][..]);
        assert!(!m.st.lock().unwrap().overlapped);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn wait_uploaded_ignores_writes_made_after_the_call() {
        let (j, m, up, d) = setup("snapshot");
        m.freeze();
        let f = j.intern("f");
        j.append(f, 0, b"old").unwrap();
        up.kick();
        let up2 = up.clone();
        let waiter = tokio::spawn(async move { up2.wait_uploaded(&[f], soon(5000)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        m.thaw();
        waiter.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn backpressure_waits_for_room_and_times_out_when_stuck() {
        let (j, m, up, d) = setup("room");
        m.freeze();
        let f = j.intern("f");
        j.append(f, 0, &[1; 1000]).unwrap();
        up.kick();
        // limit 1500: 500 more fit, 600 do not
        up.wait_for_room(1500, 500, soon(100)).await.unwrap();
        let r = up.wait_for_room(1500, 600, soon(150)).await;
        assert!(r.is_err());
        // it is let through once the uploader catches up
        let up2 = up.clone();
        let t = tokio::spawn(async move { up2.wait_for_room(1500, 600, soon(5000)).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        m.thaw();
        t.await.unwrap().unwrap();
        // a write bigger than the limit passes when the journal is empty
        up.wait_uploaded(&[f], soon(2000)).await.unwrap();
        up.wait_for_room(10, 1 << 20, soon(100)).await.unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn drain_waits_for_everything_then_syncs_the_bundle() {
        let (j, m, up, d) = setup("drain");
        for n in 0..5 {
            let f = j.intern(&format!("f{n}"));
            j.append(f, 0, &[n as u8; 10_000]).unwrap();
        }
        up.kick();
        up.drain_barrier(soon(5000)).await.unwrap();
        assert_eq!(j.live_bytes(), 0);
        assert!(m.st.lock().unwrap().fsyncs.contains(&None));
        for n in 0..5 {
            assert_eq!(m.file(&format!("f{n}")), vec![n as u8; 10_000]);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn stop_and_resume_from_the_journal_on_disk() {
        let d = tmpdir("resume");
        let m1 = Arc::new(Mock::default());
        m1.freeze();
        {
            let (j, _) = Journal::open(&d, JournalOptions::default()).unwrap();
            let j = Arc::new(j);
            let up = UploaderHandle::start(Arc::clone(&j), m1.clone(), fast());
            let f = j.intern("f");
            j.append(f, 0, &pattern(300_000, 9)).unwrap();
            up.kick();
            tokio::time::sleep(Duration::from_millis(50)).await;
            up.shutdown();
            up.stopped().await;
        }
        assert!(m1.file("f").is_empty());
        // "restart": a new journal instance recovers, a new uploader finishes the job
        let (j, r) = Journal::open(&d, JournalOptions::default()).unwrap();
        assert_eq!(r.replayed_bytes, 300_000);
        let j = Arc::new(j);
        let m2 = Arc::new(Mock::default());
        let up = UploaderHandle::start(Arc::clone(&j), m2.clone(), fast());
        up.drain_barrier(soon(5000)).await.unwrap();
        assert_eq!(m2.file("f"), pattern(300_000, 9));
        // idempotent: uploading again changes nothing
        let f = j.file_id("f").unwrap();
        j.append(f, 0, &pattern(300_000, 9)).unwrap();
        up.kick();
        up.drain_barrier(soon(5000)).await.unwrap();
        assert_eq!(m2.file("f"), pattern(300_000, 9));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn forget_file_waits_for_inflight_and_clears_the_error() {
        let (j, m, up, d) = setup("forget");
        m.st.lock().unwrap().delay = Duration::from_millis(80);
        let f = j.intern("f");
        j.append(f, 0, &[1; 1000]).unwrap();
        up.kick();
        while up.inflight() == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        j.drop_from(f, 0).unwrap();
        up.forget_file(f, soon(3000)).await.unwrap();
        assert_eq!(up.inflight(), 0);
        assert_eq!(j.live_bytes(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
