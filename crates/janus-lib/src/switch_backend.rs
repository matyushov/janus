//! `SwitchBackend`: the backend `janus-smbd` serves the share with. It lets `Configure`
//! replace the `GrpcBackend` (new endpoint, certificates, quota) without restarting the daemon.
//!
//! Handles carry the generation of the backend that issued them (top 16 bits), so a handle
//! opened before a reconfiguration keeps talking to the backend it was opened on until it is
//! closed; new opens use the new backend. Superseded backends are dropped when their last
//! handle is closed. Before the first `Configure` every operation fails with
//! `RemoteUnavailable`.
//!
//! The write-ahead journal belongs to the share, not to a backend generation: a new generation
//! pointed at the same journal directory adopts the running journal and its uploader (which then
//! sends through the new link). A journal in a different directory starts its own; the old one
//! keeps uploading until it is empty.
//!
//! The quiesce gate sits here: while it is closed, writes wait (then fail with `Busy`); what was
//! accepted before stays in the journal and keeps uploading.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::config::{FlushPolicy, ShareConfig};
use crate::control::WriteGate;
use crate::grpc_backend::{GrpcBackend, JournalRuntime, JournalSettings, destination_of};
use crate::remote::RemoteClient;
use crate::uploader::UploaderStats;
use crate::vfs::{
    BackendError, BackendHandle, FileStat, FsStats, OpenRequest, Opened, Result, SetTimes,
    StorageBackend,
};

const GEN_SHIFT: u32 = 48;
const INNER_MASK: u64 = (1 << GEN_SHIFT) - 1;

#[derive(Default)]
pub struct SwitchBackend {
    current: RwLock<Option<(u16, Arc<GrpcBackend>)>>,
    /// Superseded generations that still have open handles.
    old: Mutex<Vec<(u16, Arc<GrpcBackend>)>>,
    next_gen: Mutex<u16>,
    gate: Option<Arc<WriteGate>>,
}

impl SwitchBackend {
    pub fn new() -> SwitchBackend {
        SwitchBackend::default()
    }

    /// Stop accepting writes while `gate` is closed (`Quiesce`).
    pub fn with_gate(mut self, gate: Arc<WriteGate>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// Install a backend built from `remote` and the share configuration (quota, journal).
    /// Fails if the journal cannot be opened, or if it still holds unuploaded bytes for a
    /// different destination (another endpoint or client certificate: those bytes belong to
    /// the old receiver and must not flow to the new one); the previous backend then stays in
    /// place. With an empty journal a changed destination is accepted, and the handles opened
    /// for the old destination are retired.
    pub fn apply(&self, remote: &RemoteClient, share: &ShareConfig) -> std::io::Result<()> {
        let destination = destination_of(share);
        let backend = GrpcBackend::from_remote(remote, share.quota_bytes)
            .with_destination(destination.clone());
        let backend = if share.journal.enabled {
            let dir = share
                .journal
                .resolve_dir()
                .ok_or_else(|| std::io::Error::other("no journal directory (set HOME)"))?;
            let settings = JournalSettings {
                max_backlog: share.journal.max_backlog(),
                local_journal: share.flush_policy == FlushPolicy::LocalJournal,
            };
            match self.journal_runtime().filter(|rt| rt.dir() == dir) {
                Some(rt) => {
                    if rt.retarget(&destination)? {
                        // Handles of the old destination share this journal: they must not
                        // append to it any more (their bytes would go to the new receiver).
                        self.retire_sharing(&rt);
                    }
                    backend.with_journal_runtime(rt, settings)
                }
                None => backend.with_journal(&dir, settings)?,
            }
        } else {
            backend
        };
        self.install(backend);
        Ok(())
    }

    /// Drop the open handles of every generation that writes into `rt`.
    fn retire_sharing(&self, rt: &Arc<JournalRuntime>) {
        let current = self.current.read().expect("backend lock poisoned");
        let old = self.old.lock().expect("old poisoned");
        for b in current
            .iter()
            .map(|(_, b)| b)
            .chain(old.iter().map(|(_, b)| b))
        {
            if b.journal_runtime().is_some_and(|x| Arc::ptr_eq(x, rt)) {
                b.retire_handles();
            }
        }
    }

    /// The journal of the current backend.
    pub fn journal_runtime(&self) -> Option<Arc<JournalRuntime>> {
        self.current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .and_then(|(_, b)| b.journal_runtime().cloned())
    }

    /// Every distinct journal that may still hold data: the current one and those of
    /// superseded generations.
    fn runtimes(&self) -> Vec<Arc<JournalRuntime>> {
        let mut v: Vec<Arc<JournalRuntime>> = Vec::new();
        let cur = self
            .current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .and_then(|(_, b)| b.journal_runtime().cloned());
        let old = self
            .old
            .lock()
            .expect("old poisoned")
            .iter()
            .filter_map(|(_, b)| b.journal_runtime().cloned())
            .collect::<Vec<_>>();
        for rt in cur.into_iter().chain(old) {
            if !v.iter().any(|x| Arc::ptr_eq(x, &rt)) {
                v.push(rt);
            }
        }
        v
    }

    /// Upload statistics summed over all journals; `None` = no journal.
    pub fn journal_stats(&self) -> Option<UploaderStats> {
        let rts = self.runtimes();
        if rts.is_empty() {
            return None;
        }
        let mut t = UploaderStats::default();
        for rt in rts {
            let s = rt.stats();
            t.backlog_bytes += s.backlog_bytes;
            t.uploaded_bytes_total += s.uploaded_bytes_total;
            t.upload_errors += s.upload_errors;
            t.last_ack_unix_ms = t.last_ack_unix_ms.max(s.last_ack_unix_ms);
            t.oldest_age_ms = t.oldest_age_ms.max(s.oldest_age_ms);
            t.sticky_files += s.sticky_files;
            if t.last_error.is_empty() {
                t.last_error = s.last_error;
            }
        }
        Some(t)
    }

    /// Wait until every journal is empty and fsynced on the receiver. `(drained, remaining)`.
    pub async fn drain(&self, timeout: Duration) -> (bool, u64) {
        let deadline = Instant::now() + timeout;
        let (mut ok, mut remaining) = (true, 0);
        for rt in self.runtimes() {
            let left = deadline.saturating_duration_since(Instant::now());
            let (d, r) = rt.drain(left).await;
            ok &= d;
            remaining += r;
        }
        (ok, remaining)
    }

    /// Open handles over all generations.
    pub fn open_handles(&self) -> usize {
        let cur = self
            .current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .map_or(0, |(_, b)| b.open_handles());
        cur + self
            .old
            .lock()
            .expect("old poisoned")
            .iter()
            .map(|(_, b)| b.open_handles())
            .sum::<usize>()
    }

    pub fn install(&self, backend: GrpcBackend) {
        let gen_ = {
            let mut g = self.next_gen.lock().expect("gen poisoned");
            *g = g.wrapping_add(1);
            *g
        };
        let prev = self
            .current
            .write()
            .expect("backend lock poisoned")
            .replace((gen_, Arc::new(backend)));
        if let Some(p) = prev {
            self.old.lock().expect("old poisoned").push(p);
        }
        self.prune();
    }

    pub fn is_configured(&self) -> bool {
        self.current
            .read()
            .expect("backend lock poisoned")
            .is_some()
    }

    fn prune(&self) {
        let cur = self.journal_runtime();
        self.old.lock().expect("old poisoned").retain(|(_, b)| {
            let own_backlog = b.journal_runtime().is_some_and(|rt| {
                !cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, rt)) && rt.stats().backlog_bytes > 0
            });
            b.open_handles() > 0 || own_backlog
        });
    }

    fn current(&self) -> Result<Arc<GrpcBackend>> {
        self.current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .map(|(_, b)| Arc::clone(b))
            .ok_or(BackendError::RemoteUnavailable)
    }

    fn route(&self, h: BackendHandle) -> Result<(Arc<GrpcBackend>, BackendHandle)> {
        let gen_ = (h.0 >> GEN_SHIFT) as u16;
        let inner = BackendHandle(h.0 & INNER_MASK);
        if let Some((g, b)) = self.current.read().expect("backend lock poisoned").as_ref()
            && *g == gen_
        {
            return Ok((Arc::clone(b), inner));
        }
        self.old
            .lock()
            .expect("old poisoned")
            .iter()
            .find(|(g, _)| *g == gen_)
            .map(|(_, b)| (Arc::clone(b), inner))
            .ok_or(BackendError::BadHandle)
    }

    fn tag(gen_: u16, h: BackendHandle) -> BackendHandle {
        BackendHandle(((gen_ as u64) << GEN_SHIFT) | (h.0 & INNER_MASK))
    }

    fn current_gen(&self) -> u16 {
        self.current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .map(|(g, _)| *g)
            .unwrap_or(0)
    }
}

impl StorageBackend for SwitchBackend {
    async fn open(&self, rel_path: &str, req: OpenRequest) -> Result<Opened> {
        // Capture generation and backend together: a switch in between must not mislabel.
        let (gen_, b) = {
            let c = self.current.read().expect("backend lock poisoned");
            let (g, b) = c.as_ref().ok_or(BackendError::RemoteUnavailable)?;
            (*g, Arc::clone(b))
        };
        let mut o = b.open(rel_path, req).await?;
        o.handle = Self::tag(gen_, o.handle);
        Ok(o)
    }

    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        let (b, h) = self.route(h)?;
        b.stat_handle(h).await
    }

    async fn read(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let (b, h) = self.route(h)?;
        b.read(h, offset, len).await
    }

    async fn write(&self, h: BackendHandle, offset: u64, data: &[u8]) -> Result<()> {
        if let Some(g) = &self.gate {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !g.is_open() {
                if Instant::now() >= deadline {
                    return Err(BackendError::Busy);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let (b, h) = self.route(h)?;
        b.write(h, offset, data).await
    }

    async fn flush(&self, h: BackendHandle, fullfsync: bool) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.flush(h, fullfsync).await
    }

    async fn close(&self, h: BackendHandle) -> Result<()> {
        let (b, inner) = self.route(h)?;
        let r = b.close(inner).await;
        self.prune();
        r
    }

    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        self.current()?.rename(from, to, replace).await
    }

    async fn set_delete_on_close(&self, h: BackendHandle, on: bool) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.set_delete_on_close(h, on).await
    }

    async fn truncate(&self, h: BackendHandle, new_len: u64) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.truncate(h, new_len).await
    }

    async fn set_times(&self, h: BackendHandle, times: SetTimes) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.set_times(h, times).await
    }

    async fn list(&self, rel_dir: &str) -> Result<Vec<FileStat>> {
        self.current()?.list(rel_dir).await
    }

    async fn stat(&self, rel_path: &str) -> Result<FileStat> {
        self.current()?.stat(rel_path).await
    }

    async fn statfs(&self) -> Result<FsStats> {
        self.current()?.statfs().await
    }
}
