//! `GrpcBackend`: the production `StorageBackend`.
//!
//! Two modes:
//! - **journal** (J3b, the default): data writes are appended to a local write-ahead journal and
//!   acknowledged at once; the uploader sends them to the receiver in the background. Reads,
//!   `stat` and listings overlay the not-yet-uploaded bytes (read-your-writes). `flush` and the
//!   close of a dirty file wait until the data reached the receiver and was fsynced there
//!   (policy `SYNC_THROUGH`), or only fsync the journal (`LOCAL_JOURNAL`, unsafe for backups).
//!   Metadata operations stay synchronous and are ordered after the data of the files they
//!   touch (see `settle_*`).
//! - **sync-through** (J3a, `journal.enabled = false`): every operation goes to the receiver
//!   immediately; the latency of an SMB reply equals the RTT.
//!
//! Handles live on the client: `BackendHandle → (current rel path, kind, flags)`. The server
//! never sees them, every RPC carries a path, which keeps all writes idempotent (by offset).
//! `LocalFsBackend` is the behavioural reference; `tests/backend_contract.rs` runs one
//! set of assertions against it and against both modes of this backend.
//!
//! Retries: only calls that are idempotent by construction (reads, stat, list, `WriteRange`,
//! `Fsync`, truncate, set-times) are retried, and only on `UNAVAILABLE`. Exclusive create,
//! rename and delete are NOT retried: a lost reply would turn success into a spurious
//! `AlreadyExists`/`NotFound`.

use crate::jlog;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use janus_proto::v1 as pb;
use janus_proto::v1::band_transport_client::BandTransportClient;
use pb::{bundle_op_reply, bundle_op_request, fsync_request};
use tonic::transport::Channel;
use tonic::{Code, Status};

use crate::journal::{Chunk, Journal, JournalOptions};
use crate::remote::{RemoteClient, Timeouts, is_transport_failure};
use crate::uploader::{
    BoxFut, Sticky, UploadError, UploadFail, UploadTarget, UploaderConfig, UploaderHandle,
    UploaderStats,
};
use crate::vfs::{
    BackendError, BackendHandle, Disposition, FileStat, FsStats, Kind, OpenRequest, Opened, Result,
    SetTimes, StorageBackend,
};

/// Contract limit of one `WriteRange`/`ReadRange` payload.
pub const MAX_CHUNK: usize = 1 << 20;
/// Volume size reported when neither the receiver nor the configuration gives a quota (1 TiB).
const DEFAULT_QUOTA: u64 = 1 << 40;

/// How long a cached stat or listing may be served. This gateway is the only writer of its
/// machine's store, and every mutation made through it invalidates what it touches, so the TTL
/// only bounds staleness against changes made on the receiver itself (cleanup, retention).
const META_TTL: Duration = Duration::from_secs(2);
/// Entry caps; a cache that grows past them is simply emptied.
const META_MAX_STATS: usize = 4096;
const META_MAX_LISTINGS: usize = 64;
/// Larger directories are not cached (a band directory can hold tens of thousands of files).
const META_MAX_LISTING_LEN: usize = 2048;

/// Short-lived cache of `stat` and `list` answers. macOS opens the same few paths (the
/// AppleDouble `._name`, the parent directory) dozens of times per copied file, and each
/// uncached `Stat` is a full round trip to the receiver. It holds what the RECEIVER said; the
/// journal overlay is applied on top of every answer.
#[derive(Default)]
struct MetaCache {
    /// `None` = the path was absent.
    stats: HashMap<String, (Instant, Option<FileStat>)>,
    lists: HashMap<String, (Instant, Vec<FileStat>)>,
}

#[derive(Default)]
pub(crate) struct Meta {
    cache: Mutex<MetaCache>,
    /// Bumped by every invalidation: a lookup that overlapped one is not cached.
    mutations: AtomicU64,
}

impl Meta {
    /// Forget what is cached about `paths` and their parent directories. Call after a
    /// mutation has finished (successfully or not).
    fn invalidate(&self, paths: &[&str]) {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        let mut m = self.cache.lock().expect("meta cache poisoned");
        for p in paths {
            for key in [*p, parent_of(p)] {
                m.stats.remove(key);
                m.lists.remove(key);
            }
        }
    }

    /// Delete and rename can affect whole subtrees: drop everything.
    fn invalidate_all(&self) {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        let mut m = self.cache.lock().expect("meta cache poisoned");
        m.stats.clear();
        m.lists.clear();
    }
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

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

/// The connection to the receiver: pool, compression, time budgets, the degraded-peer logic.
/// Shared by the backend's foreground operations and by the uploader.
pub(crate) struct Link {
    /// Connection pool, never empty; calls are spread round-robin.
    clients: Vec<BandTransportClient<Channel>>,
    /// The same pool sending zstd-compressed requests, and whether to use it.
    zstd_clients: Vec<BandTransportClient<Channel>>,
    zstd: Arc<AtomicBool>,
    zstd_allowed: bool,
    zstd_probed: AtomicBool,
    zstd_next_probe: Mutex<Option<Instant>>,
    next_client: AtomicUsize,
    retry: RetryPolicy,
    pub(crate) timeouts: Timeouts,
    /// When a call last timed out (a silent peer); cleared by the next success. Errors the receiver
    /// or the network report promptly (refused connection, `UNAVAILABLE`) do not set it.
    degraded: Mutex<Option<Instant>>,
}

impl Link {
    fn new(client: BandTransportClient<Channel>) -> Link {
        Link {
            clients: vec![client],
            zstd_clients: Vec::new(),
            zstd: Arc::new(AtomicBool::new(false)),
            zstd_allowed: false,
            zstd_probed: AtomicBool::new(false),
            zstd_next_probe: Mutex::new(None),
            next_client: AtomicUsize::new(0),
            retry: RetryPolicy::default(),
            timeouts: Timeouts::default(),
            degraded: Mutex::new(None),
        }
    }

    /// Ask the receiver (`Ping`) whether it can read zstd-compressed requests. Done until it
    /// has answered once; after a failed probe the next one waits `PROBE_RETRY` so that a
    /// silent receiver is not asked on every call.
    async fn probe_compression(&self) {
        const PROBE_RETRY: Duration = Duration::from_secs(10);
        const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
        if !self.zstd_allowed || self.zstd_probed.load(Ordering::Acquire) {
            return;
        }
        {
            let mut next = self.zstd_next_probe.lock().expect("probe poisoned");
            if next.is_some_and(|t| Instant::now() < t) {
                return;
            }
            *next = Some(Instant::now() + PROBE_RETRY);
        }
        let mut c = self.clients[0].clone();
        let ping = c.ping(pb::PingRequest {
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        });
        if let Ok(Ok(r)) =
            tokio::time::timeout(PROBE_TIMEOUT.min(self.timeouts.request), ping).await
        {
            self.zstd_probed.store(true, Ordering::Release);
            if crate::remote::accepts_zstd(r.metadata()) {
                self.zstd.store(true, Ordering::Relaxed);
            }
        }
    }

    fn pick_client(&self) -> BandTransportClient<Channel> {
        let i = self.next_client.fetch_add(1, Ordering::Relaxed);
        if self.zstd.load(Ordering::Relaxed) && !self.zstd_clients.is_empty() {
            return self.zstd_clients[i % self.zstd_clients.len()].clone();
        }
        self.clients[i % self.clients.len()].clone()
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
        if !degraded {
            self.probe_compression().await;
        }
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
            let outcome =
                match tokio::time::timeout(per_attempt.min(left), call(self.pick_client())).await {
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

    async fn fsync_remote(&self, path: Option<&str>) -> Result<()> {
        self.rpc(true, false, |mut c| {
            let req = pb::FsyncRequest {
                scope: Some(match path {
                    Some(p) => fsync_request::Scope::File(pb::FileRef {
                        rel_path: p.to_owned(),
                    }),
                    None => fsync_request::Scope::AllBundle(true),
                }),
            };
            async move { c.fsync(req).await }
        })
        .await?;
        Ok(())
    }
}

fn classify(e: BackendError) -> UploadFail {
    match e {
        BackendError::RemoteUnavailable | BackendError::Busy => {
            UploadFail::Transient("receiver unavailable".into())
        }
        BackendError::NoSpace => UploadFail::Permanent(Sticky::NoSpace),
        BackendError::AccessDenied => UploadFail::Permanent(Sticky::AccessDenied),
        other => UploadFail::Permanent(Sticky::Other(format!("receiver error: {other:?}"))),
    }
}

/// What the uploader talks to: the link, plus the cache invalidation a finished upload needs
/// (the receiver-side size and mtime of the file changed).
struct LinkTarget {
    link: Arc<Link>,
    meta: Arc<Meta>,
}

impl UploadTarget for LinkTarget {
    fn write_range<'a>(
        &'a self,
        path: &'a str,
        offset: u64,
        data: Vec<u8>,
        write_id: u64,
    ) -> BoxFut<'a, std::result::Result<(), UploadFail>> {
        Box::pin(async move {
            // Repeating a WriteRange is safe (same offset, same bytes).
            let r = self
                .link
                .rpc(true, true, |mut c| {
                    let req = pb::WriteRangeRequest {
                        file: file_ref(path),
                        offset,
                        data: data.clone(),
                        write_id,
                    };
                    async move { c.write_range(req).await }
                })
                .await;
            self.meta.invalidate(&[path]);
            r.map(|_| ()).map_err(classify)
        })
    }

    fn fsync<'a>(
        &'a self,
        path: Option<&'a str>,
    ) -> BoxFut<'a, std::result::Result<(), UploadFail>> {
        Box::pin(async move { self.link.fsync_remote(path).await.map_err(classify) })
    }
}

/// Journal tunables that may change on reconfiguration.
#[derive(Debug, Clone, Copy)]
pub struct JournalSettings {
    /// Unuploaded data the journal may hold.
    pub max_backlog: u64,
    /// `LOCAL_JOURNAL`: `flush` only fsyncs the journal. Unsafe for backups.
    pub local_journal: bool,
}

/// The journal and its uploader. Shared by the backend generations of `SwitchBackend`
/// (a reconfiguration keeps the journal and just points the uploader at the new link).
pub struct JournalRuntime {
    pub journal: Arc<Journal>,
    pub uploader: UploaderHandle,
    settings: RwLock<JournalSettings>,
    dir: PathBuf,
    /// Set when the journal was reopened with fsync (`LOCAL_JOURNAL`).
    durable: bool,
    /// Who the unuploaded bytes belong to (see `destination_of`); empty = not tracked.
    /// Mirrors the `destination` file in the journal directory.
    destination: Mutex<String>,
}

/// Name of the file in the journal directory that remembers the journal's destination.
const DESTINATION_FILE: &str = "destination";

impl JournalRuntime {
    fn open(
        dir: &Path,
        settings: JournalSettings,
        target: Arc<dyn UploadTarget>,
        destination: &str,
    ) -> std::io::Result<Arc<JournalRuntime>> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(std::io::Error::other("the journal needs a tokio runtime"));
        }
        let (journal, report) = Journal::open(
            dir,
            JournalOptions {
                durable: settings.local_journal,
                exclude_from_backups: true,
                ..Default::default()
            },
        )?;
        // Unuploaded bytes recovered from disk belong to the destination they were written
        // for; they must not silently flow to a different receiver (another machine's store).
        // Checked before the uploader starts.
        check_destination(dir, destination, report.replayed_bytes)?;
        if report.replayed_bytes > 0
            || report.dropped_tail_bytes > 0
            || !report.corrupt_segments.is_empty()
        {
            jlog!(
                Info,
                "backend",
                "journal {} recovered: {} unuploaded bytes in {} records, \
                 {} torn bytes dropped, corrupt segments {:?}",
                dir.display(),
                report.replayed_bytes,
                report.replayed_records,
                report.dropped_tail_bytes,
                report.corrupt_segments
            );
        }
        let journal = Arc::new(journal);
        let uploader =
            UploaderHandle::start(Arc::clone(&journal), target, UploaderConfig::default());
        Ok(Arc::new(JournalRuntime {
            journal,
            uploader,
            settings: RwLock::new(settings),
            dir: dir.to_owned(),
            durable: settings.local_journal,
            destination: Mutex::new(destination.to_owned()),
        }))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Switch the journal to a new destination. Refused while it holds unuploaded bytes
    /// (they belong to the old receiver); with an empty journal the destination is simply
    /// recorded. `Ok(true)` = the destination really changed.
    pub fn retarget(&self, destination: &str) -> std::io::Result<bool> {
        let mut cur = self.destination.lock().expect("destination poisoned");
        if *cur == destination {
            return Ok(false);
        }
        let pending = self.journal.live_bytes();
        if pending > 0 && !cur.is_empty() {
            return Err(destination_changed_error(&self.dir, pending, &cur));
        }
        if !destination.is_empty() {
            write_destination(&self.dir, destination)?;
        }
        *cur = destination.to_owned();
        Ok(true)
    }

    pub fn settings(&self) -> JournalSettings {
        *self.settings.read().expect("settings poisoned")
    }

    pub fn stats(&self) -> UploaderStats {
        self.uploader.stats()
    }

    /// Wait until everything reached the receiver and was fsynced there. `(drained, remaining
    /// bytes)`.
    pub async fn drain(&self, timeout: Duration) -> (bool, u64) {
        match self.uploader.drain_barrier(Instant::now() + timeout).await {
            Ok(()) => (true, 0),
            Err(_) => (false, self.journal.live_bytes()),
        }
    }
}

fn map_upload_err(e: UploadError) -> BackendError {
    match e {
        UploadError::RemoteUnavailable | UploadError::Timeout => BackendError::RemoteUnavailable,
        UploadError::Sticky(Sticky::NoSpace) => BackendError::NoSpace,
        UploadError::Sticky(Sticky::AccessDenied) => BackendError::AccessDenied,
        UploadError::Sticky(Sticky::Other(m)) => BackendError::Io(std::io::Error::other(m)),
        UploadError::Journal(m) => BackendError::Io(std::io::Error::other(m)),
    }
}

async fn statfs_via(link: &Link, fallback_quota: u64) -> Result<FsStats> {
    let r = link
        .rpc(true, false, |mut c| async move {
            c.stat_fs(pb::StatFsRequest {}).await
        })
        .await?;
    Ok(FsStats {
        quota_bytes: if r.quota_bytes == 0 {
            fallback_quota
        } else {
            r.quota_bytes
        },
        used_bytes: r.used_bytes,
    })
}

/// `(when, the answer or None if the receiver could not be asked, bytes uploaded by then)`.
/// Identity of the receiver a share sends to: the endpoint (without scheme) plus the client
/// identity, i.e. a hash of the client certificate file (or the Keychain reference). A change
/// of either may mean another machine's store on the receiver, so the journal treats it as a
/// different destination.
pub fn destination_of(share: &crate::config::ShareConfig) -> String {
    use sha2::{Digest, Sha256};
    let endpoint = share
        .appliance_endpoint
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let identity = if !share.client_cert_path.is_empty() {
        match std::fs::read(&share.client_cert_path) {
            Ok(bytes) => Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            // unreadable now: the connection will fail anyway; keep the path as the identity
            Err(_) => format!("path:{}", share.client_cert_path),
        }
    } else if !share.tls_identity_ref.is_empty() {
        format!("ref:{}", share.tls_identity_ref)
    } else {
        "plain".to_owned()
    };
    format!("{endpoint}|{identity}")
}

fn destination_changed_error(dir: &Path, pending: u64, old: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "the journal {} holds {pending} unuploaded bytes for another destination ({old}); \
         let them upload first (janus-cli client drain), or use another journal directory",
        dir.display()
    ))
}

fn write_destination(dir: &Path, destination: &str) -> std::io::Result<()> {
    crate::journal::write_atomic(&dir.join(DESTINATION_FILE), destination.as_bytes(), true)
}

/// Compare the journal directory's recorded destination with `destination`. Unuploaded bytes
/// (`pending`) for a different destination are an error; an empty journal, or one without a
/// record (created before records existed, or brand new), just takes the new destination.
fn check_destination(dir: &Path, destination: &str, pending: u64) -> std::io::Result<()> {
    if destination.is_empty() {
        return Ok(());
    }
    match std::fs::read_to_string(dir.join(DESTINATION_FILE)) {
        Ok(old) => {
            let old = old.trim();
            if old == destination {
                return Ok(());
            }
            if pending > 0 {
                return Err(destination_changed_error(dir, pending, old));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_destination(dir, destination)
}

type QuotaCache = Option<(Instant, Option<FsStats>, u64)>;

/// How long a cached `statfs` may be used for the quota check of a write.
const QUOTA_TTL: Duration = Duration::from_secs(5);

pub struct GrpcBackend {
    link: Arc<Link>,
    /// Used when the receiver reports "no quota" (0).
    fallback_quota: u64,
    next_handle: AtomicU64,
    next_write_id: AtomicU64,
    handles: Mutex<HashMap<u64, Arc<HandleEntry>>>,
    meta: Arc<Meta>,
    journal: Option<Arc<JournalRuntime>>,
    /// `(when, answer)` of the last `statfs` taken for a quota check; `None` = it failed.
    quota_cache: Arc<Mutex<QuotaCache>>,
    quota_refreshing: Arc<AtomicBool>,
    /// Who this backend talks to (see `destination_of`); empty = not tracked.
    destination: String,
}

impl GrpcBackend {
    pub fn new(client: BandTransportClient<Channel>, fallback_quota: u64) -> GrpcBackend {
        GrpcBackend {
            link: Arc::new(Link::new(client)),
            fallback_quota: if fallback_quota == 0 {
                DEFAULT_QUOTA
            } else {
                fallback_quota
            },
            next_handle: AtomicU64::new(1),
            next_write_id: AtomicU64::new(1),
            handles: Mutex::new(HashMap::new()),
            meta: Arc::new(Meta::default()),
            journal: None,
            quota_cache: Arc::default(),
            quota_refreshing: Arc::default(),
            destination: String::new(),
        }
    }

    /// Name the receiver this backend sends to (`destination_of`). Set before `with_journal`:
    /// the journal remembers whom its unuploaded bytes belong to and refuses to hand them to
    /// another destination.
    pub fn with_destination(mut self, destination: impl Into<String>) -> Self {
        self.destination = destination.into();
        self
    }

    /// Forget every open handle: they were opened for a destination this backend must no
    /// longer write to. Operations on them fail with `BadHandle`.
    pub fn retire_handles(&self) {
        self.handles.lock().expect("handle table poisoned").clear();
    }

    fn link_mut(&mut self) -> &mut Link {
        Arc::get_mut(&mut self.link).expect("configure the link before enabling the journal")
    }

    pub fn from_remote(remote: &RemoteClient, fallback_quota: u64) -> GrpcBackend {
        let mut b =
            GrpcBackend::new(remote.transport(), fallback_quota).with_timeouts(remote.timeouts());
        let l = b.link_mut();
        l.clients = remote.transports();
        (l.zstd_clients, l.zstd) = remote.compressed_transports();
        l.zstd_allowed = remote.compression_allowed();
        b
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.link_mut().timeouts = timeouts;
        self
    }

    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.link_mut().retry = retry;
        self
    }

    fn target(&self) -> Arc<dyn UploadTarget> {
        Arc::new(LinkTarget {
            link: Arc::clone(&self.link),
            meta: Arc::clone(&self.meta),
        })
    }

    /// Enable the write-ahead journal in `dir` (recovering whatever it holds). Call after the
    /// link is configured, inside a tokio runtime.
    pub fn with_journal(mut self, dir: &Path, settings: JournalSettings) -> std::io::Result<Self> {
        self.journal = Some(JournalRuntime::open(
            dir,
            settings,
            self.target(),
            &self.destination,
        )?);
        Ok(self)
    }

    /// Continue with the journal of a previous generation: the uploader now sends through this
    /// backend's link.
    pub fn with_journal_runtime(
        mut self,
        rt: Arc<JournalRuntime>,
        settings: JournalSettings,
    ) -> Self {
        *rt.settings.write().expect("settings poisoned") = settings;
        rt.uploader.set_target(self.target());
        self.journal = Some(rt);
        self
    }

    pub fn journal_runtime(&self) -> Option<&Arc<JournalRuntime>> {
        self.journal.as_ref()
    }

    /// Requests are being sent zstd-compressed (the receiver said it can read them).
    pub fn compressing(&self) -> bool {
        self.link.zstd.load(Ordering::Relaxed)
    }

    fn invalidate(&self, paths: &[&str]) {
        self.meta.invalidate(paths);
    }

    async fn rpc<T, F, Fut>(&self, idempotent: bool, bulk: bool, call: F) -> Result<T>
    where
        F: Fn(BandTransportClient<Channel>) -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, Status>>,
    {
        self.link.rpc(idempotent, bulk, call).await
    }

    async fn within<T>(&self, op: impl Future<Output = Result<T>>) -> Result<T> {
        self.link.within(op).await
    }

    async fn bundle(
        &self,
        idempotent: bool,
        op: bundle_op_request::Op,
    ) -> Result<bundle_op_reply::Result> {
        let path_of = |f: &Option<pb::FileRef>| f.as_ref().map(|f| f.rel_path.clone());
        let touched: Option<Option<String>> = match &op {
            bundle_op_request::Op::Create(o) => Some(path_of(&o.file)),
            bundle_op_request::Op::Truncate(o) => Some(path_of(&o.file)),
            bundle_op_request::Op::SetTimes(o) => Some(path_of(&o.file)),
            bundle_op_request::Op::Delete(_) | bundle_op_request::Op::Rename(_) => Some(None),
            _ => None,
        };
        let outcome = self
            .rpc(idempotent, false, |mut c| {
                let op = op.clone();
                async move { c.bundle_op(pb::BundleOpRequest { op: Some(op) }).await }
            })
            .await;
        match touched {
            Some(Some(p)) => self.invalidate(&[&p]),
            Some(None) => self.meta.invalidate_all(),
            None => {}
        }
        let reply = outcome?;
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

    /// Size of a file as the client sees it: what the receiver has, or more if unuploaded
    /// writes extend it.
    fn overlay_size(&self, path: &str, st: &mut FileStat) {
        if st.directory {
            return;
        }
        if let Some(rt) = &self.journal
            && let Some(id) = rt.journal.file_id(path)
            && let Some(end) = rt.journal.dirty_end(id)
        {
            st.size = st.size.max(end);
        }
    }

    async fn stat_path(&self, rel: &str) -> Result<FileStat> {
        let mut st = self.stat_path_remote(rel).await?;
        self.overlay_size(rel, &mut st);
        Ok(st)
    }

    async fn stat_path_remote(&self, rel: &str) -> Result<FileStat> {
        let hit = {
            let m = self.meta.cache.lock().expect("meta cache poisoned");
            m.stats
                .get(rel)
                .filter(|(at, _)| at.elapsed() < META_TTL)
                .map(|(_, s)| s.clone())
        };
        match hit {
            Some(Some(s)) => return Ok(s),
            Some(None) => return Err(BackendError::NotFound),
            None => {}
        }
        let epoch = self.meta.mutations.load(Ordering::SeqCst);
        let fetched = self.stat_path_uncached(rel).await;
        let entry = match &fetched {
            Ok(s) => Some(Some(s.clone())),
            Err(BackendError::NotFound) => Some(None),
            Err(_) => None,
        };
        if let Some(entry) = entry
            && self.meta.mutations.load(Ordering::SeqCst) == epoch
        {
            let mut m = self.meta.cache.lock().expect("meta cache poisoned");
            if m.stats.len() >= META_MAX_STATS {
                m.stats.clear();
            }
            m.stats.insert(rel.to_owned(), (Instant::now(), entry));
        }
        fetched
    }

    async fn stat_path_uncached(&self, rel: &str) -> Result<FileStat> {
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
    // ---- journal helpers -----------------------------------------------------------

    fn deadline(&self) -> Instant {
        Instant::now() + self.link.timeouts.budget
    }

    /// Data → metadata ordering: wait until the unuploaded writes made so far to the file or
    /// directory tree at `path` reached the receiver.
    async fn settle_uploaded(&self, path: &str) -> Result<()> {
        let Some(rt) = &self.journal else {
            return Ok(());
        };
        let ids = rt.journal.dirty_files_under(path);
        if ids.is_empty() {
            return Ok(());
        }
        // The same long wait as a flush: the file's data has to be there first.
        rt.uploader
            .wait_uploaded_unless_down(
                &ids,
                Instant::now() + self.link.timeouts.barrier,
                Some(self.link.timeouts.barrier_down_after),
            )
            .await
            .map_err(map_upload_err)
    }

    /// The file is going away (or is truncated to nothing): its unuploaded bytes are
    /// discarded, durably, and batches already on the wire are waited for so that none lands
    /// after the receiver-side change.
    async fn settle_discard(&self, path: &str) -> Result<()> {
        let Some(rt) = &self.journal else {
            return Ok(());
        };
        let Some(id) = rt.journal.file_id(path) else {
            return Ok(());
        };
        rt.journal.drop_from(id, 0).map_err(BackendError::Io)?;
        rt.uploader
            .forget_file(id, self.deadline())
            .await
            .map_err(map_upload_err)
    }

    async fn statfs_remote(&self) -> Result<FsStats> {
        statfs_via(&self.link, self.fallback_quota).await
    }

    fn refresh_quota_in_background(&self, uploaded: u64) {
        if self.quota_refreshing.swap(true, Ordering::AcqRel) {
            return;
        }
        let (link, cache, flag, fallback) = (
            Arc::clone(&self.link),
            Arc::clone(&self.quota_cache),
            Arc::clone(&self.quota_refreshing),
            self.fallback_quota,
        );
        tokio::spawn(async move {
            let fresh = statfs_via(&link, fallback).await.ok();
            let mut c = cache.lock().expect("quota cache poisoned");
            // keep the last good answer if the receiver cannot be asked now
            let keep = fresh.or(c.as_ref().and_then(|x| x.1));
            *c = Some((Instant::now(), keep, uploaded));
            flag.store(false, Ordering::Release);
        });
    }

    /// `NoSpace` right away if the receiver's usage plus the unuploaded backlog plus this
    /// write would exceed the quota: Time Machine has to get its thinning signal while it is
    /// still writing, not at the fsync. Works from a cached `statfs` (filled by `statfs`, which
    /// Time Machine calls all the time, or refreshed in the background), so a write never waits
    /// for a dead receiver. Without an answer the write is let through (the uploader reports
    /// the real error).
    fn check_quota(&self, rt: &JournalRuntime, len: u64) -> Result<()> {
        let uploaded = rt.uploader.uploaded_bytes_total();
        let cached = *self.quota_cache.lock().expect("quota cache poisoned");
        let (stats, uploaded_then) = match cached {
            None => {
                self.refresh_quota_in_background(uploaded);
                (None, uploaded)
            }
            Some((at, s, up)) => {
                if at.elapsed() >= QUOTA_TTL {
                    self.refresh_quota_in_background(uploaded);
                }
                (s, up)
            }
        };
        let Some(s) = stats else {
            return Ok(());
        };
        // used(then) + backlog(now) + what was uploaded since = total now, without counting
        // the bytes that moved from the backlog to the receiver in between twice.
        let uploaded_since = uploaded.saturating_sub(uploaded_then);
        let total = s
            .used_bytes
            .saturating_add(rt.journal.live_bytes())
            .saturating_add(uploaded_since)
            .saturating_add(len);
        if total > s.quota_bytes {
            return Err(BackendError::NoSpace);
        }
        Ok(())
    }

    fn overlay_list(&self, dir: &str, entries: &mut [FileStat]) {
        let Some(rt) = &self.journal else {
            return;
        };
        if !rt.journal.has_any_dirty() {
            return;
        }
        let ends = rt.journal.dirty_ends_in(dir);
        for e in entries.iter_mut().filter(|e| !e.directory) {
            if let Some(end) = ends.get(&e.rel_path) {
                e.size = e.size.max(*end);
            }
        }
    }

    // ---- operations ----------------------------------------------------------------

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
                        self.settle_discard(&rel).await?;
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

    /// Plain read from the receiver, in 1 MiB calls.
    async fn remote_read(&self, path: &str, offset: u64, want: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(want.min(4 * MAX_CHUNK));
        while out.len() < want {
            let chunk = (want - out.len()).min(MAX_CHUNK);
            let pos = offset + out.len() as u64;
            let reply = self
                .rpc(true, true, |mut c| {
                    let req = pb::ReadRangeRequest {
                        file: file_ref(path),
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

    async fn read_inner(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let e = self.entry(h)?;
        if e.directory {
            return Err(BackendError::IsADirectory);
        }
        let path = e.path();
        // Never let offset+len pass u64::MAX: such a read is simply short.
        let want = (len as u64).min(u64::MAX - offset) as usize;
        if let Some(rt) = &self.journal
            && let Some(id) = rt.journal.file_id(&path)
            && rt.journal.has_dirty(id)
        {
            let chunks = rt
                .journal
                .read_overlay(id, offset, want as u64)
                .map_err(BackendError::Io)?;
            let dirty_end = rt.journal.dirty_end(id).unwrap_or(0);
            return self.assemble(&path, chunks, dirty_end).await;
        }
        self.remote_read(&path, offset, want).await
    }

    /// Merge journal pieces with what the receiver has for the holes between them. A hole
    /// that is short because the receiver's file ends there, but lies below the end of the
    /// unuploaded data, is a gap in a sparse file and reads as zeros; past that it is the end
    /// of the file.
    async fn assemble(&self, path: &str, chunks: Vec<Chunk>, dirty_end: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for c in &chunks {
            match c {
                Chunk::Wal { data, .. } => out.extend_from_slice(data),
                Chunk::Missing { offset, len } => {
                    let got = self.remote_read(path, *offset, *len as usize).await?;
                    out.extend_from_slice(&got);
                    if (got.len() as u64) < *len {
                        let end = offset + len;
                        let upto = (offset + got.len() as u64).max(dirty_end.min(end));
                        out.resize(out.len() + (upto - offset - got.len() as u64) as usize, 0);
                        if upto < end {
                            break;
                        }
                    }
                }
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
        if let Some(rt) = &self.journal {
            return self.write_journaled(rt, &path, offset, data).await;
        }
        let written = async {
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
        .await;
        // Size and mtime changed (even a failed write may have landed partly).
        self.invalidate(&[&path]);
        written
    }

    /// Journal mode: quota check, backpressure, append, acknowledge. The uploader does the rest.
    async fn write_journaled(
        &self,
        rt: &Arc<JournalRuntime>,
        path: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<()> {
        self.check_quota(rt, data.len() as u64)?;
        // A full backlog is backpressure, never DISK_FULL (that means the receiver is out of
        // space): wait for the uploader, then give up with a network error.
        rt.uploader
            .wait_for_room(
                rt.settings().max_backlog,
                data.len() as u64,
                self.deadline(),
            )
            .await
            .map_err(map_upload_err)?;
        let id = rt.journal.intern(path);
        rt.uploader.clear_sticky(id);
        rt.journal
            .append(id, offset, data)
            .map_err(BackendError::Io)?;
        rt.uploader.kick();
        Ok(())
    }

    /// Make the file's data safe: `SYNC_THROUGH` waits for the receiver (and its fsync),
    /// `LOCAL_JOURNAL` only fsyncs the journal.
    async fn sync_file(&self, rt: &Arc<JournalRuntime>, path: &str) -> Result<()> {
        if rt.settings().local_journal {
            return rt.journal.sync().map_err(BackendError::Io);
        }
        let id = rt.journal.intern(path);
        rt.uploader
            .flush_barrier_unless_down(
                id,
                Instant::now() + self.link.timeouts.barrier,
                Some(self.link.timeouts.barrier_down_after),
            )
            .await
            .map_err(map_upload_err)
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
        if let Some(rt) = &self.journal {
            if !e.writable {
                return Ok(());
            }
            return self.sync_file(rt, &path).await;
        }
        // Sync-through: F_FULLFSYNC and plain flush both wait for the receiver's fsync.
        self.link.fsync_remote(Some(&path)).await
    }

    async fn close(&self, h: BackendHandle) -> Result<()> {
        let e = self
            .handles
            .lock()
            .expect("handle table poisoned")
            .remove(&h.0)
            .ok_or(BackendError::BadHandle)?;
        let path = e.path();
        if e.delete_on_close.load(Ordering::Relaxed) {
            // The handle is gone either way; if the receiver is unreachable the delete is
            // reported as failed and not retried.
            self.settle_discard(&path).await?;
            self.bundle_ok(
                false,
                bundle_op_request::Op::Delete(pb::DeleteOp {
                    file: file_ref(&path),
                    non_recursive: true,
                }),
            )
            .await?;
        } else if let Some(rt) = &self.journal
            && e.writable
            && !e.directory
            && rt
                .journal
                .file_id(&path)
                .is_some_and(|id| rt.journal.has_dirty(id))
        {
            // Closing a file with unuploaded data is a barrier; its upload error surfaces here.
            self.sync_file(rt, &path).await?;
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        let (src, dst) = (normalize(from)?, normalize(to)?);
        if let Some(rt) = &self.journal {
            // Data first: the source's bytes reach the receiver under the old name, and a
            // restart must not replay them under it afterwards.
            self.settle_uploaded(&src).await?;
            if replace {
                // The target's unuploaded bytes are NOT discarded up front: if the receiver
                // then refuses the rename (missing source, network error), the target still
                // exists and those writes would be lost. They are uploaded first and simply
                // replaced by the rename; the cost is some wasted upload, never data loss.
                self.settle_uploaded(&dst).await?;
            }
            rt.journal.forget_under(&src).map_err(BackendError::Io)?;
        }
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
        let path = e.path();
        if let Some(rt) = &self.journal {
            if let Some(id) = rt.journal.file_id(&path) {
                rt.uploader.mark_unsynced(id);
            }
            if new_len == 0 {
                self.settle_discard(&path).await?;
            } else {
                self.settle_uploaded(&path).await?;
                if let Some(id) = rt.journal.file_id(&path) {
                    rt.journal
                        .drop_from(id, new_len)
                        .map_err(BackendError::Io)?;
                }
            }
        }
        self.bundle_ok(
            true,
            bundle_op_request::Op::Truncate(pb::TruncateOp {
                file: file_ref(&path),
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
        let path = e.path();
        // The receiver's mtime moves with every upload: set it after the data is there.
        self.settle_uploaded(&path).await?;
        if let Some(rt) = &self.journal
            && let Some(id) = rt.journal.file_id(&path)
        {
            rt.uploader.mark_unsynced(id);
        }
        self.bundle_ok(
            true,
            bundle_op_request::Op::SetTimes(pb::SetTimesOp {
                file: file_ref(&path),
                atime_unix_ns: times.atime_unix_ns,
                mtime_unix_ns: times.mtime_unix_ns,
            }),
        )
        .await
    }

    async fn list(&self, rel_dir: &str) -> Result<Vec<FileStat>> {
        let dir = normalize(rel_dir)?;
        {
            let m = self.meta.cache.lock().expect("meta cache poisoned");
            if let Some((at, v)) = m.lists.get(&dir)
                && at.elapsed() < META_TTL
            {
                let mut v = v.clone();
                drop(m);
                self.overlay_list(&dir, &mut v);
                return Ok(v);
            }
        }
        let epoch = self.meta.mutations.load(Ordering::SeqCst);
        let out = match self
            .bundle(
                true,
                bundle_op_request::Op::List(pb::ListOp {
                    rel_dir: dir.clone(),
                }),
            )
            .await?
        {
            bundle_op_reply::Result::Listing(l) => {
                let mut out: Vec<FileStat> = l.entries.into_iter().map(stat_from_proto).collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                out
            }
            other => return Err(unexpected(other)),
        };
        if out.len() <= META_MAX_LISTING_LEN && self.meta.mutations.load(Ordering::SeqCst) == epoch
        {
            let mut m = self.meta.cache.lock().expect("meta cache poisoned");
            if m.lists.len() >= META_MAX_LISTINGS {
                m.lists.clear();
            }
            m.lists.insert(dir.clone(), (Instant::now(), out.clone()));
        }
        let mut out = out;
        self.overlay_list(&dir, &mut out);
        Ok(out)
    }

    async fn stat(&self, rel_path: &str) -> Result<FileStat> {
        self.stat_path(&normalize(rel_path)?).await
    }

    async fn statfs(&self) -> Result<FsStats> {
        let Some(rt) = &self.journal else {
            return self.statfs_remote().await;
        };
        // used = what the receiver has + what is still in the journal. The two move into each
        // other as batches are acknowledged, so sample them while nothing is in flight.
        let mut fs = self.statfs_remote().await?;
        for _ in 0..3 {
            let settle = Instant::now() + Duration::from_millis(200);
            while rt.uploader.inflight() > 0 && Instant::now() < settle {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let before = rt.uploader.uploaded_bytes_total();
            fs = self.statfs_remote().await?;
            if rt.uploader.uploaded_bytes_total() == before && rt.uploader.inflight() == 0 {
                break;
            }
        }
        // what the quota check works from: the receiver's own usage
        *self.quota_cache.lock().expect("quota cache poisoned") =
            Some((Instant::now(), Some(fs), rt.uploader.uploaded_bytes_total()));
        fs.used_bytes = fs.used_bytes.saturating_add(rt.journal.live_bytes());
        Ok(fs)
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
