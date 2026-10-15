//! Implementation of the `BandTransport` gRPC service on top of `FileStore`.
//!
//! MILESTONE (dev): one store per process, no mTLS and no per-machine routing.
//! UPGRADE: Router + IdentityMap (cert → machine → store) + a network-less StoreWorker
//! (see README, the "janus-receiverd" section).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use janus_proto::v1::band_transport_server::BandTransport;
use janus_proto::v1::{
    BundleOpReply, BundleOpRequest, DirListing, FileStat, FsyncReply, FsyncRequest, PingReply,
    PingRequest, ReadRangeReply, ReadRangeRequest, StatFsReply, StatFsRequest, WriteRangeReply,
    WriteRangeRequest, bundle_op_reply, bundle_op_request, fsync_request,
};
use tonic::{Request, Response, Status};

use crate::worker::{ErrClass, FileStore, FsyncScope, StatInfo};

/// How long a computed "used bytes" figure is trusted.
const USED_TTL: Duration = Duration::from_secs(2);

/// Cache of the store's used bytes. Walking the tree on every write would be O(files); instead
/// the figure is refreshed at most every `USED_TTL`, grows by the size of each accepted write
/// (an over-estimate for overwrites, so quota checks err on the strict side), and is dropped
/// by anything that can shrink the store.
#[derive(Default)]
struct UsedCache {
    /// (computed at, bytes, exact since the last walk: no writes counted on top)
    state: Mutex<Option<(Instant, u64, bool)>>,
}

impl UsedCache {
    fn get(&self, store: &FileStore, need_exact: bool) -> std::io::Result<u64> {
        {
            let st = self.state.lock().expect("used cache poisoned");
            if let Some((at, bytes, exact)) = *st
                && at.elapsed() < USED_TTL
                && (exact || !need_exact)
            {
                return Ok(bytes);
            }
        }
        let bytes = store.used_bytes()?;
        *self.state.lock().expect("used cache poisoned") = Some((Instant::now(), bytes, true));
        Ok(bytes)
    }

    fn added(&self, n: u64) {
        if let Some((_, bytes, exact)) = self.state.lock().expect("used cache poisoned").as_mut() {
            *bytes = bytes.saturating_add(n);
            *exact = false;
        }
    }

    fn invalidate(&self) {
        *self.state.lock().expect("used cache poisoned") = None;
    }
}

/// A service on top of a single store (one machine). The quota is the ceiling for StatFs and
/// for writes (0 = no limit).
pub struct BandTransportService {
    store: Arc<FileStore>,
    quota_bytes: u64,
    used: UsedCache,
    last_activity_ms: AtomicI64,
}

impl BandTransportService {
    pub fn new(store: Arc<FileStore>, quota_bytes: u64) -> Self {
        BandTransportService {
            store,
            quota_bytes,
            used: UsedCache::default(),
            last_activity_ms: AtomicI64::new(0),
        }
    }

    pub fn store(&self) -> &Arc<FileStore> {
        &self.store
    }

    pub fn quota_bytes(&self) -> u64 {
        self.quota_bytes
    }

    /// Used bytes for reporting (exact when the cache is fresh and no write was added).
    pub fn used_bytes(&self) -> std::io::Result<u64> {
        self.used.get(&self.store, true)
    }

    /// Unix ms of the last request, 0 = none yet.
    pub fn last_activity_unix_ms(&self) -> i64 {
        self.last_activity_ms.load(Ordering::Relaxed)
    }

    fn touch(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.last_activity_ms.store(now, Ordering::Relaxed);
    }
}

/// Trailing-metadata key with the fine-grained error class (see the proto header).
pub const ERROR_CLASS_KEY: &str = "janus-error";

fn with_class(mut st: Status, class: &'static str) -> Status {
    st.metadata_mut()
        .insert(ERROR_CLASS_KEY, class.parse().expect("ascii"));
    st
}

/// io::Error → gRPC Status preserving the error class: the client decides by the code
/// whether to retry or fail (NotFound/AlreadyExists/PermissionDenied: do not retry).
pub(crate) fn io_to_status(e: std::io::Error) -> Status {
    use std::io::ErrorKind::*;
    if e.get_ref()
        .and_then(|i| i.downcast_ref::<ErrClass>())
        .is_some()
    {
        return with_class(Status::not_found(e.to_string()), "path-not-found");
    }
    match e.kind() {
        NotFound => Status::not_found(e.to_string()),
        AlreadyExists => Status::already_exists(e.to_string()),
        PermissionDenied => Status::permission_denied(e.to_string()),
        NotADirectory => with_class(
            Status::failed_precondition(e.to_string()),
            "not-a-directory",
        ),
        IsADirectory => with_class(Status::failed_precondition(e.to_string()), "is-a-directory"),
        DirectoryNotEmpty => with_class(Status::failed_precondition(e.to_string()), "not-empty"),
        StorageFull | QuotaExceeded => Status::resource_exhausted(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

fn stat_to_proto(s: StatInfo) -> FileStat {
    FileStat {
        rel_path: s.rel_path,
        size: s.size,
        directory: s.directory,
        mtime_unix_ns: s.mtime_unix_ns,
        atime_unix_ns: s.atime_unix_ns,
        ctime_unix_ns: s.ctime_unix_ns,
        btime_unix_ns: s.btime_unix_ns,
        read_only: s.read_only,
        file_id: s.file_id,
    }
}

/// Contract limit of one `WriteRange`/`ReadRange` payload.
pub const MAX_CHUNK: usize = 1 << 20;

/// Wire protocol revision implemented by this receiver (see `PingReply.proto_rev`).
pub const PROTO_REV: u32 = 2;

#[tonic::async_trait]
impl BandTransport for BandTransportService {
    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        self.touch();
        let _client = req.into_inner().client_version;
        Ok(Response::new(PingReply {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            proto_rev: PROTO_REV,
        }))
    }

    async fn stat_fs(&self, _req: Request<StatFsRequest>) -> Result<Response<StatFsReply>, Status> {
        self.touch();
        let used = self.used_bytes().map_err(io_to_status)?;
        Ok(Response::new(StatFsReply {
            quota_bytes: self.quota_bytes,
            used_bytes: used,
        }))
    }

    async fn write_range(
        &self,
        req: Request<WriteRangeRequest>,
    ) -> Result<Response<WriteRangeReply>, Status> {
        let r = req.into_inner();
        let file = r
            .file
            .ok_or_else(|| Status::invalid_argument("file is required"))?;
        if r.data.len() > MAX_CHUNK {
            return Err(Status::invalid_argument("WriteRange data exceeds 1 MiB"));
        }
        // Quota: exceeding it → resource_exhausted (the client maps it to STATUS_DISK_FULL).
        if self.quota_bytes > 0 {
            let used = self.used.get(&self.store, false).map_err(io_to_status)?;
            if used.saturating_add(r.data.len() as u64) > self.quota_bytes {
                return Err(Status::resource_exhausted("store quota exceeded"));
            }
        }
        self.touch();
        self.store
            .write_range(&file.rel_path, r.offset, &r.data)
            .map_err(io_to_status)?;
        self.used.added(r.data.len() as u64);
        Ok(Response::new(WriteRangeReply {}))
    }

    async fn read_range(
        &self,
        req: Request<ReadRangeRequest>,
    ) -> Result<Response<ReadRangeReply>, Status> {
        let r = req.into_inner();
        let file = r
            .file
            .ok_or_else(|| Status::invalid_argument("file is required"))?;
        if r.length as usize > MAX_CHUNK {
            return Err(Status::invalid_argument("ReadRange length exceeds 1 MiB"));
        }
        self.touch();
        let data = self
            .store
            .read_range(&file.rel_path, r.offset, r.length)
            .map_err(io_to_status)?;
        let eof = (data.len() as u32) < r.length;
        Ok(Response::new(ReadRangeReply { data, eof }))
    }

    async fn fsync(&self, req: Request<FsyncRequest>) -> Result<Response<FsyncReply>, Status> {
        self.touch();
        let scope = match req.into_inner().scope {
            Some(fsync_request::Scope::File(f)) => FsyncScope::File(f.rel_path),
            Some(fsync_request::Scope::AllBundle(_)) | None => FsyncScope::AllBundle,
        };
        self.store.fsync(scope).map_err(io_to_status)?;
        Ok(Response::new(FsyncReply {}))
    }

    async fn bundle_op(
        &self,
        req: Request<BundleOpRequest>,
    ) -> Result<Response<BundleOpReply>, Status> {
        self.touch();
        let op = req
            .into_inner()
            .op
            .ok_or_else(|| Status::invalid_argument("op is required"))?;
        // Whatever can shrink the store makes the cached figure stale (dropped after the op).
        let shrinks = matches!(
            op,
            bundle_op_request::Op::Delete(_)
                | bundle_op_request::Op::Truncate(_)
                | bundle_op_request::Op::Rename(_)
        );

        let result = match op {
            bundle_op_request::Op::Create(c) => {
                let f = c
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store
                    .create(&f.rel_path, c.directory, c.exclusive, !c.no_create_parents)
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::Delete(d) => {
                let f = d
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store
                    .delete(&f.rel_path, !d.non_recursive)
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::Rename(rn) => {
                let from = rn
                    .from
                    .ok_or_else(|| Status::invalid_argument("from is required"))?;
                let to = rn
                    .to
                    .ok_or_else(|| Status::invalid_argument("to is required"))?;
                self.store
                    .rename(
                        &from.rel_path,
                        &to.rel_path,
                        rn.replace,
                        !rn.no_create_parents,
                    )
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::Truncate(t) => {
                let f = t
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store
                    .truncate(&f.rel_path, t.new_length)
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::SetTimes(t) => {
                let f = t
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store
                    .set_times(&f.rel_path, t.atime_unix_ns, t.mtime_unix_ns)
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::List(l) => {
                let entries = self.store.list(&l.rel_dir).map_err(io_to_status)?;
                bundle_op_reply::Result::Listing(DirListing {
                    entries: entries.into_iter().map(stat_to_proto).collect(),
                })
            }
            bundle_op_request::Op::Stat(s) => {
                let f = s
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                let st = self.store.stat(&f.rel_path).map_err(io_to_status)?;
                bundle_op_reply::Result::Stat(stat_to_proto(st))
            }
        };

        if shrinks {
            self.used.invalidate();
        }
        Ok(Response::new(BundleOpReply {
            result: Some(result),
        }))
    }
}
