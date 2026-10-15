//! Implementation of the `BandTransport` gRPC service on top of `FileStore`.
//!
//! MILESTONE (dev): one store per process, no mTLS and no per-machine routing.
//! UPGRADE: Router + IdentityMap (cert → machine → store) + a network-less StoreWorker
//! (see README, the "janus-receiverd" section).

use std::sync::Arc;

use janus_proto::v1::band_transport_server::BandTransport;
use janus_proto::v1::{
    BundleOpReply, BundleOpRequest, DirListing, FileStat, FsyncReply, FsyncRequest, PingReply,
    PingRequest, ReadRangeReply, ReadRangeRequest, StatFsReply, StatFsRequest, WriteRangeReply,
    WriteRangeRequest, bundle_op_reply, bundle_op_request, fsync_request,
};
use tonic::{Request, Response, Status};

use crate::worker::{FileStore, FsyncScope, StatInfo};

/// A service on top of a single store. The quota is the ceiling for StatFs (0 = no limit).
pub struct BandTransportService {
    store: Arc<FileStore>,
    quota_bytes: u64,
}

impl BandTransportService {
    pub fn new(store: Arc<FileStore>, quota_bytes: u64) -> Self {
        BandTransportService { store, quota_bytes }
    }
}

/// io::Error → gRPC Status preserving the error class: the client decides by the code
/// whether to retry or fail (NotFound/AlreadyExists/PermissionDenied: do not retry).
fn io_to_status(e: std::io::Error) -> Status {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => Status::not_found(e.to_string()),
        AlreadyExists => Status::already_exists(e.to_string()),
        PermissionDenied => Status::permission_denied(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

fn stat_to_proto(s: StatInfo) -> FileStat {
    FileStat {
        rel_path: s.rel_path,
        size: s.size,
        directory: s.directory,
        mtime_unix_ns: s.mtime_unix_ns,
    }
}

#[tonic::async_trait]
impl BandTransport for BandTransportService {
    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let _client = req.into_inner().client_version;
        Ok(Response::new(PingReply {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            proto_rev: 1,
        }))
    }

    async fn stat_fs(&self, _req: Request<StatFsRequest>) -> Result<Response<StatFsReply>, Status> {
        let used = self.store.used_bytes().map_err(io_to_status)?;
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
        // Quota: exceeding it → resource_exhausted (the client maps it to STATUS_DISK_FULL).
        if self.quota_bytes > 0 {
            let used = self.store.used_bytes().map_err(io_to_status)?;
            if used.saturating_add(r.data.len() as u64) > self.quota_bytes {
                return Err(Status::resource_exhausted("store quota exceeded"));
            }
        }
        self.store
            .write_range(&file.rel_path, r.offset, &r.data)
            .map_err(io_to_status)?;
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
        let data = self
            .store
            .read_range(&file.rel_path, r.offset, r.length)
            .map_err(io_to_status)?;
        let eof = (data.len() as u32) < r.length;
        Ok(Response::new(ReadRangeReply { data, eof }))
    }

    async fn fsync(&self, req: Request<FsyncRequest>) -> Result<Response<FsyncReply>, Status> {
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
        let op = req
            .into_inner()
            .op
            .ok_or_else(|| Status::invalid_argument("op is required"))?;

        let result = match op {
            bundle_op_request::Op::Create(c) => {
                let f = c
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store
                    .create(&f.rel_path, c.directory, c.exclusive)
                    .map_err(io_to_status)?;
                bundle_op_reply::Result::Ok(true)
            }
            bundle_op_request::Op::Delete(d) => {
                let f = d
                    .file
                    .ok_or_else(|| Status::invalid_argument("file is required"))?;
                self.store.delete(&f.rel_path).map_err(io_to_status)?;
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
                    .rename(&from.rel_path, &to.rel_path, rn.replace)
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

        Ok(Response::new(BundleOpReply {
            result: Some(result),
        }))
    }
}
