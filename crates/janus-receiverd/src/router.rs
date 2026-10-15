//! Router: maps the authenticated TLS peer to a machine and forwards each call to that
//! machine's worker (`BandTransportService` over its own `FileStore`).
//!
//! Isolation model of this milestone: one worker (store root + quota + usage cache) per
//! machine inside the process; a request can only reach the store of the machine whose
//! certificate fingerprint it was authenticated with, and store-relative paths cannot leave it
//! (`FileStore` rejects `..`, absolute paths and symlinks). A separate process or jail per
//! worker (FreeBSD jail / Linux uid+mount-ns) remains the later hardening step.
//!
//! `--dev` mode: one built-in store, no identity.

#![allow(clippy::result_large_err)] // tonic::Status is the natural error of every RPC here

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use janus_proto::v1::band_transport_server::BandTransport;
use janus_proto::v1::{
    BundleOpReply, BundleOpRequest, FsyncReply, FsyncRequest, PingReply, PingRequest,
    ReadRangeReply, ReadRangeRequest, StatFsReply, StatFsRequest, WriteRangeReply,
    WriteRangeRequest,
};
use tonic::{Request, Response, Status};

use crate::identity::IdentityMap;
use crate::service::BandTransportService;
use crate::tls::PeerInfo;
use crate::worker::FileStore;

/// One line of `ListMachines`.
#[derive(Debug, Clone)]
pub struct MachineSnapshot {
    pub id: String,
    pub store_path: String,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub worker_active: bool,
    pub last_activity_unix_ms: i64,
}

enum Mode {
    /// `--dev`: everything goes to one store, no authentication.
    Single {
        id: String,
        worker: Arc<BandTransportService>,
    },
    /// Production: the peer certificate decides.
    Mapped(IdentityMap),
}

pub struct Router {
    mode: Mode,
    workers: Mutex<HashMap<String, Arc<BandTransportService>>>,
}

impl Router {
    pub fn single(id: &str, store: Arc<FileStore>, quota_bytes: u64) -> Router {
        Router {
            mode: Mode::Single {
                id: id.to_string(),
                worker: Arc::new(BandTransportService::new(store, quota_bytes)),
            },
            workers: Mutex::new(HashMap::new()),
        }
    }

    pub fn mapped(map: IdentityMap) -> Router {
        Router {
            mode: Mode::Mapped(map),
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// The worker that serves this peer.
    ///
    /// - dev mode: the one built-in worker;
    /// - production: no verified peer → `UNAUTHENTICATED`; a certificate that is not enrolled
    ///   → `PERMISSION_DENIED` (the TLS handshake already proved it is signed by our CA).
    pub fn worker_for(&self, peer: Option<&PeerInfo>) -> Result<Arc<BandTransportService>, Status> {
        match &self.mode {
            Mode::Single { worker, .. } => Ok(Arc::clone(worker)),
            Mode::Mapped(map) => {
                let peer = peer.ok_or_else(|| Status::unauthenticated("no client certificate"))?;
                let Some(m) = map.resolve(&peer.fingerprint) else {
                    eprintln!(
                        "janus-receiverd: rejected unenrolled certificate sha256:{}",
                        peer.fingerprint
                    );
                    return Err(Status::permission_denied("certificate is not enrolled"));
                };
                let mut workers = self.workers.lock().expect("worker table poisoned");
                if let Some(w) = workers.get(&m.id) {
                    return Ok(Arc::clone(w));
                }
                let store = FileStore::open(&m.store_dir).map_err(|e| {
                    eprintln!("janus-receiverd: cannot open store of {}: {e}", m.id);
                    Status::internal("store unavailable")
                })?;
                let w = Arc::new(BandTransportService::new(Arc::new(store), m.quota_bytes));
                workers.insert(m.id.clone(), Arc::clone(&w));
                eprintln!("janus-receiverd: worker started for {}", m.id);
                Ok(w)
            }
        }
    }

    pub fn machines_known(&self) -> usize {
        match &self.mode {
            Mode::Single { .. } => 1,
            Mode::Mapped(map) => map.machines().len(),
        }
    }

    pub fn active_workers(&self) -> usize {
        match &self.mode {
            Mode::Single { .. } => 1,
            Mode::Mapped(_) => self.workers.lock().expect("worker table poisoned").len(),
        }
    }

    /// Real list of machines with their usage (what `janus-cli server machines` shows).
    pub fn snapshot(&self) -> Vec<MachineSnapshot> {
        match &self.mode {
            Mode::Single { id, worker } => vec![snapshot_of(id, worker, true)],
            Mode::Mapped(map) => {
                let workers = self.workers.lock().expect("worker table poisoned").clone();
                map.machines()
                    .iter()
                    .map(|m| match workers.get(&m.id) {
                        Some(w) => snapshot_of(&m.id, w, true),
                        None => MachineSnapshot {
                            id: m.id.clone(),
                            store_path: m.store_dir.display().to_string(),
                            quota_bytes: m.quota_bytes,
                            used_bytes: FileStore::open_existing(&m.store_dir)
                                .and_then(|s| s.used_bytes())
                                .unwrap_or(0),
                            worker_active: false,
                            last_activity_unix_ms: 0,
                        },
                    })
                    .collect()
            }
        }
    }
}

fn snapshot_of(id: &str, w: &BandTransportService, active: bool) -> MachineSnapshot {
    MachineSnapshot {
        id: id.to_string(),
        store_path: w.store().root().display().to_string(),
        quota_bytes: w.quota_bytes(),
        used_bytes: w.used_bytes().unwrap_or(0),
        worker_active: active,
        last_activity_unix_ms: w.last_activity_unix_ms(),
    }
}

fn peer_of<T>(req: &Request<T>) -> Option<PeerInfo> {
    req.extensions().get::<PeerInfo>().cloned()
}

/// `BandTransport` over the router. Newtype so the router itself can be shared with the
/// control plane.
pub struct RouterService(pub Arc<Router>);

#[tonic::async_trait]
impl BandTransport for RouterService {
    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.ping(req).await
    }

    async fn stat_fs(&self, req: Request<StatFsRequest>) -> Result<Response<StatFsReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.stat_fs(req).await
    }

    async fn write_range(
        &self,
        req: Request<WriteRangeRequest>,
    ) -> Result<Response<WriteRangeReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.write_range(req).await
    }

    async fn read_range(
        &self,
        req: Request<ReadRangeRequest>,
    ) -> Result<Response<ReadRangeReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.read_range(req).await
    }

    async fn fsync(&self, req: Request<FsyncRequest>) -> Result<Response<FsyncReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.fsync(req).await
    }

    async fn bundle_op(
        &self,
        req: Request<BundleOpRequest>,
    ) -> Result<Response<BundleOpReply>, Status> {
        let w = self.0.worker_for(peer_of(&req).as_ref())?;
        w.bundle_op(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::TestPki;

    fn map_for(dir: &std::path::Path, fps: &[(&str, &str, u64)]) -> IdentityMap {
        let entries: Vec<String> = fps
            .iter()
            .map(|(id, fp, q)| {
                format!(r#"{{"id":"{id}","fingerprint":"{fp}","store":"{id}","quota_bytes":{q}}}"#)
            })
            .collect();
        IdentityMap::from_json(
            format!(r#"{{"machines":[{}]}}"#, entries.join(",")).as_bytes(),
            dir,
            0,
        )
        .unwrap()
    }

    #[test]
    fn workers_start_lazily_and_the_listing_is_real() {
        let dir = std::env::temp_dir().join(format!("janus-router-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pki = TestPki::new();
        let (a, b) = (pki.issue_client("a"), pki.issue_client("b"));
        let router = Router::mapped(map_for(
            &dir,
            &[("mac-a", &a.fingerprint, 10), ("mac-b", &b.fingerprint, 20)],
        ));
        assert_eq!((router.machines_known(), router.active_workers()), (2, 0));
        let snap = router.snapshot();
        assert_eq!(
            snap.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            ["mac-a", "mac-b"]
        );
        assert!(snap.iter().all(|m| !m.worker_active));
        assert!(!dir.join("mac-a").exists(), "listing creates nothing");

        let pa = PeerInfo {
            fingerprint: a.fingerprint.clone(),
        };
        let w1 = router.worker_for(Some(&pa)).unwrap();
        let w2 = router.worker_for(Some(&pa)).unwrap();
        assert!(Arc::ptr_eq(&w1, &w2), "one worker per machine");
        assert_eq!(router.active_workers(), 1);
        let snap = router.snapshot();
        assert!(snap[0].worker_active && !snap[1].worker_active);
        assert_eq!((snap[0].quota_bytes, snap[1].quota_bytes), (10, 20));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_and_missing_peers_are_refused() {
        let dir = std::env::temp_dir().join(format!("janus-router2-{}", std::process::id()));
        let router = Router::mapped(map_for(&dir, &[]));
        let stranger = PeerInfo {
            fingerprint: "0".repeat(64),
        };
        assert_eq!(
            router.worker_for(Some(&stranger)).err().unwrap().code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            router.worker_for(None).err().unwrap().code(),
            tonic::Code::Unauthenticated
        );
        assert!(!dir.exists());
    }
}
