//! Behaviour specific to `GrpcBackend`: wire-level chunking, retries, errors on a dead or
//! restarting receiver, quota. Behaviour shared with `LocalFsBackend` is in `backend_contract.rs`.

#![cfg(feature = "backend-grpc")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use janus_lib::grpc_backend::{GrpcBackend, RetryPolicy};
use janus_lib::remote::{RemoteClient, RemoteConfig};
use janus_lib::vfs::{BackendError, Disposition, Kind, OpenRequest, StorageBackend};
use janus_proto::v1 as pb;
use janus_proto::v1::band_transport_server::{BandTransport, BandTransportServer};
use janus_receiverd::testkit::TestServer;
use tonic::{Request, Response, Status};

const MIB: usize = 1 << 20;

fn req(d: Disposition) -> OpenRequest {
    OpenRequest {
        disposition: d,
        kind: Kind::File,
        write: true,
        delete_on_close: false,
    }
}

fn backend_for(addr: std::net::SocketAddr) -> GrpcBackend {
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: addr.to_string(),
        ..Default::default()
    })
    .unwrap();
    GrpcBackend::from_remote(&remote, 0).with_retry(RetryPolicy {
        attempts: 3,
        base_delay: Duration::from_millis(20),
    })
}

// ---- a recording mock of the receiver ---------------------------------------------------

#[derive(Default)]
struct Mock {
    writes: Mutex<Vec<(u64, usize, u64)>>, // (offset, len, write_id)
    write_failures_left: AtomicU32,
    bundle_ops: Mutex<Vec<&'static str>>,
    fail_bundle_mutations: bool,
}

struct MockSvc(Arc<Mock>);
impl std::ops::Deref for MockSvc {
    type Target = Mock;
    fn deref(&self) -> &Mock {
        &self.0
    }
}

#[tonic::async_trait]
impl BandTransport for MockSvc {
    async fn ping(&self, _: Request<pb::PingRequest>) -> Result<Response<pb::PingReply>, Status> {
        Ok(Response::new(pb::PingReply {
            server_version: "mock".into(),
            proto_rev: 2,
        }))
    }
    async fn stat_fs(
        &self,
        _: Request<pb::StatFsRequest>,
    ) -> Result<Response<pb::StatFsReply>, Status> {
        Ok(Response::new(pb::StatFsReply {
            quota_bytes: 0,
            used_bytes: 5,
        }))
    }
    async fn write_range(
        &self,
        r: Request<pb::WriteRangeRequest>,
    ) -> Result<Response<pb::WriteRangeReply>, Status> {
        let r = r.into_inner();
        self.writes
            .lock()
            .unwrap()
            .push((r.offset, r.data.len(), r.write_id));
        let left = self.write_failures_left.load(Ordering::SeqCst);
        if left > 0 {
            self.write_failures_left.store(left - 1, Ordering::SeqCst);
            return Err(Status::unavailable("flaky"));
        }
        Ok(Response::new(pb::WriteRangeReply {}))
    }
    async fn read_range(
        &self,
        _: Request<pb::ReadRangeRequest>,
    ) -> Result<Response<pb::ReadRangeReply>, Status> {
        Err(Status::unimplemented("mock"))
    }
    async fn fsync(
        &self,
        _: Request<pb::FsyncRequest>,
    ) -> Result<Response<pb::FsyncReply>, Status> {
        Ok(Response::new(pb::FsyncReply {}))
    }
    async fn bundle_op(
        &self,
        r: Request<pb::BundleOpRequest>,
    ) -> Result<Response<pb::BundleOpReply>, Status> {
        use pb::bundle_op_request::Op;
        let op = r.into_inner().op.unwrap();
        let (name, result) = match op {
            Op::Stat(s) => (
                "stat",
                pb::bundle_op_reply::Result::Stat(pb::FileStat {
                    rel_path: s.file.unwrap().rel_path,
                    ..Default::default()
                }),
            ),
            Op::Rename(_) => ("rename", pb::bundle_op_reply::Result::Ok(true)),
            Op::Delete(_) => ("delete", pb::bundle_op_reply::Result::Ok(true)),
            Op::Truncate(_) => ("truncate", pb::bundle_op_reply::Result::Ok(true)),
            _ => ("other", pb::bundle_op_reply::Result::Ok(true)),
        };
        self.bundle_ops.lock().unwrap().push(name);
        if self.fail_bundle_mutations && (name == "rename" || name == "delete") {
            return Err(Status::unavailable("down"));
        }
        Ok(Response::new(pb::BundleOpReply {
            result: Some(result),
        }))
    }
}

async fn start_mock(mock: Arc<Mock>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(BandTransportServer::new(MockSvc(mock)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });
    addr
}

#[tokio::test]
async fn writes_are_cut_into_chunks_of_at_most_1_mib_with_increasing_write_ids() {
    let mock = Arc::new(Mock::default());
    let b = backend_for(start_mock(mock.clone()).await);
    let o = b.open("f", req(Disposition::Open)).await.unwrap();
    let data = vec![7u8; 3 * MIB + MIB / 2];
    b.write(o.handle, 100, &data).await.unwrap();
    b.write(o.handle, 0, b"x").await.unwrap();

    let w = mock.writes.lock().unwrap().clone();
    let lens: Vec<_> = w.iter().map(|x| x.1).collect();
    assert_eq!(lens, [MIB, MIB, MIB, MIB / 2, 1]);
    let offs: Vec<_> = w.iter().map(|x| x.0).collect();
    assert_eq!(
        offs,
        [
            100,
            100 + MIB as u64,
            100 + 2 * MIB as u64,
            100 + 3 * MIB as u64,
            0
        ]
    );
    let ids: Vec<_> = w.iter().map(|x| x.2).collect();
    assert!(
        ids.windows(2).all(|p| p[0] < p[1]),
        "write_id strictly increasing: {ids:?}"
    );
}

#[tokio::test]
async fn a_failed_write_range_is_retried_with_the_same_id_and_offset() {
    let mock = Arc::new(Mock::default());
    mock.write_failures_left.store(2, Ordering::SeqCst);
    let b = backend_for(start_mock(mock.clone()).await);
    let o = b.open("f", req(Disposition::Open)).await.unwrap();
    b.write(o.handle, 42, b"payload").await.unwrap();
    let w = mock.writes.lock().unwrap().clone();
    assert_eq!(w.len(), 3, "two failures + one success");
    assert!(w.iter().all(|x| x.0 == 42 && x.1 == 7 && x.2 == w[0].2));
}

#[tokio::test]
async fn retries_give_up_after_the_configured_attempts() {
    let mock = Arc::new(Mock::default());
    mock.write_failures_left.store(100, Ordering::SeqCst);
    let b = backend_for(start_mock(mock.clone()).await);
    let o = b.open("f", req(Disposition::Open)).await.unwrap();
    let e = b.write(o.handle, 0, b"x").await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    assert_eq!(mock.writes.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn rename_and_delete_on_close_are_not_retried() {
    let mock = Arc::new(Mock {
        fail_bundle_mutations: true,
        ..Default::default()
    });
    let b = backend_for(start_mock(mock.clone()).await);
    let e = b.rename("a", "b", false).await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    let o = b
        .open(
            "f",
            OpenRequest {
                delete_on_close: true,
                ..req(Disposition::Open)
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        b.close(o.handle).await,
        Err(BackendError::RemoteUnavailable)
    ));
    let ops = mock.bundle_ops.lock().unwrap().clone();
    assert_eq!(ops.iter().filter(|o| **o == "rename").count(), 1);
    assert_eq!(ops.iter().filter(|o| **o == "delete").count(), 1);
}

#[tokio::test]
async fn statfs_uses_the_fallback_quota_when_the_receiver_has_none() {
    let mock = Arc::new(Mock::default());
    let addr = start_mock(mock).await;
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: addr.to_string(),
        ..Default::default()
    })
    .unwrap();
    let b = GrpcBackend::from_remote(&remote, 777);
    let s = b.statfs().await.unwrap();
    assert_eq!((s.quota_bytes, s.used_bytes), (777, 5));
}

// ---- a real receiver ----------------------------------------------------------------------

#[tokio::test]
async fn quota_exhaustion_is_no_space() {
    let srv = TestServer::start("grpc-quota", 100).await.unwrap();
    let b = backend_for(srv.addr);
    let a = b.open("a", req(Disposition::Create)).await.unwrap();
    b.write(a.handle, 0, &[1u8; 60]).await.unwrap();
    let c = b.open("c", req(Disposition::Create)).await.unwrap();
    let e = b.write(c.handle, 0, &[1u8; 60]).await.unwrap_err();
    assert!(matches!(e, BackendError::NoSpace), "{e:?}");
    // freeing space makes it work again
    b.truncate(a.handle, 0).await.unwrap();
    b.write(c.handle, 0, &[1u8; 60]).await.unwrap();
    let s = b.statfs().await.unwrap();
    assert_eq!((s.quota_bytes, s.used_bytes), (100, 60));
}

#[tokio::test]
async fn an_unreachable_receiver_is_remote_unavailable_not_not_found() {
    // a port that nothing listens on
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let b = backend_for(addr);
    let t = std::time::Instant::now();
    for r in [
        b.stat("x").await.map(|_| ()),
        b.open("x", req(Disposition::OpenOrCreate))
            .await
            .map(|_| ()),
        b.list("").await.map(|_| ()),
        b.statfs().await.map(|_| ()),
    ] {
        assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    }
    assert!(
        t.elapsed() < Duration::from_secs(15),
        "must fail fast, took {:?}",
        t.elapsed()
    );
}

/// Receiver on a fixed listener that can be stopped and started again over the same store.
struct Restartable {
    addr: std::net::SocketAddr,
    store: Arc<janus_receiverd::worker::FileStore>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Restartable {
    async fn start(dir: &std::path::Path, bind: &str) -> Restartable {
        let store = Arc::new(janus_receiverd::worker::FileStore::open(dir).unwrap());
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let st = Arc::clone(&store);
        let join = tokio::spawn(async move {
            let _ = janus_receiverd::server::serve_on_listener(listener, st, 0, async {
                let _ = rx.await;
            })
            .await;
        });
        Restartable {
            addr,
            store,
            stop: Some(tx),
            join: Some(join),
        }
    }
    async fn stop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), j).await;
        }
    }
}

#[tokio::test]
async fn a_stopped_receiver_fails_writes_quickly_and_work_resumes_after_restart() {
    let dir = std::env::temp_dir().join(format!("janus-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut srv = Restartable::start(&dir, "127.0.0.1:0").await;
    let b = backend_for(srv.addr);

    let o = b.open("f", req(Disposition::Create)).await.unwrap();
    b.write(o.handle, 0, b"before").await.unwrap();

    srv.stop().await;
    let t = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(20), b.write(o.handle, 6, b"-during"))
        .await
        .expect("a write against a dead receiver must not hang");
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(
        t.elapsed() < Duration::from_secs(15),
        "took {:?}",
        t.elapsed()
    );
    assert!(matches!(
        b.stat("f").await,
        Err(BackendError::RemoteUnavailable)
    ));

    // same address, same store
    let srv2 = Restartable::start(&dir, &srv.addr.to_string()).await;
    let mut ok = false;
    for _ in 0..20 {
        if b.write(o.handle, 6, b"-after").await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "writes must resume after the receiver is back");
    assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"before-after");
    drop(srv2.store);
    let _ = std::fs::remove_dir_all(&dir);
}
