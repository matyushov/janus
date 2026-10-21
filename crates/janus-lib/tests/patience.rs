//! `Timeouts::patience`: calls a client is waiting for (stat, open, create, ...) keep trying
//! while the receiver is unreachable, up to the configured time, instead of failing after the
//! operation budget; a Create whose reply was lost is not reported as a collision when it is
//! repeated. The numbers behind the defaults are in docs/macos-smb-client-timeouts.md.

#![cfg(feature = "backend-grpc")]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use janus_lib::grpc_backend::GrpcBackend;
use janus_lib::remote::{RemoteClient, RemoteConfig, Timeouts};
use janus_lib::vfs::{BackendError, Disposition, Kind, OpenRequest, StorageBackend};
use janus_proto::v1 as pb;
use janus_proto::v1::band_transport_server::{BandTransport, BandTransportServer};
use tonic::{Request, Response, Status};

const MS: fn(u64) -> Duration = Duration::from_millis;

fn timeouts(patience: u64) -> Timeouts {
    Timeouts {
        connect: MS(300),
        request: MS(300),
        bulk_request: MS(300),
        degraded_probe: MS(150),
        fail_fast: MS(100),
        budget: MS(700),
        barrier: MS(30_000),
        barrier_down_after: MS(patience),
        patience: Some(MS(patience)),
        keepalive_interval: Duration::from_secs(3600),
        keepalive_timeout: Duration::from_secs(3600),
    }
}

#[derive(Default)]
struct Mock {
    /// Bundle operations stall (no answer) while set.
    frozen: AtomicBool,
    files: std::sync::Mutex<HashSet<String>>,
    /// The first Create is applied but its reply comes too late.
    lose_first_create_reply: AtomicBool,
    creates: AtomicU32,
}

struct Svc(Arc<Mock>);

#[allow(clippy::result_large_err)]
fn reply(result: pb::bundle_op_reply::Result) -> Result<Response<pb::BundleOpReply>, Status> {
    Ok(Response::new(pb::BundleOpReply {
        result: Some(result),
    }))
}

#[tonic::async_trait]
impl BandTransport for Svc {
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
        Err(Status::unimplemented("mock"))
    }
    async fn write_range(
        &self,
        _: Request<pb::WriteRangeRequest>,
    ) -> Result<Response<pb::WriteRangeReply>, Status> {
        Err(Status::unimplemented("mock"))
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
        Err(Status::unimplemented("mock"))
    }
    async fn bundle_op(
        &self,
        r: Request<pb::BundleOpRequest>,
    ) -> Result<Response<pb::BundleOpReply>, Status> {
        while self.0.frozen.load(Ordering::SeqCst) {
            tokio::time::sleep(MS(20)).await;
        }
        match r.into_inner().op {
            Some(pb::bundle_op_request::Op::Stat(s)) => {
                let rel = s.file.unwrap().rel_path;
                if rel.is_empty() || self.0.files.lock().unwrap().contains(&rel) {
                    reply(pb::bundle_op_reply::Result::Stat(pb::FileStat {
                        rel_path: rel,
                        directory: false,
                        ..Default::default()
                    }))
                } else {
                    Err(Status::not_found("no such file"))
                }
            }
            Some(pb::bundle_op_request::Op::Create(c)) => {
                let rel = c.file.unwrap().rel_path;
                let first = self.0.creates.fetch_add(1, Ordering::SeqCst) == 0;
                let fresh = self.0.files.lock().unwrap().insert(rel);
                if first && self.0.lose_first_create_reply.load(Ordering::SeqCst) {
                    tokio::time::sleep(MS(1500)).await; // the client has given up on this try
                }
                if fresh {
                    reply(pb::bundle_op_reply::Result::Ok(true))
                } else {
                    Err(Status::already_exists("exists"))
                }
            }
            _ => reply(pb::bundle_op_reply::Result::Ok(true)),
        }
    }
}

async fn start(mock: Arc<Mock>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(BandTransportServer::new(Svc(mock)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(l))
            .await;
    });
    addr
}

fn backend(addr: SocketAddr, t: Timeouts) -> GrpcBackend {
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: addr.to_string(),
        timeouts: t,
        ..Default::default()
    })
    .unwrap();
    GrpcBackend::from_remote(&remote, 0)
}

fn open_req(disposition: Disposition) -> OpenRequest {
    OpenRequest {
        disposition,
        kind: Kind::File,
        write: true,
        delete_on_close: false,
    }
}

#[tokio::test]
async fn a_call_waits_for_a_silent_receiver_and_succeeds_when_it_answers_again() {
    let mock = Arc::new(Mock::default());
    mock.files.lock().unwrap().insert("f".into());
    mock.frozen.store(true, Ordering::SeqCst);
    let b = Arc::new(backend(start(mock.clone()).await, timeouts(10_000)));
    let started = Instant::now();
    let call = {
        let b = Arc::clone(&b);
        tokio::spawn(async move { b.stat("f").await })
    };
    // Well past the operation budget (700 ms): still waiting.
    tokio::time::sleep(MS(1800)).await;
    assert!(!call.is_finished(), "must still be waiting");
    mock.frozen.store(false, Ordering::SeqCst);
    let st = call
        .await
        .unwrap()
        .expect("succeeds once the receiver answers");
    assert_eq!(st.rel_path, "f");
    assert!(started.elapsed() > MS(1800));
}

#[tokio::test]
async fn a_call_gives_up_when_the_receiver_has_been_down_for_the_patience() {
    let mock = Arc::new(Mock::default());
    mock.frozen.store(true, Ordering::SeqCst);
    let b = backend(start(mock).await, timeouts(1200));
    let started = Instant::now();
    let e = b.stat("f").await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    let took = started.elapsed();
    assert!(
        took >= MS(1200) && took < MS(3500),
        "gave up at the patience, not earlier or much later: {took:?}"
    );
}

#[tokio::test]
async fn without_patience_the_call_fails_within_the_budget_as_before() {
    let mock = Arc::new(Mock::default());
    mock.frozen.store(true, Ordering::SeqCst);
    let mut t = timeouts(5000);
    t.patience = None;
    let b = backend(start(mock).await, t);
    let started = Instant::now();
    let e = b.stat("f").await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    assert!(started.elapsed() < MS(1500), "{:?}", started.elapsed());
}

#[tokio::test]
async fn a_create_whose_reply_was_lost_is_not_reported_as_a_collision() {
    let mock = Arc::new(Mock::default());
    mock.lose_first_create_reply.store(true, Ordering::SeqCst);
    let b = backend(start(mock.clone()).await, timeouts(10_000));
    // The first Create lands but its reply is late; the repeat finds the file and the caller,
    // who asked for "create", gets its file anyway.
    let opened = b
        .open("g", open_req(Disposition::OpenOrCreate))
        .await
        .expect("open succeeds");
    assert!(opened.created);
    assert!(
        mock.creates.load(Ordering::SeqCst) >= 2,
        "the call was repeated"
    );
    assert!(mock.files.lock().unwrap().contains("g"));
}

#[tokio::test]
async fn a_healthy_receiver_is_called_exactly_once_per_operation() {
    let mock = Arc::new(Mock::default());
    let b = backend(start(mock.clone()).await, timeouts(10_000));
    let opened = b
        .open("h", open_req(Disposition::Create))
        .await
        .expect("open succeeds");
    assert!(opened.created);
    assert_eq!(mock.creates.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_stat_of_a_known_path_is_answered_from_the_last_answer_when_the_receiver_is_silent() {
    let mock = Arc::new(Mock::default());
    mock.files.lock().unwrap().insert("f".into());
    let b = backend(start(mock.clone()).await, timeouts(30_000));
    let first = b.stat("f").await.expect("healthy stat");
    // let the 2 s cache expire, then the receiver goes silent
    tokio::time::sleep(MS(2100)).await;
    mock.frozen.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let again = b.stat("f").await.expect("served from the last answer");
    assert_eq!(again.rel_path, first.rel_path);
    assert!(
        started.elapsed() < MS(3500),
        "answered after the stale-stat delay, not after the patience: {:?}",
        started.elapsed()
    );
    // a path the gateway has never seen has no last answer: it waits (and then gives up)
    let unknown = tokio::time::timeout(MS(4000), b.stat("never-seen")).await;
    assert!(
        unknown.is_err(),
        "no last answer, so the call keeps waiting"
    );
}
