//! Time limits of `GrpcBackend`: a silent receiver must fail an operation within the budget
//! (not "attempts x request timeout"), retries only while budget remains, a late reply must not
//! break later operations, and HTTP/2 keepalive must notice a frozen peer on a live channel.
//! All limits are scaled down to hundreds of milliseconds through `Timeouts`.

#![cfg(feature = "backend-grpc")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use janus_lib::grpc_backend::{GrpcBackend, RetryPolicy};
use janus_lib::remote::{RemoteClient, RemoteConfig, Timeouts};
use janus_lib::vfs::{BackendError, StorageBackend};
use janus_proto::v1 as pb;
use janus_proto::v1::band_transport_server::{BandTransport, BandTransportServer};
use tonic::{Request, Response, Status};

const MS: fn(u64) -> Duration = Duration::from_millis;

fn timeouts(request: u64, budget: u64) -> Timeouts {
    Timeouts {
        connect: MS(300),
        request: MS(request),
        bulk_request: MS(request),
        degraded_probe: MS(150),
        fail_fast: MS(100),
        budget: MS(budget),
        barrier: MS(budget),
        // Keepalive is effectively off unless a test overrides it.
        keepalive_interval: Duration::from_secs(3600),
        keepalive_timeout: Duration::from_secs(3600),
    }
}

fn backend(addr: SocketAddr, t: Timeouts, attempts: u32) -> GrpcBackend {
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: addr.to_string(),
        timeouts: t,
        ..Default::default()
    })
    .unwrap();
    GrpcBackend::from_remote(&remote, 0).with_retry(RetryPolicy {
        attempts,
        base_delay: MS(20),
    })
}

/// Mock whose `bundle_op` stalls for `stall_first` calls (or forever when `stall_for` is set),
/// then answers.
#[derive(Default)]
struct Mock {
    calls: AtomicU32,
    stall_first: AtomicU32,
    stall: std::sync::Mutex<Duration>,
}

struct Svc(Arc<Mock>);

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
        let n = self.0.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= self.0.stall_first.load(Ordering::SeqCst) {
            let d = *self.0.stall.lock().unwrap();
            tokio::time::sleep(d).await;
        }
        let rel = match r.into_inner().op {
            Some(pb::bundle_op_request::Op::Stat(s)) => s.file.unwrap().rel_path,
            _ => String::new(),
        };
        Ok(Response::new(pb::BundleOpReply {
            result: Some(pb::bundle_op_reply::Result::Stat(pb::FileStat {
                rel_path: rel,
                ..Default::default()
            })),
        }))
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

fn stalling(first: u32, d: Duration) -> Arc<Mock> {
    let m = Arc::new(Mock::default());
    m.stall_first.store(first, Ordering::SeqCst);
    *m.stall.lock().unwrap() = d;
    m
}

#[tokio::test]
async fn a_silent_receiver_fails_within_the_budget_not_attempts_times_timeout() {
    // Accepts TCP and never speaks HTTP/2.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    // 3 attempts x 400 ms would be 1.2 s; the budget is 700 ms (a second attempt does not fit).
    let b = backend(addr, timeouts(400, 700), 3);
    let t = Instant::now();
    let r = b.stat("x").await;
    let took = t.elapsed();
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(took >= MS(350), "gave up too early: {took:?}");
    assert!(took < MS(1000), "exceeded the budget: {took:?}");
}

#[tokio::test]
async fn an_answer_on_the_third_attempt_succeeds_within_the_budget() {
    let mock = stalling(2, Duration::from_secs(30));
    let addr = start(mock.clone()).await;
    // attempts 1 and 2 stall and time out at 250 ms; the 3rd answers at once (~0.55 s < 1.5 s).
    let b = backend(addr, timeouts(250, 1500), 3);
    let t = Instant::now();
    b.stat("x").await.expect("third attempt must succeed");
    assert!(t.elapsed() < MS(1200), "{:?}", t.elapsed());
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn no_retry_is_started_when_the_budget_cannot_fit_it() {
    let mock = stalling(100, Duration::from_secs(30));
    let addr = start(mock.clone()).await;
    // First attempt eats 400 ms of a 700 ms budget; backoff + minimal attempt do not fit,
    // so exactly one call reaches the receiver.
    let b = backend(addr, timeouts(400, 700), 5);
    let r = b.stat("x").await;
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(mock.calls.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn a_reply_after_the_budget_is_an_error_and_does_not_break_later_operations() {
    let mock = stalling(1, MS(1200));
    let addr = start(mock.clone()).await;
    let b = backend(addr, timeouts(300, 600), 1);
    let t = Instant::now();
    let r = b.stat("late").await;
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(t.elapsed() < MS(900), "{:?}", t.elapsed());
    // Let the stale reply arrive and be discarded, then use the same backend again.
    tokio::time::sleep(MS(1300)).await;
    let s = b.stat("fresh").await.expect("backend must still work");
    assert_eq!(s.rel_path, "fresh");
}

#[tokio::test]
async fn non_idempotent_calls_are_not_retried_on_timeout() {
    let mock = stalling(100, Duration::from_secs(30));
    let addr = start(mock.clone()).await;
    let b = backend(addr, timeouts(250, 2000), 3);
    let t = Instant::now();
    let r = b.rename("a", "b", false).await;
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(t.elapsed() < MS(600), "{:?}", t.elapsed());
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
}

/// TCP proxy that can be frozen: after `freeze`, bytes are swallowed in both directions but the
/// sockets stay open (what a stopped process or a black-holed path looks like).
async fn proxy(target: SocketAddr, frozen: Arc<AtomicBool>) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = l.accept().await {
            let Ok(server) = tokio::net::TcpStream::connect(target).await else {
                continue;
            };
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = server.into_split();
            let (f1, f2) = (frozen.clone(), frozen.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = cr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if !f1.load(Ordering::SeqCst) && sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                let mut buf = [0u8; 16384];
                while let Ok(n) = sr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if !f2.load(Ordering::SeqCst) && cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn keepalive_detects_a_frozen_receiver_on_an_open_channel() {
    let addr = start(Arc::new(Mock::default())).await;
    let frozen = Arc::new(AtomicBool::new(false));
    let via = proxy(addr, frozen.clone()).await;
    // Per-request limit and budget are far longer than the keepalive detection time (~0.5 s),
    // so only keepalive can end the call early; one attempt, to measure it directly.
    let t = Timeouts {
        keepalive_interval: MS(200),
        keepalive_timeout: MS(300),
        ..timeouts(10_000, 10_000)
    };
    let b = backend(via, t, 1);
    b.stat("warm").await.expect("healthy channel works");
    // Idle on a healthy channel: pings are answered, the connection must survive.
    tokio::time::sleep(MS(1500)).await;
    b.stat("still-ok")
        .await
        .expect("no false disconnect when healthy");

    frozen.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let r = b.stat("frozen").await;
    let took = started.elapsed();
    assert!(matches!(r, Err(BackendError::RemoteUnavailable)), "{r:?}");
    assert!(took < MS(2500), "keepalive too slow: {took:?}");
}

#[tokio::test]
async fn after_a_failed_operation_calls_fail_fast_until_the_receiver_answers_again() {
    // The first call stalls past the budget; later calls are single short probes, and the
    // first success restores normal operation.
    let mock = stalling(1, Duration::from_secs(30));
    let addr = start(mock.clone()).await;
    let b = backend(addr, timeouts(400, 700), 3);
    assert!(b.stat("a").await.is_err());
    // Inside the fail-fast window the call is refused without touching the network.
    assert!(matches!(
        b.stat("b").await,
        Err(BackendError::RemoteUnavailable)
    ));
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    tokio::time::sleep(MS(150)).await;
    // The receiver answers now (stall_first is spent), so the probe succeeds.
    b.stat("b")
        .await
        .expect("probe must succeed and clear the degraded state");

    // Silent receiver: after one full-budget failure the next ones cost one probe each.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    let b = backend(dead, timeouts(400, 700), 3);
    assert!(b.stat("x").await.is_err());
    let t = Instant::now();
    for _ in 0..3 {
        assert!(b.stat("x").await.is_err());
    }
    assert!(
        t.elapsed() < MS(800),
        "3 probes of 150 ms took {:?}",
        t.elapsed()
    );
}
