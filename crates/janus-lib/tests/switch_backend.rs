//! `Configure` swaps the share's backend without a restart; handles survive the swap.

#![cfg(feature = "backend-grpc")]

use std::sync::Arc;

use janus_lib::control::{ControlService, DaemonState};
use janus_lib::switch_backend::SwitchBackend;
use janus_lib::vfs::{BackendError, Disposition, Kind, OpenRequest, StorageBackend};
use janus_proto::v1::ConfigureRequest;
use janus_proto::v1::smb_front_control_server::SmbFrontControl;
use janus_receiverd::testkit::TestServer;
use tonic::Request;

fn req(d: Disposition) -> OpenRequest {
    OpenRequest {
        disposition: d,
        kind: Kind::File,
        write: true,
        delete_on_close: false,
    }
}

fn configure(endpoint: String, quota: u64) -> Request<ConfigureRequest> {
    Request::new(ConfigureRequest {
        appliance_endpoint: endpoint,
        quota_bytes: quota,
        // this test is about generations of the backend, not about the journal
        journal_enabled: Some(false),
        ..Default::default()
    })
}

#[tokio::test]
async fn unconfigured_share_fails_as_unavailable_not_as_empty() {
    let sw = SwitchBackend::new();
    assert!(!sw.is_configured());
    assert!(matches!(
        sw.stat("").await,
        Err(BackendError::RemoteUnavailable)
    ));
    assert!(matches!(
        sw.open("f", req(Disposition::Create)).await,
        Err(BackendError::RemoteUnavailable)
    ));
    assert!(matches!(
        sw.statfs().await,
        Err(BackendError::RemoteUnavailable)
    ));
    assert!(matches!(
        sw.read(janus_lib::vfs::BackendHandle(1), 0, 1).await,
        Err(BackendError::BadHandle)
    ));
}

#[tokio::test]
async fn configure_installs_and_replaces_the_backend_keeping_open_handles_alive() {
    let (s1, s2) = (
        TestServer::start("sw1", 0).await.unwrap(),
        TestServer::start("sw2", 0).await.unwrap(),
    );
    let sw = Arc::new(SwitchBackend::new());
    let state = Arc::new(tokio::sync::Mutex::new(DaemonState::default()));
    let svc = ControlService::new(Arc::clone(&state), Arc::default()).with_backend(Arc::clone(&sw));

    let ack = svc
        .configure(configure(s1.addr.to_string(), 4096))
        .await
        .unwrap()
        .into_inner();
    assert!(ack.ok, "{}", ack.error);
    assert!(sw.is_configured());

    let h1 = sw.open("one.txt", req(Disposition::Create)).await.unwrap();
    sw.write(h1.handle, 0, b"first").await.unwrap();
    assert_eq!(s1.store.read_file("one.txt").unwrap(), b"first");

    // reconfigure to the second receiver while h1 is open
    assert!(
        svc.configure(configure(s2.addr.to_string(), 0))
            .await
            .unwrap()
            .into_inner()
            .ok
    );
    sw.write(h1.handle, 5, b"+more").await.unwrap(); // still goes to receiver 1
    assert_eq!(s1.store.read_file("one.txt").unwrap(), b"first+more");

    let h2 = sw.open("two.txt", req(Disposition::Create)).await.unwrap();
    assert_ne!(h1.handle, h2.handle);
    sw.write(h2.handle, 0, b"second").await.unwrap();
    assert_eq!(s2.store.read_file("two.txt").unwrap(), b"second");
    assert!(!s1.store.exists("two.txt"));
    assert!(
        matches!(sw.stat("one.txt").await, Err(BackendError::NotFound)),
        "new backend sees receiver 2"
    );

    sw.close(h1.handle).await.unwrap();
    assert!(matches!(
        sw.read(h1.handle, 0, 1).await,
        Err(BackendError::BadHandle)
    ));
    sw.close(h2.handle).await.unwrap();
}

// ---- the journal across reconfiguration, status, drain, quiesce ----

use janus_lib::control::WriteGate;
use janus_proto::v1::{DrainRequest, Empty, ShutdownRequest};
use std::time::Duration;

fn journal_dir(tag: &str) -> String {
    let mut r = [0u8; 4];
    getrandom::fill(&mut r).unwrap();
    std::env::temp_dir()
        .join(format!(
            "janus-sw-{tag}-{}-{}",
            std::process::id(),
            u32::from_le_bytes(r)
        ))
        .to_string_lossy()
        .into_owned()
}

fn configure_j(endpoint: String, dir: &str) -> Request<ConfigureRequest> {
    Request::new(ConfigureRequest {
        appliance_endpoint: endpoint,
        journal_dir: dir.to_owned(),
        ..Default::default()
    })
}

struct Rig {
    sw: Arc<SwitchBackend>,
    svc: ControlService,
    gate: Arc<WriteGate>,
    srv: TestServer,
    dir: String,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn rig(tag: &str) -> Rig {
    let srv = TestServer::start(tag, 0).await.unwrap();
    let gate = Arc::new(WriteGate::default());
    let sw = Arc::new(SwitchBackend::new().with_gate(Arc::clone(&gate)));
    let (tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let svc = ControlService::new(Arc::default(), Arc::clone(&gate))
        .with_backend(Arc::clone(&sw))
        .with_shutdown(tx)
        .with_shutdown_drain_timeout(Duration::from_millis(600));
    let dir = journal_dir(tag);
    let ack = svc
        .configure(configure_j(srv.addr.to_string(), &dir))
        .await
        .unwrap()
        .into_inner();
    assert!(ack.ok, "{}", ack.error);
    Rig {
        sw,
        svc,
        gate,
        srv,
        dir,
        shutdown_rx,
    }
}

fn pause(r: &Rig, on: bool) {
    r.sw.journal_runtime().unwrap().uploader.set_paused(on);
}

#[tokio::test]
async fn reconfigure_keeps_the_journal_and_uploads_through_the_new_link() {
    let r = rig("adopt").await;
    let h =
        r.sw.open("f", req(Disposition::Create))
            .await
            .unwrap()
            .handle;
    pause(&r, true);
    r.sw.write(h, 0, &[7; 5000]).await.unwrap();
    let before = r.sw.journal_runtime().unwrap();
    assert!(r.srv.store.read_file("f").unwrap().is_empty());

    // a new generation (same directory) adopts the running journal
    let ack = r
        .svc
        .configure(configure_j(r.srv.addr.to_string(), &r.dir))
        .await
        .unwrap()
        .into_inner();
    assert!(ack.ok, "{}", ack.error);
    assert!(Arc::ptr_eq(&before, &r.sw.journal_runtime().unwrap()));
    // the old handle keeps working and its data is read back from the shared journal
    r.sw.write(h, 5000, &[8; 10]).await.unwrap();
    assert_eq!(
        r.sw.read(h, 4995, 10).await.unwrap(),
        [7, 7, 7, 7, 7, 8, 8, 8, 8, 8]
    );
    pause(&r, false);
    let reply = r
        .svc
        .drain(Request::new(DrainRequest { timeout_sec: 10 }))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.drained && reply.remaining_bytes == 0);
    assert_eq!(r.srv.store.read_file("f").unwrap().len(), 5010);
    r.sw.close(h).await.unwrap();
}

#[tokio::test]
async fn status_reports_the_backlog_and_drain_waits_for_it() {
    let r = rig("status").await;
    let h =
        r.sw.open("f", req(Disposition::Create))
            .await
            .unwrap()
            .handle;
    pause(&r, true);
    r.sw.write(h, 0, &[1; 30_000]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let s = r
        .svc
        .status(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(s.journal_backlog_bytes, 30_000);
    assert!(s.oldest_unuploaded_age_ms >= 20);
    assert_eq!(s.uploaded_bytes_total, 0);
    assert_eq!(s.open_handles, 1);

    // a drain that cannot finish says how much is left
    let d = r
        .svc
        .drain(Request::new(DrainRequest { timeout_sec: 1 }))
        .await
        .unwrap()
        .into_inner();
    assert!(!d.drained);
    assert_eq!(d.remaining_bytes, 30_000);

    pause(&r, false);
    let d = r
        .svc
        .drain(Request::new(DrainRequest { timeout_sec: 10 }))
        .await
        .unwrap()
        .into_inner();
    assert!(d.drained);
    let s = r
        .svc
        .status(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(s.journal_backlog_bytes, 0);
    assert_eq!(s.uploaded_bytes_total, 30_000);
    assert!(s.last_appliance_ack_unix_ms > 0);
    assert_eq!(s.oldest_unuploaded_age_ms, 0);
    assert!(s.last_upload_error.is_empty());
    r.sw.close(h).await.unwrap();
}

#[tokio::test]
async fn quiesce_stops_new_writes_without_losing_accepted_ones() {
    let r = rig("quiesce").await;
    let h =
        r.sw.open("f", req(Disposition::Create))
            .await
            .unwrap()
            .handle;
    pause(&r, true);
    r.sw.write(h, 0, &[1; 1000]).await.unwrap();
    r.svc.quiesce(Request::new(Empty {})).await.unwrap();
    let w = r.sw.write(h, 1000, &[2; 1000]);
    tokio::pin!(w);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut w)
            .await
            .is_err()
    );
    // reads and what was accepted are unaffected
    assert_eq!(r.sw.read(h, 0, 1000).await.unwrap(), vec![1; 1000]);
    r.svc.resume(Request::new(Empty {})).await.unwrap();
    w.await.unwrap();
    assert!(r.gate.is_open());
    pause(&r, false);
    r.sw.close(h).await.unwrap();
    assert_eq!(r.srv.store.read_file("f").unwrap().len(), 2000);
}

#[tokio::test]
async fn shutdown_with_drain_refuses_to_stop_while_data_is_pending() {
    let mut r = rig("shutdown").await;
    let h =
        r.sw.open("f", req(Disposition::Create))
            .await
            .unwrap()
            .handle;
    pause(&r, true);
    r.sw.write(h, 0, &[1; 4000]).await.unwrap();
    let ack = r
        .svc
        .shutdown(Request::new(ShutdownRequest { drain_first: true }))
        .await
        .unwrap()
        .into_inner();
    assert!(!ack.ok);
    assert!(ack.error.contains("4000"), "{}", ack.error);
    assert!(
        r.shutdown_rx.try_recv().is_err(),
        "the daemon keeps running"
    );

    pause(&r, false);
    let ack = r
        .svc
        .shutdown(Request::new(ShutdownRequest { drain_first: true }))
        .await
        .unwrap()
        .into_inner();
    assert!(ack.ok, "{}", ack.error);
    assert!((&mut r.shutdown_rx).await.is_ok());
    assert_eq!(r.srv.store.read_file("f").unwrap().len(), 4000);
}
