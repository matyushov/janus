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
