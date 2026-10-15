//! Startup of the receiver's gRPC servers. Split out of main so that
//! integration tests start the server programmatically (ephemeral port,
//! temporary store).
//!
//! There are two planes:
//! - **data** (`BandTransport`): a network listener, receiving bands;
//! - **control** (`ReceiverControl`): the fixed loopback port 50052,
//!   where `janus-cli server …` comes.

use std::sync::Arc;

use janus_proto::v1::band_transport_server::BandTransportServer;
use janus_proto::v1::receiver_control_server::ReceiverControlServer;
use tokio::net::TcpListener;

use crate::control::{ReceiverControlService, ReceiverState};
use crate::service::BandTransportService;
use crate::worker::FileStore;

/// The receiver's control port (fixed, loopback). Symmetric to the client (50051).
pub const CONTROL_ADDR: &str = "127.0.0.1:50052";

/// Bring up both planes and serve until the Shutdown command arrives.
pub async fn serve_dev(
    listen: &str,
    store_dir: &str,
    quota_bytes: u64,
    control_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    let local = listener.local_addr()?;
    let store = Arc::new(FileStore::open(store_dir)?);
    eprintln!(
        "janus-receiverd: data plane on {local}, store={} (quota={})",
        store.root().display(),
        if quota_bytes == 0 {
            "unlimited".to_string()
        } else {
            quota_bytes.to_string()
        }
    );

    // --- control plane ---
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let state = Arc::new(ReceiverState {
        store: Arc::clone(&store),
        quota_bytes,
        machine_id: "local".to_string(),
        shutdown: tokio::sync::Mutex::new(Some(shutdown_tx)),
    });
    let control_listener = TcpListener::bind(control_addr).await?;
    eprintln!("janus-receiverd: control plane on {control_addr} (janus-cli server …)");
    let control_svc = ReceiverControlService::new(state);
    let control = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(control_listener);
        tonic::transport::Server::builder()
            .add_service(ReceiverControlServer::new(control_svc))
            .serve_with_incoming(incoming)
            .await
    });

    // The data plane lives until the Shutdown command from the control plane.
    let data = serve_on_listener(listener, store, quota_bytes, async move {
        let _ = shutdown_rx.await;
        eprintln!("janus-receiverd: shutdown command received");
    });

    tokio::select! {
        r = data => r?,
        r = control => {
            r.map_err(|e| format!("control plane failed: {e}"))??;
        }
    }
    Ok(())
}

/// Serve on a ready listener until `shutdown` fires.
/// Used by tests (an ephemeral port + controlled stop).
pub async fn serve_on_listener(
    listener: TcpListener,
    store: Arc<FileStore>,
    quota_bytes: u64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let svc = BandTransportService::new(store, quota_bytes);
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tonic::transport::Server::builder()
        .add_service(BandTransportServer::new(svc))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await?;
    Ok(())
}
