//! Startup of the receiver's gRPC servers. Split out of main so that
//! integration tests start the server programmatically (ephemeral port,
//! temporary store).
//!
//! There are two planes:
//! - **data** (`BandTransport`): a network listener, receiving bands (mTLS in production);
//! - **control** (`ReceiverControl`): the fixed loopback port 50052,
//!   where `janus-cli server …` comes.

use std::sync::Arc;

use janus_proto::v1::band_transport_server::BandTransportServer;
use janus_proto::v1::receiver_control_server::ReceiverControlServer;
use tokio::net::TcpListener;
use tonic::codec::CompressionEncoding;

use crate::control::{ReceiverControlService, ReceiverState};
use crate::identity::IdentityMap;
use crate::router::{Router, RouterService};
use crate::tls::{self, TlsPaths};
use crate::worker::FileStore;

/// The receiver's control port (fixed, loopback). Symmetric to the client (50051).
pub const CONTROL_ADDR: &str = "127.0.0.1:50052";

/// Production settings (mTLS + IdentityMap).
#[derive(Debug, Clone)]
pub struct ProdConfig {
    pub listen: String,
    /// Parent directory of the per-machine stores.
    pub store_root: String,
    /// Quota for machines whose entry has none (0 = unlimited).
    pub default_quota: u64,
    pub tls: TlsPaths,
    pub machines: std::path::PathBuf,
    pub control_addr: String,
}

/// Dev mode: plain gRPC, one built-in store, no identity. Both planes, until Shutdown.
pub async fn serve_dev(
    listen: &str,
    store_dir: &str,
    quota_bytes: u64,
    control_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    let store = Arc::new(FileStore::open(store_dir)?);
    eprintln!(
        "janus-receiverd: data plane on {} (plain, dev), store={} (quota={})",
        listener.local_addr()?,
        store.root().display(),
        quota_label(quota_bytes)
    );
    let router = Arc::new(Router::single("local", store, quota_bytes));
    run(listener, router, None, control_addr).await
}

/// Production: mTLS (TLS 1.3, client certificate required) + IdentityMap. Everything is
/// validated before the first socket is opened, so a bad configuration fails the start.
pub async fn serve_mtls(cfg: ProdConfig) -> Result<(), Box<dyn std::error::Error>> {
    let tls = tls::server_config(&cfg.tls)?;
    std::fs::create_dir_all(&cfg.store_root)?;
    let map = IdentityMap::load(
        &cfg.machines,
        std::path::Path::new(&cfg.store_root),
        cfg.default_quota,
    )?;
    if map.machines().is_empty() {
        eprintln!(
            "janus-receiverd: warning: {} lists no machines",
            cfg.machines.display()
        );
    }
    let listener = TcpListener::bind(&cfg.listen).await?;
    eprintln!(
        "janus-receiverd: data plane on {} (mTLS, TLS 1.3), store root {}, {} machine(s)",
        listener.local_addr()?,
        cfg.store_root,
        map.machines().len()
    );
    run(
        listener,
        Arc::new(Router::mapped(map)),
        Some(tls),
        &cfg.control_addr,
    )
    .await
}

fn quota_label(quota_bytes: u64) -> String {
    if quota_bytes == 0 {
        "unlimited".to_string()
    } else {
        quota_bytes.to_string()
    }
}

async fn run(
    listener: TcpListener,
    router: Arc<Router>,
    tls: Option<Arc<rustls::ServerConfig>>,
    control_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- control plane ---
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let state = Arc::new(ReceiverState {
        router: Arc::clone(&router),
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
    let data = serve_router_on_listener(listener, router, tls, async move {
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

/// Serve one machine's store in plain gRPC on a ready listener until `shutdown` fires.
/// Used by tests (an ephemeral port + controlled stop).
pub async fn serve_on_listener(
    listener: TcpListener,
    store: Arc<FileStore>,
    quota_bytes: u64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = Arc::new(Router::single("local", store, quota_bytes));
    serve_router_on_listener(listener, router, None, shutdown).await
}

/// Serve a router on a ready listener: plain when `tls` is `None`, mTLS otherwise.
pub async fn serve_router_on_listener(
    listener: TcpListener,
    router: Arc<Router>,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    // zstd both ways; clients that do not ask for it get plain messages.
    let svc = BandTransportServer::new(RouterService(router))
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);
    let mut builder = tonic::transport::Server::builder();
    match tls {
        None => {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            builder
                .add_service(svc)
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await?;
        }
        Some(cfg) => {
            builder
                .add_service(svc)
                .serve_with_incoming_shutdown(tls::incoming(listener, cfg), shutdown)
                .await?;
        }
    }
    Ok(())
}
