//! janus-smbd: the janus SMB gateway (client side).
//!
//! A daemon: it starts and runs, waiting for instructions from `janus-cli client …`
//! on a fixed control port. The receiving server, the mount point and
//! the share parameters arrive with the `configure` command and are not
//! set by startup parameters.
//!
//! Arguments:
//!   (no arguments)    normal start (systemd/launchd)
//!   --dev             foreground debug mode: verbose output, does not
//!                     daemonize, does not wait for socket activation
//!
//! The configuration is persisted (`JANUS_CONFIG`, default `~/.config/janus/config`, 0600) and
//! restored on start.
//!
//! Addresses are overridden only through the environment (dev setups, parallel
//! instances): `JANUS_CLIENT_ADDR` is control, `JANUS_SMB_ADDR` is the SMB listener
//! (there is no `--smb-port` flag).
//!
//! SMB user: `JANUS_SMB_USER`/`JANUS_SMB_PASSWORD` (dev) or the file
//! `JANUS_SMB_CREDS_FILE` / `~/.config/janus/smb-credentials` (mode 0600;
//! created by `janus-cli client configure`). There is no guest access.

mod launchd;

use std::sync::Arc;

use janus_lib::config::ConfigStore;
use janus_lib::control::{ControlService, DaemonState, WriteGate};
use janus_lib::credentials::CredentialStore;
use janus_lib::jlog;
use janus_lib::switch_backend::SwitchBackend;
use janus_lib::vfs::{LocalFsBackend, StorageBackend};
use janus_proto::v1::smb_front_control_server::SmbFrontControlServer;
use smb_core::server::{DevServer, ServerConfig};
use tokio::sync::Mutex;

/// The share host is a model invariant (SMB does not leave the machine). Not a parameter.
const HOST: &str = "127.0.0.1";
/// Control address: `janus-cli client` talks here. Symmetric to the server (50052).
const CONTROL_ADDR: &str = "127.0.0.1:50051";
/// Default SMB listener. 445 is taken by the system SMB server on Windows and
/// needs privileges, so for debugging we take a high port.
const SMB_PORT: u16 = 4445;

/// Overrides for dev setups and tests.
const CONTROL_ADDR_ENV: &str = "JANUS_CLIENT_ADDR";
const SMB_ADDR_ENV: &str = "JANUS_SMB_ADDR";
/// Directory served by the local backend instead of the receiver (dev only).
const LOCAL_ROOT_ENV: &str = "JANUS_SMB_LOCAL_ROOT";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut dev = false;
    for arg in &args {
        match arg.as_str() {
            "--dev" => dev = true,
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("janus-smbd: unknown argument {other}\n");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    run(dev);
}

fn print_usage() {
    eprintln!(
        "janus-smbd — janus SMB gateway.\n\n\
         Usage: janus-smbd [--dev]\n\n  \
         --dev    foreground debug mode (verbose output)\n\n\
         The daemon awaits instructions on {CONTROL_ADDR}. Setup:\n  \
         janus-cli client configure --endpoint <host:port> --client-cert <pem> \\\n    \
         --client-key <pem> --ca <pem> [--share <name>] [--port <n>]\n\n\
         Address overrides (dev): {CONTROL_ADDR_ENV}, {SMB_ADDR_ENV}.\n\
         Share directory (dev only): {LOCAL_ROOT_ENV} serves a local folder instead of the receiver.\n\
         SMB user: JANUS_SMB_USER/JANUS_SMB_PASSWORD or the JANUS_SMB_CREDS_FILE file."
    );
}

fn spawn_smb<B: StorageBackend>(
    state: &Arc<Mutex<DaemonState>>,
    credentials: &Arc<CredentialStore>,
    pending: &Arc<janus_lib::observability::PendingOps>,
    backend: Arc<B>,
    listener: tokio::net::TcpListener,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    let server = Arc::new(
        DevServer::new(
            ServerConfig::default(),
            Arc::clone(state),
            Arc::clone(credentials),
            backend,
        )
        .with_pending_ops(Arc::clone(pending)),
    );
    tokio::spawn(async move { server.serve(listener).await })
}

fn run(dev: bool) {
    let control_addr = std::env::var(CONTROL_ADDR_ENV).unwrap_or_else(|_| CONTROL_ADDR.to_string());
    let smb_addr = std::env::var(SMB_ADDR_ENV).unwrap_or_else(|_| format!("{HOST}:{SMB_PORT}"));

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        // Persisted configuration: a restart comes back with the previous share.
        let config_path = janus_lib::config::default_path();
        let config = Arc::new(match &config_path {
            Some(p) => match ConfigStore::load(p) {
                Ok(c) => {
                    if c.is_configured() {
                        jlog!(Info, "daemon", "configuration restored from {}", p.display());
                    }
                    c
                }
                Err(e) => {
                    jlog!(Error, "daemon", "cannot use config file {}: {e}", p.display());
                    std::process::exit(1);
                }
            },
            None => {
                jlog!(Warn, "daemon", "no config path (set JANUS_CONFIG); configuration is not persisted");
                ConfigStore::in_memory()
            }
        });
        let state = Arc::new(Mutex::new(DaemonState::from_config(&config)));
        let gate = Arc::new(WriteGate::default());
        let pending_ops = Arc::new(janus_lib::observability::PendingOps::default());
        let switch = Arc::new(SwitchBackend::new().with_gate(Arc::clone(&gate)));
        if let Err(e) = state.lock().await.install_backend(&switch) {
            jlog!(Error, "daemon", "cannot start the journal: {e}");
            std::process::exit(1);
        }
        // SMB account: dev uses JANUS_SMB_USER/JANUS_SMB_PASSWORD, otherwise a 0600 file
        // (created by `janus-cli client configure`). There is no guest access.
        let credentials = Arc::new(CredentialStore::from_process_env());
        match credentials.get() {
            Some(c) => jlog!(Info, "daemon", "SMB user \"{}\" (password is not logged)", c.user),
            None => jlog!(Warn, "daemon", 
                "no SMB credentials — logins are rejected until `janus-cli client configure` \
                 (or set {}/{})",
                janus_lib::credentials::USER_ENV,
                janus_lib::credentials::PASSWORD_ENV
            ),
        }

        // --- control plane (janus-cli client / the orchestrator agent) ---
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let control_svc =
            ControlService::new(Arc::clone(&state), Arc::clone(&gate))
                .with_shutdown(shutdown_tx)
                .with_config(Arc::clone(&config))
                .with_pending_ops(Arc::clone(&pending_ops))
                .with_backend(Arc::clone(&switch))
                .with_credentials(Arc::clone(&credentials));
        let control_listener = match tokio::net::TcpListener::bind(&control_addr).await {
            Ok(l) => l,
            Err(e) => {
                jlog!(Error, "daemon", "failed to listen on control {control_addr}: {e}");
                std::process::exit(1);
            }
        };
        jlog!(Info, "daemon", "control plane on {control_addr} (janus-cli client …)");
        let control = tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(control_listener);
            tonic::transport::Server::builder()
                .add_service(SmbFrontControlServer::new(control_svc))
                .serve_with_incoming(incoming)
                .await
        });

        // --- SMB listener ---
        // TODO(prod): in normal mode the socket comes from launchd/systemd
        // (socket activation) and is not bound here; see launchd.rs.
        let smb_listener = match tokio::net::TcpListener::bind(&smb_addr).await {
            Ok(l) => l,
            Err(e) => {
                jlog!(Error, "daemon", "failed to listen on SMB {smb_addr}: {e}");
                std::process::exit(1);
            }
        };
        jlog!(Info, "daemon", "SMB on {smb_addr} (mount point smb://{smb_addr}/<share>)");
        if dev {
            jlog!(Info, "daemon", "dev mode; configure with: janus-cli client configure …");
        }
        // Backend: production serves the share from the receiver (gRPC/mTLS), built from the
        // persisted/pushed configuration and rebuilt on every `Configure`. Setting
        // JANUS_SMB_LOCAL_ROOT selects a plain local directory instead (dev, no receiver).
        let smb = if let Some(root) = std::env::var_os(LOCAL_ROOT_ENV) {
            let root = std::path::PathBuf::from(root);
            let backend = match LocalFsBackend::new(&root) {
                Ok(b) => Arc::new(b),
                Err(e) => {
                    jlog!(Error, "daemon", 
                        "cannot use {} as the share directory: {e}",
                        root.display()
                    );
                    std::process::exit(1);
                }
            };
            jlog!(Info, "daemon", 
                "DEV share directory {} ({LOCAL_ROOT_ENV}); no receiver is used",
                root.display()
            );
            spawn_smb(&state, &credentials, &pending_ops, backend, smb_listener)
        } else {
            let backend = Arc::clone(&switch);
            jlog!(Info, "daemon", 
                "share backend: receiver over gRPC/mTLS (waits for `janus-cli client configure` if not configured)"
            );
            spawn_smb(&state, &credentials, &pending_ops, backend, smb_listener)
        };

        // The failure of either plane is fatal for the daemon.
        tokio::select! {
            r = control => jlog!(Warn, "daemon", "control plane stopped: {r:?}"),
            r = smb => jlog!(Warn, "daemon", "SMB plane stopped: {r:?}"),
            _ = shutdown_rx => {
                jlog!(Info, "daemon", "stopping on shutdown command");
                // Let the gRPC reply to Shutdown reach the client.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                std::process::exit(0);
            }
        }
        std::process::exit(1);
    });
}
