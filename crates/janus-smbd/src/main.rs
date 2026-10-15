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
//! Addresses are overridden only through the environment (dev setups, parallel
//! instances): `JANUS_CLIENT_ADDR` is control, `JANUS_SMB_ADDR` is the SMB listener
//! (there is no `--smb-port` flag).
//!
//! SMB user: `JANUS_SMB_USER`/`JANUS_SMB_PASSWORD` (dev) or the file
//! `JANUS_SMB_CREDS_FILE` / `~/.config/janus/smb-credentials` (mode 0600;
//! created by `janus-cli client configure`). There is no guest access.

mod launchd;

use std::sync::Arc;

use janus_lib::control::{ControlService, DaemonState, WriteGate};
use janus_lib::credentials::CredentialStore;
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
                eprintln!("janus-smbd: неизвестный аргумент {other}\n");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    run(dev);
}

fn print_usage() {
    eprintln!(
        "janus-smbd — SMB-шлюз janus.\n\n\
         Использование: janus-smbd [--dev]\n\n  \
         --dev    foreground-режим отладки (подробный вывод)\n\n\
         Демон ожидает указаний на {CONTROL_ADDR}. Настройка:\n  \
         janus-cli client configure --endpoint <host:port> --client-cert <pem> \\\n    \
         --client-key <pem> --ca <pem> [--share <name>] [--port <n>]\n\n\
         Переопределение адресов (dev): {CONTROL_ADDR_ENV}, {SMB_ADDR_ENV}.\n\
         SMB-пользователь: JANUS_SMB_USER/JANUS_SMB_PASSWORD или файл JANUS_SMB_CREDS_FILE."
    );
}

fn run(dev: bool) {
    let control_addr = std::env::var(CONTROL_ADDR_ENV).unwrap_or_else(|_| CONTROL_ADDR.to_string());
    let smb_addr = std::env::var(SMB_ADDR_ENV).unwrap_or_else(|_| format!("{HOST}:{SMB_PORT}"));

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let state = Arc::new(Mutex::new(DaemonState::default()));
        let gate = Arc::new(WriteGate::default());
        // SMB account: dev uses JANUS_SMB_USER/JANUS_SMB_PASSWORD, otherwise a 0600 file
        // (created by `janus-cli client configure`). There is no guest access.
        let credentials = Arc::new(CredentialStore::from_process_env());
        match credentials.get() {
            Some(c) => eprintln!("janus-smbd: SMB-пользователь «{}» (пароль не логируется)", c.user),
            None => eprintln!(
                "janus-smbd: SMB-учётных данных нет — входы отклоняются до `janus-cli client configure` \
                 (или задайте {}/{})",
                janus_lib::credentials::USER_ENV,
                janus_lib::credentials::PASSWORD_ENV
            ),
        }

        // --- control plane (janus-cli client / the orchestrator agent) ---
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let control_svc =
            ControlService::new(Arc::clone(&state), Arc::clone(&gate))
                .with_shutdown(shutdown_tx)
                .with_credentials(Arc::clone(&credentials));
        let control_listener = match tokio::net::TcpListener::bind(&control_addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("janus-smbd: не удалось слушать control {control_addr}: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("janus-smbd: control-плоскость на {control_addr} (janus-cli client …)");
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
                eprintln!("janus-smbd: не удалось слушать SMB {smb_addr}: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("janus-smbd: SMB на {smb_addr} (точка монтирования smb://{smb_addr}/<share>)");
        if dev {
            eprintln!("janus-smbd: dev-режим; настроить: janus-cli client configure …");
        }
        let smb_server = Arc::new(DevServer::new(
            ServerConfig::default(),
            Arc::clone(&state),
            Arc::clone(&credentials),
        ));
        let smb = tokio::spawn(async move { smb_server.serve(smb_listener).await });

        // The failure of either plane is fatal for the daemon.
        tokio::select! {
            r = control => eprintln!("janus-smbd: control-плоскость остановлена: {r:?}"),
            r = smb => eprintln!("janus-smbd: SMB-плоскость остановлена: {r:?}"),
            _ = shutdown_rx => {
                eprintln!("janus-smbd: остановка по команде shutdown");
                // Let the gRPC reply to Shutdown reach the client.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                std::process::exit(0);
            }
        }
        std::process::exit(1);
    });
}
