//! Control service for the orchestrator agent and `janus-cli`
//! (gRPC over a unix socket in production, TCP loopback in dev mode).
//!
//! A facade with no state of its own beyond the configuration; the only touch of the
//! hot path is the atomic `WriteGate` check in the write backend.
//!
//! Wire types are generated from the contract (`janus_proto::v1`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use janus_proto::v1::smb_front_control_server::SmbFrontControl;
use janus_proto::v1::{
    Ack, ConfigureRequest, DiagnosticsBundle, DrainReply, DrainRequest, Empty, Event, Readiness,
    RotateRequest, ShutdownRequest, StatusReply,
};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::config::{FlushPolicy, ShareConfig};
use crate::remote::{RemoteClient, RemoteConfig};

/// The quiesce gate IN FRONT of the journal. Open/Quiesced are the only states.
#[derive(Debug, Default)]
pub struct WriteGate(AtomicU8);

impl WriteGate {
    const OPEN: u8 = 0;
    const QUIESCED: u8 = 1;

    pub fn quiesce(&self) {
        self.0.store(Self::QUIESCED, Ordering::Release);
    }
    pub fn resume(&self) {
        self.0.store(Self::OPEN, Ordering::Release);
    }
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::OPEN
    }
}

/// Current daemon state managed by the control plane.
#[derive(Default)]
pub struct DaemonState {
    /// Share configuration; None means not configured yet (`Configure` has not arrived).
    pub share: Option<ShareConfig>,
    /// Receiver client; created on `Configure`, the connection is lazy.
    pub remote: Option<RemoteClient>,
}

/// Implementation of the `SmbFrontControl` RPC.
pub struct ControlService {
    state: Arc<Mutex<DaemonState>>,
    gate: Arc<WriteGate>,
    version: &'static str,
    /// Daemon stop signal (on the Shutdown command); one-shot.
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// The share's SMB account; generated on `Configure` if it does not exist yet.
    credentials: Option<Arc<crate::credentials::CredentialStore>>,
}

impl ControlService {
    pub fn new(state: Arc<Mutex<DaemonState>>, gate: Arc<WriteGate>) -> Self {
        ControlService {
            state,
            gate,
            version: env!("CARGO_PKG_VERSION"),
            shutdown: Mutex::new(None),
            credentials: None,
        }
    }

    pub fn with_credentials(mut self, store: Arc<crate::credentials::CredentialStore>) -> Self {
        self.credentials = Some(store);
        self
    }

    /// Connect the stop channel: `Shutdown` sends a signal into it and the daemon
    /// shuts down gracefully (like receiverd).
    pub fn with_shutdown(mut self, tx: tokio::sync::oneshot::Sender<()>) -> Self {
        self.shutdown = Mutex::new(Some(tx));
        self
    }
}

/// `ConfigureRequest` → the internal share configuration.
fn share_from_request(req: &ConfigureRequest) -> ShareConfig {
    ShareConfig {
        appliance_endpoint: req.appliance_endpoint.clone(),
        tls_identity_ref: req.tls_identity_ref.clone(),
        client_cert_path: req.client_cert_path.clone(),
        client_key_path: req.client_key_path.clone(),
        share_name: req.share_name.clone(),
        smb_user: req.smb_user.clone(),
        smb_password_ref: req.smb_password_ref.clone(),
        quota_bytes: req.quota_bytes,
        flush_policy: match req.flush_policy {
            1 => FlushPolicy::SyncThrough,
            2 => FlushPolicy::LocalJournal,
            _ => FlushPolicy::Unspecified,
        },
        advertise_bonjour: req.advertise_bonjour,
        profile: Default::default(),
    }
}

#[tonic::async_trait]
impl SmbFrontControl for ControlService {
    /// Apply the configuration: save it and build the receiver client.
    /// The network is not touched here: the connection is lazy, the check is in `EnsureReady`.
    async fn configure(&self, req: Request<ConfigureRequest>) -> Result<Response<Ack>, Status> {
        let req = req.into_inner();
        if req.appliance_endpoint.is_empty() {
            return Err(Status::invalid_argument("appliance_endpoint is required"));
        }

        let share = share_from_request(&req);
        let remote_cfg = RemoteConfig {
            endpoint: req.appliance_endpoint.clone(),
            ca_pem: req.ca_pem.clone(),
            client_cert_path: req.client_cert_path.clone(),
            client_key_path: req.client_key_path.clone(),
        };
        let remote = RemoteClient::connect_lazy(&remote_cfg)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        // There is no guest access: SMB does not work without a login/password pair.
        if let Some(store) = &self.credentials
            && let Err(e) = store.ensure_generated()
        {
            return Ok(Response::new(Ack {
                ok: false,
                error: format!("не удалось создать учётные данные SMB: {e}"),
            }));
        }

        let mut st = self.state.lock().await;
        st.share = Some(share);
        st.remote = Some(remote);

        // TODO(persist): ConfigStore::apply, to survive a daemon restart.
        // TODO(bonjour/SMB): rebuild the advertisement and the listener for the new port/share.

        Ok(Response::new(Ack {
            ok: true,
            error: String::new(),
        }))
    }

    /// An ordered chain of checks; the first one to fail goes into `blocker`,
    /// so that the operator sees "what to fix", not just "not ready".
    async fn ensure_ready(&self, _req: Request<Empty>) -> Result<Response<Readiness>, Status> {
        let mut st = self.state.lock().await;

        if st.share.is_none() {
            return Ok(Response::new(Readiness {
                ready: false,
                blocker: "no-config".into(),
            }));
        }

        let Some(remote) = st.remote.as_mut() else {
            return Ok(Response::new(Readiness {
                ready: false,
                blocker: "no-remote-client".into(),
            }));
        };

        match remote.ping().await {
            Ok(_server_version) => Ok(Response::new(Readiness {
                ready: true,
                blocker: String::new(),
            })),
            Err(e) => Ok(Response::new(Readiness {
                ready: false,
                blocker: format!("appliance-unreachable: {e}"),
            })),
        }
    }

    async fn status(&self, _req: Request<Empty>) -> Result<Response<StatusReply>, Status> {
        // TODO(metrics): a snapshot of the observability::Metrics atomics.
        let st = self.state.lock().await;
        Ok(Response::new(StatusReply {
            smb_sessions: 0,
            open_handles: 0,
            durable_handles_parked: 0,
            journal_backlog_bytes: 0,
            uploaded_bytes_total: 0,
            upload_errors: 0,
            last_appliance_ack_unix_ms: 0,
            version: format!(
                "{} ({})",
                self.version,
                if st.share.is_some() {
                    "configured"
                } else {
                    "unconfigured"
                }
            ),
        }))
    }

    async fn drain(&self, _req: Request<DrainRequest>) -> Result<Response<DrainReply>, Status> {
        // TODO: forward to Uploader::drain_barrier.
        Ok(Response::new(DrainReply {
            drained: true,
            remaining_bytes: 0,
        }))
    }

    async fn quiesce(&self, _req: Request<Empty>) -> Result<Response<Ack>, Status> {
        self.gate.quiesce();
        Ok(Response::new(Ack {
            ok: true,
            error: String::new(),
        }))
    }

    async fn resume(&self, _req: Request<Empty>) -> Result<Response<Ack>, Status> {
        self.gate.resume();
        Ok(Response::new(Ack {
            ok: true,
            error: String::new(),
        }))
    }

    type WatchEventsStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<Event, Status>> + Send>>;

    async fn watch_events(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(Status::unimplemented("WatchEvents: TODO (EventBus)"))
    }

    async fn rotate_credentials(
        &self,
        _req: Request<RotateRequest>,
    ) -> Result<Response<Ack>, Status> {
        Err(Status::unimplemented("RotateCredentials: TODO"))
    }

    async fn get_diagnostics(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<DiagnosticsBundle>, Status> {
        Err(Status::unimplemented("GetDiagnostics: TODO"))
    }

    /// Stop the daemon. `drain_first` is not honoured yet: `drain` is a stub
    /// (TODO: forward to Uploader::drain_barrier), so there is nothing to build on here.
    async fn shutdown(&self, _req: Request<ShutdownRequest>) -> Result<Response<Ack>, Status> {
        match self.shutdown.lock().await.take() {
            Some(tx) => {
                let _ = tx.send(());
                Ok(Response::new(Ack {
                    ok: true,
                    error: String::new(),
                }))
            }
            None => Ok(Response::new(Ack {
                ok: false,
                error: "остановка уже запрошена".into(),
            })),
        }
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use crate::credentials::CredentialStore;

    #[tokio::test]
    async fn configure_generates_smb_credentials_once() {
        let dir = std::env::temp_dir().join(format!("janus-ctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("smb-credentials");
        let store = Arc::new(CredentialStore::load(None, None, Some(file.clone())));
        let svc = ControlService::new(Arc::default(), Arc::default())
            .with_credentials(Arc::clone(&store));
        assert!(store.get().is_none());

        let req = || {
            Request::new(ConfigureRequest {
                appliance_endpoint: "127.0.0.1:1".into(),
                ..Default::default()
            })
        };
        assert!(svc.configure(req()).await.unwrap().into_inner().ok);
        let first = store.get().expect("пара создана при configure");
        assert!(file.exists());

        // a repeated configure does not change the pair
        assert!(svc.configure(req()).await.unwrap().into_inner().ok);
        assert_eq!(store.get().unwrap(), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shutdown_signals_once_then_reports_already_requested() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let svc = ControlService::new(Arc::default(), Arc::default()).with_shutdown(tx);
        let req = || Request::new(ShutdownRequest { drain_first: false });

        let first = svc.shutdown(req()).await.unwrap().into_inner();
        assert!(first.ok);
        assert!(rx.await.is_ok());

        let second = svc.shutdown(req()).await.unwrap().into_inner();
        assert!(!second.ok);
    }
}
