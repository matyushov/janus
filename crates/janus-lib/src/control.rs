//! Control service for the orchestrator agent and `janus-cli`
//! (gRPC over a unix socket in production, TCP loopback in dev mode).
//!
//! A facade with no state of its own beyond the configuration; the only touch of the
//! hot path is the atomic `WriteGate` check in the write backend.
//!
//! Wire types are generated from the contract (`janus_proto::v1`).

use crate::jlog;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use janus_proto::v1::smb_front_control_server::SmbFrontControl;
use janus_proto::v1::{
    Ack, ConfigureRequest, DiagnosticsBundle, DrainReply, DrainRequest, Empty, Event, LogLine,
    LogRequest, Readiness, RotateRequest, ShutdownRequest, StatusReply,
};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::config::{ConfigStore, FlushPolicy, ShareConfig};
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

impl DaemonState {
    /// Backend for the restored state (see `from_config`).
    #[cfg(feature = "backend-grpc")]
    pub fn install_backend(
        &self,
        switch: &crate::switch_backend::SwitchBackend,
    ) -> std::io::Result<()> {
        if let (Some(remote), Some(share)) = (&self.remote, &self.share) {
            switch.apply(remote, share)?;
        }
        Ok(())
    }

    /// State restored from the persisted configuration (daemon start). An unusable stored
    /// config is reported to stderr and ignored: the daemon then waits for `Configure`.
    pub fn from_config(store: &ConfigStore) -> DaemonState {
        if !store.is_configured() {
            return DaemonState::default();
        }
        let share = (*store.current()).clone();
        match RemoteClient::connect_lazy(&RemoteConfig::from_share(&share)) {
            Ok(remote) => DaemonState {
                share: Some(share),
                remote: Some(remote),
            },
            Err(e) => {
                jlog!(
                    Warn,
                    "control",
                    "stored configuration is unusable ({e}); waiting for configure"
                );
                DaemonState::default()
            }
        }
    }
}

/// Implementation of the `SmbFrontControl` RPC.
pub struct ControlService {
    state: Arc<Mutex<DaemonState>>,
    gate: Arc<WriteGate>,
    version: &'static str,
    /// Daemon stop signal (on the Shutdown command); one-shot.
    shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// How long `shutdown --drain` waits for the journal to empty.
    shutdown_drain_timeout: std::time::Duration,
    /// The share's SMB account; generated on `Configure` if it does not exist yet.
    credentials: Option<Arc<crate::credentials::CredentialStore>>,
    /// Persistent configuration; `None` = memory only (tests).
    config: Option<Arc<ConfigStore>>,
    /// SMB operations currently waiting behind an interim response (shown by `status`).
    pending_ops: Option<Arc<crate::observability::PendingOps>>,
    /// The share's backend; `Configure` swaps a new `GrpcBackend` into it.
    #[cfg(feature = "backend-grpc")]
    backend: Option<Arc<crate::switch_backend::SwitchBackend>>,
}

impl ControlService {
    pub fn new(state: Arc<Mutex<DaemonState>>, gate: Arc<WriteGate>) -> Self {
        ControlService {
            state,
            gate,
            version: env!("CARGO_PKG_VERSION"),
            shutdown: Mutex::new(None),
            shutdown_drain_timeout: SHUTDOWN_DRAIN_TIMEOUT,
            credentials: None,
            config: None,
            pending_ops: None,
            #[cfg(feature = "backend-grpc")]
            backend: None,
        }
    }

    /// `Configure` rebuilds the backend in this switch without restarting the daemon.
    #[cfg(feature = "backend-grpc")]
    pub fn with_backend(mut self, b: Arc<crate::switch_backend::SwitchBackend>) -> Self {
        self.backend = Some(b);
        self
    }

    pub fn with_shutdown_drain_timeout(mut self, t: std::time::Duration) -> Self {
        self.shutdown_drain_timeout = t;
        self
    }

    /// Persist every accepted `Configure` through this store.
    pub fn with_config(mut self, store: Arc<ConfigStore>) -> Self {
        self.config = Some(store);
        self
    }

    /// Report the SMB layer's pending operations in `status`.
    pub fn with_pending_ops(mut self, p: Arc<crate::observability::PendingOps>) -> Self {
        self.pending_ops = Some(p);
        self
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
        ca_pem: req.ca_pem.clone(),
        share_name: req.share_name.clone(),
        mount_port: req.mount_port,
        smb_user: req.smb_user.clone(),
        smb_password_ref: req.smb_password_ref.clone(),
        quota_bytes: req.quota_bytes,
        flush_policy: match req.flush_policy {
            1 => FlushPolicy::SyncThrough,
            2 => FlushPolicy::LocalJournal,
            _ => FlushPolicy::Unspecified,
        },
        advertise_bonjour: req.advertise_bonjour,
        profile: match req.profile {
            2 => crate::profile::ClientProfile::WindowsGeneric,
            3 => crate::profile::ClientProfile::PosixGeneric,
            _ => crate::profile::ClientProfile::TimeMachine,
        },
        journal: crate::config::JournalConfig {
            enabled: req.journal_enabled.unwrap_or(true),
            dir: req.journal_dir.clone(),
            max_backlog_bytes: req.max_backlog_bytes,
        },
        smb_wait: crate::config::SmbWaitConfig {
            interim_after_ms: req.smb_interim_after_ms,
            max_wait_sec: req.smb_max_wait_sec,
            down_after_sec: req.smb_down_after_sec,
        },
    }
}

/// Why `ControlService::apply_share` did not apply a configuration.
#[derive(Debug)]
pub enum ApplyError {
    /// The configuration itself is wrong (a bad argument).
    Invalid(String),
    /// The configuration is fine but could not be put in place (disk, journal, backend).
    Refused(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Invalid(e) | ApplyError::Refused(e) => f.write_str(e),
        }
    }
}

impl ControlService {
    /// `Configure` without the wire types: validate, persist, install the backend, publish.
    pub async fn apply_share(&self, share: ShareConfig) -> Result<(), ApplyError> {
        if let Err(e) = share.validate() {
            return Err(ApplyError::Invalid(e.to_string()));
        }
        let remote_cfg = RemoteConfig::from_share(&share);
        let remote = RemoteClient::connect_lazy(&remote_cfg)
            .map_err(|e| ApplyError::Invalid(e.to_string()))?;

        // There is no guest access: SMB does not work without a login/password pair.
        if let Some(store) = &self.credentials
            && let Err(e) = store.ensure_generated()
        {
            return Err(ApplyError::Refused(format!(
                "failed to create SMB credentials: {e}"
            )));
        }

        // What to restore if the backend refuses the new configuration after it was persisted
        // (only a gRPC backend can refuse, so only that build needs it).
        #[cfg(feature = "backend-grpc")]
        let previous = self
            .config
            .as_ref()
            .filter(|c| c.is_configured())
            .map(|c| (*c.current()).clone());

        // Persist first: if the disk refuses, the running state stays as it was.
        if let Some(cfg) = &self.config
            && let Err(e) = cfg.apply(share.clone())
        {
            return Err(ApplyError::Refused(format!(
                "failed to persist configuration: {e}"
            )));
        }

        #[cfg(feature = "backend-grpc")]
        if let Some(b) = &self.backend
            && let Err(e) = b.apply(&remote, &share)
        {
            // The running state stays as it was, so must the file: otherwise a restart would
            // come back with a configuration that was refused.
            if let (Some(cfg), Some(prev)) = (&self.config, previous)
                && let Err(re) = cfg.apply(prev)
            {
                jlog!(
                    Error,
                    "control",
                    "could not restore the previous configuration: {re}"
                );
            }
            return Err(ApplyError::Refused(format!("configuration refused: {e}")));
        }

        let mut st = self.state.lock().await;
        st.share = Some(share);
        st.remote = Some(remote);

        // The Bonjour advertisement follows the new share by itself (janus-smbd re-reads the
        // configuration every few seconds). TODO: rebuild the SMB listener for a new port.

        Ok(())
    }
}

impl ControlService {
    /// The ordered readiness chain behind `EnsureReady`.
    pub async fn readiness(&self) -> Readiness {
        let mut st = self.state.lock().await;

        if st.share.is_none() {
            return Readiness {
                ready: false,
                blocker: "no-config".into(),
            };
        }

        let Some(remote) = st.remote.as_mut() else {
            return Readiness {
                ready: false,
                blocker: "no-remote-client".into(),
            };
        };

        match remote.ping().await {
            Ok(_server_version) => Readiness {
                ready: true,
                blocker: String::new(),
            },
            Err(e) => Readiness {
                ready: false,
                blocker: format!("appliance-unreachable: {e}"),
            },
        }
    }

    /// What `Status` reports.
    pub async fn status_reply(&self) -> StatusReply {
        let st = self.state.lock().await;
        #[cfg_attr(not(feature = "backend-grpc"), allow(unused_mut))]
        let mut reply = StatusReply {
            version: format!(
                "{} ({}{})",
                self.version,
                if st.share.is_some() {
                    "configured"
                } else {
                    "unconfigured"
                },
                if self.gate.is_open() {
                    ""
                } else {
                    ", quiesced"
                }
            ),
            ..Default::default()
        };
        if let Some(p) = &self.pending_ops {
            let (n, oldest) = p.snapshot();
            reply.pending_smb_ops = n as u32;
            reply.oldest_pending_smb_op_ms = oldest.map_or(0, |d| d.as_millis() as u64);
        }
        #[cfg(feature = "backend-grpc")]
        if let Some(b) = &self.backend {
            reply.open_handles = b.open_handles() as u32;
            if let Some(s) = b.journal_stats() {
                reply.journal_backlog_bytes = s.backlog_bytes;
                reply.uploaded_bytes_total = s.uploaded_bytes_total;
                reply.upload_errors = s.upload_errors.min(u32::MAX as u64) as u32;
                reply.last_appliance_ack_unix_ms = s.last_ack_unix_ms as i64;
                reply.oldest_unuploaded_age_ms = s.oldest_age_ms;
                reply.last_upload_error = s.last_error;
                reply.sticky_error_files = s.sticky_files as u32;
            }
        }
        reply
    }

    /// Wait until everything accepted so far reached the receiver and was fsynced there.
    pub async fn drain_for(&self, timeout: std::time::Duration) -> DrainReply {
        #[cfg(feature = "backend-grpc")]
        if let Some(b) = &self.backend {
            let (drained, remaining_bytes) = b.drain(timeout).await;
            return DrainReply {
                drained,
                remaining_bytes,
            };
        }
        let _ = timeout;
        DrainReply {
            drained: true,
            remaining_bytes: 0,
        }
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
        match self.apply_share(share_from_request(&req)).await {
            Ok(()) => Ok(Response::new(Ack {
                ok: true,
                error: String::new(),
            })),
            Err(ApplyError::Invalid(e)) => Err(Status::invalid_argument(e)),
            Err(ApplyError::Refused(error)) => Ok(Response::new(Ack { ok: false, error })),
        }
    }

    /// An ordered chain of checks; the first one to fail goes into `blocker`,
    /// so that the operator sees "what to fix", not just "not ready".
    async fn ensure_ready(&self, _req: Request<Empty>) -> Result<Response<Readiness>, Status> {
        Ok(Response::new(self.readiness().await))
    }

    async fn status(&self, _req: Request<Empty>) -> Result<Response<StatusReply>, Status> {
        Ok(Response::new(self.status_reply().await))
    }

    /// Wait until everything accepted so far reached the receiver and was fsynced there.
    async fn drain(&self, req: Request<DrainRequest>) -> Result<Response<DrainReply>, Status> {
        let timeout = std::time::Duration::from_secs(req.into_inner().timeout_sec.max(1) as u64);
        Ok(Response::new(self.drain_for(timeout).await))
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

    type StreamLogsStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<LogLine, Status>> + Send>>;

    async fn stream_logs(
        &self,
        req: Request<LogRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        use crate::log;
        let req = req.into_inner();
        let filter = log::Filter {
            min_level: Some(log::Level::from_u32(req.min_level)),
            components: req.components,
            contains: req.contains,
        };
        let (old, mut rx) = log::subscribe(req.tail as usize, &filter);
        let to_msg = |l: log::Line| LogLine {
            seq: l.seq,
            unix_ms: l.unix_ms,
            level: l.level as u32,
            component: l.component.to_owned(),
            text: l.text,
        };
        let (tx, out) = tokio::sync::mpsc::channel(256);
        tokio::spawn(async move {
            for l in old {
                if tx.send(Ok(to_msg(l))).await.is_err() {
                    return;
                }
            }
            if !req.follow {
                return;
            }
            loop {
                match rx.recv().await {
                    Ok(l) if filter.matches(&l) => {
                        if tx.send(Ok(to_msg(l))).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    // The reader was too slow; say so instead of silently skipping lines.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        let note = LogLine {
                            level: log::Level::Warn as u32,
                            component: "control".into(),
                            text: format!("log stream lagged: {n} lines skipped"),
                            ..Default::default()
                        };
                        if tx.send(Ok(note)).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(out),
        )))
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

    /// Stop the daemon. With `drain_first` the journal is emptied first (bounded by
    /// `shutdown_drain_timeout`); if that fails the daemon keeps running and the reply says
    /// how much is left. Without it the journal stays on disk and is uploaded at the next start.
    async fn shutdown(&self, req: Request<ShutdownRequest>) -> Result<Response<Ack>, Status> {
        #[cfg(feature = "backend-grpc")]
        if req.into_inner().drain_first
            && let Some(b) = &self.backend
        {
            let (drained, remaining) = b.drain(self.shutdown_drain_timeout).await;
            if !drained {
                return Ok(Response::new(Ack {
                    ok: false,
                    error: format!(
                        "drain incomplete: {remaining} bytes are still not on the receiver; \
                         not stopping (shutdown without --drain keeps the journal for the next start)"
                    ),
                }));
            }
        }
        #[cfg(not(feature = "backend-grpc"))]
        let _ = req;
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
                error: "shutdown already requested".into(),
            })),
        }
    }
}

/// Default of how long `shutdown --drain` waits for the journal to empty.
const SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

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
        let first = store.get().expect("pair created on configure");
        assert!(file.exists());

        // a repeated configure does not change the pair
        assert!(svc.configure(req()).await.unwrap().into_inner().ok);
        assert_eq!(store.get().unwrap(), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn configuration_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("janus-ctl-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config");

        let store = Arc::new(ConfigStore::load(&path).unwrap());
        let state = Arc::new(Mutex::new(DaemonState::from_config(&store)));
        assert!(state.lock().await.share.is_none());
        let svc =
            ControlService::new(Arc::clone(&state), Arc::default()).with_config(Arc::clone(&store));
        let ack = svc
            .configure(Request::new(ConfigureRequest {
                appliance_endpoint: "127.0.0.1:7443".into(),
                share_name: "tm".into(),
                mount_port: 4445,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(ack.ok, "{}", ack.error);

        // "restart": a new store and state from the same file
        let store2 = ConfigStore::load(&path).unwrap();
        let st2 = DaemonState::from_config(&store2);
        let share = st2.share.expect("restored");
        assert_eq!(share.appliance_endpoint, "127.0.0.1:7443");
        assert_eq!(share.share_name, "tm");
        assert_eq!(share.mount_port, 4445);
        assert!(st2.remote.is_some());

        // LOCAL_JOURNAL without a journal is refused, the stored config stays intact
        let err = svc
            .configure(Request::new(ConfigureRequest {
                appliance_endpoint: "127.0.0.1:1".into(),
                flush_policy: 2,
                journal_enabled: Some(false),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            ConfigStore::load(&path)
                .unwrap()
                .current()
                .appliance_endpoint,
            "127.0.0.1:7443"
        );
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
