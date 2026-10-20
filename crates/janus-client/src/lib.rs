//! janus-client: the client core. It runs the local SMB endpoint (loopback only), the
//! write-ahead journal and the mTLS link to the receiver, inside the calling process.
//!
//! ```text
//! let client = Client::start(config)?;     // listeners are up, the runtime is owned by `client`
//! let info = client.mount_info();           // smb://127.0.0.1:<port>/<share> + user + password
//! client.ready()?;                          // the receiver is reachable over mTLS
//! client.stop(StopMode::Drain(timeout));    // wait for the upload, close everything
//! ```
//!
//! Rules of the library: no `process::exit`, no reading of the environment, `HOME` or default
//! paths (everything arrives in [`ClientConfig`]); the tokio runtime belongs to the client;
//! every method is callable from any thread that is not one of the client's own workers.
//! One client per process (the log hub is global): a second `start` fails until `stop`.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use janus_lib::config::{ConfigStore, ShareConfig};
use janus_lib::control::{ControlService, DaemonState, WriteGate};
use janus_lib::credentials::CredentialStore;
use janus_lib::jlog;
use janus_lib::switch_backend::SwitchBackend;
use janus_lib::vfs::{LocalFsBackend, StorageBackend};
use janus_proto::v1::smb_front_control_server::SmbFrontControlServer;
use serde::Serialize;
use smb_core::server::{DEFAULT_SHARE, DevServer, ServerConfig};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

pub use janus_lib::log::{Level, Line, Sink};

/// The share host is a model invariant (SMB does not leave the machine).
pub const SMB_HOST: &str = "127.0.0.1";
/// How long `stop` waits for the runtime's remaining tasks before abandoning them.
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(5);

/// Everything the client needs, explicitly. `Default` is the SDK profile: a free loopback
/// port, no control port, no Bonjour, a generated in-memory password, nothing persisted.
#[derive(Clone)]
pub struct ClientConfig {
    /// Share configuration applied at start (and persisted when there is a config file).
    /// `None` = whatever the config file holds, or "unconfigured" (wait for `configure`).
    pub share: Option<ShareConfig>,
    /// Directory for the config, the journal (unless the share names one) and the SMB
    /// credentials. `None` = nothing persisted and no default journal directory.
    pub state_dir: Option<PathBuf>,
    /// Persisted configuration file. `None` = `<state_dir>/config`, or memory only.
    pub config_file: Option<PathBuf>,
    /// SMB listener. Port 0 = a free port (see [`Client::mount_info`]).
    pub smb_listen: String,
    /// Accept a non-loopback `smb_listen`. Only for the standalone daemon's dev setups.
    pub allow_non_loopback: bool,
    /// gRPC control plane (for `janus-cli client …`). `None` = off.
    pub control_listen: Option<String>,
    /// SMB account. Both set = this pair (never written to disk).
    pub smb_user: Option<String>,
    pub smb_password: Option<String>,
    /// File with `user:password` (0600). `None` = `<state_dir>/smb-credentials`, or memory only.
    pub smb_credentials_file: Option<PathBuf>,
    /// Generate a pair at start when there is none (otherwise at the first `configure`).
    pub generate_credentials: bool,
    /// Serve this local directory instead of the receiver (dev, no receiver).
    pub local_root: Option<PathBuf>,
    /// Advertise the share over Bonjour (macOS; needs `share.advertise_bonjour`).
    pub bonjour: bool,
    /// Advertise the default share name even when no share is configured (dev).
    pub bonjour_without_share: bool,
    /// SMB trace level: 0 off, 1 commands, 2 also request hex.
    pub trace: u8,
    /// Runtime worker threads (0 = one per CPU).
    pub worker_threads: usize,
    /// Receives every log line of the process while the client runs.
    pub log_sink: Option<Sink>,
    /// Keep printing log lines to stderr.
    pub log_stderr: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            share: None,
            state_dir: None,
            config_file: None,
            smb_listen: format!("{SMB_HOST}:0"),
            allow_non_loopback: false,
            control_listen: None,
            smb_user: None,
            smb_password: None,
            smb_credentials_file: None,
            generate_credentials: true,
            local_root: None,
            bonjour: false,
            bonjour_without_share: false,
            trace: 0,
            worker_threads: 2,
            log_sink: None,
            log_stderr: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// A client is already running in this process.
    AlreadyStarted,
    /// The configuration is unusable (message says what).
    InvalidConfig(String),
    /// A listener could not be bound.
    Bind(String),
    /// The receiver is not reachable yet / not configured; carries the blocker.
    NotReady(String),
    /// The journal did not drain in time; carries the bytes still not on the receiver.
    Timeout { remaining_bytes: u64 },
    /// The journal could not be started.
    Journal(String),
    /// The configuration was fine but could not be applied.
    Refused(String),
    /// Anything else (a panicked task, a runtime that would not start).
    Internal(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::AlreadyStarted => f.write_str("a janus client is already running"),
            ClientError::InvalidConfig(m)
            | ClientError::Bind(m)
            | ClientError::Journal(m)
            | ClientError::Refused(m)
            | ClientError::Internal(m) => f.write_str(m),
            ClientError::NotReady(b) => write!(f, "not ready: {b}"),
            ClientError::Timeout { remaining_bytes } => {
                write!(
                    f,
                    "drain timed out, {remaining_bytes} bytes not on the receiver"
                )
            }
        }
    }
}

impl std::error::Error for ClientError {}

/// How to mount the share. The password is never in `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MountInfo {
    /// `smb://127.0.0.1:<port>/<share>`
    pub url: String,
    pub host: String,
    pub port: u16,
    pub share: String,
    /// Empty until credentials exist (before the first `configure` without `generate_credentials`).
    pub user: String,
    pub password: String,
}

impl std::fmt::Debug for MountInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountInfo")
            .field("url", &self.url)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// A snapshot for dashboards and the host application.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClientStatus {
    pub version: String,
    pub configured: bool,
    pub pending_smb_ops: u32,
    pub oldest_pending_smb_op_ms: u64,
    pub open_handles: u32,
    pub journal_backlog_bytes: u64,
    pub uploaded_bytes_total: u64,
    pub upload_errors: u32,
    pub last_appliance_ack_unix_ms: i64,
    pub oldest_unuploaded_age_ms: u64,
    pub last_upload_error: String,
    pub sticky_error_files: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// Close at once; the journal keeps its bytes for the next start.
    Immediate,
    /// Wait up to this long for the journal to reach the receiver first.
    Drain(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReport {
    /// `true` unless a requested drain ran out of time.
    pub drained: bool,
    pub remaining_bytes: u64,
}

/// Why [`Client::wait`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// A `Shutdown` command arrived on the control plane.
    ShutdownRequested,
    ControlStopped(String),
    SmbStopped(String),
}

/// At most one client per process.
static RUNNING: AtomicBool = AtomicBool::new(false);

struct SingleInstance;

impl SingleInstance {
    fn acquire() -> Result<SingleInstance, ClientError> {
        RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| SingleInstance)
            .map_err(|_| ClientError::AlreadyStarted)
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

type Bonjour = Arc<StdMutex<janus_lib::bonjour::BonjourAdvertiser>>;

pub struct Client {
    rt: Option<tokio::runtime::Runtime>,
    state: Arc<Mutex<DaemonState>>,
    control: Arc<ControlService>,
    switch: Arc<SwitchBackend>,
    credentials: Arc<CredentialStore>,
    smb_addr: SocketAddr,
    control_addr: Option<SocketAddr>,
    exit: watch::Receiver<Option<ExitReason>>,
    tasks: Vec<JoinHandle<()>>,
    bonjour: Option<Bonjour>,
    /// Released last, after the runtime is gone.
    _single: SingleInstance,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("smb_addr", &self.smb_addr)
            .field("control_addr", &self.control_addr)
            .finish_non_exhaustive()
    }
}

fn invalid(msg: impl Into<String>) -> ClientError {
    ClientError::InvalidConfig(msg.into())
}

impl Client {
    /// Bring the client up: the listeners are bound when this returns.
    pub fn start(cfg: ClientConfig) -> Result<Client, ClientError> {
        let single = SingleInstance::acquire()?;
        if cfg.smb_listen.trim().is_empty() {
            return Err(invalid("smb_listen is empty"));
        }
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all().thread_name("janus-client");
        if cfg.worker_threads > 0 {
            builder.worker_threads(cfg.worker_threads);
        }
        let rt = builder
            .build()
            .map_err(|e| ClientError::Internal(format!("cannot start the runtime: {e}")))?;

        janus_lib::log::set_stderr(cfg.log_stderr);
        janus_lib::log::set_sink(cfg.log_sink.clone());
        let parts = rt.block_on(Self::bring_up(&cfg));
        let parts = match parts {
            Ok(p) => p,
            Err(e) => {
                reset_log();
                rt.shutdown_timeout(RUNTIME_SHUTDOWN);
                return Err(e);
            }
        };
        Ok(Client {
            rt: Some(rt),
            state: parts.state,
            control: parts.control,
            switch: parts.switch,
            credentials: parts.credentials,
            smb_addr: parts.smb_addr,
            control_addr: parts.control_addr,
            exit: parts.exit,
            tasks: parts.tasks,
            bonjour: parts.bonjour,
            _single: single,
        })
    }

    async fn bring_up(cfg: &ClientConfig) -> Result<Parts, ClientError> {
        // Persisted configuration: a restart comes back with the previous share.
        let config_file = cfg
            .config_file
            .clone()
            .or_else(|| cfg.state_dir.as_ref().map(|d| d.join("config")));
        let config = Arc::new(match &config_file {
            Some(p) => match ConfigStore::load(p) {
                Ok(c) => {
                    if c.is_configured() {
                        jlog!(
                            Info,
                            "daemon",
                            "configuration restored from {}",
                            p.display()
                        );
                    }
                    c
                }
                Err(e) => {
                    return Err(invalid(format!(
                        "cannot use config file {}: {e}",
                        p.display()
                    )));
                }
            },
            None => ConfigStore::in_memory(),
        });
        if let Some(share) = &cfg.share {
            config
                .apply(share.clone())
                .map_err(|e| invalid(format!("invalid share configuration: {e}")))?;
        }
        let state = Arc::new(Mutex::new(DaemonState::from_config(&config)));
        let gate = Arc::new(WriteGate::default());
        let pending_ops = Arc::new(janus_lib::observability::PendingOps::default());
        let switch = Arc::new(
            SwitchBackend::new()
                .with_gate(Arc::clone(&gate))
                .with_state_dir(cfg.state_dir.clone()),
        );
        if let Err(e) = state.lock().await.install_backend(&switch) {
            return Err(ClientError::Journal(format!(
                "cannot start the journal: {e}"
            )));
        }

        // SMB account. There is no guest access.
        let creds_file = cfg
            .smb_credentials_file
            .clone()
            .or_else(|| cfg.state_dir.as_ref().map(|d| d.join("smb-credentials")));
        let credentials = Arc::new(CredentialStore::load(
            cfg.smb_user.clone(),
            cfg.smb_password.clone(),
            creds_file,
        ));
        if cfg.generate_credentials
            && let Err(e) = credentials.ensure_generated()
        {
            return Err(ClientError::Internal(format!(
                "cannot create SMB credentials: {e}"
            )));
        }
        match credentials.get() {
            Some(c) => jlog!(
                Info,
                "daemon",
                "SMB user \"{}\" (password is not logged)",
                c.user
            ),
            None => jlog!(
                Warn,
                "daemon",
                "no SMB credentials — logins are rejected until `janus-cli client configure` \
                 (or set {}/{})",
                janus_lib::credentials::USER_ENV,
                janus_lib::credentials::PASSWORD_ENV
            ),
        }

        // Both listeners are bound before anything is spawned: a failure leaves nothing behind.
        let control_listener = match &cfg.control_listen {
            Some(addr) => Some(tokio::net::TcpListener::bind(addr).await.map_err(|e| {
                ClientError::Bind(format!("failed to listen on control {addr}: {e}"))
            })?),
            None => None,
        };
        let smb_listener = tokio::net::TcpListener::bind(&cfg.smb_listen)
            .await
            .map_err(|e| {
                ClientError::Bind(format!("failed to listen on SMB {}: {e}", cfg.smb_listen))
            })?;
        let smb_addr = smb_listener
            .local_addr()
            .map_err(|e| ClientError::Internal(format!("SMB listener address: {e}")))?;
        if !smb_addr.ip().is_loopback() && !cfg.allow_non_loopback {
            return Err(invalid(format!(
                "smb_listen {} is not a loopback address (SMB never leaves the machine)",
                cfg.smb_listen
            )));
        }
        let control_addr = control_listener.as_ref().and_then(|l| l.local_addr().ok());

        let local_backend = match &cfg.local_root {
            Some(root) => Some((
                root,
                LocalFsBackend::new(root).map(Arc::new).map_err(|e| {
                    invalid(format!(
                        "cannot use {} as the share directory: {e}",
                        root.display()
                    ))
                })?,
            )),
            None => None,
        };

        // Shutdown requests and plane failures end up in one watch channel.
        let (exit_tx, exit_rx) = watch::channel(None::<ExitReason>);
        let exit_tx = Arc::new(exit_tx);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let control = Arc::new(
            ControlService::new(Arc::clone(&state), Arc::clone(&gate))
                .with_shutdown(shutdown_tx)
                .with_config(Arc::clone(&config))
                .with_pending_ops(Arc::clone(&pending_ops))
                .with_backend(Arc::clone(&switch))
                .with_credentials(Arc::clone(&credentials)),
        );

        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        {
            let tx = Arc::clone(&exit_tx);
            tasks.push(tokio::spawn(async move {
                if shutdown_rx.await.is_ok() {
                    set_exit(&tx, ExitReason::ShutdownRequested);
                }
            }));
        }
        if let Some(listener) = control_listener {
            let addr = cfg.control_listen.clone().unwrap_or_default();
            jlog!(
                Info,
                "daemon",
                "control plane on {addr} (janus-cli client …)"
            );
            let svc = Arc::clone(&control);
            let tx = Arc::clone(&exit_tx);
            tasks.push(tokio::spawn(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                let r = tonic::transport::Server::builder()
                    .add_service(SmbFrontControlServer::from_arc(svc))
                    .serve_with_incoming(incoming)
                    .await;
                jlog!(Warn, "daemon", "control plane stopped: {r:?}");
                set_exit(&tx, ExitReason::ControlStopped(format!("{r:?}")));
            }));
        }

        jlog!(
            Info,
            "daemon",
            "SMB on {} (mount point smb://{}/<share>)",
            smb_addr,
            smb_addr
        );
        let bonjour = cfg.bonjour.then(|| {
            spawn_bonjour(
                &state,
                smb_addr.port(),
                cfg.bonjour_without_share,
                &mut tasks,
            )
        });

        let shared = open_shared(&state, &switch).await;
        let trace = cfg.trace;
        match local_backend {
            Some((root, backend)) => {
                jlog!(
                    Info,
                    "daemon",
                    "DEV share directory {}; no receiver is used",
                    root.display()
                );
                spawn_smb(
                    &state,
                    &credentials,
                    &pending_ops,
                    backend,
                    smb_listener,
                    shared,
                    trace,
                    &exit_tx,
                    &mut tasks,
                );
            }
            None => {
                jlog!(
                    Info,
                    "daemon",
                    "share backend: receiver over gRPC/mTLS (waits for `janus-cli client configure` if not configured)"
                );
                spawn_smb(
                    &state,
                    &credentials,
                    &pending_ops,
                    Arc::clone(&switch),
                    smb_listener,
                    shared,
                    trace,
                    &exit_tx,
                    &mut tasks,
                );
            }
        }

        Ok(Parts {
            state,
            control,
            switch,
            credentials,
            smb_addr,
            control_addr,
            exit: exit_rx,
            tasks,
            bonjour,
        })
    }

    /// Run `f` on the client's runtime and wait for it. Safe from any thread that is not a
    /// worker of this client; a panic inside `f` becomes `Internal`.
    fn block<F>(&self, f: F) -> Result<F::Output, ClientError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let Some(rt) = &self.rt else {
            return Err(ClientError::Internal("client is stopped".into()));
        };
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            let _ = tx.send(f.await);
        });
        rx.recv()
            .map_err(|_| ClientError::Internal("client task panicked or was cancelled".into()))
    }

    /// The local SMB endpoint.
    pub fn smb_addr(&self) -> SocketAddr {
        self.smb_addr
    }

    /// The control plane's address, when it is on.
    pub fn control_addr(&self) -> Option<SocketAddr> {
        self.control_addr
    }

    /// URL and account to mount the share with. Follows `configure` (the share name may change).
    pub fn mount_info(&self) -> Result<MountInfo, ClientError> {
        let state = Arc::clone(&self.state);
        let share = self.block(async move {
            let st = state.lock().await;
            st.share
                .as_ref()
                .map(|s| s.share_name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| DEFAULT_SHARE.to_owned())
        })?;
        let creds = self.credentials.get();
        let (user, password) = creds.map(|c| (c.user, c.password)).unwrap_or_default();
        let port = self.smb_addr.port();
        Ok(MountInfo {
            url: format!("smb://{}:{port}/{share}", self.smb_addr.ip()),
            host: self.smb_addr.ip().to_string(),
            port,
            share,
            user,
            password,
        })
    }

    /// `Ok` when a share is configured and the receiver answers over mTLS.
    pub fn ready(&self) -> Result<(), ClientError> {
        let control = Arc::clone(&self.control);
        let r = self.block(async move { control.readiness().await })?;
        if r.ready {
            Ok(())
        } else {
            Err(ClientError::NotReady(r.blocker))
        }
    }

    pub fn status(&self) -> Result<ClientStatus, ClientError> {
        let control = Arc::clone(&self.control);
        let r = self.block(async move { control.status_reply().await })?;
        Ok(ClientStatus {
            configured: r.version.contains("(configured"),
            version: r.version,
            pending_smb_ops: r.pending_smb_ops,
            oldest_pending_smb_op_ms: r.oldest_pending_smb_op_ms,
            open_handles: r.open_handles,
            journal_backlog_bytes: r.journal_backlog_bytes,
            uploaded_bytes_total: r.uploaded_bytes_total,
            upload_errors: r.upload_errors,
            last_appliance_ack_unix_ms: r.last_appliance_ack_unix_ms,
            oldest_unuploaded_age_ms: r.oldest_unuploaded_age_ms,
            last_upload_error: r.last_upload_error,
            sticky_error_files: r.sticky_error_files,
        })
    }

    /// Apply (and persist) a new share configuration.
    pub fn configure(&self, share: ShareConfig) -> Result<(), ClientError> {
        let control = Arc::clone(&self.control);
        self.block(async move { control.apply_share(share).await })?
            .map_err(|e| match e {
                janus_lib::control::ApplyError::Invalid(m) => ClientError::InvalidConfig(m),
                janus_lib::control::ApplyError::Refused(m) => ClientError::Refused(m),
            })
    }

    /// Wait until everything accepted so far is on the receiver.
    pub fn drain(&self, timeout: Duration) -> Result<(), ClientError> {
        let control = Arc::clone(&self.control);
        let r = self.block(async move { control.drain_for(timeout).await })?;
        if r.drained {
            Ok(())
        } else {
            Err(ClientError::Timeout {
                remaining_bytes: r.remaining_bytes,
            })
        }
    }

    /// Block until a `Shutdown` command arrives or a plane dies (the standalone daemon's main
    /// loop). Embedding applications do not need it.
    pub fn wait(&self) -> ExitReason {
        let mut rx = self.exit.clone();
        self.block(async move {
            loop {
                if let Some(r) = rx.borrow_and_update().clone() {
                    return r;
                }
                if rx.changed().await.is_err() {
                    return ExitReason::ControlStopped("client is gone".into());
                }
            }
        })
        .unwrap_or_else(|e| ExitReason::ControlStopped(e.to_string()))
    }

    /// Stop the client: optionally drain, close the listeners, end the tasks, stop Bonjour.
    /// The ports are free when this returns. Never fails: a drain that ran out of time is
    /// reported, and the client is stopped anyway (the journal keeps the rest).
    pub fn stop(mut self, mode: StopMode) -> StopReport {
        let mut report = StopReport {
            drained: true,
            remaining_bytes: 0,
        };
        if let StopMode::Drain(timeout) = mode {
            let switch = Arc::clone(&self.switch);
            if let Ok((drained, remaining_bytes)) =
                self.block(async move { switch.drain(timeout).await })
            {
                report = StopReport {
                    drained,
                    remaining_bytes,
                };
            }
        }
        self.shutdown();
        report
    }

    fn shutdown(&mut self) {
        let Some(rt) = self.rt.take() else {
            return;
        };
        for t in &self.tasks {
            t.abort();
        }
        let tasks = std::mem::take(&mut self.tasks);
        // Inside another runtime's thread we cannot block; the abort still takes effect.
        let can_block = tokio::runtime::Handle::try_current().is_err();
        if can_block {
            rt.block_on(async {
                for t in tasks {
                    let _ = t.await;
                }
            });
        }
        // The dns-sd children would outlive the process otherwise.
        if let Some(b) = self.bonjour.take() {
            b.lock().unwrap_or_else(|e| e.into_inner()).stop();
        }
        if can_block {
            rt.shutdown_timeout(RUNTIME_SHUTDOWN);
        } else {
            rt.shutdown_background();
        }
        reset_log();
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Parts {
    state: Arc<Mutex<DaemonState>>,
    control: Arc<ControlService>,
    switch: Arc<SwitchBackend>,
    credentials: Arc<CredentialStore>,
    smb_addr: SocketAddr,
    control_addr: Option<SocketAddr>,
    exit: watch::Receiver<Option<ExitReason>>,
    tasks: Vec<JoinHandle<()>>,
    bonjour: Option<Bonjour>,
}

fn reset_log() {
    janus_lib::log::set_sink(None);
    janus_lib::log::set_stderr(true);
}

fn set_exit(tx: &watch::Sender<Option<ExitReason>>, reason: ExitReason) {
    tx.send_if_modified(|cur| {
        if cur.is_none() {
            *cur = Some(reason);
            true
        } else {
            false
        }
    });
}

/// Durable handles parked by a dropped connection are kept next to the journal, so a client
/// can reclaim them after a restart too.
async fn open_shared(
    state: &Arc<Mutex<DaemonState>>,
    switch: &SwitchBackend,
) -> Arc<smb_core::shared::Shared> {
    let dir = {
        let st = state.lock().await;
        match &st.share {
            Some(s) => switch.journal_dir_of(s),
            None => switch.journal_dir_of(&ShareConfig::default()),
        }
    };
    let store = match dir.map(|d| janus_lib::journal::ParkedHandleStore::in_dir(&d)) {
        Some(Ok(store)) => store,
        Some(Err(e)) => {
            jlog!(
                Warn,
                "daemon",
                "durable handles will not survive a restart: {e}"
            );
            janus_lib::journal::ParkedHandleStore::in_memory()
        }
        None => janus_lib::journal::ParkedHandleStore::in_memory(),
    };
    Arc::new(smb_core::shared::Shared::new(store))
}

/// Keeps the mDNS advertisement in line with the configured share (set by `Configure`, so it
/// is re-read periodically) and restarts it if `dns-sd` dies. macOS only; elsewhere a no-op.
fn spawn_bonjour(
    state: &Arc<Mutex<DaemonState>>,
    port: u16,
    without_share: bool,
    tasks: &mut Vec<JoinHandle<()>>,
) -> Bonjour {
    let state = Arc::clone(state);
    let adv = Arc::new(StdMutex::new(
        janus_lib::bonjour::BonjourAdvertiser::default(),
    ));
    let handle = Arc::clone(&adv);
    tasks.push(tokio::spawn(async move {
        loop {
            let wanted = {
                let st = state.lock().await;
                match &st.share {
                    Some(s) if s.advertise_bonjour => Some(s.share_name.clone()),
                    Some(_) => None,
                    None if without_share => Some(DEFAULT_SHARE.to_owned()),
                    None => None,
                }
            };
            let wanted = wanted.map(|share| janus_lib::bonjour::Registration {
                share: if share.is_empty() {
                    DEFAULT_SHARE.to_owned()
                } else {
                    share
                },
                port,
            });
            adv.lock().unwrap_or_else(|e| e.into_inner()).sync(wanted);
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }));
    handle
}

#[allow(clippy::too_many_arguments)]
fn spawn_smb<B: StorageBackend>(
    state: &Arc<Mutex<DaemonState>>,
    credentials: &Arc<CredentialStore>,
    pending: &Arc<janus_lib::observability::PendingOps>,
    backend: Arc<B>,
    listener: tokio::net::TcpListener,
    shared: Arc<smb_core::shared::Shared>,
    trace: u8,
    exit: &Arc<watch::Sender<Option<ExitReason>>>,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    let server = Arc::new(
        DevServer::new(
            ServerConfig::default(),
            Arc::clone(state),
            Arc::clone(credentials),
            backend,
        )
        .with_pending_ops(Arc::clone(pending))
        .with_shared(shared)
        .with_trace(trace),
    );
    let tx = Arc::clone(exit);
    tasks.push(tokio::spawn(async move {
        let r = server.serve(listener).await;
        jlog!(Warn, "daemon", "SMB plane stopped: {r:?}");
        set_exit(&tx, ExitReason::SmbStopped(format!("{r:?}")));
    }));
}
