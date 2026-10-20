//! Core entry point: accepting and serving connections.
//!
//! MILESTONE 1 (dev): a simple read → dispatch → write loop per connection, without
//! a separate write_loop or durable tables. Enough for a real
//! SMB client to pass NEGOTIATE → SESSION_SETUP → TREE_CONNECT and later
//! commands as they get implemented.
//!
//! UPGRADE (full architecture, internals §2.2): an actor with a SINGLE
//! write_loop (mpsc queue) for server-initiated send (lease break),
//! durable handle tables in ServerShared (surviving a TCP drop). This
//! linear loop is then replaced by split read/write tasks.

use janus_lib::jlog;
use janus_lib::log::Level;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::profile::ClientProfile;
use janus_lib::vfs::StorageBackend;
use smb_wire::messages::filetime_now;
use smb_wire::ntlm::Credentials;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::conn::{AUTH_TIMEOUT, AsyncConfig, ConnState};
use crate::dispatch::{
    DeferredSlow, Dispatcher, IoMeta, Out, Reply, ServerCtx, status, system_random,
};
use crate::files::Post;
use crate::shared::{Push, Shared};
use crate::transport::{read_message, write_message};

/// TCP connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// READ/WRITE backend calls of one connection that may be in flight at once. Each holds up to
/// `MAX_IO` of payload; a high-latency backend needs several in flight to fill the link.
const MAX_INFLIGHT_IO: usize = 8;
/// Packets queued behind pending operations before the loop stops reading.
const MAX_HELD: usize = 256;

/// Aborts the reader task when the connection loop ends (otherwise it would hold the socket).
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Share name until `configure` sets one.
pub const DEFAULT_SHARE: &str = "backup";
/// Volume size reported to the client when no quota is set (1 TiB).
const DEFAULT_VOLUME_BYTES: u64 = 1 << 40;
/// NetBIOS server name (NTLM TargetName).
const SERVER_NAME: &str = "JANUS";
/// First SessionId (non-zero; the high bits distinguish it from "empty" values).
const FIRST_SESSION_ID: u64 = 0x0000_0001_0000_0001;

/// Minimal shared server configuration (grows into ServerShared).
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_guid: [u8; 16],
}

impl Default for ServerConfig {
    fn default() -> Self {
        // Dev: a deterministic GUID. UPGRADE: generate a random one at startup.
        ServerConfig {
            server_guid: *b"janus-dev-smb001",
        }
    }
}

pub struct DevServer<B: StorageBackend> {
    config: Arc<ServerConfig>,
    /// Storage behind the share.
    backend: Arc<B>,
    /// Share configuration (name, profile) from the control plane.
    daemon: Arc<Mutex<DaemonState>>,
    credentials: Arc<CredentialStore>,
    next_conn: AtomicU64,
    next_session: AtomicU64,
    /// `JANUS_SMB_TRACE=1`: print every command and the reply status; `=2` also the request hex
    /// (once the session is established; contains paths and signatures, but not passwords).
    trace: u8,
    started_filetime: u64,
    async_cfg: AsyncConfig,
    /// Operations behind an interim response, for `janus-cli client status`.
    pending: Arc<janus_lib::observability::PendingOps>,
    /// Parked durable handles and leases.
    shared: Arc<Shared>,
}

impl<B: StorageBackend> DevServer<B> {
    pub fn new(
        config: ServerConfig,
        daemon: Arc<Mutex<DaemonState>>,
        credentials: Arc<CredentialStore>,
        backend: Arc<B>,
    ) -> Self {
        DevServer {
            config: Arc::new(config),
            backend,
            daemon,
            credentials,
            next_conn: AtomicU64::new(1),
            next_session: AtomicU64::new(FIRST_SESSION_ID),
            started_filetime: filetime_now(),
            async_cfg: AsyncConfig::default(),
            pending: Arc::default(),
            shared: Arc::default(),
            trace: 0,
        }
    }

    /// Trace level (0 = off, 1 = commands and statuses, 2 = also request hex). The caller reads
    /// `JANUS_SMB_TRACE` if it wants it; the library does not look at the environment.
    pub fn with_trace(mut self, level: u8) -> Self {
        self.trace = level.min(2);
        self
    }

    /// Timing of the interim STATUS_PENDING path (see `AsyncConfig`).
    pub fn with_async_config(mut self, cfg: AsyncConfig) -> Self {
        self.async_cfg = cfg;
        self
    }

    /// Use this shared state (a `Shared` built on a `ParkedHandleStore` keeps durable handles
    /// across a daemon restart).
    pub fn with_shared(mut self, shared: Arc<Shared>) -> Self {
        self.shared = shared;
        self
    }

    /// Share the pending-operation counter with the control plane's `status`.
    pub fn with_pending_ops(mut self, p: Arc<janus_lib::observability::PendingOps>) -> Self {
        self.pending = p;
        self
    }

    /// Listen on TCP and serve connections (dev mode; in production the listener
    /// comes from launchd, see janus-smbd).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        // Parked durable handles whose time is up are closed here.
        let me = Arc::clone(&self);
        let sweeper = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                me.shared.heartbeat();
                for handle in me.shared.take_expired(Instant::now()) {
                    let _ = me.backend.close(handle).await;
                }
            }
        });
        let _sweeper = AbortOnDrop(sweeper);
        loop {
            let (stream, peer) = listener.accept().await?;
            // Request/response protocol: Nagle + delayed ACK would add tens of ms per exchange.
            let _ = stream.set_nodelay(true);
            let conn_id = ConnId(
                self.next_conn
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.serve_conn(stream, conn_id).await {
                    jlog!(Warn, "smb", "conn {conn_id:?} ({peer}) error: {e}");
                }
            });
        }
    }

    async fn serve_conn(&self, stream: TcpStream, conn_id: ConnId) -> std::io::Result<()> {
        let mut conn = ConnState::default();
        jlog!(Info, "smb", "conn {conn_id:?} established");
        let push_rx = self.shared.register_conn(conn_id);
        let result = self.conn_loop(stream, &mut conn, conn_id, push_rx).await;
        // Whatever ended the connection: durable handles are parked, the rest is released.
        Dispatcher::cleanup(&mut conn, &*self.backend, &self.shared).await;
        self.shared.unregister_conn(conn_id);
        jlog!(Info, "smb", "conn {conn_id:?} closed");
        result
    }

    /// Reads packets on a separate task (cancel-safe `recv`) and runs plain READ/WRITE requests
    /// concurrently, up to `MAX_INFLIGHT_IO`. Everything else is a barrier: it waits until the
    /// in-flight I/O is replied to, so CLOSE/FLUSH/SET_INFO and friends see all earlier writes
    /// and the order of every other command is exactly the order of arrival. Replies to
    /// READ/WRITE may overtake each other, which SMB2 allows (clients match by MessageId).
    ///
    /// FLUSH, CLOSE and SET_INFO may wait for the journal for a long time. They run as
    /// *pending operations*: after `interim_after` the client gets an interim STATUS_PENDING,
    /// the final reply follows when the backend is done, the client cancels or `max_wait`
    /// passes. While any operation is pending the loop keeps reading: CANCEL and ECHO are
    /// handled at once, everything else queues in `held` and runs, in arrival order, once the
    /// pending operations are finished (so a held CREATE still sees the rename before it).
    async fn conn_loop(
        &self,
        stream: TcpStream,
        conn: &mut ConnState,
        conn_id: ConnId,
        mut push_rx: tokio::sync::mpsc::UnboundedReceiver<Push>,
    ) -> std::io::Result<()> {
        let (mut rd, wr) = stream.into_split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<Option<Vec<u8>>>>(2);
        let _reader = AbortOnDrop(tokio::spawn(async move {
            loop {
                let r = read_message(&mut rd).await;
                let last = !matches!(r, Ok(Some(_)));
                if tx.send(r).await.is_err() || last {
                    break;
                }
            }
        }));
        let mut io = ConnIo {
            wr,
            inflight: FuturesUnordered::new(),
            slow: FuturesUnordered::new(),
            slow_ctx: HashMap::new(),
            held: VecDeque::new(),
            pending_tokens: HashMap::new(),
            pending_stats: Arc::clone(&self.pending),
        };
        loop {
            // While authentication is in progress, wait for the next packet only for a bounded time.
            let auth_wait = conn.has_pending_auth() && io.inflight.is_empty() && io.slow.is_empty();
            let interim_due = conn.pending_async.next_interim_due();
            let next = tokio::select! {
                biased;
                Some((async_id, end)) = io.slow.next(), if !io.slow.is_empty() => {
                    self.send_slow_reply(&mut io, conn, conn_id, async_id, end).await?;
                    // Pending operations are over: run what queued up behind them.
                    while io.slow.is_empty() {
                        let Some(raw) = io.held.pop_front() else { break };
                        if self.process(&mut io, conn, conn_id, raw, true).await?.is_break() {
                            return Ok(());
                        }
                    }
                    continue;
                }
                Some(push) = push_rx.recv() => {
                    let Push::LeaseBreak(n) = push;
                    jlog!(Info, "smb", "conn {conn_id:?} lease break {:#x} → {:#x} (ack required: {})", n.current_state, n.new_state, n.ack_required);
                    write_message(&mut io.wr, &n.encode_packet()).await?;
                    continue;
                }
                Some((meta, out, raw)) = io.inflight.next(), if !io.inflight.is_empty() => {
                    self.send_io_reply(&mut io.wr, conn, conn_id, meta, out, raw).await?;
                    continue;
                }
                _ = tokio::time::sleep_until(interim_due.unwrap_or_else(Instant::now).into()), if interim_due.is_some() => {
                    self.send_interims(&mut io, conn, conn_id).await?;
                    continue;
                }
                m = rx.recv(), if io.inflight.len() < MAX_INFLIGHT_IO && io.held.len() < MAX_HELD => match m {
                    Some(r) => r?,
                    None => break,
                },
                _ = tokio::time::sleep(AUTH_TIMEOUT), if auth_wait => {
                    jlog!(Warn, "smb", "conn {conn_id:?} auth timeout; closing");
                    break;
                }
            };
            let Some(raw) = next else { break };
            if self
                .process(&mut io, conn, conn_id, raw, false)
                .await?
                .is_break()
            {
                break;
            }
        }
        Ok(())
    }

    /// One packet. `from_held`: it already waited its turn in the queue.
    async fn process<'a>(
        &'a self,
        io: &mut ConnIo<'a>,
        conn: &mut ConnState,
        conn_id: ConnId,
        raw: Vec<u8>,
        from_held: bool,
    ) -> std::io::Result<std::ops::ControlFlow<()>> {
        use std::ops::ControlFlow::{Break, Continue};
        let backend = &*self.backend;
        if self.trace > 1 && !from_held {
            trace_request_hex(conn_id, &raw);
        }
        // CANCEL never waits behind anything and never gets a reply.
        if Dispatcher::try_cancel(&raw, conn) {
            return Ok(Continue(()));
        }
        let urgent = Dispatcher::is_echo(&raw);
        if !urgent {
            // Plain READ/WRITE of an unrelated file may pass pending operations, but only when
            // nothing is queued (queued packets keep their order).
            let queued = !from_held && !io.held.is_empty();
            if !queued
                && let Some((meta, job)) = Dispatcher::try_defer_io(&raw, conn, &self.backend)
            {
                let keep = (self.trace > 0).then_some(raw);
                io.inflight.push(Box::pin(
                    async move { (meta, job.run(backend).await, keep) },
                ));
                return Ok(Continue(()));
            }
            if !from_held && (queued || !io.slow.is_empty()) {
                io.held.push_back(raw);
                return Ok(Continue(()));
            }
        }
        if !urgent {
            conn.io_epoch += 1; // anything but plain READ/WRITE may change what readahead holds
            // Barrier: finish the I/O in flight before anything else is looked at.
            while let Some((meta, out, raw)) = io.inflight.next().await {
                self.send_io_reply(&mut io.wr, conn, conn_id, meta, out, raw)
                    .await?;
            }
        }

        // Snapshot of the share configuration and credentials for the duration of packet handling.
        let (share_name, profile, volume_bytes, async_cfg) = {
            let st = self.daemon.lock().await;
            match &st.share {
                Some(s) => (
                    if s.share_name.is_empty() {
                        DEFAULT_SHARE.to_owned()
                    } else {
                        s.share_name.clone()
                    },
                    s.profile,
                    if s.quota_bytes == 0 {
                        DEFAULT_VOLUME_BYTES
                    } else {
                        s.quota_bytes
                    },
                    AsyncConfig {
                        interim_after: s
                            .smb_wait
                            .interim_after()
                            .unwrap_or(self.async_cfg.interim_after),
                        max_wait: s.smb_wait.max_wait().unwrap_or(self.async_cfg.max_wait),
                    },
                ),
                None => (
                    DEFAULT_SHARE.to_owned(),
                    ClientProfile::default(),
                    DEFAULT_VOLUME_BYTES,
                    self.async_cfg,
                ),
            }
        };
        let credentials = self
            .credentials
            .get()
            .map(|c| Credentials::from_password(&c.user, &c.password));
        let ctx = ServerCtx {
            server_guid: self.config.server_guid,
            server_name: SERVER_NAME,
            share_name: &share_name,
            caps: profile.caps(),
            credentials,
            next_session_id: &self.next_session,
            filetime: filetime_now(),
            started_filetime: self.started_filetime,
            volume_bytes,
            now: Instant::now(),
            random: system_random,
            conn_id,
            shared: &self.shared,
        };

        if !urgent && let Some(d) = Dispatcher::try_defer_slow(&raw, conn, &ctx, &async_cfg) {
            let DeferredSlow {
                async_id,
                cancel,
                meta,
                job,
            } = d;
            let max_wait = async_cfg.max_wait;
            let backend = Arc::clone(&self.backend);
            let (op, post) = (job.op, job.post);
            if self.trace > 0 {
                jlog!(
                    Debug,
                    "smb",
                    "conn {conn_id:?} → {:?} mid={} deferred (async_id={async_id})",
                    meta.header().command,
                    meta.header().message_id
                );
            }
            io.slow_ctx.insert(async_id, (meta, post));
            io.slow.push(Box::pin(async move {
                // The backend call runs as its own task: when the client cancels or `max_wait`
                // passes, only the wait ends. The call (and the journal behind it) carries on.
                let mut task = tokio::spawn(async move { op.run(&*backend).await });
                let end = tokio::select! {
                    r = &mut task => SlowEnd::Done(r.unwrap_or_else(|_| Out::err(status::UNEXPECTED_IO_ERROR))),
                    _ = cancel.notified() => SlowEnd::Cancelled,
                    _ = tokio::time::sleep(max_wait) => SlowEnd::TimedOut,
                };
                (async_id, end)
            }));
            return Ok(Continue(()));
        }

        let result = Dispatcher::handle(&raw, conn, &ctx, backend).await;
        if self.trace > 0 {
            trace_exchange(conn_id, &raw, &result);
        }
        match result {
            Ok(Reply::Now(bytes)) => write_message(&mut io.wr, &bytes).await?,
            Ok(Reply::None) => {}
            Err(e) => {
                jlog!(Warn, "smb", "conn {conn_id:?} protocol error: {e}; closing");
                return Ok(Break(()));
            }
        }
        if conn.close_after_reply {
            jlog!(Warn, "smb", "conn {conn_id:?} closing after failed logons");
            return Ok(Break(()));
        }
        Ok(Continue(()))
    }

    /// Interim STATUS_PENDING for every operation that has been waiting long enough.
    async fn send_interims(
        &self,
        io: &mut ConnIo<'_>,
        conn: &mut ConnState,
        conn_id: ConnId,
    ) -> std::io::Result<()> {
        for (async_id, message_id, _, command, started) in
            conn.pending_async.take_due(Instant::now())
        {
            let Some((meta, _)) = io.slow_ctx.get(&async_id) else {
                continue;
            };
            let bytes = Dispatcher::interim_reply(meta, async_id, conn);
            jlog!(
                Info,
                "smb",
                "conn {conn_id:?} {command:?} mid={message_id} now asynchronous (async_id={async_id}); interim STATUS_PENDING sent"
            );
            io.pending_tokens
                .insert(async_id, self.pending.begin(started));
            write_message(&mut io.wr, &bytes).await?;
        }
        Ok(())
    }

    /// Final reply of a pending operation.
    async fn send_slow_reply(
        &self,
        io: &mut ConnIo<'_>,
        conn: &mut ConnState,
        conn_id: ConnId,
        async_id: u64,
        end: SlowEnd,
    ) -> std::io::Result<()> {
        let Some((meta, post)) = io.slow_ctx.remove(&async_id) else {
            return Ok(());
        };
        if let Some(t) = io.pending_tokens.remove(&async_id) {
            self.pending.end(t);
        }
        let announced = conn.pending_async.announced(async_id);
        let waited = conn
            .pending_async
            .complete(async_id)
            .map(|o| o.started.elapsed());
        let (out, what) = match end {
            SlowEnd::Done(out) => {
                if let Some(session) = conn.sessions.get_mut(&meta.header().session_id) {
                    post.apply(&out, session);
                }
                (out, "completed")
            }
            // MS-SMB2 §3.3.5.16: the cancelled request completes with STATUS_CANCELLED.
            SlowEnd::Cancelled => (Out::err(status::CANCELLED), "cancelled by the client"),
            // The wait is over but the data is not lost: the journal keeps uploading. The
            // network-error status makes SMB clients fail the call without dropping the share.
            SlowEnd::TimedOut => (
                Out::err(status::UNEXPECTED_NETWORK_ERROR),
                "gave up waiting",
            ),
        };
        // Quick operations that never went asynchronous are routine: Debug. Everything the
        // client was kept waiting for, and every failure, is Info/Warn.
        let level = if !announced && out.status == status::SUCCESS {
            Level::Debug
        } else if out.status == status::SUCCESS {
            Level::Info
        } else {
            Level::Warn
        };
        janus_lib::log::emit(
            level,
            "smb",
            format!(
                "conn {conn_id:?} {:?} mid={} (op {async_id}) {what} after {:?}: status={:#010x}",
                meta.header().command,
                meta.header().message_id,
                waited.unwrap_or_default(),
                out.status
            ),
        );
        let bytes = Dispatcher::finish_slow(&meta, async_id, announced, out, conn);
        write_message(&mut io.wr, &bytes).await
    }
}

/// Everything a connection loop owns besides the `ConnState`.
struct ConnIo<'a> {
    wr: tokio::net::tcp::OwnedWriteHalf,
    inflight: FuturesUnordered<BoxFuture<'a, IoDone>>,
    /// Pending FLUSH/CLOSE/SET_INFO tasks.
    slow: FuturesUnordered<BoxFuture<'a, (u64, SlowEnd)>>,
    /// What the final reply of each pending operation needs, by AsyncId.
    slow_ctx: HashMap<u64, (IoMeta, Post)>,
    /// Packets that arrived while operations were pending, in arrival order.
    held: VecDeque<Vec<u8>>,
    /// `PendingOps` tokens of the operations the client has been told about.
    pending_tokens: HashMap<u64, u64>,
    pending_stats: Arc<janus_lib::observability::PendingOps>,
}

impl Drop for ConnIo<'_> {
    /// The connection is gone: its pending operations no longer count.
    fn drop(&mut self) {
        for t in self.pending_tokens.values() {
            self.pending_stats.end(*t);
        }
    }
}

/// A finished READ/WRITE: its reply metadata, outcome and (when tracing) the request.
type IoDone = (IoMeta, Out, Option<Vec<u8>>);

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// How a pending operation ended.
enum SlowEnd {
    Done(Out),
    Cancelled,
    TimedOut,
}

impl<B: StorageBackend> DevServer<B> {
    async fn send_io_reply(
        &self,
        wr: &mut tokio::net::tcp::OwnedWriteHalf,
        conn: &mut ConnState,
        conn_id: ConnId,
        meta: IoMeta,
        out: crate::dispatch::Out,
        raw: Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        let bytes = Dispatcher::finish_io(&meta, out, conn);
        if let Some(raw) = raw {
            trace_exchange(conn_id, &raw, &Ok(Reply::Now(bytes.clone())));
        }
        write_message(wr, &bytes).await
    }
}

/// `JANUS_SMB_TRACE=2` request dump: one hex line per compound element, with the payload of a
/// WRITE cut off (file contents never reach the trace). `tools/smb-trace-summary.py` reads it.
fn trace_request_hex(conn_id: ConnId, raw: &[u8]) {
    const WRITE: u16 = 9;
    if smb_wire::messages::is_smb1(raw) || raw.len() < 64 || raw[..4] != [0xfe, b'S', b'M', b'B'] {
        return;
    }
    let mut rest = raw;
    while rest.len() >= 64 {
        let next = u32::from_le_bytes([rest[20], rest[21], rest[22], rest[23]]) as usize;
        let end = if next == 0 || next > rest.len() {
            rest.len()
        } else {
            next
        };
        let mut elem = &rest[..end];
        if u16::from_le_bytes([elem[12], elem[13]]) == WRITE && elem.len() >= 68 {
            let data_off = u16::from_le_bytes([elem[66], elem[67]]) as usize;
            elem = &elem[..data_off.clamp(64, elem.len())];
        }
        let hex: String = elem.iter().map(|b| format!("{b:02x}")).collect();
        jlog!(Debug, "smb", "conn {conn_id:?} raw → {hex}");
        if end == rest.len() {
            break;
        }
        rest = &rest[end..];
    }
}

/// Exchange trace: one line per command (compound is expanded), status and reply size.
fn trace_exchange(conn_id: ConnId, raw: &[u8], result: &Result<Reply, smb_wire::WireError>) {
    let describe = |buf: &[u8]| -> String {
        match smb_wire::Message::decode_single(buf) {
            Ok(m) => format!(
                "{:?} mid={} sid={:#x} tid={} flags={:#x} status={:#010x}",
                m.header.command,
                m.header.message_id,
                m.header.session_id,
                m.header.tree_id,
                m.header.flags,
                m.header.status
            ),
            Err(e) => format!("<unparsed: {e}>"),
        }
    };
    let elements = |buf: &[u8]| -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = buf;
        while rest.len() >= 24 {
            let next = u32::from_le_bytes([rest[20], rest[21], rest[22], rest[23]]) as usize;
            let end = if next == 0 || next > rest.len() {
                rest.len()
            } else {
                next
            };
            out.push(describe(&rest[..end]));
            if end == rest.len() {
                break;
            }
            rest = &rest[end..];
        }
        out
    };
    let req = if smb_wire::messages::is_smb1(raw) {
        vec!["SMB1 NEGOTIATE".to_owned()]
    } else {
        elements(raw)
    };
    let resp = match result {
        Ok(Reply::Now(b)) if smb_wire::messages::is_smb1(raw) || !b.is_empty() => elements(b),
        Ok(_) => vec!["(no response)".to_owned()],
        Err(e) => vec![format!("ERROR {e}")],
    };
    jlog!(Debug, "smb", "conn {conn_id:?} → {}", req.join(" | "));
    jlog!(Debug, "smb", "conn {conn_id:?} ← {}", resp.join(" | "));
}
