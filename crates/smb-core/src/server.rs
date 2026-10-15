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

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::profile::ClientProfile;
use smb_wire::messages::filetime_now;
use smb_wire::ntlm::Credentials;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::conn::{AUTH_TIMEOUT, ConnState};
use crate::dispatch::{Dispatcher, Reply, ServerCtx, system_random};
use crate::transport::{read_message, write_message};

/// TCP connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

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

pub struct DevServer {
    config: Arc<ServerConfig>,
    /// Share configuration (name, profile) from the control plane.
    daemon: Arc<Mutex<DaemonState>>,
    credentials: Arc<CredentialStore>,
    next_conn: AtomicU64,
    next_session: AtomicU64,
    /// `JANUS_SMB_TRACE=1`: print every command and the reply status; `=2` also the request hex
    /// (once the session is established; contains paths and signatures, but not passwords).
    trace: u8,
    started_filetime: u64,
}

impl DevServer {
    pub fn new(
        config: ServerConfig,
        daemon: Arc<Mutex<DaemonState>>,
        credentials: Arc<CredentialStore>,
    ) -> Self {
        DevServer {
            config: Arc::new(config),
            daemon,
            credentials,
            next_conn: AtomicU64::new(1),
            next_session: AtomicU64::new(FIRST_SESSION_ID),
            started_filetime: filetime_now(),
            trace: match std::env::var("JANUS_SMB_TRACE").as_deref() {
                Ok("1") => 1,
                Ok("2") => 2,
                _ => 0,
            },
        }
    }

    /// Listen on TCP and serve connections (dev mode; in production the listener
    /// comes from launchd, see janus-smbd).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let conn_id = ConnId(
                self.next_conn
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.serve_conn(stream, conn_id).await {
                    eprintln!("janus: conn {conn_id:?} ({peer}) error: {e}");
                }
            });
        }
    }

    async fn serve_conn(&self, mut stream: TcpStream, conn_id: ConnId) -> std::io::Result<()> {
        let mut conn = ConnState::default();
        eprintln!("janus: conn {conn_id:?} established");

        loop {
            // While authentication is in progress, wait for the next packet only for a bounded time.
            let next = if conn.has_pending_auth() {
                match tokio::time::timeout(AUTH_TIMEOUT, read_message(&mut stream)).await {
                    Ok(r) => r?,
                    Err(_) => {
                        eprintln!("janus: conn {conn_id:?} auth timeout; closing");
                        break;
                    }
                }
            } else {
                read_message(&mut stream).await?
            };
            let Some(raw) = next else { break };

            // Snapshot of the share configuration and credentials for the duration of packet handling.
            let (share_name, profile, volume_bytes) = {
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
                    ),
                    None => (
                        DEFAULT_SHARE.to_owned(),
                        ClientProfile::default(),
                        DEFAULT_VOLUME_BYTES,
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
            };

            let result = Dispatcher::handle(&raw, &mut conn, &ctx);
            if self.trace > 0 {
                trace_exchange(conn_id, &raw, &result);
            }
            if self.trace > 1 && !smb_wire::messages::is_smb1(&raw) {
                let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("janus: conn {conn_id:?} raw → {hex}");
            }
            match result {
                Ok(Reply::Now(bytes)) => write_message(&mut stream, &bytes).await?,
                Ok(Reply::None) => {}
                Ok(Reply::Async { .. }) => {
                    // UPGRADE: the interim STATUS_PENDING has already been sent, the final reply comes later.
                }
                Err(e) => {
                    eprintln!("janus: conn {conn_id:?} protocol error: {e}; closing");
                    break;
                }
            }
            if conn.close_after_reply {
                eprintln!("janus: conn {conn_id:?} closing after failed logons");
                break;
            }
        }
        eprintln!("janus: conn {conn_id:?} closed");
        Ok(())
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
            Err(e) => format!("<не разобран: {e}>"),
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
        Ok(_) => vec!["(без ответа)".to_owned()],
        Err(e) => vec![format!("ОШИБКА {e}")],
    };
    eprintln!("janus: conn {conn_id:?} → {}", req.join(" | "));
    eprintln!("janus: conn {conn_id:?} ← {}", resp.join(" | "));
}
