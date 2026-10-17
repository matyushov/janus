//! Per-connection state: dialect, preauth chain, credits, sessions, async operations.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smb_wire::frame::Dialect;
use tokio::sync::Notify;

use crate::session::{Session, SessionState};

/// Ceiling on credits granted but not yet spent (per connection).
pub const MAX_OUTSTANDING_CREDITS: u32 = 512;
/// Maximum number of credits granted in a single response.
pub const MAX_GRANT_PER_RESPONSE: u16 = 256;
/// Concurrent unfinished authentications per connection.
pub const MAX_PENDING_SESSIONS: usize = 4;
/// Failed logons per connection before a forced disconnect.
pub const MAX_AUTH_FAILURES: u32 = 3;
/// How long an unfinished authentication lives.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// State of a single TCP connection (lives in the actor, dies with it).
#[derive(Debug)]
pub struct ConnState {
    /// Negotiated dialect; the target is 3.1.1.
    pub dialect: Option<Dialect>,
    /// Preauth integrity chain (SHA-512): NEGOTIATE; sessions accumulate their own from this value.
    pub preauth_hash: [u8; 64],
    pub credits: CreditWindow,
    pub pending_async: AsyncOpRegistry,
    pub sessions: HashMap<u64, Session>,
    /// Failed logon attempts on this connection.
    pub auth_failures: u32,
    /// Close the connection after sending the current reply.
    pub close_after_reply: bool,
    /// This connection has already seen an SMB1 multi-protocol NEGOTIATE (only one is allowed).
    pub smb1_negotiated: bool,
    /// FileId of the last successful CREATE in the current compound chain (related operations).
    pub compound_file: Option<[u8; 16]>,
    /// Bumped by every WRITE and every command that is not a plain READ/WRITE. Prefetched
    /// reads started under an older value may predate a change and are discarded.
    pub io_epoch: u64,
    /// ClientGuid from NEGOTIATE (durable handles are reclaimed by the same client only).
    pub client_guid: [u8; 16],
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            dialect: None,
            preauth_hash: [0; 64],
            credits: CreditWindow::default(),
            pending_async: AsyncOpRegistry::default(),
            sessions: HashMap::new(),
            auth_failures: 0,
            close_after_reply: false,
            smb1_negotiated: false,
            compound_file: None,
            io_epoch: 0,
            client_guid: [0; 16],
        }
    }
}

impl ConnState {
    /// Whether there is an unfinished authentication (the server then bounds the read time).
    pub fn has_pending_auth(&self) -> bool {
        self.sessions
            .values()
            .any(|s| matches!(s.state, SessionState::Authenticating(_)))
    }

    pub fn pending_auth_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state, SessionState::Authenticating(_)))
            .count()
    }

    /// Drop unfinished authentications older than `AUTH_TIMEOUT`.
    pub fn purge_expired_auth(&mut self, now: Instant) {
        self.sessions.retain(|_, s| match &s.state {
            SessionState::Authenticating(p) => now.duration_since(p.started) < AUTH_TIMEOUT,
            SessionState::Active { .. } => true,
        });
    }
}

/// Credit window: credits are granted in EVERY response, including interim STATUS_PENDING
/// (otherwise the client chokes on a long FLUSH).
///
/// `outstanding` is granted and not yet spent. A new connection starts with one
/// credit (for NEGOTIATE, MS-SMB2 §3.3.5.4). A request spends `max(CreditCharge, 1)`.
#[derive(Debug)]
pub struct CreditWindow {
    outstanding: u32,
}

impl Default for CreditWindow {
    fn default() -> Self {
        CreditWindow { outstanding: 1 }
    }
}

/// A request needs more credits than the window holds (a client protocol error).
#[derive(Debug, PartialEq, Eq)]
pub struct InsufficientCredits;

impl CreditWindow {
    pub fn outstanding(&self) -> u32 {
        self.outstanding
    }

    /// Charge credits for a request; on shortage the window is unchanged.
    pub fn charge(&mut self, charge: u16) -> Result<(), InsufficientCredits> {
        let need = u32::from(charge.max(1));
        if need > self.outstanding {
            return Err(InsufficientCredits);
        }
        self.outstanding -= need;
        Ok(())
    }

    /// Grant credits in a reply: the requested amount (at least 1), no more than
    /// `MAX_GRANT_PER_RESPONSE` and not above the window ceiling. Returns the amount granted.
    pub fn grant(&mut self, requested: u16) -> u16 {
        let want = u32::from(requested.clamp(1, MAX_GRANT_PER_RESPONSE));
        let room = MAX_OUTSTANDING_CREDITS.saturating_sub(self.outstanding);
        let granted = want.min(room);
        self.outstanding += granted;
        granted as u16
    }
}

/// Timing of the asynchronous (interim `STATUS_PENDING`) path.
#[derive(Debug, Clone, Copy)]
pub struct AsyncConfig {
    /// An operation still running after this long gets an interim `STATUS_PENDING`.
    pub interim_after: Duration,
    /// An operation still running after this long is answered with an error. Only the wait is
    /// abandoned: the backend call (and the journal behind it) carries on.
    pub max_wait: Duration,
}

/// Default for `AsyncConfig::interim_after`: well below the 30 s the macOS client waits.
pub const DEFAULT_INTERIM_AFTER: Duration = Duration::from_millis(1500);
/// Default for `AsyncConfig::max_wait`.
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(600);

impl Default for AsyncConfig {
    fn default() -> Self {
        AsyncConfig {
            interim_after: DEFAULT_INTERIM_AFTER,
            max_wait: DEFAULT_MAX_WAIT,
        }
    }
}

/// A request that has left the synchronous path: its reply comes when the backend is done.
#[derive(Debug)]
pub struct PendingOp {
    pub async_id: u64,
    pub message_id: u64,
    pub session_id: u64,
    pub command: smb_wire::Command,
    pub started: Instant,
    /// When the interim response is due; `None` once it has been sent.
    pub interim_due: Option<Instant>,
    /// Wakes the task waiting for the backend when the client cancels.
    pub cancel: Arc<Notify>,
}

/// Long operations (FLUSH, CLOSE, SET_INFO that wait for the journal): after a short time the
/// client gets an interim STATUS_PENDING with an AsyncId, the final reply follows on completion
/// (MS-SMB2 §3.3.4.2). Entries live from the moment the request is taken until its final reply.
#[derive(Debug, Default)]
pub struct AsyncOpRegistry {
    last_async_id: u64,
    ops: HashMap<u64, PendingOp>,
}

impl AsyncOpRegistry {
    /// Track a request; the AsyncId is allocated now (non-zero, unique on the connection) but
    /// only becomes visible to the client with the interim response.
    pub fn register(
        &mut self,
        message_id: u64,
        session_id: u64,
        command: smb_wire::Command,
        now: Instant,
        interim_after: Duration,
    ) -> (u64, Arc<Notify>) {
        self.last_async_id += 1;
        let async_id = self.last_async_id;
        let cancel = Arc::new(Notify::new());
        self.ops.insert(
            async_id,
            PendingOp {
                async_id,
                message_id,
                session_id,
                command,
                started: now,
                interim_due: Some(now + interim_after),
                cancel: Arc::clone(&cancel),
            },
        );
        (async_id, cancel)
    }

    /// The earliest moment an interim response is due.
    pub fn next_interim_due(&self) -> Option<Instant> {
        self.ops.values().filter_map(|o| o.interim_due).min()
    }

    /// Operations whose interim response is due at `now`; marks them as announced.
    pub fn take_due(&mut self, now: Instant) -> Vec<(u64, u64, u64, smb_wire::Command, Instant)> {
        let mut due: Vec<_> = self
            .ops
            .values_mut()
            .filter(|o| o.interim_due.is_some_and(|t| t <= now))
            .map(|o| {
                o.interim_due = None;
                (o.async_id, o.message_id, o.session_id, o.command, o.started)
            })
            .collect();
        due.sort_unstable_by_key(|d| d.0);
        due
    }

    /// Whether the client has been told about this operation (interim sent).
    pub fn announced(&self, async_id: u64) -> bool {
        self.ops
            .get(&async_id)
            .is_some_and(|o| o.interim_due.is_none())
    }

    /// SMB2 CANCEL (MS-SMB2 §3.3.5.16): by AsyncId when the request carries the async flag,
    /// otherwise by MessageId within the session. Returns whether an operation was found.
    pub fn cancel(&mut self, by_async: bool, id: u64, session_id: u64) -> bool {
        let found = self.ops.values().find(|o| {
            if by_async {
                o.async_id == id && o.interim_due.is_none()
            } else {
                o.message_id == id && o.session_id == session_id
            }
        });
        match found {
            Some(o) => {
                o.cancel.notify_one();
                true
            }
            None => false,
        }
    }

    /// The final reply is being sent: forget the operation.
    pub fn complete(&mut self, async_id: u64) -> Option<PendingOp> {
        self.ops.remove(&async_id)
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Age of the oldest pending operation.
    pub fn oldest_age(&self, now: Instant) -> Option<Duration> {
        self.ops
            .values()
            .map(|o| now.saturating_duration_since(o.started))
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_connection_has_one_credit_for_negotiate() {
        let mut w = CreditWindow::default();
        assert_eq!(w.outstanding(), 1);
        assert!(w.charge(0).is_ok()); // charge 0 == 1
        assert_eq!(w.outstanding(), 0);
        assert_eq!(w.charge(1), Err(InsufficientCredits));
    }

    #[test]
    fn grant_gives_at_least_one_and_caps_per_response() {
        let mut w = CreditWindow::default();
        w.charge(1).unwrap();
        assert_eq!(w.grant(0), 1);
        w.charge(1).unwrap();
        assert_eq!(w.grant(10), 10);
        assert_eq!(w.outstanding(), 10);
        assert_eq!(w.grant(u16::MAX), MAX_GRANT_PER_RESPONSE);
    }

    #[test]
    fn window_never_exceeds_ceiling() {
        let mut w = CreditWindow::default();
        let mut total = 0u32;
        w.charge(1).unwrap();
        for _ in 0..10 {
            total += u32::from(w.grant(MAX_GRANT_PER_RESPONSE));
        }
        assert_eq!(total, MAX_OUTSTANDING_CREDITS);
        assert_eq!(w.outstanding(), MAX_OUTSTANDING_CREDITS);
        // the window is full: we grant no more, but do not fail either
        assert_eq!(w.grant(5), 0);
    }

    #[test]
    fn charge_over_window_is_rejected_and_window_unchanged() {
        let mut w = CreditWindow::default();
        w.charge(1).unwrap();
        w.grant(8);
        assert_eq!(w.charge(9), Err(InsufficientCredits));
        assert_eq!(w.outstanding(), 8);
        assert!(w.charge(8).is_ok());
        assert_eq!(w.outstanding(), 0);
    }

    #[test]
    fn steady_state_request_response_keeps_window_stable() {
        let mut w = CreditWindow::default();
        for _ in 0..1000 {
            w.charge(1).unwrap();
            assert_eq!(w.grant(1), 1);
        }
        assert_eq!(w.outstanding(), 1);
    }

    #[test]
    fn registry_allocates_unique_nonzero_ids_and_announces_due_ops() {
        use smb_wire::Command;
        let t0 = Instant::now();
        let mut r = AsyncOpRegistry::default();
        let (a, _) = r.register(10, 7, Command::Flush, t0, Duration::from_secs(1));
        let (b, _) = r.register(11, 7, Command::Close, t0, Duration::from_secs(2));
        assert!(a != 0 && b != 0 && a != b);
        assert_eq!(r.next_interim_due(), Some(t0 + Duration::from_secs(1)));
        assert!(r.take_due(t0).is_empty());
        let due = r.take_due(t0 + Duration::from_secs(1));
        assert_eq!(due, vec![(a, 10, 7, Command::Flush, t0)]);
        assert!(r.announced(a) && !r.announced(b));
        assert_eq!(r.next_interim_due(), Some(t0 + Duration::from_secs(2)));
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.oldest_age(t0 + Duration::from_secs(5)),
            Some(Duration::from_secs(5))
        );
        assert!(r.complete(a).is_some());
        assert!(r.complete(a).is_none());
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn cancel_matches_by_message_id_or_async_id_and_wakes_the_waiter() {
        use smb_wire::Command;
        let t0 = Instant::now();
        let mut r = AsyncOpRegistry::default();
        let (a, wake) = r.register(10, 7, Command::Flush, t0, Duration::from_secs(1));
        // wrong session / unknown id
        assert!(!r.cancel(false, 10, 8));
        assert!(!r.cancel(false, 99, 7));
        // by AsyncId only once announced
        assert!(!r.cancel(true, a, 7));
        assert!(r.cancel(false, 10, 7));
        tokio::time::timeout(Duration::from_millis(100), wake.notified())
            .await
            .expect("woken");
        r.take_due(t0 + Duration::from_secs(1));
        assert!(r.cancel(true, a, 7));
    }
}
