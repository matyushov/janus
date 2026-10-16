//! Per-connection state: dialect, preauth chain, credits, sessions, async operations.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use smb_wire::frame::Dialect;

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

/// Long operations (FLUSH with sync-through, CHANGE_NOTIFY, Lock):
/// interim STATUS_PENDING with an async_id → the final reply on completion.
#[derive(Debug, Default)]
pub struct AsyncOpRegistry {
    next_async_id: u64,
}

impl AsyncOpRegistry {
    pub fn register(&mut self, _message_id: u64) -> u64 {
        todo!("allocate async_id, remember context for the final response")
    }

    pub fn complete(&mut self, _async_id: u64) {
        todo!("match and send the final response via write_loop")
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
}
