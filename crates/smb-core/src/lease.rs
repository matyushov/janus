//! Lease V2 with a break state machine (server-initiated!).
//! Granted → BreakPending (we send LeaseBreakNotify) → Downgraded (internals §2.3).

use crate::server::ConnId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseKey(pub [u8; 16]);

/// State bit mask: R (read caching), W (write caching), H (handle caching).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseState(pub u32);

impl LeaseState {
    pub const READ: u32 = 0x01;
    pub const HANDLE: u32 = 0x02;
    pub const WRITE: u32 = 0x04;
}

#[derive(Debug)]
pub enum LeaseBreakState {
    None,
    /// LeaseBreakNotify sent, waiting for the ack (with a forced-downgrade timer).
    Pending {
        to_state: LeaseState,
    },
}

#[derive(Debug)]
pub struct Lease {
    pub key: LeaseKey,
    pub state: LeaseState,
    pub epoch: u16,
    pub break_state: LeaseBreakState,
    /// Who to send the break to. PoC question: the fate of a lease on a Parked handle (no connection).
    pub owner_conn: Option<ConnId>,
}
