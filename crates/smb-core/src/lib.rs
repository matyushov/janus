//! smb-core: the SMB server core (ours, not a fork; see design §6).
//!
//! Designed around two requirements that cut across everything:
//! - server-initiated send (lease break is a message outside the req/resp cycle) →
//!   a single socket writer: write_loop with an mpsc queue;
//! - a durable handle survives a TCP drop → handle tables live in
//!   `ServerShared`, NOT in the connection actor (Active → Parked with a timer).
//!
//! Design: README.md (Architecture), §2.2–2.4.
//!
//! Implementation status (MILESTONE 1/J1): transport → dispatch → conn/session: NEGOTIATE 3.1.1,
//! SESSION_SETUP (NTLMv2, signing), TREE_CONNECT/DISCONNECT, LOGOFF, ECHO.
//! Modules of the full architecture (`shared`/`handle`/`lease`/`apple`) are a typed groundwork
//! for UPGRADE, enabled as commands get implemented.

#![allow(dead_code)] // skeleton

pub mod conn;
pub mod dispatch;
pub mod server;
pub mod session;
pub mod transport;

// Groundwork for the full architecture (durable/lease/AAPL). Enabled as
// CREATE gets implemented. Not in the build graph yet: the types refer
// to the future actor/StorageBackend plumbing.
// pub mod apple;
// pub mod handle;
// pub mod lease;
// pub mod shared;
