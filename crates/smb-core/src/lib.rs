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
//! Implementation status (J1/J2): transport → dispatch → conn/session: NEGOTIATE 3.1.1,
//! SESSION_SETUP (NTLMv2, signing), TREE_CONNECT/DISCONNECT, LOGOFF, ECHO, and the file model
//! (`files`: CREATE/CLOSE/READ/WRITE/FLUSH/QUERY_INFO/QUERY_DIRECTORY/SET_INFO) on a backend.
//! `shared` holds what outlives a connection (parked durable handles, leases); `apple` the
//! Apple extensions.

#![allow(dead_code)] // skeleton

pub mod conn;
pub mod dispatch;
pub mod files;
pub mod server;
pub mod session;
pub mod transport;

pub mod apple;
pub mod shared;
