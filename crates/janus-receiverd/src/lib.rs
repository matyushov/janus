//! janus-receiverd as a library: so that integration tests (and future
//! consumers) can start the server programmatically. The binary is a thin wrapper.

pub mod control;
pub mod router;
pub mod server;
pub mod service;
pub mod testkit;
pub mod worker;
