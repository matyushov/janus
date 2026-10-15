//! Apple extensions: the AAPL create context and F_FULLFSYNC.
//! Primary source: Apple Time Machine Over SMB Specification.
//! Acceptance test of the layer is the backupd validation handshake (see internals §2.1 of the main doc):
//! CREATE+AAPL (root) → CREATE `.com.apple.timemachine.supported` (durable V2,
//! Timeout=0) → CLOSE → compound CREATE/SET_INFO/CLOSE (delete) → repeat with Timeout=30.

use smb_wire::create::{AAPL_SUPPORTS_FULL_SYNC, AaplContext};

pub struct AppleExt;

impl AppleExt {
    /// Reply to the AAPL server query on the share root: we advertise F_FULLFSYNC.
    /// Active only with `CompatCaps::advertise_aapl` (TimeMachine profile);
    /// for Windows/POSIX profiles the context is ignored as Unknown.
    pub fn on_create_root(_req: &AaplContext) -> AaplContext {
        todo!("AAPL reply: server_caps |= AAPL_SUPPORTS_FULL_SYNC")
    }

    /// F_FULLFSYNC = SMB2 FLUSH c Reserved1 == 0xFFFF (Apple spec).
    pub fn is_fullfsync(reserved1: u16) -> bool {
        reserved1 == 0xFFFF
    }

    /// Capability bit that must be present in the AAPL reply.
    pub const REQUIRED_CAPS: u64 = AAPL_SUPPORTS_FULL_SYNC;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fullfsync_is_reserved1_ffff() {
        assert!(AppleExt::is_fullfsync(0xFFFF));
        assert!(!AppleExt::is_fullfsync(0x0000));
    }
}
