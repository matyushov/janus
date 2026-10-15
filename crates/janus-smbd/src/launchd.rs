//! launchd integration: check-in and obtaining the sockets from the plist `Sockets`
//! (socket activation: launchd owns 127.0.0.1:445, the process needs no root
//! to bind).
//!
//! The implementation is macOS-only (libc::launch_activate_socket or a wrapper crate);
//! on other platforms it is a stub for the dev build.

#![allow(dead_code)] // skeleton

/// Sockets handed out by launchd under the names from the plist.
pub struct LaunchdSockets {
    /// "smb-listener" is 127.0.0.1:445 (or an alias/port per the PoC outcome).
    pub smb: Vec<std::net::TcpListener>,
    /// "control" is the unix socket /var/run/janus/janus-smbd.sock (0600).
    pub control_fd: Option<i32>,
}

pub fn checkin() -> std::io::Result<LaunchdSockets> {
    todo!(
        "launch_activate_socket(\"smb-listener\") + \"control\"; outside macOS — an error hinting at dev mode"
    )
}
