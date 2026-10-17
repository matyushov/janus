//! Client compatibility profiles: one enum per share from which all
//! protocol switches are derived. The core (smb-core) knows nothing about "platforms",
//! only about the capabilities in `CompatCaps`.
//!
//! Invariants common to all profiles (NOT switchable):
//! - dialect 3.1.1 only (this removes FSCTL_VALIDATE_NEGOTIATE_INFO from 3.0/3.0.2);
//! - signing is mandatory (an Apple requirement and the Windows 11 24H2+ default);
//! - NTLM authentication, no guest access.

/// Who the client of this share is. Set in Configure (janus.v1.ClientProfile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ClientProfile {
    /// macOS backupd (Time Machine), the most demanding client.
    #[default]
    TimeMachine,
    /// A general-purpose Windows client (Explorer/robocopy/wbadmin/File History).
    WindowsGeneric,
    /// Linux cifs.ko / smbclient.
    PosixGeneric,
}

/// Derived capabilities; consumers are smb-core (the dispatcher, name resolution)
/// and the vfs layer.
#[derive(Debug, Clone, Copy)]
pub struct CompatCaps {
    /// false → case-insensitive name lookup (what a Windows client expects).
    /// A TM bundle lives in a case-sensitive APFS world, where this is strictly true.
    pub case_sensitive_names: bool,
    /// Answer the AAPL create context + advertise kAAPL_SUPPORTS_FULL_SYNC.
    pub advertise_aapl: bool,
    /// Treat FLUSH(Reserved1=0xFFFF) as F_FULLFSYNC.
    pub fullfsync: bool,
    /// Negotiate SMB 3.1.1 POSIX extensions (a negotiate context):
    /// honest POSIX attributes/symlinks for Linux clients. Nice to have.
    pub posix_extensions: bool,
    /// Windows probes alternate data streams / security descriptors:
    /// answer with a correct "emptiness" rather than an error.
    pub serve_empty_windows_metadata: bool,
    /// Advertise SMB2_GLOBAL_CAP_LEASING and grant lease V2 / durable handles V2.
    /// `tmutil` mounts the share but refuses it ("Operation not supported") without them.
    pub leasing: bool,
}

impl ClientProfile {
    pub fn caps(self) -> CompatCaps {
        match self {
            ClientProfile::TimeMachine => CompatCaps {
                case_sensitive_names: true,
                advertise_aapl: true,
                fullfsync: true,
                posix_extensions: false,
                serve_empty_windows_metadata: false,
                leasing: true,
            },
            ClientProfile::WindowsGeneric => CompatCaps {
                case_sensitive_names: false,
                advertise_aapl: false,
                fullfsync: false,
                posix_extensions: false,
                serve_empty_windows_metadata: true,
                leasing: false,
            },
            ClientProfile::PosixGeneric => CompatCaps {
                case_sensitive_names: true,
                advertise_aapl: false,
                fullfsync: false,
                posix_extensions: true,
                serve_empty_windows_metadata: false,
                leasing: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_machine_is_default_and_case_sensitive_with_aapl() {
        let caps = ClientProfile::default().caps();
        assert!(caps.case_sensitive_names);
        assert!(caps.advertise_aapl);
        assert!(caps.fullfsync);
        assert!(caps.leasing);
    }

    #[test]
    fn windows_is_case_insensitive_without_aapl() {
        let caps = ClientProfile::WindowsGeneric.caps();
        assert!(!caps.case_sensitive_names);
        assert!(!caps.advertise_aapl);
        assert!(caps.serve_empty_windows_metadata);
    }

    #[test]
    fn posix_gets_extensions() {
        assert!(ClientProfile::PosixGeneric.caps().posix_extensions);
    }
}
