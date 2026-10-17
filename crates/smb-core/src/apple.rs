//! Apple extensions: the AAPL create context and F_FULLFSYNC.
//! Primary source: Apple Time Machine Over SMB Specification; the exchange was checked against
//! live `mount_smbfs` and `tmutil setdestination` traces (macOS 26).
//!
//! `tmutil` mounts the share and refuses it ("does not support SMB FullFSync") unless the reply
//! to the AAPL server query carries `kAAPL_SUPPORTS_FULL_SYNC` in the volume capabilities.

use janus_lib::profile::CompatCaps;
use smb_wire::create::{
    AAPL_BIT_MODEL_INFO, AAPL_BIT_SERVER_CAPS, AAPL_BIT_VOLUME_CAPS, AAPL_CASE_SENSITIVE,
    AAPL_SUPPORTS_FULL_SYNC, AaplQuery, AaplReply,
};

/// Model string reported to the client (it only picks the icon in Finder).
const MODEL: &str = "Macmini9,1";

pub struct AppleExt;

impl AppleExt {
    /// Reply to an AAPL server query. `None` when the profile does not answer AAPL
    /// (Windows/POSIX profiles: the context is then ignored like any unknown one).
    ///
    /// Server capabilities stay empty: we do not implement read-dir-attr, copyfile or NFS ACEs,
    /// so we do not claim them. Volume capabilities: full sync (the point of the exercise) and
    /// case sensitivity as configured; resolve-id is not implemented and not claimed.
    pub fn reply_to_query(caps: &CompatCaps, q: &AaplQuery) -> Option<AaplReply> {
        if !caps.advertise_aapl {
            return None;
        }
        let mut volume_caps = 0;
        if caps.fullfsync {
            volume_caps |= AAPL_SUPPORTS_FULL_SYNC;
        }
        if caps.case_sensitive_names {
            volume_caps |= AAPL_CASE_SENSITIVE;
        }
        Some(AaplReply {
            bitmap: q.request_bitmap
                & (AAPL_BIT_SERVER_CAPS | AAPL_BIT_VOLUME_CAPS | AAPL_BIT_MODEL_INFO),
            server_caps: 0,
            volume_caps,
            model: MODEL.to_owned(),
        })
    }

    /// F_FULLFSYNC = SMB2 FLUSH c Reserved1 == 0xFFFF (Apple spec).
    pub fn is_fullfsync(reserved1: u16) -> bool {
        reserved1 == 0xFFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_lib::profile::ClientProfile;

    fn query() -> AaplQuery {
        AaplQuery {
            request_bitmap: 7,
            client_caps: 0x3f,
        }
    }

    #[test]
    fn fullfsync_is_reserved1_ffff() {
        assert!(AppleExt::is_fullfsync(0xFFFF));
        assert!(!AppleExt::is_fullfsync(0x0000));
    }

    #[test]
    fn time_machine_profile_advertises_full_sync() {
        let r = AppleExt::reply_to_query(&ClientProfile::TimeMachine.caps(), &query()).unwrap();
        assert_eq!(r.bitmap, 7);
        assert_eq!(r.server_caps, 0);
        assert_eq!(r.volume_caps, AAPL_SUPPORTS_FULL_SYNC | AAPL_CASE_SENSITIVE);
        assert!(!r.model.is_empty());
    }

    #[test]
    fn reply_is_limited_to_what_we_know() {
        let mut q = query();
        q.request_bitmap = 0xFF;
        let r = AppleExt::reply_to_query(&ClientProfile::TimeMachine.caps(), &q).unwrap();
        assert_eq!(r.bitmap, 7);
    }

    #[test]
    fn other_profiles_ignore_aapl() {
        assert!(
            AppleExt::reply_to_query(&ClientProfile::WindowsGeneric.caps(), &query()).is_none()
        );
        assert!(AppleExt::reply_to_query(&ClientProfile::PosixGeneric.caps(), &query()).is_none());
    }
}
