//! mDNS advertisement of the TM share (an Apple spec requirement; whether it is needed with an explicit
//! setdestination is a PoC question, hence behind the `advertise_bonjour` flag).
//!
//! Spec requirements: `_smb._tcp` (port 445) + `_adisk._tcp` with ONE service
//! name; TXT: `adVN` = share name, `adVF` = 0x82 (SMB + TM-allowed).
//! Implementation: FFI to dnssd (DNSServiceRegister), we advertise ourselves.

use crate::config::ShareConfig;

#[derive(Debug, Default)]
pub struct BonjourAdvertiser;

impl BonjourAdvertiser {
    /// Bring the advertisement in line with the config (on/off, share name).
    pub fn sync_with(&mut self, _cfg: &ShareConfig) {
        todo!("register/unregister _smb._tcp + _adisk._tcp (adVF=0x82)")
    }
}
