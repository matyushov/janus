//! mDNS advertisement of the share (Time Machine discovery).
//!
//! Spec requirements (Apple "Time Machine over SMB"): `_smb._tcp` on the SMB port and
//! `_adisk._tcp` under ONE service name; the `_adisk` TXT carries `sys=adVF=0x100` and
//! `dk0=adVN=<share>,adVF=0x82` (0x80 = Time Machine allowed, 0x02 = SMB).
//!
//! Implementation: the system `dns-sd` tool, one child process per service, registered
//! `-lo` (local-only): janus serves SMB on loopback, so the service is visible on this machine
//! only and resolves to `localhost`; nothing is announced to the network. This needs no
//! dependency and no FFI. `tmutil setdestination` with a URL works without any advertisement
//! (checked on macOS 26); the advertisement makes the share show up in the Time Machine
//! "Add Backup Disk" list. Other platforms: no advertisement.

use std::process::Child;

use crate::jlog;

/// Service instance name (the same for both services).
pub const SERVICE_NAME: &str = "janus";
/// `_adisk` carries no traffic; Apple uses the discard port.
const ADISK_PORT: u16 = 9;

/// What is advertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The share name (`adVN`).
    pub share: String,
    /// The SMB port of the share.
    pub port: u16,
}

/// `dns-sd` argument lists (without the program name) for the two services.
pub fn dns_sd_args(reg: &Registration) -> [Vec<String>; 2] {
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    let port = reg.port.to_string();
    let mut adisk = s(&[
        "-lo",
        "-R",
        SERVICE_NAME,
        "_adisk._tcp",
        ".",
        &ADISK_PORT.to_string(),
    ]);
    adisk.push("sys=adVF=0x100".to_owned());
    adisk.push(format!("dk0=adVN={},adVF=0x82", reg.share));
    [
        s(&["-lo", "-R", SERVICE_NAME, "_smb._tcp", ".", &port]),
        adisk,
    ]
}

/// Keeps the advertisement in line with the configuration.
#[derive(Debug, Default)]
pub struct BonjourAdvertiser {
    current: Option<Registration>,
    children: Vec<Child>,
}

impl BonjourAdvertiser {
    /// Bring the advertisement in line with the wanted state: `None` withdraws it. Idempotent;
    /// also restarts services whose `dns-sd` process has died (for example after an
    /// mDNSResponder restart). Returns whether anything is being advertised afterwards.
    pub fn sync(&mut self, wanted: Option<Registration>) -> bool {
        if wanted != self.current || !self.all_alive() {
            self.stop();
            if let Some(reg) = wanted {
                kill_stale(&reg);
                self.children = spawn_all(&reg);
                if !self.children.is_empty() {
                    jlog!(
                        Info,
                        "bonjour",
                        "advertising \"{}\" (share {}, SMB port {}) on this machine",
                        SERVICE_NAME,
                        reg.share,
                        reg.port
                    );
                    self.current = Some(reg);
                }
            }
        }
        !self.children.is_empty()
    }

    /// Withdraw the advertisement.
    pub fn stop(&mut self) {
        for mut c in self.children.drain(..) {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.current = None;
    }

    fn all_alive(&mut self) -> bool {
        self.children
            .iter_mut()
            .all(|c| matches!(c.try_wait(), Ok(None)))
    }
}

impl Drop for BonjourAdvertiser {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A previous daemon killed with SIGKILL leaves its `dns-sd` children behind; registering the
/// same name twice would get the new one renamed. `dns-sd` rewrites its own argument list in
/// `ps` (the domain and port come out blank), so only the prefix of the command line can be
/// matched: the program, `-lo -R`, our service name and the service type.
#[cfg(target_os = "macos")]
fn kill_stale(_reg: &Registration) {
    use std::process::Command;
    for ty in ["_smb._tcp", "_adisk._tcp"] {
        let pattern = format!("^/usr/bin/dns-sd -lo -R {SERVICE_NAME} {ty}");
        let _ = Command::new("/usr/bin/pkill")
            .args(["-f", &pattern])
            .status();
    }
}

#[cfg(not(target_os = "macos"))]
fn kill_stale(_reg: &Registration) {}

#[cfg(target_os = "macos")]
fn spawn_all(reg: &Registration) -> Vec<Child> {
    use std::process::{Command, Stdio};
    let mut children = Vec::new();
    for args in dns_sd_args(reg) {
        match Command::new("/usr/bin/dns-sd")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => children.push(c),
            Err(e) => {
                jlog!(Warn, "bonjour", "cannot start dns-sd: {e}");
                for mut c in children.drain(..) {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                break;
            }
        }
    }
    children
}

#[cfg(not(target_os = "macos"))]
fn spawn_all(_reg: &Registration) -> Vec<Child> {
    jlog!(Debug, "bonjour", "no mDNS advertisement on this platform");
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registration {
        Registration {
            share: "backup".into(),
            port: 4445,
        }
    }

    #[test]
    fn both_services_share_one_name_and_are_local_only() {
        let [smb, adisk] = dns_sd_args(&reg());
        assert_eq!(smb, ["-lo", "-R", "janus", "_smb._tcp", ".", "4445"]);
        assert_eq!(&adisk[..6], ["-lo", "-R", "janus", "_adisk._tcp", ".", "9"]);
        assert_eq!(adisk[6], "sys=adVF=0x100");
        assert_eq!(adisk[7], "dk0=adVN=backup,adVF=0x82");
    }

    #[test]
    fn disabled_advertiser_does_nothing_and_stop_is_idempotent() {
        let mut a = BonjourAdvertiser::default();
        assert!(!a.sync(None));
        a.stop();
        a.stop();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_platforms_advertise_nothing() {
        let mut a = BonjourAdvertiser::default();
        assert!(!a.sync(Some(reg())));
    }
}
