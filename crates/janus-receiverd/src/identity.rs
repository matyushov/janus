//! IdentityMap: client certificate → machine → store subdirectory → quota.
//!
//! **Machine identity = SHA-256 fingerprint of the client certificate (DER).** Chosen over
//! SAN/CN because it is not an attacker-influenced name: whatever a CA signs, only the exact
//! enrolled certificate maps to a machine, and revoking a machine is deleting a line. Cost:
//! renewing a certificate means updating the line (certificate rotation is out of J3a scope).
//! Enrolment is manual (`janus-cli server enroll` is out of scope).
//!
//! The mapping file is JSON (mode 0600 expected; a wider mode only warns):
//!
//! ```json
//! { "machines": [
//!   { "id": "alex-mbp", "fingerprint": "<64 hex, ':' allowed>",
//!     "store": "alex-mbp", "quota_bytes": 107374182400 }
//! ] }
//! ```
//!
//! `store` is a single directory name below the store root (no separators, no dots-only
//! names), unique per machine, so two machines can never share or nest directories.
//! `quota_bytes` omitted → the default quota (`JANUS_QUOTA`, 0 = unlimited).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// SHA-256 fingerprint of a DER certificate, lowercase hex.
pub fn fingerprint_of(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub id: String,
    pub fingerprint: String,
    /// Absolute store directory (store root + `store` from the file).
    pub store_dir: PathBuf,
    pub quota_bytes: u64,
}

#[derive(Debug, Default)]
pub struct IdentityMap {
    by_fingerprint: HashMap<String, usize>,
    machines: Vec<Machine>,
}

#[derive(Deserialize)]
struct FileFormat {
    machines: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    fingerprint: String,
    store: String,
    quota_bytes: Option<u64>,
}

fn bad(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

fn normalize_fingerprint(raw: &str) -> Option<String> {
    let f: String = raw
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (f.len() == 64 && f.chars().all(|c| c.is_ascii_hexdigit())).then_some(f)
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

impl IdentityMap {
    pub fn from_json(
        json: &[u8],
        store_root: &Path,
        default_quota: u64,
    ) -> std::io::Result<IdentityMap> {
        let f: FileFormat =
            serde_json::from_slice(json).map_err(|e| bad(format!("machines file: {e}")))?;
        let mut map = IdentityMap::default();
        let (mut ids, mut stores) = (HashSet::new(), HashSet::new());
        for e in f.machines {
            if !valid_name(&e.id) {
                return Err(bad(format!("invalid machine id {:?}", e.id)));
            }
            if !valid_name(&e.store) {
                return Err(bad(format!(
                    "machine {}: invalid store {:?} (one plain directory name expected)",
                    e.id, e.store
                )));
            }
            let fp = normalize_fingerprint(&e.fingerprint).ok_or_else(|| {
                bad(format!(
                    "machine {}: fingerprint must be 64 hex digits (SHA-256 of the DER certificate)",
                    e.id
                ))
            })?;
            if !ids.insert(e.id.clone()) {
                return Err(bad(format!("duplicate machine id {}", e.id)));
            }
            if !stores.insert(e.store.clone()) {
                return Err(bad(format!("duplicate store {}", e.store)));
            }
            if map.by_fingerprint.contains_key(&fp) {
                return Err(bad(format!("duplicate fingerprint for machine {}", e.id)));
            }
            map.by_fingerprint.insert(fp.clone(), map.machines.len());
            map.machines.push(Machine {
                id: e.id,
                fingerprint: fp,
                store_dir: store_root.join(&e.store),
                quota_bytes: e.quota_bytes.unwrap_or(default_quota),
            });
        }
        Ok(map)
    }

    pub fn load(path: &Path, store_root: &Path, default_quota: u64) -> std::io::Result<Self> {
        warn_if_group_or_world_accessible(path);
        let bytes = std::fs::read(path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        Self::from_json(&bytes, store_root, default_quota)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
    }

    pub fn resolve(&self, fingerprint: &str) -> Option<&Machine> {
        self.by_fingerprint
            .get(fingerprint)
            .map(|&i| &self.machines[i])
    }

    pub fn machines(&self) -> &[Machine] {
        &self.machines
    }
}

/// Secrets and identity files should not be readable by others (unix only).
pub fn warn_if_group_or_world_accessible(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path)
            && md.permissions().mode() & 0o077 != 0
        {
            eprintln!(
                "janus-receiverd: warning: {} is accessible by group/others (mode {:o}); expected 0600",
                path.display(),
                md.permissions().mode() & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";
    const FP_B: &str = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22";

    fn parse(json: &str) -> std::io::Result<IdentityMap> {
        IdentityMap::from_json(json.as_bytes(), Path::new("/srv/store"), 500)
    }

    #[test]
    fn maps_fingerprint_to_machine_store_and_quota() {
        let m = parse(&format!(
            r#"{{"machines":[
              {{"id":"a","fingerprint":"{FP_A}","store":"a-dir","quota_bytes":100}},
              {{"id":"b","fingerprint":"{}","store":"b-dir"}}]}}"#,
            FP_B.to_uppercase()
        ))
        .unwrap();
        let a = m.resolve(FP_A).unwrap();
        assert_eq!((a.id.as_str(), a.quota_bytes), ("a", 100));
        assert_eq!(a.store_dir, Path::new("/srv/store/a-dir"));
        let b = m.resolve(FP_B).unwrap();
        assert_eq!(b.quota_bytes, 500, "default quota");
        assert!(m.resolve(&"cc".repeat(32)).is_none());
        assert_eq!(m.machines().len(), 2);
    }

    #[test]
    fn colon_separated_fingerprints_are_accepted() {
        let colon: Vec<_> = FP_A
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let m = parse(&format!(
            r#"{{"machines":[{{"id":"a","fingerprint":"{}","store":"a"}}]}}"#,
            colon.join(":")
        ))
        .unwrap();
        assert!(m.resolve(FP_A).is_some());
    }

    #[test]
    fn hostile_or_sloppy_entries_are_rejected() {
        let e = |id: &str, fp: &str, store: &str| {
            format!(r#"{{"machines":[{{"id":"{id}","fingerprint":"{fp}","store":"{store}"}}]}}"#)
        };
        for store in [
            "../x", "/abs", "a/b", "a\\b", ".", "..", ".hidden", "", "a:b",
        ] {
            assert!(parse(&e("m", FP_A, store)).is_err(), "store {store:?}");
        }
        assert!(parse(&e("m/x", FP_A, "s")).is_err());
        assert!(parse(&e("m", "deadbeef", "s")).is_err());
        assert!(parse("{not json").is_err());
        assert!(parse(r#"{"machines":[{"id":"m"}]}"#).is_err());
    }

    #[test]
    fn duplicates_are_rejected() {
        let two = |a: (&str, &str, &str), b: (&str, &str, &str)| {
            format!(
                r#"{{"machines":[
                {{"id":"{}","fingerprint":"{}","store":"{}"}},
                {{"id":"{}","fingerprint":"{}","store":"{}"}}]}}"#,
                a.0, a.1, a.2, b.0, b.1, b.2
            )
        };
        assert!(
            parse(&two(("a", FP_A, "s1"), ("a", FP_B, "s2"))).is_err(),
            "id"
        );
        assert!(
            parse(&two(("a", FP_A, "s"), ("b", FP_B, "s"))).is_err(),
            "store shared"
        );
        assert!(
            parse(&two(("a", FP_A, "s1"), ("b", FP_A, "s2"))).is_err(),
            "fingerprint"
        );
        assert!(parse(&two(("a", FP_A, "s1"), ("b", FP_B, "s2"))).is_ok());
    }

    #[test]
    fn fingerprint_is_sha256_hex_of_der() {
        // SHA-256("") — a known vector
        assert_eq!(
            fingerprint_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
