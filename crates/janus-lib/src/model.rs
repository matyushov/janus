//! sparsebundle model: classification of paths inside the bundle and the write policy by type.

/// Type of an object inside a sparsebundle/backupbundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectKind {
    /// `bands/<hex>` is 99% of the traffic, offset writes.
    Band(u32),
    /// `Info.plist` / `Info.bckup`.
    InfoPlist,
    /// `com.apple.TimeMachine.MachineID.*`
    MachineId,
    /// `lock` / `token`.
    LockToken,
    /// `.com.apple.timemachine.supported` is the validation-handshake file.
    ValidationProbe,
    Dir,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// Hot path: WAL + uploader (bands).
    Journaled,
    /// Small critical metafiles: synchronously up to the appliance.
    WriteThrough,
}

#[derive(Debug, Default)]
pub struct SparsebundleModel;

impl SparsebundleModel {
    pub fn classify(&self, rel_path: &str) -> ObjectKind {
        let path = rel_path.trim_matches('/');
        if let Some(band) = path.strip_prefix("bands/")
            && let Ok(no) = u32::from_str_radix(band, 16)
        {
            return ObjectKind::Band(no);
        }
        match path {
            "Info.plist" | "Info.bckup" => ObjectKind::InfoPlist,
            "lock" | "token" => ObjectKind::LockToken,
            ".com.apple.timemachine.supported" => ObjectKind::ValidationProbe,
            p if p.contains("com.apple.TimeMachine.MachineID") => ObjectKind::MachineId,
            "" | "bands" => ObjectKind::Dir,
            other => ObjectKind::Other(other.to_owned()),
        }
    }

    pub fn policy(&self, kind: &ObjectKind) -> WritePolicy {
        match kind {
            ObjectKind::Band(_) => WritePolicy::Journaled,
            _ => WritePolicy::WriteThrough,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_bands_as_hex() {
        let m = SparsebundleModel;
        assert_eq!(m.classify("bands/1a7"), ObjectKind::Band(0x1a7));
        assert_eq!(m.classify("bands/0"), ObjectKind::Band(0));
    }

    #[test]
    fn bands_are_journaled_meta_is_writethrough() {
        let m = SparsebundleModel;
        assert_eq!(m.policy(&m.classify("bands/2f")), WritePolicy::Journaled);
        assert_eq!(
            m.policy(&m.classify("Info.plist")),
            WritePolicy::WriteThrough
        );
        assert_eq!(
            m.policy(&m.classify(".com.apple.timemachine.supported")),
            WritePolicy::WriteThrough
        );
    }
}
