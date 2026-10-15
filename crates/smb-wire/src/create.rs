//! SMB2 CREATE and create contexts: the busiest part of the format:
//! durable handles V2, lease V2 and Apple AAPL all live here.

/// A CREATE request (opening/creating a file on the share).
#[derive(Debug)]
pub struct CreateReq {
    /// Path relative to the share root, UTF-16 in the frame.
    pub path: String,
    pub desired_access: u32,
    /// FileAttributes requested for a new object.
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub contexts: Vec<CreateContext>,
}

/// Create contexts of the request. Unknown tags are PRESERVED (`Unknown`) rather than
/// dropped: the Apple client sends contexts outside MS-SMB2, and CREATE must not fail.
#[derive(Debug)]
pub enum CreateContext {
    /// SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2. TM validation sends timeout=0
    /// (discovering the server default), then 30 s, and compares the reply.
    DurableHandleRequestV2 {
        timeout_ms: u32,
        flags: u32,
        create_guid: [u8; 16],
    },
    /// SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2: recovery after a drop.
    DurableHandleReconnectV2 {
        file_id: [u8; 16],
        create_guid: [u8; 16],
        flags: u32,
    },
    /// SMB2_CREATE_REQUEST_LEASE_V2.
    LeaseV2Request {
        lease_key: [u8; 16],
        lease_state: u32,
        epoch: u16,
    },
    /// Apple "AAPL" server query context (see the Apple TM-over-SMB spec).
    Aapl(AaplContext),
    QueryMaximalAccess,
    /// Unknown tag: the body is kept as is.
    Unknown {
        tag: [u8; 4],
        body: Vec<u8>,
    },
}

/// The AAPL context (request and reply are structurally close; the reply side is
/// something no open Rust crate has, so we write it ourselves).
#[derive(Debug)]
pub struct AaplContext {
    pub command: AaplCommand,
    /// Bit mask of server capabilities.
    pub server_caps: u64,
    pub volume_caps: u64,
    pub model_string: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AaplCommand {
    ServerQuery,
    ResolveId,
}

/// kAAPL_SUPPORTS_FULL_SYNC: the server supports SMB2 FLUSH with F_FULLFSYNC.
/// Without this bit backupd will not trust F_FULLFSYNC (Apple spec).
pub const AAPL_SUPPORTS_FULL_SYNC: u64 = 0x0000_0000_0000_0004;

// === CREATE codec (MS-SMB2 §2.2.13 / §2.2.14) =============================

use crate::WireError;
use crate::bytes::{Reader, Writer};

/// CreateDisposition (§2.2.13).
pub mod disposition {
    pub const SUPERSEDE: u32 = 0;
    pub const OPEN: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const OPEN_IF: u32 = 3;
    pub const OVERWRITE: u32 = 4;
    pub const OVERWRITE_IF: u32 = 5;
}

/// CreateOptions: FILE_DIRECTORY_FILE.
pub const OPT_DIRECTORY_FILE: u32 = 0x0000_0001;
/// FILE_ATTRIBUTE_DIRECTORY.
pub const ATTR_DIRECTORY: u32 = 0x0000_0010;
/// CreateAction values (§2.2.14).
pub const ACTION_SUPERSEDED: u32 = 0;
pub const ACTION_OPENED: u32 = 1;
pub const ACTION_CREATED: u32 = 2;
pub const ACTION_OVERWRITTEN: u32 = 3;

/// CreateOptions bits used by the file model.
pub const OPT_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const OPT_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// FILE_ATTRIBUTE_* values.
pub const ATTR_READONLY: u32 = 0x0000_0001;
pub const ATTR_ARCHIVE: u32 = 0x0000_0020;
pub const ATTR_NORMAL: u32 = 0x0000_0080;

/// DesiredAccess bits (§2.2.13.1) that mean "will write file data".
pub const ACCESS_WRITE_DATA: u32 = 0x0000_0002;
pub const ACCESS_APPEND_DATA: u32 = 0x0000_0004;
pub const ACCESS_DELETE: u32 = 0x0001_0000;
pub const ACCESS_GENERIC_ALL: u32 = 0x1000_0000;
pub const ACCESS_GENERIC_WRITE: u32 = 0x4000_0000;

pub const ACCESS_MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const ACCESS_GENERIC_READ: u32 = 0x8000_0000;
pub const ACCESS_GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const ACCESS_READ_DATA: u32 = 0x0000_0001;
pub const ACCESS_EXECUTE: u32 = 0x0000_0020;

/// Replace generic and MAXIMUM_ALLOWED bits with the specific rights they stand for
/// (MS-SMB2 §2.2.13.1, generic mapping of files). The share grants everything.
pub fn expand_access(desired: u32) -> u32 {
    use crate::messages::ACCESS_ALL;
    let mut a = desired & 0x01FF_FFFF;
    if desired & (ACCESS_GENERIC_ALL | ACCESS_MAXIMUM_ALLOWED) != 0 {
        return ACCESS_ALL;
    }
    if desired & ACCESS_GENERIC_READ != 0 {
        a |= 0x0012_0089;
    }
    if desired & ACCESS_GENERIC_WRITE != 0 {
        a |= 0x0012_0116;
    }
    if desired & ACCESS_GENERIC_EXECUTE != 0 {
        a |= 0x0012_00A0;
    }
    a
}

/// Whether an (expanded) access mask allows writing file data.
pub fn access_wants_write(access: u32) -> bool {
    access & (ACCESS_WRITE_DATA | ACCESS_APPEND_DATA) != 0
}

/// Whether an (expanded) access mask allows reading file data.
pub fn access_wants_read(access: u32) -> bool {
    access & (ACCESS_READ_DATA | ACCESS_EXECUTE) != 0
}

/// FileId: persistent + volatile, 8 bytes each.
pub type FileId = [u8; 16];

/// "The previous CREATE of the chain" (related compound).
pub const FILE_ID_RELATED: FileId = [0xFF; 16];

impl CreateReq {
    /// `r` is the command body (after the header); offsets are counted from the start of the header.
    pub fn decode(r: &mut Reader<'_>) -> Result<CreateReq, WireError> {
        let body = r.whole();
        if r.u16()? != 57 {
            return Err(WireError::Malformed("CREATE StructureSize != 57"));
        }
        let _security_flags = r.u8()?;
        let _oplock = r.u8()?;
        let _impersonation = r.u32()?;
        let _create_flags = r.u64()?;
        let _reserved = r.u64()?;
        let desired_access = r.u32()?;
        let file_attributes = r.u32()?;
        let share_access = r.u32()?;
        let create_disposition = r.u32()?;
        let create_options = r.u32()?;
        let name_off = r.u16()? as usize;
        let name_len = r.u16()? as usize;
        let ctx_off = r.u32()? as usize;
        let ctx_len = r.u32()? as usize;

        let path = if name_len == 0 {
            String::new()
        } else {
            if !name_len.is_multiple_of(2) {
                return Err(WireError::Malformed("CREATE: odd name length"));
            }
            let start = name_off
                .checked_sub(crate::header::HEADER_LEN)
                .ok_or(WireError::Malformed("NameOffset inside the header"))?;
            let raw = body
                .get(start..start + name_len)
                .ok_or(WireError::Malformed("name outside the message"))?;
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).map_err(|_| WireError::Malformed("CREATE: UTF-16"))?
        };

        let contexts = if ctx_len == 0 {
            Vec::new()
        } else {
            let start =
                ctx_off
                    .checked_sub(crate::header::HEADER_LEN)
                    .ok_or(WireError::Malformed(
                        "CreateContextsOffset inside the header",
                    ))?;
            let chain = body
                .get(start..start + ctx_len)
                .ok_or(WireError::Malformed("contexts outside the message"))?;
            decode_contexts(chain)?
        };

        Ok(CreateReq {
            path,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            contexts,
        })
    }
}

/// A chain of create contexts. We recognise only `MxAc`; others with a 4-byte
/// name are kept as `Unknown`, the rest are skipped.
fn decode_contexts(chain: &[u8]) -> Result<Vec<CreateContext>, WireError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let mut r = Reader::new(chain);
        r.seek(at)?;
        let next = r.u32()? as usize;
        let name_off = r.u16()? as usize;
        let name_len = r.u16()? as usize;
        let _reserved = r.u16()?;
        let data_off = r.u16()? as usize;
        let data_len = r.u32()? as usize;
        let name = chain
            .get(at + name_off..at + name_off + name_len)
            .ok_or(WireError::BadContext("name"))?;
        let data = chain
            .get(at + data_off..at + data_off + data_len)
            .ok_or(WireError::BadContext("data"))?;
        if let Ok(tag) = <[u8; 4]>::try_from(name) {
            out.push(if &tag == b"MxAc" {
                CreateContext::QueryMaximalAccess
            } else {
                CreateContext::Unknown {
                    tag,
                    body: data.to_vec(),
                }
            });
        }
        if next == 0 {
            return Ok(out);
        }
        if !next.is_multiple_of(8) || at + next >= chain.len() || out.len() > 32 {
            return Err(WireError::BadContext("chain"));
        }
        at += next;
    }
}

/// A CREATE reply (the share root).
#[derive(Debug)]
pub struct CreateResp {
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub file_id: FileId,
    /// Reply to the MxAc context: MaximalAccess.
    pub maximal_access: Option<u32>,
}

impl CreateResp {
    pub fn encode(&self, w: &mut Writer) {
        w.u16(89);
        w.u8(0); // OplockLevel: NONE
        w.u8(0); // Flags
        w.u32(self.create_action);
        w.u64(self.creation_time);
        w.u64(self.last_access_time);
        w.u64(self.last_write_time);
        w.u64(self.change_time);
        w.u64(self.allocation_size);
        w.u64(self.end_of_file);
        w.u32(self.file_attributes);
        w.u32(0); // Reserved2
        w.bytes(&self.file_id);
        // Contexts start right after the fixed part (88 bytes of body), 8-byte aligned.
        let ctx_off = (crate::header::HEADER_LEN + 88) as u32;
        match self.maximal_access {
            Some(access) => {
                w.u32(ctx_off);
                w.u32(32);
                w.u32(0); // Next
                w.u16(16); // NameOffset
                w.u16(4);
                w.u16(0);
                w.u16(24); // DataOffset
                w.u32(8);
                w.bytes(b"MxAc");
                w.zeros(4);
                w.u32(0); // QueryStatus
                w.u32(access);
            }
            None => {
                w.u32(0);
                w.u32(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CREATE of the root directory as macOS `mount_smbfs` sends it (a body from a live exchange).
    const MACOS_ROOT_CREATE_BODY: &str = "39000000020000000000000000000000000000000000000080001000100000000700000001000000010000007800000080000000180000000000000000000000000000001000040000000000000000004d78416300000000";

    fn unhex(s: &str) -> Vec<u8> {
        crate::ms_vectors::unhex(s)
    }

    #[test]
    fn decodes_macos_root_create_with_mxac() {
        let body = unhex(MACOS_ROOT_CREATE_BODY);
        let req = CreateReq::decode(&mut Reader::new(&body)).unwrap();
        assert_eq!(req.path, "");
        assert_eq!(req.desired_access, 0x0010_0080);
        assert_eq!(req.create_disposition, disposition::OPEN);
        assert_eq!(req.create_options & OPT_DIRECTORY_FILE, OPT_DIRECTORY_FILE);
        assert!(matches!(
            req.contexts.as_slice(),
            [CreateContext::QueryMaximalAccess]
        ));
    }

    #[test]
    fn create_decode_rejects_garbage() {
        let body = unhex(MACOS_ROOT_CREATE_BODY);
        for n in 0..body.len() {
            assert!(
                CreateReq::decode(&mut Reader::new(&body[..n])).is_err(),
                "len {n}"
            );
        }
        let mut bad = body.clone();
        bad[0] = 58;
        assert!(CreateReq::decode(&mut Reader::new(&bad)).is_err());
    }

    #[test]
    fn create_resp_layout() {
        let mut w = Writer::new();
        CreateResp {
            create_action: ACTION_OPENED,
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: ATTR_DIRECTORY,
            file_id: [9; 16],
            maximal_access: Some(0x001F_01FF),
        }
        .encode(&mut w);
        let b = w.into_vec();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 89);
        assert_eq!(&b[64..80], &[9; 16]);
        assert_eq!(u32::from_le_bytes(b[80..84].try_into().unwrap()), 152);
        assert_eq!(u32::from_le_bytes(b[84..88].try_into().unwrap()), 32);
        assert_eq!(b.len(), 88 + 32);
        assert_eq!(&b[88 + 16..88 + 20], b"MxAc");
        assert_eq!(
            u32::from_le_bytes(b[88 + 28..88 + 32].try_into().unwrap()),
            0x001F_01FF
        );
    }

    #[test]
    fn access_expansion() {
        use crate::messages::ACCESS_ALL;
        assert_eq!(expand_access(ACCESS_GENERIC_ALL), ACCESS_ALL);
        assert_eq!(expand_access(ACCESS_MAXIMUM_ALLOWED), ACCESS_ALL);
        assert_eq!(expand_access(0x0012_0089), 0x0012_0089);
        let r = expand_access(ACCESS_GENERIC_READ);
        assert!(access_wants_read(r) && !access_wants_write(r));
        let w = expand_access(ACCESS_GENERIC_WRITE);
        assert!(access_wants_write(w) && !access_wants_read(w));
        assert!(!access_wants_write(0x0000_0080)); // attributes only
        assert_eq!(expand_access(ACCESS_DELETE) & ACCESS_DELETE, ACCESS_DELETE);
    }
}
