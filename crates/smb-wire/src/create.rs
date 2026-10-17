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
    /// SMB2_CREATE_REQUEST_LEASE (v1, 32 bytes) or _V2 (52 bytes).
    Lease(LeaseReq),
    /// Apple "AAPL" server query context (see the Apple TM-over-SMB spec).
    Aapl(AaplQuery),
    QueryMaximalAccess,
    /// Unknown tag: the body is kept as is.
    Unknown {
        tag: [u8; 4],
        body: Vec<u8>,
    },
}

/// Lease state bits (MS-SMB2 §2.2.13.2.8).
pub const LEASE_READ: u32 = 0x01;
pub const LEASE_HANDLE: u32 = 0x02;
pub const LEASE_WRITE: u32 = 0x04;
/// `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET`.
pub const LEASE_FLAG_PARENT_KEY_SET: u32 = 0x04;
/// DH2Q flag: the client asks for a persistent handle.
pub const DH2_FLAG_PERSISTENT: u32 = 0x02;

/// A lease request (`RqLs`), v1 or v2. The same shape is used for the granted reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseReq {
    pub key: [u8; 16],
    pub state: u32,
    pub flags: u32,
    pub parent_key: [u8; 16],
    pub epoch: u16,
    /// 52-byte v2 layout (parent key and epoch present).
    pub v2: bool,
}

impl LeaseReq {
    fn decode(data: &[u8]) -> Option<LeaseReq> {
        let v2 = match data.len() {
            32 => false,
            52 => true,
            _ => return None,
        };
        let mut r = Reader::new(data);
        let key = r.array::<16>().ok()?;
        let state = r.u32().ok()?;
        let flags = r.u32().ok()?;
        let _duration = r.u64().ok()?;
        let (parent_key, epoch) = if v2 {
            (r.array::<16>().ok()?, r.u16().ok()?)
        } else {
            ([0; 16], 0)
        };
        Some(LeaseReq {
            key,
            state,
            flags,
            parent_key,
            epoch,
            v2,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.key);
        w.u32(self.state);
        w.u32(self.flags);
        w.u64(0); // LeaseDuration
        if self.v2 {
            w.bytes(&self.parent_key);
            w.u16(self.epoch);
            w.u16(0);
        }
        w.into_vec()
    }
}

/// An AAPL server query (command 1): what the client asks for and what it supports.
/// The AAPL contexts are an Apple extension outside MS-SMB2; layout per the Apple
/// "Time Machine over SMB" specification, checked against live `mount_smbfs`/`tmutil` traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AaplQuery {
    /// `kAAPL_*` bits the client wants in the reply.
    pub request_bitmap: u64,
    pub client_caps: u64,
}

/// The reply to an AAPL server query. Which fields go on the wire is decided by `bitmap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AaplReply {
    pub bitmap: u64,
    pub server_caps: u64,
    pub volume_caps: u64,
    pub model: String,
}

/// AAPL command codes.
pub const AAPL_CMD_SERVER_QUERY: u32 = 1;

/// Request/reply bitmap bits of a server query.
pub const AAPL_BIT_SERVER_CAPS: u64 = 0x1;
pub const AAPL_BIT_VOLUME_CAPS: u64 = 0x2;
pub const AAPL_BIT_MODEL_INFO: u64 = 0x4;

/// Server capabilities (kAAPL_SERVER_CAPS).
pub const AAPL_SUPPORTS_READ_DIR_ATTR: u64 = 0x1;
pub const AAPL_SUPPORTS_OSX_COPYFILE: u64 = 0x2;
pub const AAPL_UNIX_BASED: u64 = 0x4;
pub const AAPL_SUPPORTS_NFS_ACE: u64 = 0x8;

/// Volume capabilities (kAAPL_VOLUME_CAPS).
pub const AAPL_SUPPORTS_RESOLVE_ID: u64 = 0x1;
pub const AAPL_CASE_SENSITIVE: u64 = 0x2;
/// kAAPL_SUPPORTS_FULL_SYNC: the volume supports SMB2 FLUSH with F_FULLFSYNC.
/// Without this bit `tmutil`/`backupd` refuse the share ("does not support SMB FullFSync").
pub const AAPL_SUPPORTS_FULL_SYNC: u64 = 0x4;

impl AaplQuery {
    /// `data` is the context body: command(4) reserved(4) request_bitmap(8) client_caps(8).
    /// Other commands (e.g. resolve-id) are not decoded.
    fn decode(data: &[u8]) -> Option<AaplQuery> {
        let mut r = Reader::new(data);
        if r.u32().ok()? != AAPL_CMD_SERVER_QUERY {
            return None;
        }
        let _reserved = r.u32().ok()?;
        Some(AaplQuery {
            request_bitmap: r.u64().ok()?,
            client_caps: r.u64().unwrap_or(0),
        })
    }
}

impl AaplReply {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(AAPL_CMD_SERVER_QUERY);
        w.u32(0);
        w.u64(self.bitmap);
        if self.bitmap & AAPL_BIT_SERVER_CAPS != 0 {
            w.u64(self.server_caps);
        }
        if self.bitmap & AAPL_BIT_VOLUME_CAPS != 0 {
            w.u64(self.volume_caps);
        }
        if self.bitmap & AAPL_BIT_MODEL_INFO != 0 {
            let utf16: Vec<u8> = self
                .model
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            w.u32(0); // pad
            w.u32(utf16.len() as u32);
            w.bytes(&utf16);
        }
        w.into_vec()
    }
}

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
            } else if let Some(q) = (&tag == b"AAPL").then(|| AaplQuery::decode(data)).flatten() {
                CreateContext::Aapl(q)
            } else if let Some(c) = decode_durable_or_lease(&tag, data) {
                c
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

/// `DH2Q`, `DH2C` and `RqLs`; `None` for other tags and for bodies of the wrong size.
fn decode_durable_or_lease(tag: &[u8; 4], data: &[u8]) -> Option<CreateContext> {
    let mut r = Reader::new(data);
    match tag {
        b"DH2Q" if data.len() == 32 => {
            let timeout_ms = r.u32().ok()?;
            let flags = r.u32().ok()?;
            let _reserved = r.u64().ok()?;
            Some(CreateContext::DurableHandleRequestV2 {
                timeout_ms,
                flags,
                create_guid: r.array::<16>().ok()?,
            })
        }
        b"DH2C" if data.len() == 36 => {
            let file_id = r.array::<16>().ok()?;
            let create_guid = r.array::<16>().ok()?;
            Some(CreateContext::DurableHandleReconnectV2 {
                file_id,
                create_guid,
                flags: r.u32().ok()?,
            })
        }
        b"RqLs" => LeaseReq::decode(data).map(CreateContext::Lease),
        _ => None,
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
    /// Reply to the AAPL server query.
    pub aapl: Option<AaplReply>,
    /// Reply to `DH2Q`: granted timeout (ms) and flags.
    pub durable: Option<(u32, u32)>,
    /// Reply to `RqLs`: the granted lease. Sets OplockLevel to LEASE (0xFF).
    pub lease: Option<LeaseReq>,
}

/// One create context in a response: header (16) + name (4) + pad (4) + data, 8-aligned.
fn push_context(out: &mut Vec<u8>, name: &[u8; 4], data: &[u8], last: bool) {
    let len = 24 + data.len();
    let padded = len.next_multiple_of(8);
    out.extend_from_slice(&(if last { 0 } else { padded as u32 }).to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes()); // NameOffset
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&24u16.to_le_bytes()); // DataOffset
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(data);
    out.resize(out.len() + (padded - len), 0);
}

impl CreateResp {
    pub fn encode(&self, w: &mut Writer) {
        w.u16(89);
        w.u8(if self.lease.is_some() { 0xFF } else { 0 }); // OplockLevel: LEASE or NONE
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
        let mut parts: Vec<([u8; 4], Vec<u8>)> = Vec::new();
        if let Some(access) = self.maximal_access {
            let mut d = Vec::with_capacity(8);
            d.extend_from_slice(&0u32.to_le_bytes()); // QueryStatus
            d.extend_from_slice(&access.to_le_bytes());
            parts.push((*b"MxAc", d));
        }
        if let Some((timeout_ms, flags)) = self.durable {
            let mut d = Vec::with_capacity(8);
            d.extend_from_slice(&timeout_ms.to_le_bytes());
            d.extend_from_slice(&flags.to_le_bytes());
            parts.push((*b"DH2Q", d));
        }
        if let Some(lease) = &self.lease {
            parts.push((*b"RqLs", lease.encode()));
        }
        if let Some(aapl) = &self.aapl {
            parts.push((*b"AAPL", aapl.encode()));
        }
        let mut chain = Vec::new();
        for (i, (name, data)) in parts.iter().enumerate() {
            push_context(&mut chain, name, data, i + 1 == parts.len());
        }
        if chain.is_empty() {
            w.u32(0);
            w.u32(0);
        } else {
            w.u32(ctx_off);
            w.u32(chain.len() as u32);
            w.bytes(&chain);
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

    /// The AAPL data macOS sends (`mount_smbfs` and `tmutil`, live traces): server query asking
    /// for server caps, volume caps and the model string; client caps 0x3f.
    const MACOS_AAPL_DATA: &str = "010000000000000007000000000000003f00000000000000";

    #[test]
    fn decodes_aapl_server_query() {
        let q = AaplQuery::decode(&unhex(MACOS_AAPL_DATA)).unwrap();
        assert_eq!(q.request_bitmap, 7);
        assert_eq!(q.client_caps, 0x3f);
        // other commands and truncated data are not queries
        let mut other = unhex(MACOS_AAPL_DATA);
        other[0] = 2;
        assert!(AaplQuery::decode(&other).is_none());
        for n in 0..16 {
            assert!(
                AaplQuery::decode(&unhex(MACOS_AAPL_DATA)[..n]).is_none(),
                "len {n}"
            );
        }
    }

    /// `DH2Q`/`RqLs` data as sent by `tmutil` for `.com.apple.timemachine.supported-<uuid>`
    /// (live trace, macOS 26): a 30 s durable handle and a lease RH with a parent key.
    const MACOS_DH2Q: &str = "307500000000000000000000000000004a2df37211224b90bfa1e9df022947d1";
    const MACOS_RQLS_V2: &str = "b5ea5a075714fd634cee9b9a8b5c44300300000004000000000000000000000042cdc50460d344d68c0dcac3e23a4ca400000000";

    #[test]
    fn decodes_durable_v2_request_and_lease_v2_from_macos() {
        let dh = decode_durable_or_lease(b"DH2Q", &unhex(MACOS_DH2Q)).unwrap();
        match dh {
            CreateContext::DurableHandleRequestV2 {
                timeout_ms,
                flags,
                create_guid,
            } => {
                assert_eq!((timeout_ms, flags), (30_000, 0));
                assert_eq!(create_guid[0], 0x4a);
            }
            other => panic!("{other:?}"),
        }
        let CreateContext::Lease(l) =
            decode_durable_or_lease(b"RqLs", &unhex(MACOS_RQLS_V2)).unwrap()
        else {
            panic!("not a lease")
        };
        assert!(l.v2);
        assert_eq!(l.state, LEASE_READ | LEASE_HANDLE);
        assert_eq!(l.flags, LEASE_FLAG_PARENT_KEY_SET);
        assert_eq!(l.key[0], 0xb5);
        assert_eq!(l.parent_key[0], 0x42);
        // a lease reply round-trips through the request decoder
        assert_eq!(LeaseReq::decode(&l.encode()), Some(l));
    }

    #[test]
    fn durable_and_lease_decoders_reject_wrong_sizes() {
        assert!(decode_durable_or_lease(b"DH2Q", &unhex(MACOS_DH2Q)[..31]).is_none());
        assert!(decode_durable_or_lease(b"RqLs", &[0; 40]).is_none());
        assert!(decode_durable_or_lease(b"DH2C", &[0; 35]).is_none());
        let rec = decode_durable_or_lease(b"DH2C", &[7; 36]).unwrap();
        assert!(
            matches!(rec, CreateContext::DurableHandleReconnectV2 { file_id, .. } if file_id == [7; 16])
        );
        let v1 = decode_durable_or_lease(b"RqLs", &[1; 32]).unwrap();
        assert!(matches!(
            v1,
            CreateContext::Lease(LeaseReq { v2: false, .. })
        ));
    }

    #[test]
    fn create_resp_carries_durable_and_lease_replies() {
        let lease = LeaseReq {
            key: [3; 16],
            state: LEASE_READ,
            flags: 0,
            parent_key: [0; 16],
            epoch: 1,
            v2: true,
        };
        let mut w = Writer::new();
        CreateResp {
            create_action: ACTION_CREATED,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: ATTR_ARCHIVE,
            file_id: [0; 16],
            maximal_access: None,
            aapl: None,
            durable: Some((30_000, 0)),
            lease: Some(lease),
        }
        .encode(&mut w);
        let b = w.into_vec();
        assert_eq!(b[2], 0xFF, "OplockLevel = LEASE");
        let chain = &b[88..];
        assert_eq!(&chain[16..20], b"DH2Q");
        assert_eq!(
            u32::from_le_bytes(chain[24..28].try_into().unwrap()),
            30_000
        );
        let next = u32::from_le_bytes(chain[0..4].try_into().unwrap()) as usize;
        assert_eq!(&chain[next + 16..next + 20], b"RqLs");
        assert_eq!(
            u32::from_le_bytes(chain[next + 12..next + 16].try_into().unwrap()),
            52
        );
    }

    #[test]
    fn aapl_reply_layout_follows_the_bitmap() {
        let reply = AaplReply {
            bitmap: AAPL_BIT_SERVER_CAPS | AAPL_BIT_VOLUME_CAPS | AAPL_BIT_MODEL_INFO,
            server_caps: 0,
            volume_caps: AAPL_SUPPORTS_FULL_SYNC | AAPL_CASE_SENSITIVE,
            model: "Jn".into(),
        };
        let d = reply.encode();
        assert_eq!(u32::from_le_bytes(d[0..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(d[8..16].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(d[16..24].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(d[24..32].try_into().unwrap()), 6);
        assert_eq!(u32::from_le_bytes(d[36..40].try_into().unwrap()), 4); // "Jn" in UTF-16
        assert_eq!(&d[40..], &[b'J', 0, b'n', 0]);
        let only_volume = AaplReply {
            bitmap: AAPL_BIT_VOLUME_CAPS,
            ..reply
        }
        .encode();
        assert_eq!(only_volume.len(), 24);
    }

    #[test]
    fn create_resp_chains_mxac_and_aapl() {
        let mut w = Writer::new();
        CreateResp {
            create_action: ACTION_OPENED,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: ATTR_DIRECTORY,
            file_id: [0; 16],
            maximal_access: Some(1),
            durable: None,
            lease: None,
            aapl: Some(AaplReply {
                bitmap: AAPL_BIT_VOLUME_CAPS,
                server_caps: 0,
                volume_caps: AAPL_SUPPORTS_FULL_SYNC,
                model: String::new(),
            }),
        }
        .encode(&mut w);
        let b = w.into_vec();
        let total = u32::from_le_bytes(b[84..88].try_into().unwrap()) as usize;
        assert_eq!(b.len(), 88 + total);
        assert_eq!(u32::from_le_bytes(b[88..92].try_into().unwrap()), 32); // Next of MxAc
        assert_eq!(&b[88 + 32 + 16..88 + 32 + 20], b"AAPL");
        assert_eq!(
            u32::from_le_bytes(b[88 + 32..88 + 36].try_into().unwrap()),
            0
        ); // last
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
            aapl: None,
            durable: None,
            lease: None,
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
