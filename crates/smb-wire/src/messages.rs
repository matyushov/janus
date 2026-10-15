//! Bodies of SMB2 commands. Implemented incrementally; first those needed for
//! the end-to-end scenario "the client sees the share and writes a file":
//! NEGOTIATE → SESSION_SETUP → TREE_CONNECT → CREATE/WRITE/READ/CLOSE.
//!
//! J1: only dialect 3.1.1, signing mandatory (SHA-512 preauth integrity,
//! AES-128-CMAC). File commands (CREATE/READ/WRITE/…) are J2.

use crate::WireError;
use crate::bytes::{Reader, Writer};
use crate::frame::Dialect;

// === NEGOTIATE (MS-SMB2 §2.2.3 / §2.2.4) ===================================

/// Types of negotiate contexts (MS-SMB2 §2.2.3.1).
pub mod ctx_type {
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    pub const ENCRYPTION: u16 = 0x0002;
}

/// SHA-512 identifier in PREAUTH_INTEGRITY_CAPABILITIES.
pub const HASH_SHA512: u16 = 0x0001;

/// Parsed negotiate contexts of the client. Unknown types are skipped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NegotiateContexts {
    /// (list of hash algorithms, salt) from PREAUTH_INTEGRITY_CAPABILITIES.
    pub preauth: Option<PreauthCaps>,
    /// Ciphers from ENCRYPTION_CAPABILITIES (parsed, but encryption is not enabled in J1).
    pub ciphers: Option<Vec<u16>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreauthCaps {
    pub hash_algorithms: Vec<u16>,
    pub salt: Vec<u8>,
}

/// A parsed NEGOTIATE request.
#[derive(Debug)]
pub struct NegotiateReq {
    pub dialects: Vec<u16>,
    pub security_mode: u16,
    pub client_guid: [u8; 16],
    /// 3.1.1 contexts; empty if the client did not offer 3.1.1.
    pub contexts: NegotiateContexts,
}

impl NegotiateReq {
    /// `r` is the command body (right after the 64-byte header). Offsets of
    /// negotiate contexts in the protocol are counted from the start of the header.
    pub fn decode(r: &mut Reader<'_>) -> Result<NegotiateReq, WireError> {
        let body = r.whole();
        let structure_size = r.u16()?;
        if structure_size != 36 {
            return Err(WireError::Malformed("NEGOTIATE StructureSize != 36"));
        }
        let dialect_count = r.u16()? as usize;
        if dialect_count == 0 {
            return Err(WireError::Malformed("NEGOTIATE без диалектов"));
        }
        let security_mode = r.u16()?;
        let _reserved = r.u16()?;
        let _capabilities = r.u32()?;
        let client_guid = r.array::<16>()?;
        // For 3.1.1: NegotiateContextOffset(4)+Count(2)+Reserved2(2);
        // for < 3.1.1 this is ClientStartTime, so we do not read contexts there.
        let ctx_offset = r.u32()? as usize;
        let ctx_count = r.u16()? as usize;
        let _reserved2 = r.u16()?;

        let mut dialects = Vec::with_capacity(dialect_count.min(64));
        for _ in 0..dialect_count {
            dialects.push(r.u16()?);
        }

        let contexts =
            if dialects.contains(&(Dialect::Smb311 as u16)) && ctx_count > 0 {
                let start = ctx_offset.checked_sub(crate::header::HEADER_LEN).ok_or(
                    WireError::Malformed("NegotiateContextOffset внутри заголовка"),
                )?;
                NegotiateContexts::decode(body, start, ctx_count)?
            } else {
                NegotiateContexts::default()
            };

        Ok(NegotiateReq {
            dialects,
            security_mode,
            client_guid,
            contexts,
        })
    }

    /// The only permitted dialect is 3.1.1 (an invariant of `profile.rs`).
    /// A client that did not offer it gets a refusal (`None`).
    pub fn select_dialect(&self) -> Option<Dialect> {
        const CEILING: Dialect = Dialect::Smb311;
        const FLOOR: Dialect = Dialect::Smb311;
        self.dialects
            .iter()
            .filter_map(|&d| Dialect::from_u16(d))
            .filter(|&d| (FLOOR..=CEILING).contains(&d))
            .max()
    }
}

impl NegotiateContexts {
    /// `body` is the whole command body, `start` is the offset of the first context in it.
    fn decode(body: &[u8], start: usize, count: usize) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        r.seek(start)?;
        let mut out = NegotiateContexts::default();
        for i in 0..count {
            if i > 0 {
                // every context is aligned to 8 bytes (from the start of the header;
                // 64 is a multiple of 8, so we align the offset within the body)
                let pad = (8 - r.position() % 8) % 8;
                r.skip(pad)?;
            }
            let ty = r.u16()?;
            let len = r.u16()? as usize;
            let _reserved = r.u32()?;
            let data = r.take(len)?;
            let mut d = Reader::new(data);
            match ty {
                ctx_type::PREAUTH_INTEGRITY => {
                    let n = d.u16()? as usize;
                    let salt_len = d.u16()? as usize;
                    let mut algs = Vec::with_capacity(n.min(16));
                    for _ in 0..n {
                        algs.push(d.u16()?);
                    }
                    let salt = d.take(salt_len)?.to_vec();
                    out.preauth = Some(PreauthCaps {
                        hash_algorithms: algs,
                        salt,
                    });
                }
                ctx_type::ENCRYPTION => {
                    let n = d.u16()? as usize;
                    let mut ciphers = Vec::with_capacity(n.min(16));
                    for _ in 0..n {
                        ciphers.push(d.u16()?);
                    }
                    out.ciphers = Some(ciphers);
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Parameters of the server's NEGOTIATE response (3.1.1).
#[derive(Debug)]
pub struct NegotiateResp {
    /// DialectRevision as on the wire: 0x0311, or 0x02FF/0x0202 in the reply to an
    /// SMB1 multi-protocol NEGOTIATE (then without negotiate contexts).
    pub dialect_revision: u16,
    pub server_guid: [u8; 16],
    pub security_mode: u16,
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    /// Current server time, FILETIME.
    pub system_time: u64,
    /// GSS/SPNEGO token (NegTokenInit) in the SecurityBuffer field.
    pub security_buffer: Vec<u8>,
    /// Salt for the PREAUTH_INTEGRITY_CAPABILITIES of the response (SHA-512).
    pub preauth_salt: Vec<u8>,
}

/// SecurityMode: signing enabled/required (MS-SMB2 §2.2.3).
pub mod security_mode {
    pub const SIGNING_ENABLED: u16 = 0x0001;
    pub const SIGNING_REQUIRED: u16 = 0x0002;
}

/// Seconds between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH_SECS: u64 = 11_644_473_600;

/// Unix time → FILETIME (100 ns intervals since 1601-01-01).
pub fn filetime_from_unix(secs: u64, nanos: u32) -> u64 {
    (secs + FILETIME_UNIX_EPOCH_SECS) * 10_000_000 + u64::from(nanos) / 100
}

/// Current time as FILETIME.
pub fn filetime_now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    filetime_from_unix(d.as_secs(), d.subsec_nanos())
}

impl NegotiateResp {
    /// Response body (after the header). The SecurityBuffer follows right after
    /// the fixed part (64 bytes of body); the contexts are 8-byte aligned.
    pub fn encode(&self, w: &mut Writer) {
        let with_contexts = self.dialect_revision == Dialect::Smb311 as u16;
        let sec_buf_offset = (crate::header::HEADER_LEN + 64) as u16;
        let sec_len = self.security_buffer.len();
        let ctx_offset = (crate::header::HEADER_LEN + 64 + sec_len).next_multiple_of(8);

        w.u16(65); // StructureSize (fixed for a response)
        w.u16(self.security_mode);
        w.u16(self.dialect_revision);
        w.u16(with_contexts as u16); // NegotiateContextCount: PREAUTH_INTEGRITY only
        w.bytes(&self.server_guid);
        w.u32(self.capabilities);
        w.u32(self.max_transact_size);
        w.u32(self.max_read_size);
        w.u32(self.max_write_size);
        w.u64(self.system_time);
        w.u64(0); // ServerStartTime: MUST be 0
        w.u16(sec_buf_offset);
        w.u16(sec_len as u16);
        w.u32(if with_contexts { ctx_offset as u32 } else { 0 });
        w.bytes(&self.security_buffer);
        if !with_contexts {
            return;
        }
        w.zeros(ctx_offset - (crate::header::HEADER_LEN + 64 + sec_len));

        // PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 + salt
        w.u16(ctx_type::PREAUTH_INTEGRITY);
        w.u16((6 + self.preauth_salt.len()) as u16);
        w.u32(0);
        w.u16(1); // HashAlgorithmCount
        w.u16(self.preauth_salt.len() as u16);
        w.u16(HASH_SHA512);
        w.bytes(&self.preauth_salt);
    }
}

// === SMB1 multi-protocol NEGOTIATE (MS-SMB2 §3.3.5.3.1) ====================

/// Is this an SMB1 packet (`\xFF SMB`)?
pub fn is_smb1(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[..4] == [0xFF, b'S', b'M', b'B']
}

/// Dialects from an SMB1 NEGOTIATE (`0x72`): strings like "NT LM 0.12", "SMB 2.002",
/// "SMB 2.???". A non-NEGOTIATE or a broken packet is an error. Needed only to reply
/// to the multi-protocol negotiate: macOS clients start the connection with exactly that.
pub fn smb1_negotiate_dialects(payload: &[u8]) -> Result<Vec<String>, WireError> {
    const SMB1_HEADER: usize = 32;
    const CMD_NEGOTIATE: u8 = 0x72;
    if !is_smb1(payload) || payload.len() < SMB1_HEADER + 3 {
        return Err(WireError::Malformed("SMB1: короткий пакет"));
    }
    if payload[4] != CMD_NEGOTIATE {
        return Err(WireError::Malformed("SMB1: не NEGOTIATE"));
    }
    let mut r = Reader::new(payload);
    r.seek(SMB1_HEADER)?;
    let word_count = r.u8()? as usize;
    r.skip(word_count * 2)?;
    let byte_count = r.u16()? as usize;
    let mut data = Reader::new(r.take(byte_count)?);
    let mut dialects = Vec::new();
    while data.remaining() > 0 {
        if data.u8()? != 0x02 {
            return Err(WireError::Malformed("SMB1: ожидали маркер диалекта 0x02"));
        }
        let mut name = Vec::new();
        loop {
            match data.u8()? {
                0 => break,
                b => name.push(b),
            }
        }
        dialects.push(String::from_utf8_lossy(&name).into_owned());
        if dialects.len() > 32 {
            return Err(WireError::Malformed("SMB1: слишком много диалектов"));
        }
    }
    Ok(dialects)
}

/// DialectRevision in the reply to an SMB1 NEGOTIATE: 0x02FF if the client offered
/// "SMB 2.???"; 0x0202 if only "SMB 2.002"; otherwise `None` (SMB1 is not served).
pub fn smb1_wildcard_revision(dialects: &[String]) -> Option<u16> {
    if dialects.iter().any(|d| d == "SMB 2.???") {
        Some(0x02FF)
    } else if dialects.iter().any(|d| d == "SMB 2.002") {
        Some(0x0202)
    } else {
        None
    }
}

// === SESSION_SETUP (MS-SMB2 §2.2.5 / §2.2.6) ===============================

pub mod session_setup_flags {
    /// Binding a channel to an existing session (multichannel) is not supported.
    pub const BINDING: u8 = 0x01;
}

#[derive(Debug)]
pub struct SessionSetupReq {
    pub flags: u8,
    pub security_mode: u8,
    pub previous_session_id: u64,
    /// The client's SPNEGO token.
    pub security_buffer: Vec<u8>,
}

impl SessionSetupReq {
    /// `r` is the command body; SecurityBufferOffset is counted from the start of the header.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let body = r.whole();
        if r.u16()? != 25 {
            return Err(WireError::Malformed("SESSION_SETUP StructureSize != 25"));
        }
        let flags = r.u8()?;
        let security_mode = r.u8()?;
        let _capabilities = r.u32()?;
        let _channel = r.u32()?;
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        let previous_session_id = r.u64()?;
        let start = off
            .checked_sub(crate::header::HEADER_LEN)
            .ok_or(WireError::Malformed(
                "SecurityBufferOffset внутри заголовка",
            ))?;
        let end = start
            .checked_add(len)
            .ok_or(WireError::Malformed("SecurityBuffer overflow"))?;
        let security_buffer = body
            .get(start..end)
            .ok_or(WireError::Malformed("SecurityBuffer вне сообщения"))?
            .to_vec();
        Ok(SessionSetupReq {
            flags,
            security_mode,
            previous_session_id,
            security_buffer,
        })
    }
}

#[derive(Debug)]
pub struct SessionSetupResp {
    /// SessionFlags (IS_GUEST/IS_NULL/ENCRYPT_DATA) are always 0 in J1.
    pub session_flags: u16,
    pub security_buffer: Vec<u8>,
}

impl SessionSetupResp {
    pub fn encode(&self, w: &mut Writer) {
        w.u16(9);
        w.u16(self.session_flags);
        w.u16((crate::header::HEADER_LEN + 8) as u16);
        w.u16(self.security_buffer.len() as u16);
        w.bytes(&self.security_buffer);
    }
}

// === TREE_CONNECT (MS-SMB2 §2.2.9 / §2.2.10) ===============================

#[derive(Debug)]
pub struct TreeConnectReq {
    /// UNC path `\\host\share` (UTF-16LE → String).
    pub path: String,
}

impl TreeConnectReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let body = r.whole();
        if r.u16()? != 9 {
            return Err(WireError::Malformed("TREE_CONNECT StructureSize != 9"));
        }
        let _flags = r.u16()?;
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        let start = off
            .checked_sub(crate::header::HEADER_LEN)
            .ok_or(WireError::Malformed("PathOffset внутри заголовка"))?;
        let end = start
            .checked_add(len)
            .ok_or(WireError::Malformed("Path overflow"))?;
        let raw = body
            .get(start..end)
            .ok_or(WireError::Malformed("Path вне сообщения"))?;
        if !raw.len().is_multiple_of(2) {
            return Err(WireError::Malformed("Path: нечётная длина UTF-16"));
        }
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let path = String::from_utf16(&units).map_err(|_| WireError::Malformed("Path: UTF-16"))?;
        Ok(TreeConnectReq { path })
    }
}

pub mod share_type {
    pub const DISK: u8 = 0x01;
}

pub mod share_flags {
    /// No offline caching on the client (SMB2_SHAREFLAG_NO_CACHING).
    pub const NO_CACHING: u32 = 0x0000_0030;
}

/// FILE_ALL_ACCESS: maximal rights on the share (writing is allowed).
pub const ACCESS_ALL: u32 = 0x001F_01FF;

#[derive(Debug)]
pub struct TreeConnectResp {
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

impl TreeConnectResp {
    pub fn encode(&self, w: &mut Writer) {
        w.u16(16);
        w.u8(self.share_type);
        w.u8(0);
        w.u32(self.share_flags);
        w.u32(self.capabilities);
        w.u32(self.maximal_access);
    }
}

// === Simple commands: LOGOFF / TREE_DISCONNECT / ECHO ====================

/// A request of two fields: StructureSize (4) + Reserved. Shared by LOGOFF
/// (§2.2.7), TREE_DISCONNECT (§2.2.11) and ECHO (§2.2.28).
pub fn decode_simple_req(r: &mut Reader<'_>) -> Result<(), WireError> {
    if r.u16()? != 4 {
        return Err(WireError::Malformed("StructureSize != 4"));
    }
    let _reserved = r.u16()?;
    Ok(())
}

pub fn encode_simple_resp(w: &mut Writer) {
    w.u16(4);
    w.u16(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Command;
    use crate::header::{Header, flags};
    use crate::ms_vectors::{NEGOTIATE_REQUEST, unhex};

    /// Build a NEGOTIATE request (body) the way a 3.1.1 client sends it.
    pub(crate) fn build_negotiate_req(dialects: &[u16], contexts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(36); // StructureSize
        w.u16(dialects.len() as u16);
        w.u16(security_mode::SIGNING_ENABLED);
        w.u16(0); // Reserved
        w.u32(0); // Capabilities
        w.bytes(&[0u8; 16]); // ClientGuid
        let dialects_end = 64 + 36 + dialects.len() * 2;
        let ctx_off = dialects_end.next_multiple_of(8);
        w.u32(if contexts.is_empty() {
            0
        } else {
            ctx_off as u32
        });
        w.u16(contexts.len() as u16);
        w.u16(0);
        for &d in dialects {
            w.u16(d);
        }
        for (ty, data) in contexts {
            w.zeros((8 - (64 + w.len()) % 8) % 8);
            w.u16(*ty);
            w.u16(data.len() as u16);
            w.u32(0);
            w.bytes(data);
        }
        w.into_vec()
    }

    pub(crate) fn preauth_ctx(salt: &[u8]) -> (u16, Vec<u8>) {
        let mut d = Writer::new();
        d.u16(1);
        d.u16(salt.len() as u16);
        d.u16(HASH_SHA512);
        d.bytes(salt);
        (ctx_type::PREAUTH_INTEGRITY, d.into_vec())
    }

    #[test]
    fn decodes_real_windows_negotiate_request() {
        // A NEGOTIATE request from the published Microsoft example (5 dialects,
        // PREAUTH SHA-512 + 32-byte salt, ENCRYPTION [GCM, CCM]).
        let pkt = unhex(NEGOTIATE_REQUEST);
        let msg = crate::Message::decode_single(&pkt).unwrap();
        let req = NegotiateReq::decode(&mut Reader::new(&msg.body)).unwrap();
        assert_eq!(req.dialects, vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
        let pre = req.contexts.preauth.as_ref().unwrap();
        assert_eq!(pre.hash_algorithms, vec![HASH_SHA512]);
        assert_eq!(pre.salt.len(), 32);
        assert_eq!(pre.salt[..4], [0xFA, 0x49, 0xE6, 0x57]);
        assert_eq!(req.contexts.ciphers, Some(vec![2, 1]));
        assert_eq!(req.select_dialect(), Some(Dialect::Smb311));
    }

    #[test]
    fn only_311_is_selected() {
        let body = build_negotiate_req(&[0x0202, 0x0210, 0x0300, 0x0302], &[]);
        let req = NegotiateReq::decode(&mut Reader::new(&body)).unwrap();
        assert_eq!(req.select_dialect(), None);
        let body = build_negotiate_req(&[0x0210, 0x0311], &[preauth_ctx(&[1; 32])]);
        let req = NegotiateReq::decode(&mut Reader::new(&body)).unwrap();
        assert_eq!(req.select_dialect(), Some(Dialect::Smb311));
        assert!(req.contexts.preauth.is_some());
    }

    #[test]
    fn unknown_dialect_has_no_common() {
        let body = build_negotiate_req(&[0x02FF], &[]);
        let req = NegotiateReq::decode(&mut Reader::new(&body)).unwrap();
        assert_eq!(req.select_dialect(), None);
    }

    #[test]
    fn malformed_requests_are_errors_not_panics() {
        assert!(NegotiateReq::decode(&mut Reader::new(&[])).is_err());
        let mut body = build_negotiate_req(&[0x0311], &[preauth_ctx(&[1; 32])]);
        body.truncate(body.len() - 10);
        assert!(NegotiateReq::decode(&mut Reader::new(&body)).is_err());
        // zero dialect count
        let mut body = build_negotiate_req(&[0x0311], &[]);
        body[2] = 0;
        assert!(NegotiateReq::decode(&mut Reader::new(&body)).is_err());
        // the context points into the header
        let mut body = build_negotiate_req(&[0x0311], &[preauth_ctx(&[1; 32])]);
        body[28..32].copy_from_slice(&10u32.to_le_bytes());
        assert!(NegotiateReq::decode(&mut Reader::new(&body)).is_err());
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_from_unix(0, 0), 116_444_736_000_000_000);
        assert_eq!(filetime_from_unix(1, 500), 116_444_736_010_000_005);
        assert!(filetime_now() > 133_000_000_000_000_000); // after 2022
    }

    fn resp(sec: Vec<u8>) -> Vec<u8> {
        let mut w = Writer::new();
        NegotiateResp {
            dialect_revision: 0x0311,
            server_guid: [7u8; 16],
            security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: 0x01D0_0000_0000_0000,
            security_buffer: sec,
            preauth_salt: vec![0xAB; 32],
        }
        .encode(&mut w);
        w.into_vec()
    }

    #[test]
    fn response_layout_with_contexts() {
        for sec_len in [0usize, 5, 8] {
            let body = resp(vec![0x60; sec_len]);
            let mut r = Reader::new(&body);
            assert_eq!(r.u16().unwrap(), 65);
            assert_eq!(r.u16().unwrap(), 3); // signing enabled|required
            assert_eq!(r.u16().unwrap(), 0x0311);
            assert_eq!(r.u16().unwrap(), 1); // context count
            r.skip(16 + 4 + 12).unwrap(); // guid, caps, max sizes
            assert_eq!(r.u64().unwrap(), 0x01D0_0000_0000_0000);
            assert_eq!(r.u64().unwrap(), 0); // ServerStartTime
            assert_eq!(r.u16().unwrap(), 128); // SecurityBufferOffset
            assert_eq!(r.u16().unwrap() as usize, sec_len);
            let ctx_off = r.u32().unwrap() as usize;
            assert_eq!(ctx_off % 8, 0);
            assert!(ctx_off >= 128 + sec_len);
            // the contexts are parsed by the same decoder as the client's
            let ctxs = NegotiateContexts::decode(&body, ctx_off - 64, 1).unwrap();
            let p = ctxs.preauth.unwrap();
            assert_eq!(p.hash_algorithms, vec![HASH_SHA512]);
            assert_eq!(p.salt, vec![0xAB; 32]);
        }
    }

    #[test]
    fn response_with_header_sets_server_flag() {
        let req_hdr = Header {
            credit_charge: 1,
            status: 0,
            command: Command::Negotiate,
            credit_req_grant: 1,
            flags: 0,
            next_command: 0,
            message_id: 0,
            tree_id: 0,
            async_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let mut w = Writer::new();
        Header::response_to(&req_hdr, 0).encode(&mut w);
        w.bytes(&resp(Vec::new()));
        let bytes = w.into_vec();
        let h = Header::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(h.flags & flags::SERVER_TO_REDIR, flags::SERVER_TO_REDIR);
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::ms_vectors::*;

    #[test]
    fn decodes_real_session_setup_requests() {
        let f = unhex(SS_REQUEST_1);
        let m = crate::Message::decode_single(&f).unwrap();
        let req = SessionSetupReq::decode(&mut Reader::new(&m.body)).unwrap();
        assert_eq!(req.flags & session_setup_flags::BINDING, 0);
        assert_eq!(req.previous_session_id, 0);
        assert_eq!(req.security_buffer.len(), 0x4A);
        assert_eq!(req.security_buffer[0], 0x60);

        let f = unhex(SS_REQUEST_2);
        let m = crate::Message::decode_single(&f).unwrap();
        let req = SessionSetupReq::decode(&mut Reader::new(&m.body)).unwrap();
        assert_eq!(req.security_buffer.len(), 0x1CF);
    }

    #[test]
    fn session_setup_decode_rejects_bad_buffers() {
        let f = unhex(SS_REQUEST_1);
        let m = crate::Message::decode_single(&f).unwrap();
        let mut body = m.body.clone();
        body.truncate(body.len() - 1);
        assert!(SessionSetupReq::decode(&mut Reader::new(&body)).is_err());
        let mut body = m.body.clone();
        body[12..14].copy_from_slice(&10u16.to_le_bytes()); // offset inside the header
        assert!(SessionSetupReq::decode(&mut Reader::new(&body)).is_err());
        assert!(SessionSetupReq::decode(&mut Reader::new(&[])).is_err());
    }

    #[test]
    fn session_setup_resp_layout() {
        let mut w = Writer::new();
        SessionSetupResp {
            session_flags: 0,
            security_buffer: vec![1, 2, 3],
        }
        .encode(&mut w);
        let b = w.into_vec();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 9);
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 72);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 3);
        assert_eq!(&b[8..], &[1, 2, 3]);
    }

    fn tree_connect_body(path: &str) -> Vec<u8> {
        let utf16: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut w = Writer::new();
        w.u16(9);
        w.u16(0);
        w.u16(72);
        w.u16(utf16.len() as u16);
        w.bytes(&utf16);
        w.into_vec()
    }

    #[test]
    fn tree_connect_path_roundtrip() {
        let body = tree_connect_body("\\\\127.0.0.1\\backup");
        let req = TreeConnectReq::decode(&mut Reader::new(&body)).unwrap();
        assert_eq!(req.path, "\\\\127.0.0.1\\backup");
        // Cyrillic and surrogates do not break parsing
        let body = tree_connect_body("\\\\h\\шара😀");
        assert_eq!(
            TreeConnectReq::decode(&mut Reader::new(&body))
                .unwrap()
                .path,
            "\\\\h\\шара😀"
        );
    }

    #[test]
    fn tree_connect_rejects_malformed() {
        let mut body = tree_connect_body("\\\\h\\s");
        body.truncate(body.len() - 2);
        assert!(TreeConnectReq::decode(&mut Reader::new(&body)).is_err());
        let mut body = tree_connect_body("\\\\h\\s");
        body[6] = 5; // odd length
        assert!(TreeConnectReq::decode(&mut Reader::new(&body)).is_err());
        // a lone surrogate
        let mut body = Writer::new();
        body.u16(9);
        body.u16(0);
        body.u16(72);
        body.u16(2);
        body.u16(0xD800);
        assert!(TreeConnectReq::decode(&mut Reader::new(&body.into_vec())).is_err());
    }

    #[test]
    fn tree_connect_resp_and_simple_bodies() {
        let mut w = Writer::new();
        TreeConnectResp {
            share_type: share_type::DISK,
            share_flags: share_flags::NO_CACHING,
            capabilities: 0,
            maximal_access: ACCESS_ALL,
        }
        .encode(&mut w);
        assert_eq!(w.len(), 16);
        let mut w = Writer::new();
        encode_simple_resp(&mut w);
        assert_eq!(w.into_vec(), vec![4, 0, 0, 0]);
        assert!(decode_simple_req(&mut Reader::new(&[4, 0, 0, 0])).is_ok());
        assert!(decode_simple_req(&mut Reader::new(&[5, 0, 0, 0])).is_err());
        assert!(decode_simple_req(&mut Reader::new(&[4])).is_err());
    }
}

#[cfg(test)]
mod smb1_tests {
    use super::*;

    /// An SMB1 NEGOTIATE as macOS sends it: a 32-byte header + dialects.
    fn smb1_negotiate(dialects: &[&str]) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&[0xFF, b'S', b'M', b'B', 0x72]);
        w.zeros(27); // status, flags, flags2, pid, signature, tid, pid, uid, mid
        w.u8(0); // WordCount
        let data: Vec<u8> = dialects
            .iter()
            .flat_map(|d| [&[0x02u8][..], d.as_bytes(), &[0u8][..]].concat())
            .collect();
        w.u16(data.len() as u16);
        w.bytes(&data);
        w.into_vec()
    }

    #[test]
    fn parses_macos_style_multiprotocol_negotiate() {
        let p = smb1_negotiate(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]);
        assert!(is_smb1(&p));
        let d = smb1_negotiate_dialects(&p).unwrap();
        assert_eq!(d, vec!["NT LM 0.12", "SMB 2.002", "SMB 2.???"]);
        assert_eq!(smb1_wildcard_revision(&d), Some(0x02FF));
    }

    #[test]
    fn wildcard_revision_choice() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(smb1_wildcard_revision(&v(&["SMB 2.002"])), Some(0x0202));
        assert_eq!(smb1_wildcard_revision(&v(&["NT LM 0.12"])), None);
        assert_eq!(smb1_wildcard_revision(&[]), None);
    }

    #[test]
    fn broken_smb1_packets_are_errors() {
        assert!(smb1_negotiate_dialects(&[]).is_err());
        assert!(smb1_negotiate_dialects(&[0xFF, b'S', b'M', b'B', 0x72]).is_err());
        let mut p = smb1_negotiate(&["SMB 2.???"]);
        p[4] = 0x73; // SESSION_SETUP_ANDX
        assert!(smb1_negotiate_dialects(&p).is_err());
        let mut p = smb1_negotiate(&["SMB 2.???"]);
        p.truncate(p.len() - 3);
        assert!(smb1_negotiate_dialects(&p).is_err());
        let mut p = smb1_negotiate(&["SMB 2.???"]);
        p[33] = 0x09; // no 0x02 marker
        assert!(smb1_negotiate_dialects(&p).is_err());
    }

    #[test]
    fn wildcard_response_has_no_negotiate_contexts() {
        let mut w = Writer::new();
        NegotiateResp {
            dialect_revision: 0x02FF,
            server_guid: [1; 16],
            security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: 5,
            security_buffer: vec![0x60, 0x00],
            preauth_salt: vec![],
        }
        .encode(&mut w);
        let b = w.into_vec();
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 0x02FF);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 0, "NegotiateContextCount");
        assert_eq!(
            u32::from_le_bytes(b[60..64].try_into().unwrap()),
            0,
            "ContextOffset"
        );
        assert_eq!(b.len(), 64 + 2);
    }
}
