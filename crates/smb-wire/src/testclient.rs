//! A test SMB 3.1.1 client built on the same primitives as the server: an NTLMv2 client,
//! frame builders and a handshake driver (NEGOTIATE → SESSION_SETUP ×2 → signature).
//! Used by the dispatcher unit tests and the smb-core end-to-end test; not used in production.
//! It also checks codec symmetry: the client builds what the server parses.

use hmac::{Hmac, Mac};
use md5::Md5;
use rc4::{KeyInit, StreamCipher};

use crate::auth::{NegState, OID_NTLMSSP, SpnegoToken};
use crate::bytes::{Reader, Writer};
use crate::crypto;
use crate::header::{Header, flags};
use crate::messages::{HASH_SHA512, ctx_type, security_mode};
use crate::ntlm::nt_hash;
use crate::{Command, Message};

type HmacMd5 = Hmac<Md5>;

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <HmacMd5 as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// An SMB1 multi-protocol NEGOTIATE as macOS sends it (32-byte header + dialects).
pub fn smb1_negotiate(dialects: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&[0xFF, b'S', b'M', b'B', 0x72]);
    w.zeros(27);
    w.u8(0); // WordCount
    let data: Vec<u8> = dialects
        .iter()
        .flat_map(|d| [&[0x02u8][..], d.as_bytes(), &[0u8][..]].concat())
        .collect();
    w.u16(data.len() as u16);
    w.bytes(&data);
    w.into_vec()
}

// --- NTLMv2 client --------------------------------------------------

pub fn ntlm_negotiate_message() -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"NTLMSSP\0");
    w.u32(1);
    // UNICODE|REQUEST_TARGET|SIGN|NTLM|ALWAYS_SIGN|EXTENDED|VERSION|128|KEY_EXCH|56
    w.u32(0xE288_8215);
    w.zeros(16); // domain/workstation: empty
    w.bytes(&[6, 3, 0x80, 0x25, 0, 0, 0, 15]);
    w.into_vec()
}

/// Client parameters for AUTHENTICATE.
pub struct NtlmClientParams<'a> {
    pub user: &'a str,
    pub domain: &'a str,
    pub password: &'a str,
    pub client_challenge: [u8; 8],
    /// ExportedSessionKey, random for a real client.
    pub exported_session_key: [u8; 16],
}

/// Build AUTHENTICATE_MESSAGE (NTLMv2, KEY_EXCH, MIC) in reply to a CHALLENGE.
/// Returns the message and the ExportedSessionKey.
pub fn ntlm_authenticate_message(
    negotiate: &[u8],
    challenge: &[u8],
    p: &NtlmClientParams<'_>,
) -> Result<Vec<u8>, &'static str> {
    if challenge.len() < 56 || &challenge[..8] != b"NTLMSSP\0" {
        return Err("bad challenge");
    }
    let server_challenge: [u8; 8] = challenge[24..32].try_into().unwrap();
    let ti_len = u16::from_le_bytes([challenge[40], challenge[41]]) as usize;
    let ti_off = u32::from_le_bytes(challenge[44..48].try_into().unwrap()) as usize;
    let target_info = challenge
        .get(ti_off..ti_off + ti_len)
        .ok_or("bad target info")?;

    // AV pairs: take the ones received (without EOL), look for the Timestamp, add MsvAvFlags=MIC and EOL
    let mut av = Vec::new();
    let mut timestamp = [0u8; 8];
    let mut rest = target_info;
    while rest.len() >= 4 {
        let id = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        let val = rest.get(4..4 + len).ok_or("bad av")?;
        if id == 0 {
            break;
        }
        if id == 7 && len == 8 {
            timestamp.copy_from_slice(val);
        }
        av.extend_from_slice(&rest[..4 + len]);
        rest = &rest[4 + len..];
    }
    av.extend_from_slice(&[6, 0, 4, 0, 2, 0, 0, 0]); // MsvAvFlags = 0x2 (MIC)
    av.extend_from_slice(&[0, 0, 0, 0]); // EOL

    let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
    temp.extend_from_slice(&timestamp);
    temp.extend_from_slice(&p.client_challenge);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(&av);
    temp.extend_from_slice(&[0; 4]);

    let ntowf = hmac_md5(
        &nt_hash(p.password),
        &[&utf16le(&format!("{}{}", p.user.to_uppercase(), p.domain))],
    );
    let proof = hmac_md5(&ntowf, &[&server_challenge, &temp]);
    let session_base_key = hmac_md5(&ntowf, &[&proof]);
    let mut enc_key = p.exported_session_key;
    rc4::Rc4::<rc4::consts::U16>::new((&session_base_key).into()).apply_keystream(&mut enc_key);

    let mut nt_response = proof.to_vec();
    nt_response.extend_from_slice(&temp);
    let lm_response = [0u8; 24];

    let domain = utf16le(p.domain);
    let user = utf16le(p.user);
    let workstation = utf16le("CLIENT");
    // Fixed part of 88 bytes (with Version and MIC), then the payload.
    let mut off = 88u32;
    let mut w = Writer::new();
    w.bytes(b"NTLMSSP\0");
    w.u32(3);
    let mut payload = Vec::new();
    for field in [
        &lm_response[..],
        &nt_response[..],
        &domain[..],
        &user[..],
        &workstation[..],
        &enc_key[..],
    ] {
        w.u16(field.len() as u16);
        w.u16(field.len() as u16);
        w.u32(off);
        off += field.len() as u32;
        payload.extend_from_slice(field);
    }
    w.u32(0xE288_8215);
    w.bytes(&[6, 3, 0x80, 0x25, 0, 0, 0, 15]);
    w.zeros(16); // MIC
    w.bytes(&payload);
    let mut msg = w.into_vec();
    let mic = hmac_md5(&p.exported_session_key, &[negotiate, challenge, &msg]);
    msg[72..88].copy_from_slice(&mic);
    Ok(msg)
}

// --- Frames ---------------------------------------------------------

pub fn request_header(command: Command, message_id: u64, session_id: u64, tree_id: u32) -> Header {
    Header {
        credit_charge: 1,
        status: 0,
        command,
        credit_req_grant: 16,
        flags: 0,
        next_command: 0,
        message_id,
        tree_id,
        async_id: 0,
        session_id,
        signature: [0; 16],
    }
}

/// Frame = header + body.
pub fn frame(h: &Header, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    h.encode(&mut w);
    w.bytes(body);
    w.into_vec()
}

/// Sign a frame (set SIGNED and the signature).
pub fn sign_frame(frame: &mut [u8], key: &[u8; 16]) {
    let f = u32::from_le_bytes(frame[16..20].try_into().unwrap()) | flags::SIGNED;
    frame[16..20].copy_from_slice(&f.to_le_bytes());
    let sig = crypto::sign_cmac(key, frame);
    frame[48..64].copy_from_slice(&sig);
}

pub fn negotiate_body(dialects: &[u16], with_preauth: bool, salt: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(36);
    w.u16(dialects.len() as u16);
    w.u16(security_mode::SIGNING_ENABLED);
    w.u16(0);
    w.u32(0);
    w.bytes(&[0x42; 16]);
    let ctx_off = (64 + 36 + dialects.len() * 2).next_multiple_of(8);
    w.u32(if with_preauth { ctx_off as u32 } else { 0 });
    w.u16(with_preauth as u16);
    w.u16(0);
    for &d in dialects {
        w.u16(d);
    }
    if with_preauth {
        w.zeros(ctx_off - (64 + 36 + dialects.len() * 2));
        w.u16(ctx_type::PREAUTH_INTEGRITY);
        w.u16((6 + salt.len()) as u16);
        w.u32(0);
        w.u16(1);
        w.u16(salt.len() as u16);
        w.u16(HASH_SHA512);
        w.bytes(salt);
    }
    w.into_vec()
}

pub fn session_setup_body(token: &[u8], flags: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(25);
    w.u8(flags);
    w.u8(security_mode::SIGNING_ENABLED as u8);
    w.u32(0);
    w.u32(0);
    w.u16(88); // 64 header + 24 fixed part of the request
    w.u16(token.len() as u16);
    w.u64(0);
    w.bytes(token);
    w.into_vec()
}

pub fn tree_connect_body(path: &str) -> Vec<u8> {
    let p = utf16le(path);
    let mut w = Writer::new();
    w.u16(9);
    w.u16(0);
    w.u16(72);
    w.u16(p.len() as u16);
    w.bytes(&p);
    w.into_vec()
}

/// CREATE body: path, disposition, options, optionally the MxAc context.
pub fn create_body(path: &str, disposition: u32, options: u32, mxac: bool) -> Vec<u8> {
    create_body_ex(path, 0x0010_0080, 0x10, disposition, options, mxac)
}

/// CREATE body with explicit access mask and file attributes.
pub fn create_body_ex(
    path: &str,
    access: u32,
    attributes: u32,
    disposition: u32,
    options: u32,
    mxac: bool,
) -> Vec<u8> {
    let name = utf16le(path);
    let mut w = Writer::new();
    w.u16(57);
    w.u8(0);
    w.u8(0);
    w.u32(2); // Impersonation
    w.zeros(16);
    w.u32(access); // DesiredAccess
    w.u32(attributes);
    w.u32(7);
    w.u32(disposition);
    w.u32(options);
    let name_off = 64 + 56;
    w.u16(name_off as u16);
    w.u16(name.len() as u16);
    let ctx_off = (name_off + name.len().max(1)).next_multiple_of(8);
    w.u32(if mxac { ctx_off as u32 } else { 0 });
    w.u32(if mxac { 24 } else { 0 });
    w.bytes(&name);
    if name.is_empty() {
        w.zeros(1); // the buffer is at least 1 byte (StructureSize 57)
    }
    if mxac {
        let pos = 64 + w.len();
        w.zeros(ctx_off - pos);
        w.u32(0);
        w.u16(16);
        w.u16(4);
        w.u16(0);
        w.u16(0);
        w.u32(0);
        w.bytes(b"MxAc");
        w.zeros(4);
    }
    w.into_vec()
}

/// READ body (no channel).
pub fn read_body(file_id: [u8; 16], length: u32, offset: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(49);
    w.u8(0x50);
    w.u8(0);
    w.u32(length);
    w.u64(offset);
    w.bytes(&file_id);
    w.u32(0); // MinimumCount
    w.u32(0); // Channel
    w.u32(0); // RemainingBytes
    w.u16(0);
    w.u16(0);
    w.u8(0); // Buffer
    w.into_vec()
}

/// WRITE body; data right after the 48 fixed bytes (offset 112).
pub fn write_body(file_id: [u8; 16], offset: u64, data: &[u8], write_flags: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(49);
    w.u16(112);
    w.u32(data.len() as u32);
    w.u64(offset);
    w.bytes(&file_id);
    w.u32(0); // Channel
    w.u32(0); // RemainingBytes
    w.u16(0);
    w.u16(0);
    w.u32(write_flags);
    w.bytes(data);
    w.into_vec()
}

/// FLUSH body; `fullfsync` sets Apple's Reserved1 = 0xFFFF.
pub fn flush_body(file_id: [u8; 16], fullfsync: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(24);
    w.u16(if fullfsync { 0xFFFF } else { 0 });
    w.u32(0);
    w.bytes(&file_id);
    w.into_vec()
}

/// SET_INFO body for InfoType FILE.
pub fn set_info_body(class: u8, file_id: [u8; 16], buffer: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(33);
    w.u8(0x01);
    w.u8(class);
    w.u32(buffer.len() as u32);
    w.u16(96);
    w.u16(0);
    w.u32(0);
    w.bytes(&file_id);
    w.bytes(buffer);
    w.into_vec()
}

/// FileRenameInformation payload (class 10).
pub fn rename_info(target: &str, replace: bool) -> Vec<u8> {
    let name = utf16le(target);
    let mut w = Writer::new();
    w.u8(replace as u8);
    w.zeros(7);
    w.u64(0);
    w.u32(name.len() as u32);
    w.bytes(&name);
    w.into_vec()
}

/// FileEndOfFileInformation payload (class 20).
pub fn eof_info(len: u64) -> Vec<u8> {
    len.to_le_bytes().to_vec()
}

/// FileDispositionInformation payload (class 13).
pub fn disposition_info(delete: bool) -> Vec<u8> {
    vec![delete as u8]
}

/// FileBasicInformation payload (class 4): only access and write times are set.
pub fn basic_info(accessed: u64, written: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(0);
    w.u64(accessed);
    w.u64(written);
    w.u64(0);
    w.u32(0);
    w.u32(0);
    w.into_vec()
}

pub fn query_info_body(info_type: u8, class: u8, out_len: u32, file_id: [u8; 16]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(41);
    w.u8(info_type);
    w.u8(class);
    w.u32(out_len);
    w.u16(0);
    w.u16(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.bytes(&file_id);
    w.into_vec()
}

pub fn close_body(file_id: [u8; 16]) -> Vec<u8> {
    close_body_ex(file_id, 0)
}

/// CLOSE body with flags (1 = return attributes).
pub fn close_body_ex(file_id: [u8; 16], flags: u16) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(24);
    w.u16(flags);
    w.u32(0);
    w.bytes(&file_id);
    w.into_vec()
}

pub fn query_directory_body(file_id: [u8; 16]) -> Vec<u8> {
    query_directory_body_ex(file_id, 1, 0, "*", 65536)
}

/// QUERY_DIRECTORY body.
pub fn query_directory_body_ex(
    file_id: [u8; 16],
    class: u8,
    flags: u8,
    pattern: &str,
    out_len: u32,
) -> Vec<u8> {
    let p = utf16le(pattern);
    let mut w = Writer::new();
    w.u16(33);
    w.u8(class);
    w.u8(flags);
    w.u32(0);
    w.bytes(&file_id);
    w.u16(96);
    w.u16(p.len() as u16);
    w.u32(out_len);
    w.bytes(&p);
    w.into_vec()
}

/// Names from a QUERY_DIRECTORY reply body of the given FileInformationClass.
pub fn dir_entry_names(body: &[u8], class: u8) -> Vec<String> {
    let len = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    let buf = &body[8..8 + len];
    let (len_at, name_at) = match class {
        1 => (60, 64),
        2 => (60, 68),
        3 => (60, 94),
        12 => (8, 12),
        37 => (60, 104),
        38 => (60, 80),
        _ => panic!("not a directory class"),
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let e = &buf[at..];
        let nl = u32::from_le_bytes(e[len_at..len_at + 4].try_into().unwrap()) as usize;
        let next = u32::from_le_bytes(e[0..4].try_into().unwrap()) as usize;
        let units: Vec<u16> = e[name_at..name_at + nl]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16(&units).unwrap());
        if next == 0 {
            return out;
        }
        at += next;
    }
}

/// FileId from a CREATE reply body.
pub fn create_reply_file_id(body: &[u8]) -> [u8; 16] {
    body[64..80].try_into().unwrap()
}

/// Data from a READ reply body.
pub fn read_reply_data(body: &[u8]) -> Vec<u8> {
    let len = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    let off = body[2] as usize - 64;
    body[off..off + len].to_vec()
}

pub fn simple_body() -> Vec<u8> {
    vec![4, 0, 0, 0]
}

/// A parsed server reply.
#[derive(Debug)]
pub struct Response {
    pub raw: Vec<u8>,
    pub message: Message,
}

impl Response {
    pub fn parse(raw: &[u8]) -> Result<Response, crate::WireError> {
        Ok(Response {
            raw: raw.to_vec(),
            message: Message::decode_single(raw)?,
        })
    }
    pub fn status(&self) -> u32 {
        self.message.header.status
    }
    pub fn header(&self) -> &Header {
        &self.message.header
    }
    /// The SecurityBuffer from the body of a SESSION_SETUP reply.
    pub fn session_setup_token(&self) -> Vec<u8> {
        let b = &self.message.body;
        let off = u16::from_le_bytes([b[4], b[5]]) as usize - 64;
        let len = u16::from_le_bytes([b[6], b[7]]) as usize;
        b[off..off + len].to_vec()
    }
}

/// Cuts a chain (compound) of replies by NextCommand.
pub fn split_compound(mut buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    loop {
        let next = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
        if next == 0 {
            out.push(buf);
            return out;
        }
        out.push(&buf[..next]);
        buf = &buf[next..];
    }
}

// --- Handshake driver -----------------------------------------------

/// State of a 3.1.1 client: accumulates the preauth hash and derives the signing key exactly as
/// the server does, but from the client side of the wire.
pub struct Client {
    pub user: String,
    pub password: String,
    pub domain: String,
    pub preauth_hash: [u8; 64],
    pub session_id: u64,
    pub signing_key: Option<[u8; 16]>,
    pub message_id: u64,
    negotiate_ntlm: Vec<u8>,
    challenge_ntlm: Vec<u8>,
    pub exported_session_key: [u8; 16],
}

impl Client {
    pub fn new(user: &str, password: &str) -> Client {
        Client {
            user: user.into(),
            password: password.into(),
            domain: "WORKGROUP".into(),
            preauth_hash: [0; 64],
            session_id: 0,
            signing_key: None,
            message_id: 0,
            negotiate_ntlm: Vec::new(),
            challenge_ntlm: Vec::new(),
            exported_session_key: [0x55; 16],
        }
    }

    pub fn next_message_id(&mut self) -> u64 {
        self.next_id()
    }

    fn next_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }

    pub fn negotiate_request(&mut self) -> Vec<u8> {
        let h = request_header(Command::Negotiate, self.next_id(), 0, 0);
        let f = frame(
            &h,
            &negotiate_body(&[0x0202, 0x0210, 0x0300, 0x0302, 0x0311], true, &[0xAB; 32]),
        );
        self.preauth_hash = crypto::preauth_chain(&self.preauth_hash, &f);
        f
    }

    pub fn on_negotiate_response(&mut self, resp: &[u8]) {
        self.preauth_hash = crypto::preauth_chain(&self.preauth_hash, resp);
    }

    pub fn session_setup_1(&mut self) -> Vec<u8> {
        self.negotiate_ntlm = ntlm_negotiate_message();
        let token = SpnegoToken::NegTokenInit {
            mech_types: vec![OID_NTLMSSP.to_vec()],
            mech_token: self.negotiate_ntlm.clone(),
        }
        .build();
        let h = request_header(Command::SessionSetup, self.next_id(), 0, 0);
        let f = frame(&h, &session_setup_body(&token, 0));
        self.preauth_hash = crypto::preauth_chain(&self.preauth_hash, &f);
        f
    }

    /// Parse the MORE_PROCESSING reply and build the second SESSION_SETUP.
    pub fn session_setup_2(&mut self, resp: &[u8]) -> Result<Vec<u8>, String> {
        let r = Response::parse(resp).map_err(|e| e.to_string())?;
        if r.status() != 0xC000_0016 {
            return Err(format!(
                "expected MORE_PROCESSING, status {:#x}",
                r.status()
            ));
        }
        self.preauth_hash = crypto::preauth_chain(&self.preauth_hash, resp);
        self.session_id = r.header().session_id;
        let token = SpnegoToken::parse(&r.session_setup_token()).map_err(|e| e.to_string())?;
        match &token {
            SpnegoToken::NegTokenResp {
                neg_state: Some(NegState::AcceptIncomplete),
                ..
            } => {}
            other => return Err(format!("unexpected SPNEGO: {other:?}")),
        }
        self.challenge_ntlm = token.ntlm_token().to_vec();
        let auth = ntlm_authenticate_message(
            &self.negotiate_ntlm,
            &self.challenge_ntlm,
            &NtlmClientParams {
                user: &self.user,
                domain: &self.domain,
                password: &self.password,
                client_challenge: [0x11; 8],
                exported_session_key: self.exported_session_key,
            },
        )?;
        let token = SpnegoToken::NegTokenResp {
            neg_state: None,
            supported_mech: None,
            response_token: auth,
        }
        .build();
        let h = request_header(Command::SessionSetup, self.next_id(), self.session_id, 0);
        let f = frame(&h, &session_setup_body(&token, 0));
        self.preauth_hash = crypto::preauth_chain(&self.preauth_hash, &f);
        // the signing key is derived from the hash as of after the second request
        self.signing_key = Some(crypto::signing_key_311(
            &self.exported_session_key,
            &self.preauth_hash,
        ));
        Ok(f)
    }

    /// A signed request after the session is established.
    pub fn signed_request(&mut self, command: Command, tree_id: u32, body: &[u8]) -> Vec<u8> {
        self.signed_request_charged(command, tree_id, body, 1)
    }

    /// Like `signed_request`, with an explicit CreditCharge (multi-credit READ/WRITE).
    pub fn signed_request_charged(
        &mut self,
        command: Command,
        tree_id: u32,
        body: &[u8],
        credit_charge: u16,
    ) -> Vec<u8> {
        let mut h = request_header(command, self.next_id(), self.session_id, tree_id);
        h.credit_charge = credit_charge;
        let mut f = frame(&h, body);
        sign_frame(&mut f, &self.signing_key.expect("session not established"));
        f
    }

    /// Verify the signature of a server reply.
    pub fn verify_response(&self, resp: &[u8]) -> bool {
        let r = Response::parse(resp).unwrap();
        let key = self.signing_key.expect("session not established");
        r.header().flags & flags::SIGNED != 0 && crypto::verify(&key, resp, &r.header().signature)
    }
}

/// Read a u16 at an offset (for structural checks in tests).
pub fn read_u16_at(b: &[u8], at: usize) -> u16 {
    Reader::new(&b[at..]).u16().unwrap()
}
