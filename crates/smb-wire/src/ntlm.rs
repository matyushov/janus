//! Server side of NTLMv2 (MS-NLMP): NEGOTIATE → CHALLENGE → AUTHENTICATE.
//!
//! NTLMv2 with extended session security only; NTLMv1/LM responses are rejected.
//! Guest/anonymous logon is not supported. Pure functions over bytes:
//! randomness (the server challenge) and time come in as parameters.
//!
//! The MIC is verified if the client sent it (MsvAvFlags & 0x2, MS-NLMP §3.2.5.1.2),
//! but is not required: the integrity of the exchange in SMB 3.1.1 is additionally protected by
//! preauth integrity.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::{KeyInit, StreamCipher};
use subtle::ConstantTimeEq;

use crate::bytes::{Reader, Writer};

type HmacMd5 = Hmac<Md5>;

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

mod flag {
    pub const UNICODE: u32 = 0x0000_0001;
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    pub const SIGN: u32 = 0x0000_0010;
    pub const SEAL: u32 = 0x0000_0020;
    pub const NTLM: u32 = 0x0000_0200;
    pub const ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    pub const EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const TARGET_INFO: u32 = 0x0080_0000;
    pub const VERSION: u32 = 0x0200_0000;
    pub const BIT_128: u32 = 0x2000_0000;
    pub const KEY_EXCH: u32 = 0x4000_0000;
    pub const BIT_56: u32 = 0x8000_0000;
}

/// Flags the server always advertises; SIGN/SEAL/KEY_EXCH only on the client's request.
const SERVER_FLAGS: u32 = flag::UNICODE
    | flag::REQUEST_TARGET
    | flag::NTLM
    | flag::ALWAYS_SIGN
    | flag::TARGET_TYPE_SERVER
    | flag::EXTENDED_SESSIONSECURITY
    | flag::TARGET_INFO
    | flag::VERSION
    | flag::BIT_128
    | flag::BIT_56;
const CLIENT_DEPENDENT: u32 = flag::SIGN | flag::SEAL | flag::KEY_EXCH;

/// Version (6.3.9600, NTLMRevision 15), as Windows does.
const VERSION_FIELD: [u8; 8] = [6, 3, 0x80, 0x25, 0, 0, 0, 15];

const AV_EOL: u16 = 0;
const AV_NB_COMPUTER: u16 = 1;
const AV_NB_DOMAIN: u16 = 2;
const AV_FLAGS: u16 = 6;
const AV_TIMESTAMP: u16 = 7;
const AV_FLAG_MIC: u32 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtlmError {
    /// The message cannot be parsed / offsets are violated.
    Malformed(&'static str),
    /// The client uses something unsupported (NTLMv1, anonymous logon, ...).
    Unsupported(&'static str),
    /// Wrong user, password or MIC.
    AuthFailed,
}

impl std::fmt::Display for NtlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtlmError::Malformed(m) => write!(f, "malformed NTLM message: {m}"),
            NtlmError::Unsupported(m) => write!(f, "unsupported NTLM feature: {m}"),
            NtlmError::AuthFailed => write!(f, "NTLM authentication failed"),
        }
    }
}

impl std::error::Error for NtlmError {}

impl From<crate::WireError> for NtlmError {
    fn from(_: crate::WireError) -> Self {
        NtlmError::Malformed("truncated")
    }
}

/// Credentials: name and NT hash (the password is not kept in memory).
#[derive(Clone)]
pub struct Credentials {
    pub user: String,
    pub nt_hash: [u8; 16],
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    pub fn from_password(user: &str, password: &str) -> Self {
        Credentials {
            user: user.to_owned(),
            nt_hash: nt_hash(password),
        }
    }
}

/// Result of a completed NTLMSSP exchange: the key for deriving signing keys.
pub struct NtlmOutcome {
    pub session_key: [u8; 16],
    pub user: String,
}

impl std::fmt::Debug for NtlmOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtlmOutcome")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

/// NTOWFv1 = MD4(UNICODE(password)).
pub fn nt_hash(password: &str) -> [u8; 16] {
    Md4::digest(utf16le(password)).into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn from_utf16le(b: &[u8]) -> Result<String, NtlmError> {
    if !b.len().is_multiple_of(2) {
        return Err(NtlmError::Malformed("odd UTF-16 length"));
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| NtlmError::Malformed("bad UTF-16"))
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// NTOWFv2 = HMAC_MD5(NTOWFv1, UNICODE(Uppercase(User) + UserDom)).
fn ntowf_v2(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let ud = utf16le(&format!("{}{}", user.to_uppercase(), domain));
    hmac_md5(nt_hash, &[&ud])
}

/// Security buffer (Len, MaxLen, Offset) → a slice of the message.
fn sec_buf<'a>(msg: &'a [u8], r: &mut Reader<'_>) -> Result<&'a [u8], NtlmError> {
    let len = r.u16()? as usize;
    let _max = r.u16()?;
    let off = r.u32()? as usize;
    let end = off
        .checked_add(len)
        .ok_or(NtlmError::Malformed("buffer overflow"))?;
    msg.get(off..end)
        .ok_or(NtlmError::Malformed("buffer outside message"))
}

fn check_header(msg: &[u8], ty: u32) -> Result<Reader<'_>, NtlmError> {
    let mut r = Reader::new(msg);
    if r.take(8)? != SIGNATURE {
        return Err(NtlmError::Malformed("bad signature"));
    }
    if r.u32()? != ty {
        return Err(NtlmError::Malformed("unexpected message type"));
    }
    Ok(r)
}

/// CHALLENGE_MESSAGE parameters set by the server.
pub struct ChallengeParams<'a> {
    pub server_challenge: [u8; 8],
    /// Current time, FILETIME (MsvAvTimestamp).
    pub timestamp: u64,
    /// NetBIOS server/domain name for TargetName and the AV pairs.
    pub server_name: &'a str,
}

/// Server-side state between CHALLENGE and AUTHENTICATE.
pub struct NtlmServer {
    server_challenge: [u8; 8],
    negotiate_msg: Vec<u8>,
    challenge_msg: Vec<u8>,
    flags: u32,
}

impl NtlmServer {
    /// Parse NEGOTIATE_MESSAGE and build CHALLENGE_MESSAGE.
    /// Returns the state and the CHALLENGE bytes to send to the client.
    pub fn accept_negotiate(
        negotiate: &[u8],
        p: &ChallengeParams<'_>,
    ) -> Result<(NtlmServer, Vec<u8>), NtlmError> {
        let mut r = check_header(negotiate, 1)?;
        let client_flags = r.u32()?;
        if client_flags & flag::UNICODE == 0 {
            return Err(NtlmError::Unsupported("OEM-only client"));
        }
        if client_flags & flag::EXTENDED_SESSIONSECURITY == 0 {
            return Err(NtlmError::Unsupported("no extended session security"));
        }
        let flags = SERVER_FLAGS | (client_flags & CLIENT_DEPENDENT);

        let name = utf16le(p.server_name);
        let mut av = Writer::new();
        for (id, val) in [(AV_NB_DOMAIN, &name), (AV_NB_COMPUTER, &name)] {
            av.u16(id);
            av.u16(val.len() as u16);
            av.bytes(val);
        }
        av.u16(AV_TIMESTAMP);
        av.u16(8);
        av.u64(p.timestamp);
        av.u16(AV_EOL);
        av.u16(0);
        let av = av.into_vec();

        const FIXED: usize = 56;
        let mut w = Writer::new();
        w.bytes(SIGNATURE);
        w.u32(2);
        w.u16(name.len() as u16);
        w.u16(name.len() as u16);
        w.u32(FIXED as u32); // TargetName right after the fixed part
        w.u32(flags);
        w.bytes(&p.server_challenge);
        w.zeros(8);
        w.u16(av.len() as u16);
        w.u16(av.len() as u16);
        w.u32((FIXED + name.len()) as u32);
        w.bytes(&VERSION_FIELD);
        w.bytes(&name);
        w.bytes(&av);
        let challenge = w.into_vec();

        Ok((
            NtlmServer {
                server_challenge: p.server_challenge,
                negotiate_msg: negotiate.to_vec(),
                challenge_msg: challenge.clone(),
                flags,
            },
            challenge,
        ))
    }

    /// Verify AUTHENTICATE_MESSAGE and derive the ExportedSessionKey.
    pub fn authenticate(&self, auth: &[u8], creds: &Credentials) -> Result<NtlmOutcome, NtlmError> {
        let mut r = check_header(auth, 3)?;
        let _lm = sec_buf(auth, &mut r)?; // the LM response is ignored
        let nt_response = sec_buf(auth, &mut r)?;
        let domain = from_utf16le(sec_buf(auth, &mut r)?)?;
        let user = from_utf16le(sec_buf(auth, &mut r)?)?;
        let _workstation = sec_buf(auth, &mut r)?;
        let enc_session_key = sec_buf(auth, &mut r)?;
        let flags = r.u32()?;

        if user.is_empty() {
            return Err(NtlmError::Unsupported("anonymous logon"));
        }
        if flags & flag::UNICODE == 0 || flags & flag::EXTENDED_SESSIONSECURITY == 0 {
            return Err(NtlmError::Unsupported("AUTHENTICATE flags"));
        }
        // the client cannot enable KEY_EXCH/SIGN/SEAL that we did not advertise
        if flags & CLIENT_DEPENDENT & !self.flags != 0 {
            return Err(NtlmError::Malformed("flags outside CHALLENGE"));
        }
        // NTLMv2: NTProofStr(16) + blob (>= 28 bytes + AV pairs); 24 bytes means NTLMv1
        if nt_response.len() <= 24 {
            return Err(NtlmError::Unsupported("NTLMv1"));
        }
        if nt_response.len() < 16 + 28 {
            return Err(NtlmError::Malformed("NT response too short"));
        }
        let (proof, temp) = nt_response.split_at(16);

        // The user is checked without disclosing the reason for the refusal to the caller.
        let user_ok = user.to_uppercase() == creds.user.to_uppercase();
        let key = ntowf_v2(&creds.nt_hash, &user, &domain);
        let expected = hmac_md5(&key, &[&self.server_challenge, temp]);
        let proof_ok: bool = expected.ct_eq(proof).into();
        if !(user_ok && proof_ok) {
            return Err(NtlmError::AuthFailed);
        }

        let key_exchange_key = hmac_md5(&key, &[proof]); // SessionBaseKey
        let exported: [u8; 16] = if flags & flag::KEY_EXCH != 0 {
            let enc: [u8; 16] = enc_session_key
                .try_into()
                .map_err(|_| NtlmError::Malformed("EncryptedRandomSessionKey != 16"))?;
            let mut k = enc;
            rc4::Rc4::<rc4::consts::U16>::new((&key_exchange_key).into()).apply_keystream(&mut k);
            k
        } else {
            key_exchange_key
        };

        // MIC (if the client sent it) covers the three messages of the exchange.
        if av_flags(&temp[28..]) & AV_FLAG_MIC != 0 {
            const MIC_OFFSET: usize = 72;
            let mut r = Reader::new(auth);
            r.seek(MIC_OFFSET)?;
            let mic: [u8; 16] = r.array::<16>()?;
            let mut zeroed = auth.to_vec();
            zeroed[MIC_OFFSET..MIC_OFFSET + 16].fill(0);
            let calc = hmac_md5(
                &exported,
                &[&self.negotiate_msg, &self.challenge_msg, &zeroed],
            );
            if !bool::from(calc.ct_eq(&mic)) {
                return Err(NtlmError::AuthFailed);
            }
        }

        Ok(NtlmOutcome {
            session_key: exported,
            user: creds.user.clone(),
        })
    }
}

/// Value of MsvAvFlags from the list of AV pairs (0 if absent / the list is broken).
fn av_flags(mut av: &[u8]) -> u32 {
    while av.len() >= 4 {
        let id = u16::from_le_bytes([av[0], av[1]]);
        let len = u16::from_le_bytes([av[2], av[3]]) as usize;
        let Some(val) = av.get(4..4 + len) else {
            return 0;
        };
        if id == AV_FLAGS && len == 4 {
            return u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
        }
        if id == AV_EOL {
            return 0;
        }
        av = &av[4 + len..];
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SpnegoToken;
    use crate::ms_vectors::*;

    /// NTLM token from the SecurityBuffer of a Microsoft SESSION_SETUP frame via the SPNEGO parser
    /// (`sec_buf_at`: offset of SecurityBufferOffset in the body: 12 for a request, 4 for a response).
    fn ntlm_token(frame_hex: &str, sec_buf_at: usize) -> Vec<u8> {
        let f = unhex(frame_hex);
        let off = u16::from_le_bytes([f[64 + sec_buf_at], f[64 + sec_buf_at + 1]]) as usize;
        let len = u16::from_le_bytes([f[64 + sec_buf_at + 2], f[64 + sec_buf_at + 3]]) as usize;
        SpnegoToken::parse(&f[off..off + len])
            .unwrap()
            .ntlm_token()
            .to_vec()
    }

    fn ms_negotiate() -> Vec<u8> {
        ntlm_token(SS_REQUEST_1, 12)
    }
    fn ms_authenticate() -> Vec<u8> {
        ntlm_token(SS_REQUEST_2, 12)
    }

    fn server_from_ms_trace() -> NtlmServer {
        NtlmServer {
            server_challenge: unhex(NTLM_SERVER_CHALLENGE).try_into().unwrap(),
            negotiate_msg: ms_negotiate(),
            challenge_msg: ntlm_token(SS_RESPONSE_1, 4),
            flags: SERVER_FLAGS | CLIENT_DEPENDENT,
        }
    }

    fn creds() -> Credentials {
        Credentials::from_password(NTLM_USER, NTLM_PASSWORD)
    }

    #[test]
    fn nt_hash_matches_microsoft_vector() {
        assert_eq!(
            nt_hash(NTLM_PASSWORD).to_vec(),
            unhex("7C4FE5EADA682714A036E39378362BAB")
        );
    }

    #[test]
    fn ntowf_v2_matches_microsoft_vector() {
        let h = ntowf_v2(&nt_hash(NTLM_PASSWORD), NTLM_USER, "SUT311");
        assert_eq!(h.to_vec(), unhex("AEE3959B44A815F1EB28C9511B4F533B"));
    }

    #[test]
    fn authenticate_reproduces_microsoft_exported_session_key_with_mic() {
        // The real AUTHENTICATE from the Microsoft example: NTProofStr, the RC4 key exchange
        // and the MIC (the client sent MsvAvFlags=0x2) are all verified.
        let out = server_from_ms_trace()
            .authenticate(&ms_authenticate(), &creds())
            .expect("auth ok");
        assert_eq!(out.session_key.to_vec(), unhex(SESSION_KEY));
        assert_eq!(out.user, NTLM_USER);
    }

    #[test]
    fn wrong_password_or_user_is_auth_failed() {
        let srv = server_from_ms_trace();
        let auth = ms_authenticate();
        let bad_pw = Credentials::from_password(NTLM_USER, "password01!");
        assert_eq!(
            srv.authenticate(&auth, &bad_pw).unwrap_err(),
            NtlmError::AuthFailed
        );
        let bad_user = Credentials::from_password("someone", NTLM_PASSWORD);
        assert_eq!(
            srv.authenticate(&auth, &bad_user).unwrap_err(),
            NtlmError::AuthFailed
        );
    }

    #[test]
    fn user_name_is_case_insensitive() {
        // in the trace the client sent "administrator", the config has a different case
        let c = Credentials::from_password("Administrator", NTLM_PASSWORD);
        assert!(
            server_from_ms_trace()
                .authenticate(&ms_authenticate(), &c)
                .is_ok()
        );
    }

    #[test]
    fn tampered_mic_or_challenge_is_rejected() {
        let auth = ms_authenticate();

        let mut bad_mic = auth.clone();
        bad_mic[72] ^= 1;
        assert_eq!(
            server_from_ms_trace()
                .authenticate(&bad_mic, &creds())
                .unwrap_err(),
            NtlmError::AuthFailed
        );

        // substituting the CHALLENGE the server saw breaks the MIC
        let mut srv = server_from_ms_trace();
        let n = srv.challenge_msg.len();
        srv.challenge_msg[n - 1] ^= 1;
        assert_eq!(
            srv.authenticate(&auth, &creds()).unwrap_err(),
            NtlmError::AuthFailed
        );

        // substituting the NEGOTIATE does too
        let mut srv = server_from_ms_trace();
        srv.negotiate_msg[20] ^= 1;
        assert_eq!(
            srv.authenticate(&auth, &creds()).unwrap_err(),
            NtlmError::AuthFailed
        );

        // a different server challenge breaks NTProofStr
        let mut srv = server_from_ms_trace();
        srv.server_challenge[0] ^= 1;
        assert_eq!(
            srv.authenticate(&auth, &creds()).unwrap_err(),
            NtlmError::AuthFailed
        );
    }

    #[test]
    fn truncated_and_garbage_messages_do_not_panic() {
        let srv = server_from_ms_trace();
        let auth = ms_authenticate();
        for n in 0..auth.len() {
            assert!(srv.authenticate(&auth[..n], &creds()).is_err(), "len {n}");
        }
        let p = ChallengeParams {
            server_challenge: [0; 8],
            timestamp: 0,
            server_name: "J",
        };
        let neg = ms_negotiate();
        // the server does not read NEGOTIATE's domain buffers: shorter than 16 bytes (signature+type+flags) is an error
        for n in 0..16 {
            assert!(
                NtlmServer::accept_negotiate(&neg[..n], &p).is_err(),
                "len {n}"
            );
        }
    }

    #[test]
    fn anonymous_user_is_rejected() {
        let mut auth = ms_authenticate();
        // UserName security buffer (offset 36): Len = 0
        auth[36] = 0;
        auth[37] = 0;
        assert!(matches!(
            server_from_ms_trace().authenticate(&auth, &creds()),
            Err(NtlmError::Unsupported(_))
        ));
    }

    #[test]
    fn ntlmv1_response_is_rejected() {
        let mut auth = ms_authenticate();
        // NtChallengeResponse security buffer (offset 20): Len = 24
        auth[20] = 24;
        auth[21] = 0;
        assert!(matches!(
            server_from_ms_trace().authenticate(&auth, &creds()),
            Err(NtlmError::Unsupported(_))
        ));
    }

    #[test]
    fn negotiate_to_challenge_has_expected_shape() {
        let p = ChallengeParams {
            server_challenge: [9; 8],
            timestamp: 0x01D0_0000_0000_0000,
            server_name: "JANUS",
        };
        let (_srv, ch) = NtlmServer::accept_negotiate(&ms_negotiate(), &p).unwrap();
        assert_eq!(&ch[..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(ch[8..12].try_into().unwrap()), 2);
        assert_eq!(&ch[24..32], &[9; 8]);
        let flags = u32::from_le_bytes(ch[20..24].try_into().unwrap());
        for f in [
            flag::UNICODE,
            flag::NTLM,
            flag::EXTENDED_SESSIONSECURITY,
            flag::TARGET_INFO,
            flag::KEY_EXCH,
        ] {
            assert_ne!(flags & f, 0, "flag {f:#x}");
        }
        // TargetInfo lies inside the message and ends with EOL
        let ti_len = u16::from_le_bytes(ch[40..42].try_into().unwrap()) as usize;
        let ti_off = u32::from_le_bytes(ch[44..48].try_into().unwrap()) as usize;
        assert_eq!(ti_off + ti_len, ch.len());
        assert_eq!(&ch[ch.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn negotiate_without_extended_security_is_unsupported() {
        let mut neg = ms_negotiate();
        let f =
            u32::from_le_bytes(neg[12..16].try_into().unwrap()) & !flag::EXTENDED_SESSIONSECURITY;
        neg[12..16].copy_from_slice(&f.to_le_bytes());
        let p = ChallengeParams {
            server_challenge: [0; 8],
            timestamp: 0,
            server_name: "J",
        };
        assert!(matches!(
            NtlmServer::accept_negotiate(&neg, &p),
            Err(NtlmError::Unsupported(_))
        ));
    }
}
