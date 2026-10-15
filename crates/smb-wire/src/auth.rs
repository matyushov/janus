//! SPNEGO tokens of SESSION_SETUP (RFC 4178, DER) and the entry into NTLMSSP.
//! The NTLM server is in `ntlm` (`sspi` was evaluated and rejected, see Cargo.toml); here only
//! SPNEGO parsing/building. The multi-leg exchange is coordinated by smb-core.

use crate::WireError;

pub use crate::ntlm::NtlmOutcome;

/// SPNEGO OID 1.3.6.1.5.5.2 (content, without tag/length).
const OID_SPNEGO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// OID NTLMSSP 1.3.6.1.4.1.311.2.2.10.
pub const OID_NTLMSSP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

const TAG_APPLICATION_0: u8 = 0x60;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0A;
const TAG_CTX_0: u8 = 0xA0;
const TAG_CTX_1: u8 = 0xA1;
const TAG_CTX_2: u8 = 0xA2;

/// negState in NegTokenResp (RFC 4178 §4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
    RequestMic = 3,
}

/// A parsed SPNEGO token from SESSION_SETUP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpnegoToken {
    /// `mech_types` are OIDs (content). `mech_token` is empty if absent.
    NegTokenInit {
        mech_types: Vec<Vec<u8>>,
        mech_token: Vec<u8>,
    },
    /// `response_token` is empty if absent.
    NegTokenResp {
        neg_state: Option<NegState>,
        supported_mech: Option<Vec<u8>>,
        response_token: Vec<u8>,
    },
}

/// One DER TLV: (tag, content, the rest after it).
fn tlv(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), WireError> {
    let tag = *buf.first().ok_or(WireError::Truncated)?;
    let l0 = *buf.get(1).ok_or(WireError::Truncated)?;
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(WireError::Malformed("DER: unsupported length"));
        }
        let bytes = buf.get(2..2 + n).ok_or(WireError::Truncated)?;
        (
            bytes.iter().fold(0usize, |a, &b| (a << 8) | b as usize),
            2 + n,
        )
    };
    let end = hdr.checked_add(len).ok_or(WireError::Truncated)?;
    let content = buf.get(hdr..end).ok_or(WireError::Truncated)?;
    Ok((tag, content, &buf[end..]))
}

fn expect(buf: &[u8], tag: u8) -> Result<(&[u8], &[u8]), WireError> {
    let (t, c, rest) = tlv(buf)?;
    if t != tag {
        return Err(WireError::Malformed("DER: unexpected tag"));
    }
    Ok((c, rest))
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xFF {
        out.extend([0x81, n as u8]);
    } else if n <= 0xFFFF {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

impl SpnegoToken {
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let (tag, _, _) = tlv(bytes)?;
        match tag {
            TAG_APPLICATION_0 => {
                // GSS-API InitialContextToken: mechanism OID + NegotiationToken
                let (inner, _) = expect(bytes, TAG_APPLICATION_0)?;
                let (oid, rest) = expect(inner, TAG_OID)?;
                if oid != OID_SPNEGO {
                    return Err(WireError::Malformed("GSS: not SPNEGO"));
                }
                let (c, _) = expect(rest, TAG_CTX_0)?;
                Self::parse_init(c)
            }
            TAG_CTX_0 => {
                let (c, _) = expect(bytes, TAG_CTX_0)?;
                Self::parse_init(c)
            }
            TAG_CTX_1 => {
                let (c, _) = expect(bytes, TAG_CTX_1)?;
                Self::parse_resp(c)
            }
            _ => Err(WireError::Malformed("SPNEGO: unknown token")),
        }
    }

    fn parse_init(seq: &[u8]) -> Result<Self, WireError> {
        let (mut body, _) = expect(seq, TAG_SEQUENCE)?;
        let mut mech_types = Vec::new();
        let mut mech_token = Vec::new();
        while !body.is_empty() {
            let (tag, c, rest) = tlv(body)?;
            body = rest;
            match tag {
                TAG_CTX_0 => {
                    let (mut list, _) = expect(c, TAG_SEQUENCE)?;
                    while !list.is_empty() {
                        let (oid, rest) = expect(list, TAG_OID)?;
                        mech_types.push(oid.to_vec());
                        list = rest;
                    }
                }
                TAG_CTX_2 => mech_token = expect(c, TAG_OCTET_STRING)?.0.to_vec(),
                _ => {} // reqFlags, mechListMIC
            }
        }
        Ok(SpnegoToken::NegTokenInit {
            mech_types,
            mech_token,
        })
    }

    fn parse_resp(seq: &[u8]) -> Result<Self, WireError> {
        let (mut body, _) = expect(seq, TAG_SEQUENCE)?;
        let mut neg_state = None;
        let mut supported_mech = None;
        let mut response_token = Vec::new();
        while !body.is_empty() {
            let (tag, c, rest) = tlv(body)?;
            body = rest;
            match tag {
                TAG_CTX_0 => {
                    let (v, _) = expect(c, TAG_ENUMERATED)?;
                    neg_state = Some(match v {
                        [0] => NegState::AcceptCompleted,
                        [1] => NegState::AcceptIncomplete,
                        [2] => NegState::Reject,
                        [3] => NegState::RequestMic,
                        _ => return Err(WireError::Malformed("SPNEGO: negState")),
                    });
                }
                TAG_CTX_1 => supported_mech = Some(expect(c, TAG_OID)?.0.to_vec()),
                TAG_CTX_2 => response_token = expect(c, TAG_OCTET_STRING)?.0.to_vec(),
                _ => {} // mechListMIC
            }
        }
        Ok(SpnegoToken::NegTokenResp {
            neg_state,
            supported_mech,
            response_token,
        })
    }

    pub fn build(&self) -> Vec<u8> {
        match self {
            SpnegoToken::NegTokenInit {
                mech_types,
                mech_token,
            } => {
                let oids: Vec<u8> = mech_types.iter().flat_map(|o| der(TAG_OID, o)).collect();
                let mut seq = der(TAG_CTX_0, &der(TAG_SEQUENCE, &oids));
                if !mech_token.is_empty() {
                    seq.extend(der(TAG_CTX_2, &der(TAG_OCTET_STRING, mech_token)));
                }
                let mut inner = der(TAG_OID, OID_SPNEGO);
                inner.extend(der(TAG_CTX_0, &der(TAG_SEQUENCE, &seq)));
                der(TAG_APPLICATION_0, &inner)
            }
            SpnegoToken::NegTokenResp {
                neg_state,
                supported_mech,
                response_token,
            } => {
                let mut seq = Vec::new();
                if let Some(s) = neg_state {
                    seq.extend(der(TAG_CTX_0, &der(TAG_ENUMERATED, &[*s as u8])));
                }
                if let Some(m) = supported_mech {
                    seq.extend(der(TAG_CTX_1, &der(TAG_OID, m)));
                }
                if !response_token.is_empty() {
                    seq.extend(der(TAG_CTX_2, &der(TAG_OCTET_STRING, response_token)));
                }
                der(TAG_CTX_1, &der(TAG_SEQUENCE, &seq))
            }
        }
    }

    /// The NTLMSSP token inside SPNEGO (mechToken / responseToken).
    pub fn ntlm_token(&self) -> &[u8] {
        match self {
            SpnegoToken::NegTokenInit { mech_token, .. } => mech_token,
            SpnegoToken::NegTokenResp { response_token, .. } => response_token,
        }
    }
}

/// SecurityBuffer of the NEGOTIATE reply: a NegTokenInit offering only NTLMSSP.
pub fn neg_token_init_ntlm() -> Vec<u8> {
    SpnegoToken::NegTokenInit {
        mech_types: vec![OID_NTLMSSP.to_vec()],
        mech_token: Vec::new(),
    }
    .build()
}

/// Server reply with the NTLM CHALLENGE: accept-incomplete + supportedMech + token.
pub fn neg_token_resp_challenge(ntlm_challenge: &[u8]) -> Vec<u8> {
    SpnegoToken::NegTokenResp {
        neg_state: Some(NegState::AcceptIncomplete),
        supported_mech: Some(OID_NTLMSSP.to_vec()),
        response_token: ntlm_challenge.to_vec(),
    }
    .build()
}

/// Final reply: accept-completed without a token.
pub fn neg_token_resp_completed() -> Vec<u8> {
    SpnegoToken::NegTokenResp {
        neg_state: Some(NegState::AcceptCompleted),
        supported_mech: None,
        response_token: Vec::new(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ms_vectors::*;

    /// A SecurityBuffer from a Microsoft SESSION_SETUP request/response frame.
    fn sec_buffer(frame_hex: &str, off_at: usize) -> Vec<u8> {
        let f = unhex(frame_hex);
        let off = u16::from_le_bytes([f[64 + off_at], f[64 + off_at + 1]]) as usize;
        let len = u16::from_le_bytes([f[64 + off_at + 2], f[64 + off_at + 3]]) as usize;
        f[off..off + len].to_vec()
    }

    #[test]
    fn parses_real_ntlm_negotiate_in_neg_token_init() {
        let t = SpnegoToken::parse(&sec_buffer(SS_REQUEST_1, 12)).unwrap();
        match &t {
            SpnegoToken::NegTokenInit {
                mech_types,
                mech_token,
            } => {
                assert_eq!(mech_types, &vec![OID_NTLMSSP.to_vec()]);
                assert_eq!(&mech_token[..8], b"NTLMSSP\0");
                assert_eq!(mech_token.len(), 40);
            }
            other => panic!("expected NegTokenInit, got {other:?}"),
        }
    }

    #[test]
    fn parses_real_challenge_response_token() {
        let t = SpnegoToken::parse(&sec_buffer(SS_RESPONSE_1, 4)).unwrap();
        match t {
            SpnegoToken::NegTokenResp {
                neg_state,
                supported_mech,
                response_token,
            } => {
                assert_eq!(neg_state, Some(NegState::AcceptIncomplete));
                assert_eq!(supported_mech.as_deref(), Some(OID_NTLMSSP));
                assert_eq!(response_token.len(), 148);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_real_authenticate_token() {
        let t = SpnegoToken::parse(&sec_buffer(SS_REQUEST_2, 12)).unwrap();
        assert!(matches!(
            t,
            SpnegoToken::NegTokenResp {
                neg_state: Some(NegState::AcceptIncomplete),
                ..
            }
        ));
        assert_eq!(t.ntlm_token().len(), 422); // without the mechListMIC tail
    }

    #[test]
    fn real_tokens_roundtrip_byte_for_byte() {
        // build(parse(x)) == x for tokens without mechListMIC/reqFlags
        for (hex, off) in [(SS_REQUEST_1, 12), (SS_RESPONSE_1, 4)] {
            let raw = sec_buffer(hex, off);
            let t = SpnegoToken::parse(&raw).unwrap();
            assert_eq!(t.build(), raw);
        }
    }

    #[test]
    fn parses_windows_negotiate_response_gss_blob() {
        // A NegTokenInit from Windows Server with several mechTypes (including NEGOEXTS)
        let f = unhex(NEGOTIATE_RESPONSE);
        let off = u16::from_le_bytes([f[64 + 56], f[64 + 57]]) as usize;
        let len = u16::from_le_bytes([f[64 + 58], f[64 + 59]]) as usize;
        let t = SpnegoToken::parse(&f[off..off + len]).unwrap();
        match t {
            SpnegoToken::NegTokenInit {
                mech_types,
                mech_token,
            } => {
                assert!(mech_types.iter().any(|m| m == OID_NTLMSSP));
                assert!(mech_types.len() >= 2);
                // Windows puts a NegoEx hint into mechToken
                assert_eq!(&mech_token[..8], b"NEGOEXTS");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn server_tokens_parse_back() {
        let init = SpnegoToken::parse(&neg_token_init_ntlm()).unwrap();
        assert_eq!(
            init,
            SpnegoToken::NegTokenInit {
                mech_types: vec![OID_NTLMSSP.to_vec()],
                mech_token: vec![]
            }
        );
        let challenge = vec![0xAA; 300]; // long form of the DER length
        let t = SpnegoToken::parse(&neg_token_resp_challenge(&challenge)).unwrap();
        assert_eq!(t.ntlm_token(), &challenge[..]);
        let done = SpnegoToken::parse(&neg_token_resp_completed()).unwrap();
        assert_eq!(
            done,
            SpnegoToken::NegTokenResp {
                neg_state: Some(NegState::AcceptCompleted),
                supported_mech: None,
                response_token: vec![]
            }
        );
    }

    #[test]
    fn garbage_is_error_not_panic() {
        assert!(SpnegoToken::parse(&[]).is_err());
        assert!(SpnegoToken::parse(&[0x60]).is_err());
        assert!(SpnegoToken::parse(&[0x60, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        assert!(SpnegoToken::parse(&[0x60, 0x80]).is_err());
        assert!(SpnegoToken::parse(&[0x42, 0x00]).is_err());
        let good = sec_buffer(SS_REQUEST_2, 12);
        for n in 0..good.len() {
            let _ = SpnegoToken::parse(&good[..n]);
        }
    }
}
