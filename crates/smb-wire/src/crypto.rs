//! 3.1.1 crypto primitives as pure functions over bytes.
//! State (the accumulated preauth hash, the NTLM legs) lives in smb-core::ConnState.
//!
//! Required by the Apple spec: signing ("including SMB 3.x signing") → AES-CMAC +
//! SP800-108 key derivation; preauth integrity SHA-512 (dialect 3.1.1).

use aes::Aes128;
use cmac::{Cmac, Mac};
use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::header::HEADER_LEN;

/// Offset of the Signature field in the SMB2 header (MS-SMB2 §2.2.1.2).
const SIGNATURE_OFFSET: usize = 48;

/// Label for deriving the 3.1.1 signing key (with a trailing NUL, as in MS-SMB2 §3.1.4.2).
pub const LABEL_SIGNING_311: &[u8] = b"SMBSigningKey\0";

/// A step of the preauth integrity chain (SHA-512 over the previous hash and the frame).
/// `frame_bytes` is the whole SMB2 packet as on the wire (without the NBSS prefix).
pub fn preauth_chain(prev: &[u8; 64], frame_bytes: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(prev);
    h.update(frame_bytes);
    h.finalize().into()
}

/// SP800-108-CTR key derivation (HMAC-SHA256, r=32, L=128) from the session key.
/// `label` is passed with the trailing NUL (see `LABEL_*`); the 0x00 separator
/// between Label and Context is added here. The output is the first 16 bytes of K(1).
pub fn derive_key(session_key: &[u8; 16], label: &[u8], context: &[u8]) -> [u8; 16] {
    use hmac::Mac as _;
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(session_key)
        .expect("HMAC принимает любой ключ");
    mac.update(&1u32.to_be_bytes()); // counter i
    mac.update(label);
    mac.update(&[0]);
    mac.update(context);
    mac.update(&128u32.to_be_bytes()); // L in bits
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out[..16]);
    key
}

/// 3.1.1 signing key: SMB3KDF(SessionKey, "SMBSigningKey\0", PreauthIntegrityHashValue).
pub fn signing_key_311(session_key: &[u8; 16], preauth_hash: &[u8; 64]) -> [u8; 16] {
    derive_key(session_key, LABEL_SIGNING_311, preauth_hash)
}

/// AES-128-CMAC signature of a frame (3.x dialects). `frame` is one SMB2 packet
/// (header + body, up to NextCommand); the Signature field is treated as zero in
/// the computation regardless of its current content. There is nothing to sign in a frame
/// shorter than the header: the caller checks the length (`verify` rejects such a frame).
pub fn sign_cmac(signing_key: &[u8; 16], frame: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(signing_key).expect("ключ 16 байт");
    if frame.len() < HEADER_LEN {
        mac.update(frame);
    } else {
        mac.update(&frame[..SIGNATURE_OFFSET]);
        mac.update(&[0u8; 16]);
        mac.update(&frame[SIGNATURE_OFFSET + 16..]);
    }
    mac.finalize().into_bytes().into()
}

/// Verification of the signature of an incoming frame (constant-time comparison).
pub fn verify(signing_key: &[u8; 16], frame: &[u8], signature: &[u8; 16]) -> bool {
    if frame.len() < HEADER_LEN {
        return false;
    }
    sign_cmac(signing_key, frame).ct_eq(signature).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ms_vectors::*;

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        unhex(s).try_into().unwrap()
    }

    // --- RFC 4493 §4: AES-CMAC (key and messages from Examples 1–4) ---
    const RFC_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const RFC_MSG: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                           30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    fn cmac_raw(key: &str, msg: &[u8]) -> [u8; 16] {
        let mut m = <Cmac<Aes128> as Mac>::new_from_slice(&unhex(key)).unwrap();
        m.update(msg);
        m.finalize().into_bytes().into()
    }

    #[test]
    fn aes_cmac_rfc4493_vectors() {
        let msg = unhex(RFC_MSG);
        for (len, want) in [
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(
                cmac_raw(RFC_KEY, &msg[..len]).to_vec(),
                unhex(want),
                "len {len}"
            );
        }
    }

    #[test]
    fn preauth_chain_matches_microsoft_vectors() {
        let h1 = preauth_chain(&[0; 64], &unhex(NEGOTIATE_REQUEST));
        assert_eq!(h1.to_vec(), unhex(HASH_AFTER_NEGOTIATE_REQUEST));
        let h2 = preauth_chain(&h1, &unhex(NEGOTIATE_RESPONSE));
        assert_eq!(h2.to_vec(), unhex(HASH_AFTER_NEGOTIATE_RESPONSE));
    }

    #[test]
    fn signing_key_matches_microsoft_vector() {
        let key = signing_key_311(&arr(SESSION_KEY), &arr(FINAL_PREAUTH_HASH));
        assert_eq!(key.to_vec(), unhex(SIGNING_KEY));
    }

    #[test]
    fn signature_of_final_session_setup_response_matches_microsoft_vector() {
        let key: [u8; 16] = arr(SIGNING_KEY);
        let frame = unhex(SESSION_SETUP_FINAL_RESPONSE);
        let sig: [u8; 16] = arr(SESSION_SETUP_FINAL_SIGNATURE);
        // the signature is already in place in the frame; sign_cmac zeroes it itself
        assert_eq!(&frame[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16], &sig);
        assert_eq!(sign_cmac(&key, &frame), sig);
        assert!(verify(&key, &frame, &sig));
    }

    #[test]
    fn verify_rejects_tampering_and_short_frames() {
        let key: [u8; 16] = arr(SIGNING_KEY);
        let mut frame = unhex(SESSION_SETUP_FINAL_RESPONSE);
        let sig: [u8; 16] = arr(SESSION_SETUP_FINAL_SIGNATURE);
        let last = frame.len() - 1;
        frame[last] ^= 1;
        assert!(!verify(&key, &frame, &sig));
        assert!(!verify(&key, &frame[..63], &sig));
        assert!(!verify(&key, &[], &sig));
    }
}
