//! smb-wire: the SMB2/3 codec: frame parsing/serialization, crypto primitives and
//! NTLMSSP/SPNEGO tokens as pure functions.
//!
//! Layer rule: if a type describes "what is in the packet", it lives here; if it is
//! "what we remember between packets", it is state and belongs in `smb-core`.
//!
//! Design: README.md (Architecture), §2.1.
//!
//! Naming note: "SMB3" means the later dialects of the SMB2 protocol
//! (0x0300/0x0302/0x0311); the frame format and commands are SMB2 (see MS-SMB2).

#![allow(dead_code)] // skeleton: some types appear before they are used

pub mod auth;
pub mod bytes;
pub mod create;
pub mod crypto;
pub mod error;
pub mod fileinfo;
pub mod frame;
pub mod header;
pub mod io;
pub mod lease;
#[cfg(test)]
mod macos_vectors;
pub mod messages;
/// Published Microsoft test vectors (for the smb-wire and smb-core tests).
#[doc(hidden)]
pub mod ms_vectors;
pub mod ntlm;
#[doc(hidden)]
pub mod testclient;

pub use error::WireError;
pub use frame::{Command, Dialect};
pub use header::Header;

/// One parsed SMB2 message: header + raw body (unparsed).
/// The dispatcher (smb-core) parses the body with the right type from
/// `messages` by `header.command`. A compound chain is cut by `header.next_command` in smb-core.
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    /// Command body (everything after the 64-byte header of this element).
    pub body: Vec<u8>,
}

impl Message {
    /// Parse a SINGLE message from the start of the buffer (no compound chain:
    /// smb-core unrolls it, knowing the boundaries from next_command).
    pub fn decode_single(buf: &[u8]) -> Result<Message, WireError> {
        let mut r = bytes::Reader::new(buf);
        let header = Header::decode(&mut r)?;
        let body = r.take(r.remaining())?.to_vec();
        Ok(Message { header, body })
    }
}
