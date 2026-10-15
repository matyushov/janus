//! SMB2 packet header (64 bytes, MS-SMB2 §2.2.1.2): decode/encode.

use crate::bytes::{Reader, Writer};
use crate::{Command, WireError};

/// `\xFE S M B` is the marker of a regular (unencrypted) SMB2 packet.
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// `\xFD S M B` is the transform header (3.x encryption).
pub const SMB2_TRANSFORM_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];

/// Header flags (MS-SMB2 §2.2.1.2).
pub mod flags {
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001; // a response (we set it)
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004; // compound related
    pub const SIGNED: u32 = 0x0000_0008;
}

pub const HEADER_LEN: usize = 64;

/// A parsed SMB2 header. `next_command` is the offset of the next element
/// of the compound chain (0 = the last one).
#[derive(Debug, Clone)]
pub struct Header {
    pub credit_charge: u16,
    pub status: u32,
    pub command: Command,
    pub credit_req_grant: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub tree_id: u32,
    /// In an async header (the ASYNC_COMMAND flag) this field is the AsyncId instead of
    /// (Reserved+TreeId). Kept raw, distinguished by the flag on serialization.
    pub async_id: u64,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Header {
    pub fn decode(r: &mut Reader<'_>) -> Result<Header, WireError> {
        let magic = r.array::<4>()?;
        if magic != SMB2_MAGIC {
            return Err(WireError::BadMagic);
        }
        let structure_size = r.u16()?;
        if structure_size != 64 {
            return Err(WireError::Malformed("header StructureSize != 64"));
        }
        let credit_charge = r.u16()?;
        let status = r.u32()?;
        let command = Command::try_from(r.u16()?)?;
        let credit_req_grant = r.u16()?;
        let flags = r.u32()?;
        let next_command = r.u32()?;
        let message_id = r.u64()?;

        let is_async = flags & flags::ASYNC_COMMAND != 0;
        let (async_id, tree_id) = if is_async {
            (r.u64()?, 0)
        } else {
            let _reserved = r.u32()?;
            let tree_id = r.u32()?;
            (0, tree_id)
        };
        let session_id = r.u64()?;
        let signature = r.array::<16>()?;

        Ok(Header {
            credit_charge,
            status,
            command,
            credit_req_grant,
            flags,
            next_command,
            message_id,
            tree_id,
            async_id,
            session_id,
            signature,
        })
    }

    pub fn encode(&self, w: &mut Writer) {
        w.bytes(&SMB2_MAGIC);
        w.u16(64);
        w.u16(self.credit_charge);
        w.u32(self.status);
        w.u16(self.command as u16);
        w.u16(self.credit_req_grant);
        w.u32(self.flags);
        w.u32(self.next_command);
        w.u64(self.message_id);
        if self.flags & flags::ASYNC_COMMAND != 0 {
            w.u64(self.async_id);
        } else {
            w.u32(0); // Reserved
            w.u32(self.tree_id);
        }
        w.u64(self.session_id);
        w.bytes(&self.signature);
    }

    /// Build the response header for this request (flip the
    /// SERVER_TO_REDIR flag, keep the message_id/session/tree correlation).
    pub fn response_to(req: &Header, status: u32) -> Header {
        Header {
            credit_charge: req.credit_charge,
            status,
            command: req.command,
            credit_req_grant: 1, // the minimum; the credit policy is refined in smb-core
            flags: flags::SERVER_TO_REDIR,
            next_command: 0,
            message_id: req.message_id,
            tree_id: req.tree_id,
            async_id: 0,
            session_id: req.session_id,
            signature: [0; 16],
        }
    }
}

impl TryFrom<u16> for Command {
    type Error = WireError;

    fn try_from(v: u16) -> Result<Self, WireError> {
        Ok(match v {
            0x0000 => Command::Negotiate,
            0x0001 => Command::SessionSetup,
            0x0002 => Command::Logoff,
            0x0003 => Command::TreeConnect,
            0x0004 => Command::TreeDisconnect,
            0x0005 => Command::Create,
            0x0006 => Command::Close,
            0x0007 => Command::Flush,
            0x0008 => Command::Read,
            0x0009 => Command::Write,
            0x000A => Command::Lock,
            0x000B => Command::Ioctl,
            0x000C => Command::Cancel,
            0x000D => Command::Echo,
            0x000E => Command::QueryDirectory,
            0x000F => Command::ChangeNotify,
            0x0010 => Command::QueryInfo,
            0x0011 => Command::SetInfo,
            0x0012 => Command::OplockBreak,
            other => return Err(WireError::UnknownCommand(other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_sync() {
        let h = Header {
            credit_charge: 1,
            status: 0,
            command: Command::Negotiate,
            credit_req_grant: 31,
            flags: 0,
            next_command: 0,
            message_id: 7,
            tree_id: 0,
            async_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let mut w = Writer::new();
        h.encode(&mut w);
        let bytes = w.into_vec();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], &SMB2_MAGIC);

        let mut r = Reader::new(&bytes);
        let d = Header::decode(&mut r).unwrap();
        assert_eq!(d.command, Command::Negotiate);
        assert_eq!(d.message_id, 7);
        assert_eq!(d.credit_req_grant, 31);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = vec![0u8; 64];
        buf[0] = 0xEE;
        let mut r = Reader::new(&buf);
        assert_eq!(Header::decode(&mut r).unwrap_err(), WireError::BadMagic);
    }

    #[test]
    fn unknown_command_rejected() {
        assert_eq!(
            Command::try_from(0x00FF).unwrap_err(),
            WireError::UnknownCommand(0x00FF)
        );
    }

    #[test]
    fn response_flips_server_flag() {
        let req = Header {
            credit_charge: 1,
            status: 0,
            command: Command::TreeConnect,
            credit_req_grant: 1,
            flags: 0,
            next_command: 0,
            message_id: 42,
            tree_id: 5,
            async_id: 0,
            session_id: 9,
            signature: [0; 16],
        };
        let resp = Header::response_to(&req, 0);
        assert_eq!(resp.flags & flags::SERVER_TO_REDIR, flags::SERVER_TO_REDIR);
        assert_eq!(resp.message_id, 42);
        assert_eq!(resp.session_id, 9);
    }
}
