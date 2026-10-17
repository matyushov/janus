//! Lease break messages (MS-SMB2 §2.2.23.2 notification, §2.2.24.2 acknowledgment, §2.2.25.2
//! response). All travel in the OPLOCK_BREAK command; the body is told apart by StructureSize.

use crate::Command;
use crate::WireError;
use crate::bytes::{Reader, Writer};
use crate::header::{Header, flags};

/// Notification flag: the client must acknowledge the break.
pub const BREAK_FLAG_ACK_REQUIRED: u32 = 0x01;
/// StructureSize of a lease break acknowledgment (and of its response).
pub const LEASE_ACK_SIZE: u16 = 36;
/// StructureSize of the oplock (non-lease) break acknowledgment.
pub const OPLOCK_ACK_SIZE: u16 = 24;

/// `MessageId` of every unsolicited server-to-client message.
pub const NOTIFICATION_MESSAGE_ID: u64 = u64::MAX;

/// A server-initiated break of a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakNotification {
    pub new_epoch: u16,
    pub ack_required: bool,
    pub key: [u8; 16],
    pub current_state: u32,
    pub new_state: u32,
}

impl LeaseBreakNotification {
    fn encode_body(&self, w: &mut Writer) {
        w.u16(44);
        w.u16(self.new_epoch);
        w.u32(if self.ack_required {
            BREAK_FLAG_ACK_REQUIRED
        } else {
            0
        });
        w.bytes(&self.key);
        w.u32(self.current_state);
        w.u32(self.new_state);
        w.u32(0); // BreakReason
        w.u32(0); // AccessMaskHint
        w.u32(0); // ShareMaskHint
    }

    /// The whole unsolicited packet: MessageId -1, no session, no tree, not signed
    /// (MS-SMB2 §3.3.4.7).
    pub fn encode_packet(&self) -> Vec<u8> {
        let h = Header {
            credit_charge: 0,
            status: 0,
            command: Command::OplockBreak,
            credit_req_grant: 0,
            flags: flags::SERVER_TO_REDIR,
            next_command: 0,
            message_id: NOTIFICATION_MESSAGE_ID,
            tree_id: 0,
            async_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let mut w = Writer::new();
        h.encode(&mut w);
        self.encode_body(&mut w);
        w.into_vec()
    }
}

/// The client's answer to a break: the state it keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseBreakAck {
    pub flags: u32,
    pub key: [u8; 16],
    pub state: u32,
}

impl LeaseBreakAck {
    /// `r` is the command body. Returns `None` for an oplock acknowledgment (other size).
    pub fn decode(r: &mut Reader<'_>) -> Result<Option<LeaseBreakAck>, WireError> {
        match r.u16()? {
            LEASE_ACK_SIZE => {}
            OPLOCK_ACK_SIZE => return Ok(None),
            _ => return Err(WireError::Malformed("OPLOCK_BREAK StructureSize")),
        }
        let _reserved = r.u16()?;
        let flags = r.u32()?;
        let key = r.array::<16>()?;
        let state = r.u32()?;
        let _duration = r.u64()?;
        Ok(Some(LeaseBreakAck { flags, key, state }))
    }

    /// Body of the SMB2 LEASE_BREAK Response.
    pub fn encode_response(key: &[u8; 16], state: u32, w: &mut Writer) {
        w.u16(LEASE_ACK_SIZE);
        w.u16(0);
        w.u32(0);
        w.bytes(key);
        w.u32(state);
        w.u64(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_packet_layout() {
        let n = LeaseBreakNotification {
            new_epoch: 5,
            ack_required: true,
            key: [9; 16],
            current_state: 7,
            new_state: 1,
        };
        let p = n.encode_packet();
        assert_eq!(p.len(), 64 + 44);
        assert_eq!(&p[..4], &[0xFE, b'S', b'M', b'B']);
        assert_eq!(u16::from_le_bytes([p[12], p[13]]), 0x12);
        assert_eq!(u64::from_le_bytes(p[24..32].try_into().unwrap()), u64::MAX);
        assert_eq!(
            u32::from_le_bytes(p[16..20].try_into().unwrap()),
            1,
            "SERVER_TO_REDIR"
        );
        assert_eq!(u16::from_le_bytes([p[64], p[65]]), 44);
        assert_eq!(u16::from_le_bytes([p[66], p[67]]), 5);
        assert_eq!(
            u32::from_le_bytes(p[68..72].try_into().unwrap()),
            1,
            "ack required"
        );
        assert_eq!(&p[72..88], &[9; 16]);
        assert_eq!(u32::from_le_bytes(p[88..92].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(p[92..96].try_into().unwrap()), 1);
    }

    #[test]
    fn ack_roundtrip_and_oplock_ack_is_distinguished() {
        let mut w = Writer::new();
        w.u16(36);
        w.u16(0);
        w.u32(0);
        w.bytes(&[4; 16]);
        w.u32(3);
        w.u64(0);
        let body = w.into_vec();
        let ack = LeaseBreakAck::decode(&mut Reader::new(&body))
            .unwrap()
            .unwrap();
        assert_eq!((ack.key, ack.state), ([4; 16], 3));
        let mut resp = Writer::new();
        LeaseBreakAck::encode_response(&ack.key, ack.state, &mut resp);
        assert_eq!(resp.into_vec(), body);
        assert!(
            LeaseBreakAck::decode(&mut Reader::new(&24u16.to_le_bytes()))
                .unwrap()
                .is_none()
        );
        assert!(LeaseBreakAck::decode(&mut Reader::new(&[1, 0])).is_err());
        for n in 0..body.len() {
            assert!(
                LeaseBreakAck::decode(&mut Reader::new(&body[..n])).is_err(),
                "len {n}"
            );
        }
    }
}
