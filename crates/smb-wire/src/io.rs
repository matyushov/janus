//! READ, WRITE and FLUSH (MS-SMB2 §2.2.19–2.2.22, §2.2.17–2.2.18).
//! Channels (RDMA) are not supported: a request with a non-zero channel is rejected by the
//! caller via `channel`.

use crate::WireError;
use crate::bytes::{Reader, Writer};
use crate::create::FileId;
use crate::header::HEADER_LEN;

#[derive(Debug)]
pub struct ReadReq {
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    pub channel: u32,
}

impl ReadReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if r.u16()? != 49 {
            return Err(WireError::Malformed("READ StructureSize != 49"));
        }
        let _padding = r.u8()?;
        let _flags = r.u8()?;
        let length = r.u32()?;
        let offset = r.u64()?;
        let file_id = r.array::<16>()?;
        let minimum_count = r.u32()?;
        let channel = r.u32()?;
        let _remaining = r.u32()?;
        let _channel_info_offset = r.u16()?;
        let _channel_info_length = r.u16()?;
        // The 1-byte Buffer is required by StructureSize but carries nothing for channel 0.
        Ok(ReadReq {
            length,
            offset,
            file_id,
            minimum_count,
            channel,
        })
    }
}

/// READ reply: 16 fixed bytes, then the data at offset 80 (header + 16).
pub fn encode_read_resp(w: &mut Writer, data: &[u8]) {
    w.u16(17);
    w.u8((HEADER_LEN + 16) as u8); // DataOffset
    w.u8(0);
    w.u32(data.len() as u32);
    w.u32(0); // DataRemaining
    w.u32(0); // Reserved2
    w.bytes(data);
}

#[derive(Debug)]
pub struct WriteReq {
    pub offset: u64,
    pub file_id: FileId,
    pub channel: u32,
    pub flags: u32,
    pub data: Vec<u8>,
}

/// WRITE flags (§2.2.21).
pub mod write_flags {
    pub const WRITE_THROUGH: u32 = 0x0000_0001;
    pub const UNBUFFERED: u32 = 0x0000_0002;
}

impl WriteReq {
    /// `r` is the command body; `DataOffset` counts from the start of the header.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let body = r.whole();
        if r.u16()? != 49 {
            return Err(WireError::Malformed("WRITE StructureSize != 49"));
        }
        let data_offset = r.u16()? as usize;
        let length = r.u32()? as usize;
        let offset = r.u64()?;
        let file_id = r.array::<16>()?;
        let channel = r.u32()?;
        let _remaining = r.u32()?;
        let _channel_info_offset = r.u16()?;
        let _channel_info_length = r.u16()?;
        let flags = r.u32()?;
        let data = if length == 0 {
            Vec::new()
        } else {
            let start = data_offset
                .checked_sub(HEADER_LEN)
                .filter(|&s| s >= 48)
                .ok_or(WireError::Malformed(
                    "WRITE DataOffset inside the fixed part",
                ))?;
            let end = start
                .checked_add(length)
                .ok_or(WireError::Malformed("WRITE length overflow"))?;
            body.get(start..end)
                .ok_or(WireError::Malformed("WRITE data outside the message"))?
                .to_vec()
        };
        Ok(WriteReq {
            offset,
            file_id,
            channel,
            flags,
            data,
        })
    }
}

pub fn encode_write_resp(w: &mut Writer, count: u32) {
    w.u16(17);
    w.u16(0);
    w.u32(count);
    w.u32(0); // Remaining
    w.u16(0); // WriteChannelInfoOffset
    w.u16(0); // WriteChannelInfoLength
}

#[derive(Debug)]
pub struct FlushReq {
    /// Reserved1: Apple sets 0xFFFF to ask for F_FULLFSYNC.
    pub reserved1: u16,
    pub file_id: FileId,
}

/// Apple's F_FULLFSYNC marker in FLUSH.Reserved1.
pub const FLUSH_FULLFSYNC: u16 = 0xFFFF;

impl FlushReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if r.u16()? != 24 {
            return Err(WireError::Malformed("FLUSH StructureSize != 24"));
        }
        let reserved1 = r.u16()?;
        let _reserved2 = r.u32()?;
        let file_id = r.array::<16>()?;
        Ok(FlushReq { reserved1, file_id })
    }
}

pub fn encode_flush_resp(w: &mut Writer) {
    w.u16(4);
    w.u16(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_body(len: u32, off: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(49);
        w.u8(0x50);
        w.u8(0);
        w.u32(len);
        w.u64(off);
        w.bytes(&[7; 16]);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u16(0);
        w.u16(0);
        w.u8(0);
        w.into_vec()
    }

    fn write_body(off: u64, data: &[u8], data_offset: u16) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(49);
        w.u16(data_offset);
        w.u32(data.len() as u32);
        w.u64(off);
        w.bytes(&[9; 16]);
        w.u32(0);
        w.u32(0);
        w.u16(0);
        w.u16(0);
        w.u32(1);
        w.bytes(data);
        w.into_vec()
    }

    #[test]
    fn read_request_fields() {
        let b = read_body(4096, 0x1_0000_0000);
        let r = ReadReq::decode(&mut Reader::new(&b)).unwrap();
        assert_eq!((r.length, r.offset, r.channel), (4096, 0x1_0000_0000, 0));
        assert_eq!(r.file_id, [7; 16]);
        for n in 0..48 {
            assert!(ReadReq::decode(&mut Reader::new(&b[..n])).is_err());
        }
    }

    #[test]
    fn read_response_layout() {
        let mut w = Writer::new();
        encode_read_resp(&mut w, b"abc");
        let b = w.into_vec();
        assert_eq!(b.len(), 19);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 17);
        assert_eq!(b[2], 80);
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 3);
        assert_eq!(&b[16..], b"abc");
    }

    #[test]
    fn write_request_takes_data_by_offset() {
        // Standard layout: data right after the 48 fixed bytes, header 64 → offset 112.
        let b = write_body(512, b"payload", 112);
        let r = WriteReq::decode(&mut Reader::new(&b)).unwrap();
        assert_eq!(r.offset, 512);
        assert_eq!(r.data, b"payload");
        assert_eq!(r.flags, 1);
        // Padding between the fixed part and the data is honoured.
        let mut padded = write_body(0, b"", 112);
        padded.truncate(48);
        padded.extend_from_slice(&[0; 8]);
        padded.extend_from_slice(b"xy");
        padded[2..4].copy_from_slice(&120u16.to_le_bytes());
        padded[4..8].copy_from_slice(&2u32.to_le_bytes());
        let r = WriteReq::decode(&mut Reader::new(&padded)).unwrap();
        assert_eq!(r.data, b"xy");
    }

    #[test]
    fn write_request_rejects_bad_offsets() {
        let ok = write_body(0, b"abcd", 112);
        // offset inside the header / inside the fixed part / past the message
        for bad in [0u16, 63, 64, 100, 200] {
            let mut b = ok.clone();
            b[2..4].copy_from_slice(&bad.to_le_bytes());
            assert!(WriteReq::decode(&mut Reader::new(&b)).is_err(), "{bad}");
        }
        // length longer than the data present
        let mut b = ok.clone();
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(WriteReq::decode(&mut Reader::new(&b)).is_err());
        for n in 0..48 {
            assert!(WriteReq::decode(&mut Reader::new(&ok[..n])).is_err());
        }
    }

    #[test]
    fn write_and_flush_responses() {
        let mut w = Writer::new();
        encode_write_resp(&mut w, 65536);
        let b = w.into_vec();
        assert_eq!(b.len(), 16);
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 65536);
        let mut w = Writer::new();
        encode_flush_resp(&mut w);
        assert_eq!(w.into_vec(), [4, 0, 0, 0]);
    }

    #[test]
    fn flush_request_carries_fullfsync_marker() {
        let mut w = Writer::new();
        w.u16(24);
        w.u16(FLUSH_FULLFSYNC);
        w.u32(0);
        w.bytes(&[3; 16]);
        let b = w.into_vec();
        let r = FlushReq::decode(&mut Reader::new(&b)).unwrap();
        assert_eq!(r.reserved1, FLUSH_FULLFSYNC);
        assert_eq!(r.file_id, [3; 16]);
    }
}
