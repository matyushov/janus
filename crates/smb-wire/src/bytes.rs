//! Byte primitives: a bounds-checked LE reader and a growing writer.
//! SMB2 is little-endian throughout (MS-SMB2 §2).

use crate::WireError;

/// A read cursor over a slice. Any read past the end → `WireError::Truncated`,
/// a panic is impossible (the crate is subject to fuzzing).
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Absolute slice of the whole source buffer (for fields addressed
    /// by an offset from the start of the SMB2 header).
    pub fn whole(&self) -> &'a [u8] {
        self.buf
    }

    pub fn seek(&mut self, abs: usize) -> Result<(), WireError> {
        if abs > self.buf.len() {
            return Err(WireError::Truncated);
        }
        self.pos = abs;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> Result<(), WireError> {
        self.take(n).map(|_| ())
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
}

/// A growing LE writer. Supports fixups: write a placeholder, remember the offset,
/// later fill in the real value (needed for offset/length fields that are
/// known only after the body is serialized).
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Fill `n` zero bytes (reserved fields, padding).
    pub fn zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    /// Current position, for a later fixup.
    pub fn mark(&self) -> usize {
        self.buf.len()
    }

    /// Write a u16 at a previously remembered offset (fixup of length/offset fields).
    pub fn patch_u16(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    pub fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_le_roundtrip() {
        let mut w = Writer::new();
        w.u8(0x11);
        w.u16(0x2233);
        w.u32(0x44556677);
        w.u64(0x8899aabbccddeeff);
        let v = w.into_vec();

        let mut r = Reader::new(&v);
        assert_eq!(r.u8().unwrap(), 0x11);
        assert_eq!(r.u16().unwrap(), 0x2233);
        assert_eq!(r.u32().unwrap(), 0x44556677);
        assert_eq!(r.u64().unwrap(), 0x8899aabbccddeeff);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reader_truncation_is_error_not_panic() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.u8().unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn seek_out_of_bounds_rejected() {
        let mut r = Reader::new(&[0u8; 4]);
        assert!(r.seek(4).is_ok());
        assert_eq!(r.seek(5).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn writer_patch() {
        let mut w = Writer::new();
        let at = w.mark();
        w.u16(0); // placeholder
        w.bytes(b"abcd");
        w.patch_u16(at, 4);
        assert_eq!(w.into_vec(), vec![0x04, 0x00, b'a', b'b', b'c', b'd']);
    }
}
