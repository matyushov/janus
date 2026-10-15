//! Codec errors. `Frame::decode` is total: any input → `Ok` or `WireError`,
//! a panic is unacceptable (the crate is subject to fuzzing).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Fewer bytes than the declared structure requires.
    Truncated,
    /// Neither `\xFE SMB2` (plain) nor `\xFD SMB2` (transform).
    BadMagic,
    /// Command code outside the known set.
    UnknownCommand(u16),
    /// A create context with a known tag but an invalid body.
    BadContext(&'static str),
    /// A structure invariant violation (offsets/sizes inside the frame).
    Malformed(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "truncated frame"),
            WireError::BadMagic => write!(f, "bad protocol magic"),
            WireError::UnknownCommand(c) => write!(f, "unknown SMB2 command 0x{c:04x}"),
            WireError::BadContext(tag) => write!(f, "bad create context '{tag}'"),
            WireError::Malformed(what) => write!(f, "malformed structure: {what}"),
        }
    }
}

impl std::error::Error for WireError {}
