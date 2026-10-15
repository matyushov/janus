//! Common protocol enumerations: SMB2 commands and dialects.
//! The header is in `header`, command bodies are in `messages`.

/// SMB2 command codes (MS-SMB2 §2.2.1). Parsing from u16 is `Command::try_from`
/// (in `header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    Ioctl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OplockBreak = 0x0012, // lease break notification/ack too
}

/// SMB2/3 dialects. The target is 3.1.1; the list is extended only deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Dialect {
    Smb202 = 0x0202,
    Smb210 = 0x0210,
    Smb300 = 0x0300,
    Smb302 = 0x0302,
    Smb311 = 0x0311,
}

impl Dialect {
    pub fn from_u16(v: u16) -> Option<Dialect> {
        Some(match v {
            0x0202 => Dialect::Smb202,
            0x0210 => Dialect::Smb210,
            0x0300 => Dialect::Smb300,
            0x0302 => Dialect::Smb302,
            0x0311 => Dialect::Smb311,
            _ => return None,
        })
    }
}
