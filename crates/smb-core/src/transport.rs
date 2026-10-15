//! SMB transport over TCP: NetBIOS Session Service framing.
//! Every SMB2 message is preceded by a 4-byte prefix: 1 type byte (0x00
//! = session message) + 3 length bytes (big-endian). MS-SMB2 uses the
//! "direct TCP" variant, where the high byte is 0 and in practice this is a 24-bit length.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum accepted size of a single message (protection against garbage).
/// 16 MiB comfortably covers 1 MiB max read/write plus headers.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Read one framed message. `Ok(None)` means the connection was closed cleanly.
pub async fn read_message<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 4];
    match r.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    // 24-bit length (the high byte is the NBSS type, 0 for a session message).
    let len = ((prefix[1] as usize) << 16) | ((prefix[2] as usize) << 8) | prefix[3] as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("NBSS length out of range: {len}"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Write one framed message.
pub async fn write_message<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = msg.len();
    debug_assert!(len <= MAX_MESSAGE);
    let prefix = [0u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    w.write_all(&prefix).await?;
    w.write_all(msg).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn frame_roundtrip() {
        let payload = b"hello-smb2";
        let mut out = Vec::new();
        write_message(&mut out, payload).await.unwrap();
        // 4 prefix bytes + body
        assert_eq!(out.len(), 4 + payload.len());
        assert_eq!(&out[0..4], &[0, 0, 0, payload.len() as u8]);

        let mut cur = Cursor::new(out);
        let got = read_message(&mut cur).await.unwrap().unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_message(&mut cur).await.unwrap().is_none());
    }
}
