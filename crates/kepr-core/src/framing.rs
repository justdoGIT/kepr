// framing.rs — length-prefixed message framing for kepr's Unix socket
//
// Wire format: <u32 big-endian length> <payload of that length>
//
// Stream sockets don't guarantee a single read() returns a whole logical
// message — the kernel may deliver fewer bytes than sent. Framing fixes
// silent truncation in the previous "read-once-into-big-buffer" approach.

use std::io::{self, Read, Write};

pub fn write_frame<W: Write>(stream: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload too large",
        ));
    }
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(payload)?;
    Ok(())
}

pub fn read_frame<R: Read>(stream: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let n = u32::from_be_bytes(header) as usize;
    if n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {n} > {max}"),
        ));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_small() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        assert_eq!(&buf[..4], &5u32.to_be_bytes());
        let mut c = Cursor::new(buf);
        let out = read_frame(&mut c, 64).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 1000]);
        let mut c = Cursor::new(buf);
        let err = read_frame(&mut c, 64).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn partial_read_is_reassembled() {
        // Simulate fragmented stream — read_exact loops internally.
        let mut buf = Vec::new();
        write_frame(&mut buf, b"the quick brown fox").unwrap();
        let mut c = Cursor::new(buf);
        let out = read_frame(&mut c, 1024).unwrap();
        assert_eq!(out, b"the quick brown fox");
    }
}
