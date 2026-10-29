// cli_desktop/dbus/auth.rs — the client side of the bus handshake:
//
//   C: \0AUTH EXTERNAL <hex of the uid in decimal>\r\n
//   S: OK <server guid>\r\n
//   C: BEGIN\r\n
//
// EXTERNAL means "the kernel already told you who I am" (SO_PEERCRED).
// The reply is read a byte at a time so nothing of the message stream
// that follows is consumed.

use std::io::{Read, Write};
use std::time::Duration;

const MAX_LINE: usize = 512;

pub fn hex_uid(uid: u32) -> String {
    uid.to_string()
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn line(r: &mut impl Read) -> Result<String, String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        r.read_exact(&mut b)
            .map_err(|e| format!("bus handshake: {e}"))?;
        out.push(b[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            return String::from_utf8(out).map_err(|_| "bus handshake: not UTF-8".to_string());
        }
        if out.len() > MAX_LINE {
            return Err("bus handshake: line too long".into());
        }
    }
}

/// Authenticate as `uid`; returns the server's GUID.
pub fn client<S: Read + Write>(s: &mut S, uid: u32) -> Result<String, String> {
    let hello = format!("\0AUTH EXTERNAL {}\r\n", hex_uid(uid));
    s.write_all(hello.as_bytes())
        .map_err(|e| format!("bus handshake: {e}"))?;
    let reply = line(s)?;
    let Some(guid) = reply.strip_prefix("OK ") else {
        return Err(format!(
            "the bus refused the login ({})",
            reply.split(' ').next().unwrap_or("?")
        ));
    };
    s.write_all(b"BEGIN\r\n")
        .map_err(|e| format!("bus handshake: {e}"))?;
    Ok(guid.to_string())
}

pub const TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn serve(reply: &'static [u8]) -> (UnixStream, std::thread::JoinHandle<Vec<u8>>) {
        let (a, mut b) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut byte = [0u8; 1];
            // Until the end of the AUTH line.
            while !got.ends_with(b"\r\n") {
                b.read_exact(&mut byte).unwrap();
                got.push(byte[0]);
            }
            b.write_all(reply).unwrap();
            // Whatever follows (BEGIN), until the client is done.
            let mut rest = Vec::new();
            let _ = b.read_to_end(&mut rest);
            got.extend(rest);
            got
        });
        (a, h)
    }

    #[test]
    fn the_uid_is_sent_as_hex_of_its_decimal_digits() {
        assert_eq!(hex_uid(1000), "31303030");
        assert_eq!(hex_uid(0), "30");
        let (mut c, h) = serve(b"OK 0123456789abcdef\r\n");
        assert_eq!(client(&mut c, 1000).unwrap(), "0123456789abcdef");
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(h.join().unwrap(), b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\n");
    }

    #[test]
    fn a_refusal_or_noise_is_an_error() {
        let (mut c, h) = serve(b"REJECTED EXTERNAL\r\n");
        assert!(client(&mut c, 1).unwrap_err().contains("refused"));
        drop(c);
        let _ = h.join();
        let mut long = Vec::new();
        long.extend(std::iter::repeat_n(b'x', 600));
        let mut cur = std::io::Cursor::new(long);
        assert!(line(&mut cur).unwrap_err().contains("too long"));
        let mut short = std::io::Cursor::new(b"OK".to_vec());
        assert!(line(&mut short).is_err());
    }
}
