// http.rs — the small slice of HTTP/1.1 the relay speaks: one request per
// connection, `Content-Length` bodies only (no chunked encoding), headers
// up to 8 KiB, bodies up to the blob cap. Every reply closes the
// connection.

use std::io::{BufRead, BufReader, Read, Write};

const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// `X-Kepr-Ttl`, seconds.
    pub ttl: Option<u64>,
    pub body: Vec<u8>,
}

/// Why a request couldn't be read: (status, reason).
pub type Refusal = (u16, &'static str);

/// A reader with one deadline for the whole request. The socket's own read
/// timeout restarts with every byte, so a client sending one byte every few
/// seconds would otherwise hold a connection (of 64) for as long as it likes.
pub struct Deadline<'a> {
    stream: &'a std::net::TcpStream,
    until: std::time::Instant,
}

impl<'a> Deadline<'a> {
    pub fn new(stream: &'a std::net::TcpStream, limit: std::time::Duration) -> Self {
        Self {
            stream,
            until: std::time::Instant::now() + limit,
        }
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .until
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        (&mut &*self.stream).read(buf)
    }
}

/// Read one request; `max_body` bounds the body.
pub fn read_request<R: Read>(stream: R, max_body: usize) -> Result<Request, Refusal> {
    let mut r = BufReader::new(stream.take((MAX_HEAD + max_body + 1) as u64));
    let mut head = 0;
    let mut line = String::new();
    let mut next = |r: &mut BufReader<_>, line: &mut String| -> Result<(), Refusal> {
        line.clear();
        let n = r.read_line(line).map_err(|_| (400, "bad request"))?;
        head += n;
        if n == 0 || head > MAX_HEAD {
            return Err((431, "request header too large"));
        }
        Ok(())
    };
    next(&mut r, &mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(p), Some(v)) if v.starts_with("HTTP/1.") => (m.to_string(), p.to_string()),
        _ => return Err((400, "bad request")),
    };
    let (mut len, mut ttl) = (0usize, None);
    loop {
        next(&mut r, &mut line)?;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let Some((k, v)) = l.split_once(':') else {
            return Err((400, "bad header"));
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.parse().map_err(|_| (400, "bad content-length"))?,
            "transfer-encoding" => return Err((411, "send a content-length")),
            "x-kepr-ttl" => ttl = Some(v.parse().map_err(|_| (400, "bad x-kepr-ttl"))?),
            _ => {}
        }
    }
    if len > max_body {
        return Err((413, "blob too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|_| (400, "short body"))?;
    Ok(Request {
        method,
        path,
        ttl,
        body,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Error",
    }
}

/// Write a reply and close. `head_only` sends the headers of a body
/// without the body (HEAD).
pub fn respond<W: Write>(mut w: W, status: u16, body: &[u8], head_only: bool) {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/octet-stream\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        reason(status),
        body.len()
    );
    let _ = w.write_all(head.as_bytes());
    if !head_only {
        let _ = w.write_all(body);
    }
    let _ = w.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_put_and_refuses_bad_requests() {
        let raw =
            b"PUT /b/abc HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nX-Kepr-Ttl: 60\r\n\r\nblob";
        let r = read_request(&raw[..], 16).unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("PUT", "/b/abc"));
        assert_eq!((r.ttl, r.body.as_slice()), (Some(60), &b"blob"[..]));
        let big = b"PUT /b/abc HTTP/1.1\r\nContent-Length: 17\r\n\r\n";
        assert_eq!(read_request(&big[..], 16).unwrap_err().0, 413);
        let chunked = b"PUT /b/abc HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(read_request(&chunked[..], 16).unwrap_err().0, 411);
        assert_eq!(read_request(&b"hello\r\n\r\n"[..], 16).unwrap_err().0, 400);
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(read_request(huge.as_bytes(), 16).unwrap_err().0, 431);
    }

    #[test]
    fn replies_close_the_connection() {
        let mut out = Vec::new();
        respond(&mut out, 410, b"", false);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 410 Gone\r\n") && s.contains("Connection: close"));
    }

    #[test]
    fn a_client_that_trickles_bytes_is_cut_off_at_the_deadline() {
        use std::net::{TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let drip = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            // One byte every 100 ms: each read is "in time", the request never ends.
            for b in b"PUT /b/x HTTP/1.1\r\nX: "
                .iter()
                .chain(std::iter::repeat_n(&b'a', 200))
            {
                if c.write_all(&[*b]).is_err() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        let (server, _) = l.accept().unwrap();
        let start = std::time::Instant::now();
        let r = read_request(
            Deadline::new(&server, std::time::Duration::from_millis(600)),
            16,
        );
        assert!(r.is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        drop(server);
        let _ = drip.join();
    }
}
