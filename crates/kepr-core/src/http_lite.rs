// http_lite.rs — the minimal HTTP/1.1 request parsing and response
// writing shared by `kepr-eso-provider` and `kepr serve` (T11.19): std
// only, no keep-alive, no chunked bodies, bounded everywhere (one
// deadline per request, line length, header count, body size).
// Moved here from crates/kepr-eso-provider/src/http.rs.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 64; // cap header count to prevent memory exhaustion
pub const MAX_HEADER_BYTES: usize = 8_192; // bound a single request/header line

/// One deadline for reading the whole request: the socket timeout alone
/// restarts on every byte, so a client trickling headers could hold a
/// worker indefinitely.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

/// Read one line, but never more than MAX_HEADER_BYTES + 1 bytes: a
/// plain read_line would buffer an endless line without a newline and
/// exhaust memory before any length check ran.
pub fn read_bounded_line(reader: &mut impl BufRead, line: &mut String) -> std::io::Result<usize> {
    reader.take(MAX_HEADER_BYTES as u64 + 1).read_line(line)
}

/// Constant-time comparison, so response timing can't reveal how much
/// of a guessed token was right.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A connected stream whose reads can time out (TCP or Unix).
pub trait TimedStream {
    fn set_read_deadline(&self, left: Duration) -> std::io::Result<()>;
    fn read_some(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl TimedStream for std::net::TcpStream {
    fn set_read_deadline(&self, left: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(left))
    }
    fn read_some(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&mut &*self).read(buf)
    }
}

impl TimedStream for UnixStream {
    fn set_read_deadline(&self, left: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(left))
    }
    fn read_some(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&mut &*self).read(buf)
    }
}

struct Deadline<'a, S: TimedStream> {
    stream: &'a S,
    until: Instant,
}

impl<S: TimedStream> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_deadline(left)?;
        self.stream.read_some(buf)
    }
}

/// Parse one request with a body of at most `max_body` bytes.
pub fn parse_request<S: TimedStream>(stream: &S, max_body: usize) -> Result<HttpRequest, String> {
    let deadline = Deadline {
        stream,
        until: Instant::now() + REQUEST_DEADLINE,
    };
    let mut reader = BufReader::new(deadline);

    let mut request_line = String::new();
    read_bounded_line(&mut reader, &mut request_line)
        .map_err(|e| format!("read request line: {e}"))?;
    if request_line.len() > MAX_HEADER_BYTES {
        return Err("request line too large".into());
    }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("malformed request line".into());
    }
    let method = parts[0].to_ascii_uppercase();
    let path = parts[1].to_string();

    let mut header_count: usize = 0;
    let mut content_length: usize = 0;
    let mut authorization = None;
    loop {
        let mut line = String::new();
        read_bounded_line(&mut reader, &mut line).map_err(|e| format!("read header: {e}"))?;
        if line.len() > MAX_HEADER_BYTES {
            return Err("header line too large".into());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if header_count >= MAX_HEADERS {
            return Err(format!("too many headers (> {MAX_HEADERS})"));
        }
        header_count += 1;
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| format!("invalid Content-Length: {e}"))?;
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_string());
            }
        }
    }

    let mut body = Vec::new();
    if content_length > max_body {
        return Err(format!("body too large: {content_length} > {max_body}"));
    }
    if content_length > 0 {
        let mut limited = reader.take(content_length as u64);
        limited
            .read_to_end(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
        if body.len() != content_length {
            return Err("request body truncated".into());
        }
    }

    Ok(HttpRequest {
        method,
        path,
        authorization,
        body,
    })
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Write a JSON response. The head is formatted; `body` is written as
/// is, so a body holding a secret is never copied into another buffer.
pub fn write_response_with(
    writer: &mut impl Write,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n",
        reason(status),
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    writer
        .write_all(head.as_bytes())
        .and_then(|()| writer.write_all(body))
        .map_err(|e| format!("write response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_over_a_unix_socket_and_bounds_the_body() {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"GET /v1/secrets HTTP/1.1\r\nAuthorization: Bearer t\r\n\r\n")
            .unwrap();
        let req = parse_request(&a, 0).unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/v1/secrets")
        );
        assert_eq!(req.authorization.as_deref(), Some("Bearer t"));
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
        assert!(parse_request(&a, 0).unwrap_err().contains("too large"));
    }

    #[test]
    fn writes_extra_headers_and_never_caches() {
        let mut out = Vec::new();
        write_response_with(&mut out, 429, &[("Retry-After", "3")], b"{}").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
        assert!(s.contains("Retry-After: 3\r\n") && s.contains("Cache-Control: no-store\r\n"));
        assert!(s.ends_with("\r\n\r\n{}"));
    }
}
