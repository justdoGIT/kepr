// http.rs — the minimal HTTP/1.1 request parsing and response writing
// the ESO provider needs (std::net only, no framework). Split out of
// server.rs, which keeps routing and the daemon calls.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

pub const MAX_BODY_BYTES: usize = 65_536; // 64 KB max HTTP body
pub const MAX_BATCH_KEYS: usize = 100; // max keys per batch request
const MAX_HEADERS: usize = 64; // cap header count to prevent memory exhaustion
pub const MAX_HEADER_BYTES: usize = 8_192; // bound a single request/header line
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

/// Parse a minimal HTTP request. Only handles what ESO sends — no
/// chunked encoding, no keep-alive, no multi-line headers.
/// One deadline for reading the whole request: the socket timeout alone
/// restarts on every byte, so a client trickling headers could hold a
/// worker indefinitely.
pub const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

struct Deadline<'a> {
    stream: &'a TcpStream,
    until: std::time::Instant,
}

impl std::io::Read for Deadline<'_> {
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

pub fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let deadline = Deadline {
        stream: &*stream,
        until: std::time::Instant::now() + REQUEST_DEADLINE,
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
    if content_length > MAX_BODY_BYTES {
        return Err(format!(
            "body too large: {content_length} > {MAX_BODY_BYTES}"
        ));
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

pub fn write_response(writer: &mut impl Write, status: u16, body: &str) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    writer
        .write_all(response.as_bytes())
        .map_err(|e| format!("write response: {e}"))
}
