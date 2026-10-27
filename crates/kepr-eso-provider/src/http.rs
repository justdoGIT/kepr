// http.rs — the ESO provider's HTTP limits and thin wrappers over
// `kepr_core::http_lite` (the parsing and response writing moved there in
// T11.19 so `kepr serve` shares it). server.rs keeps routing and the
// daemon calls.

use std::net::TcpStream;

pub use kepr_core::http_lite::{ct_eq, HttpRequest};
#[cfg(test)]
pub use kepr_core::http_lite::{read_bounded_line, MAX_HEADER_BYTES};

pub const MAX_BODY_BYTES: usize = 65_536; // 64 KB max HTTP body
pub const MAX_BATCH_KEYS: usize = 100; // max keys per batch request

/// Parse a minimal HTTP request. Only handles what ESO sends — no
/// chunked encoding, no keep-alive, no multi-line headers.
pub fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    kepr_core::http_lite::parse_request(&*stream, MAX_BODY_BYTES)
}

pub fn write_response(
    writer: &mut impl std::io::Write,
    status: u16,
    body: &str,
) -> Result<(), String> {
    kepr_core::http_lite::write_response_with(writer, status, &[], body.as_bytes())
}
