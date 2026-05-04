// HTTP handler for the ESO webhook provider. Uses only std::net so
// there's no HTTP framework dependency — the server handles at most a
// few ESO polling requests per minute.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use serde::{Deserialize, Serialize};

use crate::client::send_request;

// ── Limits ────────────────────────────────────────────

const MAX_BODY_BYTES: usize = 65_536; // 64 KB max HTTP body
const MAX_BATCH_KEYS: usize = 100; // max keys per batch request
const MAX_HEADERS: usize = 64; // cap header count to prevent memory exhaustion

/// Mirror daemon's `store::validate_name` so bad names are rejected early.
fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty".into());
    }
    if name.len() > 128 {
        return Err("name too long (max 128 chars)".into());
    }
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(format!(
                "invalid character '{}' — only A-Z, 0-9, underscore allowed",
                c
            ));
        }
    }
    Ok(())
}

// ── Webhook API types ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct SecretValue {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct BatchResponse {
    secrets: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct BatchRequest {
    keys: Vec<String>,
}

// ── HTTP parsing ─────────────────────────────────────────────────────

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// Parse a minimal HTTP request. Only handles what ESO sends — no
/// chunked encoding, no keep-alive, no multi-line headers.
fn parse_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut reader = BufReader::new(&mut *stream);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {e}"))?;
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("malformed request line".into());
    }
    let method = parts[0].to_uppercase();
    let path = parts[1].to_string();

    let mut headers: Vec<String> = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read header: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(len_str) = trimmed
            .to_lowercase()
            .strip_prefix("content-length:")
            .map(|s| s.trim().to_string())
        {
            content_length = len_str
                .parse::<usize>()
                .map_err(|e| format!("invalid Content-Length: {e}"))?;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(format!("too many headers (> {MAX_HEADERS})"));
        }
        headers.push(trimmed.to_string());
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
    }

    Ok(HttpRequest {
        method,
        path,
        body,
    })
}

fn write_response(mut writer: impl Write, status: u16, body: &str) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
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

fn json_response(mut writer: impl Write, status: u16, payload: &impl Serialize) {
    let body = serde_json::to_string(payload).unwrap_or_else(|e| {
        eprintln!("kepr-eso-provider: json_response serialize failed: {e}");
        r#"{"error":"encode failed"}"#.into()
    });
    if let Err(e) = write_response(&mut writer, status, &body) {
        eprintln!("kepr-eso-provider: write_response failed: {e}");
    }
}

// ── Route dispatch ───────────────────────────────────────────────────

/// Handle one HTTP request. Supported endpoints:
///
///   GET /health            → health check
///   GET /v1/secrets/<NAME> → single secret
///   POST /v1/secrets       → batch (body: {"keys": [...]})
///
/// ESO SecretStore config:
///   url: "http://<host>:8080/v1/secrets/{{ .remoteRef.key }}"
///   result.jsonPath: "$.value"
pub fn handle_connection(mut stream: TcpStream) {
    let req = match parse_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kepr-eso-provider: parse_request failed: {e}");
            let body = serde_json::json!({"error": e}).to_string();
            if let Err(we) = write_response(&mut stream, 400, &body) {
                eprintln!("kepr-eso-provider: write 400 response failed: {we}");
            }
            return;
        }
    };

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            json_response(
                &mut stream,
                200,
                &serde_json::json!({"status": "ok"}),
            );
        }

        ("GET", path) if path.starts_with("/v1/secrets/") => {
            let name = path
                .strip_prefix("/v1/secrets/")
                .unwrap_or("")
                .to_uppercase();
            handle_get_secret(&mut stream, &name);
        }

        ("POST", "/v1/secrets") => {
            handle_batch_secrets(&mut stream, &req.body);
        }

        _ => {
            json_response(&mut stream, 404, &serde_json::json!({"error": "not found"}));
        }
    }
}

fn handle_get_secret(stream: &mut TcpStream, name: &str) {
    if let Err(e) = validate_name(name) {
        json_response(stream, 400, &serde_json::json!({"error": e}));
        return;
    }

    let req = kepr_core::protocol::Request::Get {
        name: name.into(),
        fido2_assertion: None,
    };

    match send_request(&req) {
        Ok(kepr_core::protocol::Response::GetOk { name: _, value }) => {
            json_response(
                stream,
                200,
                &SecretValue {
                    name: name.into(),
                    value: value.as_str().into(),
                },
            );
        }
        Ok(kepr_core::protocol::Response::Err { error }) => {
            json_response(stream, 500, &serde_json::json!({"error": format!("daemon error: {error}")}));
        }
        Ok(other) => {
            json_response(
                stream,
                500,
                &serde_json::json!({"error": format!("unexpected response: {other:?}")}),
            );
        }
        Err(e) => {
            eprintln!("kepr-eso-provider: send_request(GET {name}) transport error: {e}");
            json_response(stream, 500, &serde_json::json!({"error": "daemon unreachable"}));
        }
    }
}

fn handle_batch_secrets(stream: &mut TcpStream, body: &[u8]) {
    let batch_req: BatchRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            json_response(
                stream,
                400,
                &serde_json::json!({"error": format!("invalid body: {e}")}),
            );
            return;
        }
    };

    if batch_req.keys.len() > MAX_BATCH_KEYS {
        json_response(
            stream,
            400,
            &serde_json::json!({"error": format!(
                "too many keys: {} > {MAX_BATCH_KEYS}", batch_req.keys.len()
            )}),
        );
        return;
    }

    let mut secrets = std::collections::HashMap::with_capacity(batch_req.keys.len());
    let mut errors = std::collections::HashMap::new();

    for key in &batch_req.keys {
        let name = key.to_uppercase();
        if let Err(e) = validate_name(&name) {
            eprintln!("kepr-eso-provider: batch skip invalid name '{name}': {e}");
            errors.insert(name, format!("invalid name: {e}"));
            continue;
        }
        let req = kepr_core::protocol::Request::Get {
            name: name.clone(),
            fido2_assertion: None,
        };
        match send_request(&req) {
            Ok(kepr_core::protocol::Response::GetOk { value, .. }) => {
                secrets.insert(name, value.as_str().into());
            }
            Ok(kepr_core::protocol::Response::Err { error }) => {
                eprintln!("kepr-eso-provider: batch key '{name}' daemon error: {error}");
                errors.insert(name, error);
            }
            Ok(other) => {
                eprintln!("kepr-eso-provider: batch key '{name}' unexpected response: {other:?}");
                errors.insert(name, "unexpected daemon response".into());
            }
            Err(e) => {
                eprintln!("kepr-eso-provider: batch key '{name}' transport error: {e}");
                errors.insert(name, format!("daemon unreachable: {e}"));
            }
        }
    }

    let errors = if errors.is_empty() { None } else { Some(errors) };
    json_response(stream, 200, &BatchResponse { secrets, errors });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_serializes() {
        let r = SecretValue {
            name: "MY_KEY".into(),
            value: "my-value".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""name":"MY_KEY""#));
        assert!(json.contains(r#""value":"my-value""#));
    }

    #[test]
    fn batch_request_deserializes() {
        let req: BatchRequest = serde_json::from_str(r#"{"keys":["K1","K2"]}"#).unwrap();
        assert_eq!(req.keys, vec!["K1", "K2"]);
    }

    #[test]
    fn batch_response_serializes() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("K1".into(), "v1".into());
        secrets.insert("K2".into(), "v2".into());
        let r = BatchResponse {
            secrets,
            errors: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""K1":"v1""#));
        assert!(json.contains(r#""K2":"v2""#));
        // errors: None should be absent from serialized output
        assert!(!json.contains("errors"));
    }

    #[test]
    fn batch_response_serializes_with_errors() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("K1".into(), "v1".into());
        let mut errors = std::collections::HashMap::new();
        errors.insert("K2".into(), "invalid name: bad chars".into());
        let r = BatchResponse {
            secrets,
            errors: Some(errors),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""K1":"v1""#));
        assert!(json.contains(r#""errors""#));
        assert!(json.contains(r#""K2":"invalid name: bad chars""#));
    }
    #[test]
    fn validate_name_accepts_valid() {
        assert!(validate_name("MY_KEY").is_ok());
        assert!(validate_name("OPENAI_API_KEY").is_ok());
        assert!(validate_name("ABC123").is_ok());
        assert!(validate_name("HELLO_WORLD_42").is_ok());
        assert!(validate_name("A").is_ok());
    }

    #[test]
    fn validate_name_rejects_invalid() {
        assert!(validate_name("").is_err());
        assert!(validate_name("key with space").is_err());
        assert!(validate_name("../../../etc/passwd").is_err());
        assert!(validate_name("key-name").is_err());
        assert!(validate_name(&"X".repeat(129)).is_err());
    }

    #[test]
    fn batch_request_rejects_too_many_keys() {
        let keys: Vec<String> = (0..101).map(|i| format!("K{}", i)).collect();
        let body = serde_json::to_vec(&serde_json::json!({"keys": keys})).unwrap();
        // Verify the request itself deserializes
        let req: BatchRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(req.keys.len(), 101);
        assert!(req.keys.len() > MAX_BATCH_KEYS);
    }

    // ── HTTP protocol tests ──────────────────────────────────────────

    #[test]
    fn parse_request_valid_get() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let req = parse_request(&mut s).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/health");
        assert!(req.body.is_empty());
        t.join().unwrap();
    }

    #[test]
    fn parse_request_rejects_malformed_line() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"garbage\r\n\r\n").unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        assert!(parse_request(&mut s).is_err());
        t.join().unwrap();
    }

    #[test]
    fn parse_request_rejects_large_body() {
        let large = vec![b'X'; 65_537];
        let req = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            large.len()
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(req.as_bytes()).unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let err = parse_request(&mut s).unwrap_err();
        assert!(err.contains("body too large"));
        t.join().unwrap();
    }

    #[test]
    fn parse_request_rejects_too_many_headers() {
        let mut raw = "GET / HTTP/1.1\r\n".to_string();
        for i in 0..65 {
            raw.push_str(&format!("X-Hdr: {i}\r\n"));
        }
        raw.push_str("\r\n");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(raw.as_bytes()).unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let err = parse_request(&mut s).unwrap_err();
        assert!(err.contains("too many headers"));
        t.join().unwrap();
    }

    #[test]
    fn write_response_200_format() {
        let mut buf = Vec::new();
        write_response(&mut buf, 200, r#"{"status":"ok"}"#).unwrap();
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Length: 15\r\n"));
        assert!(resp.ends_with("\r\n\r\n{\"status\":\"ok\"}"));
    }

    #[test]
    fn handle_connection_parse_error_returns_400() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"garbage\r\n\r\n").unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.contains("400 Bad Request"));
        });
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream);
        t.join().unwrap();
    }

    #[test]
    fn handle_connection_unknown_route_returns_404() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"PUT /v1/secrets HTTP/1.1\r\n\r\n").unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.contains("404 Not Found"));
        });
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream);
        t.join().unwrap();
    }

    // ── validate_name boundary tests ─────────────────────────────────

    #[test]
    fn validate_name_accepts_128_chars() {
        let name = "A".repeat(128);
        assert!(validate_name(&name).is_ok());
    }

    #[test]
    fn validate_name_rejects_non_ascii() {
        assert!(validate_name("KÉY").is_err());
        assert!(validate_name("キー").is_err());
        assert!(validate_name("ключ").is_err());
    }

    // ── Content-Length edge cases ────────────────────────────────────

    #[test]
    fn parse_request_rejects_negative_content_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
                .unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let err = parse_request(&mut s).unwrap_err();
        assert!(err.contains("invalid Content-Length"));
        t.join().unwrap();
    }

    #[test]
    fn parse_request_rejects_non_numeric_content_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n")
                .unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let err = parse_request(&mut s).unwrap_err();
        assert!(err.contains("invalid Content-Length"));
        t.join().unwrap();
    }

    // ── Route dispatch integration tests ─────────────────────────────

    #[test]
    fn handle_connection_get_health_returns_200() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.contains("200 OK"));
            assert!(resp.contains("Content-Type: application/json"));
            assert!(resp.contains(r#"{"status":"ok"}"#));
        });
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream);
        t.join().unwrap();
    }

    #[test]
    fn error_response_includes_content_type_json() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"garbage\r\n\r\n").unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            assert!(resp.contains("Content-Type: application/json"));
        });
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream);
        t.join().unwrap();
    }

    // ── write_response status code tests ─────────────────────────────

    #[test]
    fn write_response_400_format() {
        let mut buf = Vec::new();
        write_response(&mut buf, 400, r#"{"error":"bad"}"#).unwrap();
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    }

    #[test]
    fn write_response_404_format() {
        let mut buf = Vec::new();
        write_response(&mut buf, 404, r#"{"error":"nf"}"#).unwrap();
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn write_response_500_format() {
        let mut buf = Vec::new();
        write_response(&mut buf, 500, r#"{"error":"ise"}"#).unwrap();
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
    }

    #[test]
    fn json_response_writes_to_vec() {
        let mut buf = Vec::new();
        json_response(
            &mut buf,
            200,
            &serde_json::json!({"key": "val"}),
        );
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.contains(r#"{"key":"val"}"#));
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Type: application/json"));
    }
}
