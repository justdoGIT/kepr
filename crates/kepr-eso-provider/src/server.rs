// HTTP handler for the ESO webhook provider. Uses only std::net so
// there's no HTTP framework dependency — the server handles at most a
// few ESO polling requests per minute.

use std::io::Write;
use std::net::TcpStream;

use crate::http::{ct_eq, parse_request, write_response, HttpRequest, MAX_BATCH_KEYS};

use serde::{Deserialize, Serialize};

use crate::client::send_request;

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
                "invalid character '{c}' — only A-Z, 0-9, underscore allowed"
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

fn authorized(request: &HttpRequest, expected: Option<&str>) -> bool {
    match expected {
        Some(token) => request
            .authorization
            .as_deref()
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|given| ct_eq(given.as_bytes(), token.as_bytes())),
        None => true,
    }
}

fn json_response(writer: &mut impl Write, status: u16, payload: &impl Serialize) {
    let body = serde_json::to_string(payload).unwrap_or_else(|e| {
        eprintln!("kepr-eso-provider: json_response serialize failed: {e}");
        r#"{"error":"encode failed"}"#.into()
    });
    if let Err(e) = write_response(writer, status, &body) {
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
pub fn handle_connection(mut stream: TcpStream, auth_token: Option<&str>) {
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

    let protected = req.path == "/v1/secrets" || req.path.starts_with("/v1/secrets/");
    if protected && !authorized(&req, auth_token) {
        json_response(
            &mut stream,
            401,
            &serde_json::json!({"error": "unauthorized"}),
        );
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            json_response(&mut stream, 200, &serde_json::json!({"status": "ok"}));
        }

        ("GET", path) if path.starts_with("/v1/secrets/") => {
            let name = path
                .strip_prefix("/v1/secrets/")
                .unwrap_or("")
                .to_ascii_uppercase();
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
            json_response(
                stream,
                500,
                &serde_json::json!({"error": format!("daemon error: {error}")}),
            );
        }
        Ok(other) => {
            eprintln!("kepr-eso-provider: GET {name} unexpected response: {other:?}");
            json_response(
                stream,
                500,
                &serde_json::json!({"error": "unexpected daemon response"}),
            );
        }
        Err(e) => {
            eprintln!("kepr-eso-provider: send_request(GET {name}) transport error: {e}");
            json_response(
                stream,
                500,
                &serde_json::json!({"error": "daemon unreachable"}),
            );
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
        let name = key.to_ascii_uppercase();
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
                errors.insert(name, "daemon unreachable".into());
            }
        }
    }

    let errors = if errors.is_empty() {
        None
    } else {
        Some(errors)
    };
    json_response(stream, 200, &BatchResponse { secrets, errors });
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    #[test]
    fn ct_eq_and_bounded_lines() {
        assert!(crate::http::ct_eq(b"token", b"token"));
        assert!(!crate::http::ct_eq(b"token", b"tokeN"));
        assert!(!crate::http::ct_eq(b"tok", b"token"));
        let big = vec![b'a'; crate::http::MAX_HEADER_BYTES * 4];
        let mut r = std::io::BufReader::new(&big[..]);
        let mut line = String::new();
        crate::http::read_bounded_line(&mut r, &mut line).unwrap();
        assert_eq!(
            line.len(),
            crate::http::MAX_HEADER_BYTES + 1,
            "never buffers past the limit"
        );
    }

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
    fn bearer_auth_requires_exact_expected_token() {
        let request = HttpRequest {
            method: "GET".into(),
            path: "/v1/secrets/KEY".into(),
            authorization: Some("Bearer secret".into()),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert!(authorized(&request, Some("secret")));
        assert!(!authorized(&request, Some("other")));
        assert!(!authorized(&request, Some("secret ")));
        assert!(authorized(&request, None));
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
        let keys: Vec<String> = (0..101).map(|i| format!("K{i}")).collect();
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
            s.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
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
        let req = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", large.len());
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
        handle_connection(stream, None);
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
        handle_connection(stream, None);
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
        handle_connection(stream, None);
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
        handle_connection(stream, None);
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
        json_response(&mut buf, 200, &serde_json::json!({"key": "val"}));
        let resp = String::from_utf8(buf).unwrap();
        assert!(resp.contains(r#"{"key":"val"}"#));
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Type: application/json"));
    }
}
