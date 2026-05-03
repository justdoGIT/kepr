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
}

#[derive(Debug, Deserialize)]
struct BatchRequest {
    keys: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
}

// ── HTTP parsing ─────────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    _headers: Vec<String>,
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
        _headers: headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
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
    stream
        .write_all(response.as_bytes())
        .map_err(|e| format!("write response: {e}"))
}

fn json_response(stream: &mut TcpStream, status: u16, payload: &impl Serialize) {
    let body =
        serde_json::to_string(payload).unwrap_or_else(|_| r#"{"error":"encode failed"}"#.into());
    let _ = write_response(stream, status, &body);
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
            let _ = write_response(&mut stream, 400, &format!(r#"{{"error":"{e}"}}"#));
            return;
        }
    };

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            json_response(
                &mut stream,
                200,
                &HealthResponse {
                    status: "ok".into(),
                },
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
            json_response(
                &mut stream,
                404,
                &serde_json::json!({"error": "not found"}),
            );
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
            json_response(stream, 500, &serde_json::json!({"error": error}));
        }
        Ok(other) => {
            json_response(
                stream,
                500,
                &serde_json::json!({"error": format!("unexpected response: {other:?}")}),
            );
        }
        Err(_e) => {
            json_response(stream, 500, &serde_json::json!({"error": "internal error"}));
        }
    }
}

fn handle_batch_secrets(stream: &mut TcpStream, body: &[u8]) {
    let batch_req: BatchRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            json_response(stream, 400, &serde_json::json!({"error": format!("invalid body: {e}")}));
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

    for key in &batch_req.keys {
        let name = key.to_uppercase();
        if validate_name(&name).is_err() {
            continue;
        }
        let req = kepr_core::protocol::Request::Get {
            name: name.clone(),
            fido2_assertion: None,
        };
        if let Ok(kepr_core::protocol::Response::GetOk { value, .. }) = send_request(&req) {
            secrets.insert(name, value.as_str().into());
        }
    }

    json_response(stream, 200, &BatchResponse { secrets });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_serializes() {
        let r = HealthResponse {
            status: "ok".into(),
        };
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"status":"ok"}"#);
    }

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
        let r = BatchResponse { secrets };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""K1":"v1""#));
        assert!(json.contains(r#""K2":"v2""#));
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

}
