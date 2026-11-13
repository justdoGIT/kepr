//! Bounded MCP frames and bounded provider response processing.

use std::collections::HashMap;
use std::io::{BufRead, Read};
use std::time::Duration;

use super::{Attempt, Gate};
use serde_json::Value;

pub const MAX_FRAME: usize = 64 * 1024;
pub const MAX_BODY: usize = 64 * 1024;

pub fn read_frame(reader: &mut impl BufRead) -> Result<Option<String>, &'static str> {
    let mut raw = Vec::new();
    reader
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut raw)
        .map_err(|_| "could not read MCP frame")?;
    if raw.len() > MAX_FRAME {
        return Err("MCP frame exceeds 64 KiB; connection closed");
    }
    if raw.is_empty() {
        return Ok(None);
    }
    String::from_utf8(raw)
        .map(Some)
        .map_err(|_| "invalid UTF-8 MCP frame")
}

pub fn read_body(reader: impl Read) -> Result<String, String> {
    let mut raw = Vec::new();
    reader
        .take((MAX_BODY + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "could not read provider response".to_string())?;
    if raw.len() > MAX_BODY {
        return Err("provider response exceeds 64 KiB".into());
    }
    String::from_utf8(raw).map_err(|_| "provider response is not UTF-8".into())
}

pub fn validate_api(
    provider: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: Option<&Value>,
) -> Result<HashMap<String, String>, String> {
    if !kepr_core::providers::PROVIDERS
        .iter()
        .any(|p| p.name == provider)
    {
        return Err("unknown API provider".into());
    }
    if !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err("unsupported API method".into());
    }
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.len() > 4096
        || path.contains(['\\', '#'])
        || path.bytes().any(|c| c <= 32 || c == 127)
    {
        return Err("path must be a valid path on the provider's host".into());
    }
    if body.is_some_and(|b| b.len() > MAX_BODY) {
        return Err("API request body exceeds 64 KiB".into());
    }
    let mut out = HashMap::new();
    if let Some(headers) = headers {
        let headers = headers.as_object().ok_or("headers must be an object")?;
        if headers.len() > 32 {
            return Err("too many API headers".into());
        }
        for (name, value) in headers {
            let value = value.as_str().ok_or("header values must be strings")?;
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || value.len() > 4096
                || value.bytes().any(|c| c < 32 || c == 127)
            {
                return Err("invalid API header".into());
            }
            if out
                .insert(name.to_ascii_lowercase(), value.to_string())
                .is_some()
            {
                return Err("duplicate API header".into());
            }
        }
    }
    Ok(out)
}

pub fn http_attempt(
    gate: &Gate,
    provider: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    headers: &HashMap<String, String>,
) -> Result<Attempt<(u16, String)>, String> {
    let ph = gate
        .placeholders
        .get(provider)
        .ok_or("provider is outside this MCP credential grant")?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(30))
        .build();
    let mut req = agent.request(
        method,
        &format!("http://127.0.0.1:{}/{provider}{path}", gate.port),
    );
    for (name, value) in headers {
        if !matches!(
            name.as_str(),
            "authorization" | "x-api-key" | "x-goog-api-key" | "host"
        ) {
            req = req.set(name, value);
        }
    }
    req = req.set("authorization", &format!("Bearer {ph}"));
    let response = match body {
        Some(b) => req.send_string(b),
        None => req.call(),
    };
    match response {
        Ok(response) | Err(ureq::Error::Status(_, response)) => {
            let status = response.status();
            let body = read_body(response.into_reader())?;
            let body = crate::cli_gatex::mcp_tools::scrub(&body, &[ph]);
            Ok(Attempt::Done((status, body)))
        }
        Err(ureq::Error::Transport(_)) => Ok(Attempt::Unavailable(
            crate::cli_gatex::mcp_tools::GATE_GONE.into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_gatex::mcp_tools::McpConfig;
    use std::io::Cursor;

    #[test]
    fn frames_are_bounded_before_json_and_keep_separate_messages() {
        let mut input = Cursor::new(b"{}\n{}\n");
        assert_eq!(read_frame(&mut input), Ok(Some("{}\n".into())));
        assert_eq!(read_frame(&mut input), Ok(Some("{}\n".into())));
        assert_eq!(read_frame(&mut input), Ok(None));
        let mut large = Cursor::new(vec![b'x'; MAX_FRAME + 20]);
        assert!(read_frame(&mut large).is_err());
        assert_eq!(large.position(), (MAX_FRAME + 1) as u64);
        assert!(read_frame(&mut Cursor::new(vec![255])).is_err());
    }

    #[test]
    fn response_reader_stops_before_allocating_the_remaining_body() {
        let mut large = Cursor::new(vec![b'x'; MAX_BODY + 20]);
        assert!(read_body(&mut large).unwrap_err().contains("exceeds"));
        assert_eq!(large.position(), (MAX_BODY + 1) as u64);
        assert_eq!(
            read_body(Cursor::new(vec![b'x'; MAX_BODY])).unwrap().len(),
            MAX_BODY
        );
        assert!(read_body(Cursor::new(vec![255])).is_err());
    }

    #[test]
    fn invalid_headers_and_paths_never_reach_http_processing() {
        for path in [
            "//other/x",
            "/x#fragment",
            "/x\nInjected: true",
            "/x\\other",
        ] {
            assert!(validate_api("openai", "GET", path, None, None).is_err());
        }
        for headers in [
            serde_json::json!({"x-test": "one\r\nInjected: two"}),
            serde_json::json!({"x-test": 1}),
            serde_json::json!({"x-test": "one", "X-Test": "two"}),
            serde_json::json!([]),
        ] {
            assert!(validate_api("openai", "GET", "/v1/models", None, Some(&headers)).is_err());
        }
        assert!(validate_api("other", "GET", "/v1/models", None, None).is_err());
    }

    fn fake_http(body: Vec<u8>, redirect: Option<String>) -> (Gate, std::thread::JoinHandle<()>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = std::io::BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                request.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            let (status, location) = redirect.map_or((200, String::new()), |url| {
                (302, format!("Location: {url}\r\n"))
            });
            let head = format!(
                "HTTP/1.1 {status} OK\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream
                .write_all(head.as_bytes())
                .and_then(|_| stream.write_all(&body));
        });
        (
            Gate {
                port,
                placeholders: HashMap::from([("openai".into(), "session-marker".into())]),
                db_ports: HashMap::new(),
                grant: McpConfig::default().grant_for("db_query"),
            },
            thread,
        )
    }

    #[test]
    fn actual_http_response_is_bounded_and_masks_session_markers() {
        let (gate, server) = fake_http(vec![b'x'; MAX_BODY + 1], None);
        assert!(
            http_attempt(&gate, "openai", "GET", "/v1/models", None, &HashMap::new())
                .err()
                .unwrap()
                .contains("exceeds")
        );
        server.join().unwrap();
        let (gate, server) = fake_http(b"echo session-marker".to_vec(), None);
        match http_attempt(&gate, "openai", "GET", "/v1/models", None, &HashMap::new()).unwrap() {
            Attempt::Done((200, body)) => assert_eq!(body, "echo [redacted]"),
            _ => panic!("expected bounded HTTP response"),
        }
        server.join().unwrap();
    }

    #[test]
    fn actual_http_redirect_is_never_followed() {
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        other.set_nonblocking(true).unwrap();
        let target = format!("http://{}/outside", other.local_addr().unwrap());
        let (gate, server) = fake_http(Vec::new(), Some(target));
        match http_attempt(&gate, "openai", "GET", "/v1/models", None, &HashMap::new()).unwrap() {
            Attempt::Done((302, _)) => {}
            _ => panic!("expected unfollowed redirect"),
        }
        server.join().unwrap();
        assert_eq!(
            other.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
