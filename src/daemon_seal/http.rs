// daemon_seal/http.rs — the HTTP transport the KMS sealers use at daemon
// start-up (T4.11, T4.12). Behind a trait so tests can record requests or
// talk to a loopback fake instead of a cloud.
//
// Like the CLI's sync_http.rs: redirects are never followed (a 3xx could
// hand the signed request or bearer token to another host) and replies
// are kept in zeroizing buffers (a decrypt reply holds the master key).
// The system unit has no network; see systemd/kepr.service.d/kms.conf.example.

use std::sync::OnceLock;
use std::time::Duration;

use zeroize::Zeroizing;

pub type Headers = Vec<(String, String)>;

pub trait Transport: Send + Sync {
    /// POST `body` to `url`: `(status, body)` for any HTTP reply, `Err`
    /// only when no reply came back.
    fn post(
        &self,
        url: &str,
        headers: &Headers,
        body: &[u8],
    ) -> Result<(u16, Zeroizing<String>), String>;
}

pub struct UreqTransport;

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .build()
    })
}

impl Transport for UreqTransport {
    fn post(
        &self,
        url: &str,
        headers: &Headers,
        body: &[u8],
    ) -> Result<(u16, Zeroizing<String>), String> {
        let mut req = agent().post(url);
        for (k, v) in headers {
            // ureq derives Host from the URL.
            if !k.eq_ignore_ascii_case("host") {
                req = req.set(k, v);
            }
        }
        match req.send_bytes(body) {
            Ok(r) | Err(ureq::Error::Status(_, r)) => {
                let status = r.status();
                Ok((status, Zeroizing::new(r.into_string().unwrap_or_default())))
            }
            Err(_) => Err("no reply from the key service".into()),
        }
    }
}

/// The provider's error code from a JSON error body, at most 80 chars:
/// AWS `__type`, GCP `error.status`, Azure `error.code`. Never the
/// message or the body itself.
pub fn error_code(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let code = ["/__type", "/error/status", "/error/code"]
        .iter()
        .find_map(|p| v.pointer(p).and_then(|m| m.as_str()))
        .unwrap_or("");
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '#' | '-'))
        .take(80)
        .collect()
}

/// `failed` with the HTTP status and the provider's error code.
pub fn http_error(failed: &str, status: u16, body: &str) -> String {
    match error_code(body) {
        c if c.is_empty() => format!("{failed} (HTTP {status})"),
        c => format!("{failed} (HTTP {status} {c})"),
    }
}

/// Split an `https://host[:port]/path` (or loopback `http://`) URL into
/// `(host, path)`, refusing anything else.
pub fn host_and_path(url: &str) -> Result<(String, String), String> {
    let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(r), _) => (true, r),
        (None, Some(r)) => (false, r),
        _ => return Err(format!("{url}: the key service needs an https:// URL")),
    };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if !ok {
        return Err(format!("{url}: not a key service URL"));
    }
    let name = host.split(':').next().unwrap_or_default();
    if !https && !matches!(name, "127.0.0.1" | "localhost") {
        return Err(format!("{url}: the key service needs an https:// URL"));
    }
    Ok((host.to_string(), path.to_string()))
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    /// One recorded request: URL, headers, body.
    pub type Sent = (String, Headers, Vec<u8>);

    /// Records requests and answers each with the next canned reply.
    pub struct Recorder {
        pub sent: Mutex<Vec<Sent>>,
        pub replies: Mutex<Vec<(u16, String)>>,
    }

    impl Recorder {
        pub fn new(replies: &[(u16, &str)]) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.iter().map(|(s, b)| (*s, b.to_string())).collect()),
            }
        }

        pub fn sent(&self) -> Vec<Sent> {
            self.sent.lock().unwrap().clone()
        }

        pub fn json(&self, i: usize) -> serde_json::Value {
            serde_json::from_slice(&self.sent()[i].2).unwrap()
        }

        pub fn header(&self, i: usize, name: &str) -> Option<String> {
            self.sent()[i]
                .1
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        }
    }

    /// A fake key service on 127.0.0.1 for `n` requests (one connection
    /// each): `reply(head, body)` answers; the requests come back on the
    /// channel. Returns the base URL.
    pub fn loopback(
        n: usize,
        reply: impl Fn(&str, &[u8]) -> (u16, String) + Send + 'static,
    ) -> (String, std::sync::mpsc::Receiver<(String, Vec<u8>)>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..n {
                let (stream, _) = listener.accept().unwrap();
                let mut r = BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let len = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                let (status, out) = reply(&head, &body);
                let mut s = r.into_inner();
                write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                )
                .unwrap();
                let _ = tx.send((head, body));
            }
        });
        (url, rx)
    }

    impl Transport for Recorder {
        fn post(
            &self,
            url: &str,
            headers: &Headers,
            body: &[u8],
        ) -> Result<(u16, Zeroizing<String>), String> {
            self.sent
                .lock()
                .unwrap()
                .push((url.to_string(), headers.clone(), body.to_vec()));
            let mut r = self.replies.lock().unwrap();
            if r.is_empty() {
                return Err("no reply from the key service".into());
            }
            let (s, b) = r.remove(0);
            Ok((s, Zeroizing::new(b)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_never_carry_messages() {
        let aws = r#"{"__type":"AccessDeniedException","message":"User arn:aws:iam::1:user/x"}"#;
        assert_eq!(
            http_error("seal failed", 400, aws),
            "seal failed (HTTP 400 AccessDeniedException)"
        );
        let gcp = r#"{"error":{"code":403,"message":"secret","status":"PERMISSION_DENIED"}}"#;
        assert_eq!(error_code(gcp), "PERMISSION_DENIED");
        let az = r#"{"error":{"code":"Forbidden","message":"no"}}"#;
        assert_eq!(error_code(az), "Forbidden");
        assert_eq!(
            http_error("x", 500, "plain text with a key"),
            "x (HTTP 500)"
        );
    }

    #[test]
    fn urls_must_be_https_or_loopback() {
        assert_eq!(
            host_and_path("https://kms.eu-west-1.amazonaws.com/").unwrap(),
            ("kms.eu-west-1.amazonaws.com".into(), "/".into())
        );
        assert_eq!(
            host_and_path("http://127.0.0.1:8080").unwrap(),
            ("127.0.0.1:8080".into(), "/".into())
        );
        assert!(host_and_path("http://kms.example.com/").is_err());
        assert!(host_and_path("http://127.0.0.1.evil.com/").is_err());
        assert!(host_and_path("https://user@evil.com/").is_err());
        assert!(host_and_path("ftp://x/").is_err());
    }
}
