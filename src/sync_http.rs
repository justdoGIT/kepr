// sync_http.rs — the one HTTP agent for the cloud sync backends and the
// breach-range lookup, and safe error text for their replies.
//
// - Redirects are never followed: ureq re-sends custom headers such as
//   `X-Vault-Token` to wherever a 3xx points (it strips only
//   `Authorization` and `Cookie`), which would hand the token to another
//   host.
// - Error messages carry the HTTP status and the provider's own error
//   message fields, never the raw body: a reply can hold secret material.

use std::sync::OnceLock;
use std::time::Duration;

pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .build()
    })
}

/// Send `req` (with `body`, if any): `(status, body)` for any HTTP reply,
/// `Err` only for transport failures.
pub fn send(req: ureq::Request, body: Option<&[u8]>) -> Result<(u16, String), String> {
    let r = match body {
        Some(b) => req.send_bytes(b),
        None => req.call(),
    };
    match r {
        Ok(r) | Err(ureq::Error::Status(_, r)) => {
            let status = r.status();
            Ok((status, r.into_string().unwrap_or_default()))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// The provider's error message from a JSON error body (`message`,
/// `Message`, `error.message`, `errors[0]`, `__type`), at most 200 chars.
pub fn error_summary(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let msg = [
        "/message",
        "/Message",
        "/error/message",
        "/errors/0",
        "/__type",
    ]
    .iter()
    .find_map(|p| v.pointer(p).and_then(|m| m.as_str()))
    .unwrap_or("");
    msg.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_summary_never_echoes_the_body() {
        assert_eq!(
            error_summary(r#"{"errors":["permission denied"]}"#),
            "permission denied"
        );
        assert_eq!(
            error_summary(r#"{"__type":"ResourceNotFoundException","x":"y"}"#),
            "ResourceNotFoundException"
        );
        assert_eq!(
            error_summary(r#"{"data":{"data":{"password":"hunter2"}}}"#),
            ""
        );
        assert_eq!(error_summary("not json hunter2"), "");
    }
}
