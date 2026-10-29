// cli_session/serve_route.rs — the request policy of `kepr serve`
// (T11.19), kept free of sockets so it can be tested whole:
//
//   GET /v1/secrets        `list`: credential names (no values; sealed,
//                          SSH and share keys are left out)
//   GET /v1/secrets/NAME   `get`: {"name","value"} through the daemon's
//                          `GetQuiet`, which refuses sealed, SSH and
//                          share-key credentials and anything needing a
//                          prompt (consent, FIDO2, re-authentication)
//
// Order: method (405) → bearer token, constant-time (401; failures have
// their own small bucket → 429) → the token's rate limit (429 +
// Retry-After) → route (404) → `--allow` (403).

use std::sync::Mutex;
use std::time::Instant;

use kepr_core::generate::ZeroString;
use kepr_core::http_lite::{ct_eq, HttpRequest};
use serde::Serialize;
use zeroize::Zeroizing;

/// Token bucket: `per_min` requests a minute, bursts up to `per_min`.
pub struct Bucket {
    cap: f64,
    tokens: f64,
    per_sec: f64,
    last: Option<Instant>,
}

impl Bucket {
    pub fn per_minute(per_min: u32) -> Self {
        let cap = f64::from(per_min.max(1));
        Bucket {
            cap,
            tokens: cap,
            per_sec: cap / 60.0,
            last: None,
        }
    }

    /// Take one; `Err(seconds)` until one is back.
    pub fn take(&mut self, now: Instant) -> Result<(), u64> {
        if let Some(last) = self.last {
            let dt = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + dt * self.per_sec).min(self.cap);
        }
        self.last = Some(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - self.tokens) / self.per_sec).ceil().max(1.0) as u64)
        }
    }
}

/// What `kepr serve` asks the daemon (tests pass a fake).
pub trait Vault {
    fn list(&self) -> Result<Vec<String>, String>;
    fn get(&self, name: &str) -> Result<ZeroString, String>;
}

pub struct Policy {
    pub token: Zeroizing<String>,
    pub allow_list: bool,
    pub allow_get: bool,
    pub ok: Mutex<Bucket>,
    pub failed: Mutex<Bucket>,
}

pub struct Reply {
    pub status: u16,
    pub retry_after: Option<u64>,
    /// JSON; may hold a value, so it is wiped when dropped.
    pub body: Zeroizing<Vec<u8>>,
}

fn reply(status: u16, body: impl Serialize) -> Reply {
    let mut out = Zeroizing::new(Vec::new());
    let _ = serde_json::to_writer(&mut *out, &body);
    Reply {
        status,
        retry_after: None,
        body: out,
    }
}

/// `{"name","value"}`. The buffer is sized for the worst-case escaping
/// up front: growing it would free copies of the value unwiped.
fn secret(name: &str, value: &str) -> Reply {
    let mut out = Zeroizing::new(Vec::with_capacity(secret_capacity(name, value)));
    let _ = serde_json::to_writer(&mut *out, &Secret { name, value });
    Reply {
        status: 200,
        retry_after: None,
        body: out,
    }
}

fn secret_capacity(name: &str, value: &str) -> usize {
    32 + 6 * (name.len() + value.len()) // `\u00XX` is the longest escape
}

fn error(status: u16, msg: &str) -> Reply {
    reply(status, serde_json::json!({ "error": msg }))
}

/// A request that didn't parse.
pub fn bad_request() -> Reply {
    error(400, "bad request")
}

fn limited(secs: u64) -> Reply {
    Reply {
        retry_after: Some(secs),
        ..error(429, "rate limit")
    }
}

#[derive(Serialize)]
struct Secret<'a> {
    name: &'a str,
    value: &'a str,
}

fn valid_name(n: &str) -> bool {
    (1..=128).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl Policy {
    fn authorized(&self, req: &HttpRequest) -> bool {
        let given = req
            .authorization
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            .unwrap_or("");
        ct_eq(given.as_bytes(), self.token.as_bytes())
    }

    pub fn route(&self, req: &HttpRequest, now: Instant, vault: &dyn Vault) -> Reply {
        if req.method != "GET" {
            return error(405, "only GET");
        }
        if !self.authorized(req) {
            let mut b = self.failed.lock().unwrap_or_else(|p| p.into_inner());
            return match b.take(now) {
                Ok(()) => error(401, "a valid bearer token is required"),
                Err(s) => limited(s),
            };
        }
        if let Err(s) = self.ok.lock().unwrap_or_else(|p| p.into_inner()).take(now) {
            return limited(s);
        }
        let path = req.path.split('?').next().unwrap_or("");
        match path.strip_prefix("/v1/secrets") {
            Some("" | "/") if !self.allow_list => error(403, "list is not allowed (--allow)"),
            Some("" | "/") => match vault.list() {
                Ok(names) => {
                    let rows: Vec<_> = names
                        .iter()
                        .map(|n| serde_json::json!({ "name": n }))
                        .collect();
                    reply(200, serde_json::json!({ "secrets": rows }))
                }
                Err(_) => error(503, "the credential service is unavailable"),
            },
            Some(rest) => {
                let Some(name) = rest.strip_prefix('/').filter(|n| valid_name(n)) else {
                    return error(404, "not found");
                };
                if !self.allow_get {
                    return error(403, "get is not allowed (--allow)");
                }
                let name = name.to_uppercase();
                match vault.get(&name) {
                    Ok(v) => secret(&name, v.as_str()),
                    Err(_) => error(404, "credential unavailable"),
                }
            }
            None => error(404, "not found"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Fake;
    impl Vault for Fake {
        fn list(&self) -> Result<Vec<String>, String> {
            Ok(vec!["DB".into()])
        }
        fn get(&self, name: &str) -> Result<ZeroString, String> {
            match name {
                "DB" => Ok(ZeroString::from_string("s3cret".into())),
                _ => Err("credential unavailable".into()), // sealed, ssh, missing
            }
        }
    }

    #[test]
    fn the_secret_body_never_regrows() {
        let value: String = (0u8..32).map(char::from).cycle().take(500).collect();
        let r = secret("DB", &value);
        assert_eq!(r.body.capacity(), secret_capacity("DB", &value));
        let back: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(back["value"], value.as_str());
    }

    fn policy(list: bool, get: bool, per_min: u32) -> Policy {
        Policy {
            token: Zeroizing::new("t0ken-t0ken-t0ken".into()),
            allow_list: list,
            allow_get: get,
            ok: Mutex::new(Bucket::per_minute(per_min)),
            failed: Mutex::new(Bucket::per_minute(3)),
        }
    }

    fn req(method: &str, path: &str, auth: Option<&str>) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            authorization: auth.map(String::from),
            headers: vec![],
            body: vec![],
        }
    }

    const AUTH: Option<&str> = Some("Bearer t0ken-t0ken-t0ken");

    fn body(r: &Reply) -> serde_json::Value {
        serde_json::from_slice(&r.body).unwrap()
    }

    #[test]
    fn missing_or_wrong_token_is_401_then_429() {
        let p = policy(true, true, 60);
        let t = Instant::now();
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", None), t, &Fake).status,
            401
        );
        let wrong = Some("Bearer t0ken-t0ken-t0keN");
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", wrong), t, &Fake).status,
            401
        );
        assert_eq!(
            p.route(
                &req("GET", "/v1/secrets", Some("t0ken-t0ken-t0ken")),
                t,
                &Fake
            )
            .status,
            401
        );
        let r = p.route(&req("GET", "/v1/secrets", None), t, &Fake);
        assert_eq!((r.status, r.retry_after.is_some()), (429, true));
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", AUTH), t, &Fake).status,
            200
        );
    }

    #[test]
    fn ops_outside_the_allowlist_are_403() {
        let t = Instant::now();
        let only_list = policy(true, false, 60);
        assert_eq!(
            only_list
                .route(&req("GET", "/v1/secrets/DB", AUTH), t, &Fake)
                .status,
            403
        );
        let r = only_list.route(&req("GET", "/v1/secrets", AUTH), t, &Fake);
        assert_eq!(body(&r), serde_json::json!({"secrets": [{"name": "DB"}]}));
        let only_get = policy(false, true, 60);
        assert_eq!(
            only_get
                .route(&req("GET", "/v1/secrets", AUTH), t, &Fake)
                .status,
            403
        );
        let r = only_get.route(&req("GET", "/v1/secrets/db", AUTH), t, &Fake);
        assert_eq!(
            body(&r),
            serde_json::json!({"name": "DB", "value": "s3cret"})
        );
    }

    #[test]
    fn rate_limit_is_429_with_retry_after_and_refills() {
        let p = policy(true, true, 2);
        let t = Instant::now();
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", AUTH), t, &Fake).status,
            200
        );
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", AUTH), t, &Fake).status,
            200
        );
        let r = p.route(&req("GET", "/v1/secrets", AUTH), t, &Fake);
        assert_eq!((r.status, r.retry_after), (429, Some(30)));
        let later = t + Duration::from_secs(30);
        assert_eq!(
            p.route(&req("GET", "/v1/secrets", AUTH), later, &Fake)
                .status,
            200
        );
    }

    #[test]
    fn refused_values_and_odd_requests() {
        let p = policy(true, true, 60);
        let t = Instant::now();
        let r = p.route(&req("GET", "/v1/secrets/SEALED_KEY", AUTH), t, &Fake);
        assert_eq!(
            (r.status, body(&r)["error"].as_str()),
            (404, Some("credential unavailable"))
        );
        assert_eq!(
            p.route(&req("POST", "/v1/secrets", AUTH), t, &Fake).status,
            405
        );
        for path in ["/v1/secrets/../x", "/v1/secretsX", "/", "/v1/secrets/a/b"] {
            assert_eq!(
                p.route(&req("GET", path, AUTH), t, &Fake).status,
                404,
                "{path}"
            );
        }
    }
}
