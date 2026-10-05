// cli_sharing/oidc.rs — OIDC for device enrolment (T6.13): discovery,
// the device-code flow (RFC 8628) and fetching the issuer's JWKS.
// Token checks are in jwt.rs.
//
// This runs in the CLI: the daemon has no network. The new machine logs
// the user in and puts the ID token into its (HMAC'd) enrolment request;
// the first machine verifies that token again against the issuer's JWKS
// before it asks its daemon to pin the device, and the daemon refuses an
// enrolment whose token was made with `--oidc` unless an identity from
// that issuer comes with it.

use std::time::Duration;

use kepr_core::protocol_sharing::{EnrolRequest, OidcIdentity};

use super::jwt::{same_issuer, verify_id_token, Claims, Jwks};
use crate::sync_http::{agent, error_summary, send};

pub struct Provider {
    pub issuer: String,
    device_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(serde::Deserialize)]
struct Discovery {
    issuer: String,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(serde::Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default = "default_expires")]
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}
fn default_expires() -> u64 {
    600
}

/// https only; plain http just for a loopback test IdP.
fn check_url(url: &str) -> Result<(), String> {
    let host = url
        .strip_prefix("http://")
        .map(|r| r.split(['/', '?', '#']).next().unwrap_or(""))
        .map(|h| h.rsplit_once(':').map_or(h, |(h, _)| h));
    let loopback = matches!(host, Some("127.0.0.1" | "localhost" | "[::1]"));
    (url.starts_with("https://") || loopback)
        .then_some(())
        .ok_or_else(|| format!("{url}: the IdP must be reached over https"))
}

fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    check_url(url)?;
    let (status, body) = send(agent().get(url), None)?;
    if status != 200 {
        return Err(format!("{url}: HTTP {status} {}", error_summary(&body)));
    }
    serde_json::from_str(&body).map_err(|_| format!("{url}: unexpected reply"))
}

fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn post_form(url: &str, pairs: &[(&str, &str)]) -> Result<(u16, String), String> {
    check_url(url)?;
    let req = agent()
        .post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Accept", "application/json");
    send(req, Some(form(pairs).as_bytes()))
}

pub fn discover(issuer: &str) -> Result<Provider, String> {
    let base = issuer.trim_end_matches('/');
    let d: Discovery = get_json(&format!("{base}/.well-known/openid-configuration"))?;
    if !same_issuer(&d.issuer, issuer) {
        return Err(format!("the IdP says it is {}, not {issuer}", d.issuer));
    }
    Ok(Provider {
        issuer: d.issuer,
        device_endpoint: d
            .device_authorization_endpoint
            .ok_or("this IdP doesn't offer the device-code login")?,
        token_endpoint: d.token_endpoint,
        jwks_uri: d.jwks_uri,
    })
}

pub fn jwks(p: &Provider) -> Result<Jwks, String> {
    get_json(&p.jwks_uri)
}

/// One token-endpoint reply during device-code polling.
#[derive(Debug, PartialEq)]
pub enum Step {
    Pending,
    SlowDown,
    Token(String),
    Fail(String),
}

pub fn classify(status: u16, body: &str) -> Step {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    if status == 200 {
        return match v["id_token"].as_str() {
            Some(t) => Step::Token(t.to_string()),
            None => Step::Fail("the IdP returned no ID token (is `openid` allowed?)".into()),
        };
    }
    match v["error"].as_str() {
        Some("authorization_pending") => Step::Pending,
        Some("slow_down") => Step::SlowDown,
        Some("access_denied") => Step::Fail("the login was denied".into()),
        Some("expired_token") => Step::Fail("the login code expired; try again".into()),
        _ => Step::Fail(format!(
            "IdP token endpoint: HTTP {status} {}",
            error_summary(body)
        )),
    }
}

/// Poll until the user finishes the login: wait `interval` between
/// tries, 5 s more after each `slow_down` (RFC 8628 §3.5), give up after
/// `max_wait` seconds.
pub fn poll(
    mut next: impl FnMut() -> Result<(u16, String), String>,
    mut sleep: impl FnMut(u64),
    mut interval: u64,
    max_wait: u64,
) -> Result<String, String> {
    let mut waited = 0;
    loop {
        if waited >= max_wait {
            return Err("the login was not finished in time".into());
        }
        sleep(interval);
        waited += interval;
        let (status, body) = next()?;
        match classify(status, &body) {
            Step::Pending => {}
            Step::SlowDown => interval += 5,
            Step::Token(t) => return Ok(t),
            Step::Fail(e) => return Err(e),
        }
    }
}

/// Log the user in on this machine; return a verified ID token.
pub fn device_login(issuer: &str, client_id: &str) -> Result<String, String> {
    let p = discover(issuer)?;
    let (status, body) = post_form(
        &p.device_endpoint,
        &[("client_id", client_id), ("scope", "openid email profile")],
    )?;
    if status != 200 {
        return Err(format!(
            "IdP device login: HTTP {status} {}",
            error_summary(&body)
        ));
    }
    let dc: DeviceCode =
        serde_json::from_str(&body).map_err(|_| "IdP device login: unexpected reply")?;
    let url = dc
        .verification_uri_complete
        .as_ref()
        .unwrap_or(&dc.verification_uri);
    crate::cli_ui::einfo(&format!(
        "to prove it's you, open {url} and enter the code {}",
        dc.user_code
    ));
    let token = poll(
        || {
            post_form(
                &p.token_endpoint,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", &dc.device_code),
                    ("client_id", client_id),
                ],
            )
        },
        |s| std::thread::sleep(Duration::from_secs(s)),
        dc.interval.clamp(1, 60),
        dc.expires_in.min(1800),
    )?;
    check_token(&p, &token, client_id)?;
    Ok(token)
}

/// Verify `token` against the issuer's live JWKS.
pub fn check_token(p: &Provider, token: &str, client_id: &str) -> Result<Claims, String> {
    verify_id_token(
        token,
        &jwks(p)?,
        &p.issuer,
        client_id,
        crate::cli_sharing::now(),
    )
}

/// Who logged in, as shown by `kepr device ls`: the e-mail address when
/// the IdP vouches for it, else the subject id.
fn who(c: &Claims) -> String {
    match &c.email {
        Some(e) if c.email_verified != Some(false) => e.clone(),
        _ => c.sub.clone(),
    }
}

/// The first machine: verify the ID token inside an enrolment request
/// (`request`, JSON) and name who logged in. `subject`, when given, must
/// be the token's `sub` or its verified e-mail.
pub fn identity_in(
    request: &str,
    issuer: &str,
    jwks: &Jwks,
    client_id: &str,
    subject: Option<&str>,
    now: u64,
) -> Result<OidcIdentity, String> {
    let req: EnrolRequest =
        serde_json::from_str(request).map_err(|_| "not a device enrolment request")?;
    let token = req.id_token.as_deref().ok_or(
        "the request carries no IdP login (on the new machine: kepr device enroll TOKEN --oidc ISSUER --client-id ID)",
    )?;
    let c = verify_id_token(token, jwks, issuer, client_id, now)?;
    let name = who(&c);
    if let Some(s) = subject {
        if s != c.sub && s != name {
            return Err(format!("the IdP login is {name}, not {s}"));
        }
    }
    Ok(OidcIdentity {
        issuer: c.iss,
        subject: name,
    })
}

/// `identity_in` against the issuer's live discovery document and JWKS.
pub fn verify_request(
    request: &str,
    issuer: &str,
    client_id: &str,
    subject: Option<&str>,
) -> Result<OidcIdentity, String> {
    let p = discover(issuer)?;
    let keys = jwks(&p)?;
    identity_in(
        request,
        &p.issuer,
        &keys,
        client_id,
        subject,
        crate::cli_sharing::now(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replies(list: &[(u16, &str)]) -> impl FnMut() -> Result<(u16, String), String> {
        let mut v: Vec<(u16, String)> = list.iter().map(|(s, b)| (*s, b.to_string())).collect();
        v.reverse();
        move || v.pop().ok_or_else(|| "no more replies".to_string())
    }

    #[test]
    fn polling_waits_through_pending_and_slows_down() {
        let mut slept = Vec::new();
        let t = poll(
            replies(&[
                (400, r#"{"error":"authorization_pending"}"#),
                (400, r#"{"error":"slow_down"}"#),
                (400, r#"{"error":"authorization_pending"}"#),
                (200, r#"{"id_token":"a.b.c","access_token":"x"}"#),
            ]),
            |s| slept.push(s),
            5,
            600,
        )
        .unwrap();
        assert_eq!(t, "a.b.c");
        assert_eq!(slept, vec![5, 5, 10, 10]);
    }

    #[test]
    fn polling_stops_on_denial_expiry_and_timeout() {
        let denied = poll(
            replies(&[(400, r#"{"error":"access_denied"}"#)]),
            |_| {},
            5,
            60,
        );
        assert!(denied.unwrap_err().contains("denied"));
        let gone = poll(
            replies(&[(400, r#"{"error":"expired_token"}"#)]),
            |_| {},
            5,
            60,
        );
        assert!(gone.unwrap_err().contains("expired"));
        let pending = [(400, r#"{"error":"authorization_pending"}"#); 10];
        assert!(poll(replies(&pending), |_| {}, 5, 20)
            .unwrap_err()
            .contains("in time"));
        let no_id = poll(replies(&[(200, r#"{"access_token":"x"}"#)]), |_| {}, 5, 60);
        assert!(no_id.unwrap_err().contains("no ID token"));
    }

    #[test]
    fn the_first_machine_names_who_logged_in() {
        use crate::cli_sharing::jwt::tests::{claims, es256, es_fixture, CLIENT, ISS, NOW};
        use serde_json::json;
        let (sk, jwks) = es_fixture();
        let token = "KD1-00112233445566778899aabbccddeeff";
        let req = |id: Option<String>| {
            serde_json::to_string(&EnrolRequest::new(token, "h", "kepr-pk2-AA", id)).unwrap()
        };
        let good = req(Some(es256(&sk, &claims())));
        let id = identity_in(&good, ISS, &jwks, CLIENT, None, NOW).unwrap();
        assert_eq!(id.subject, "ana@example.com");
        assert_eq!(id.issuer, ISS);
        // `--subject` must match the sub or the verified e-mail.
        assert!(identity_in(&good, ISS, &jwks, CLIENT, Some("u-42"), NOW).is_ok());
        let e = identity_in(&good, ISS, &jwks, CLIENT, Some("bob"), NOW).unwrap_err();
        assert!(e.contains("not bob"), "{e}");
        // An unverified e-mail isn't shown as the identity.
        let mut c = claims();
        c["email_verified"] = json!(false);
        let id = identity_in(&req(Some(es256(&sk, &c))), ISS, &jwks, CLIENT, None, NOW).unwrap();
        assert_eq!(id.subject, "u-42");
        // No login in the request, or a token for another client: refused.
        assert!(identity_in(&req(None), ISS, &jwks, CLIENT, None, NOW).is_err());
        assert!(identity_in(&good, ISS, &jwks, "other", None, NOW).is_err());
        assert!(identity_in("{}", ISS, &jwks, CLIENT, None, NOW).is_err());
    }

    #[test]
    fn urls_and_forms() {
        assert!(check_url("https://idp.example").is_ok());
        assert!(check_url("http://127.0.0.1:8080").is_ok());
        assert!(check_url("http://idp.example").is_err());
        assert!(check_url("http://localhost.evil.example/x").is_err());
        assert!(check_url("http://localhost/x").is_ok());
        assert_eq!(
            form(&[("scope", "openid email"), ("x", "a&b=c")]),
            "scope=openid%20email&x=a%26b%3Dc"
        );
    }
}
