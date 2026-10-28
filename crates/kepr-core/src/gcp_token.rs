//! Short-lived Google access tokens (T12.08, batch: gate-providers): the
//! pure, I/O-free pieces shared by `kepr gcp add` (checks the file) and
//! kepr-gate (mints the token per session, T12.09).
//!
//! The source credential is a service-account key (signs an RS256 JWT,
//! exchanged for a token) or an `authorized_user` file (a refresh-token
//! grant). Either may then impersonate a service account through the IAM
//! Credentials API. The source is stored sealed and bound to Google API
//! hosts with `Inject::GcpToken`; it never leaves the gate, and neither do
//! the tokens. Tokens always come from `TOKEN_URL`: a file's own
//! `token_uri` is ignored, so a planted file can't send the signed JWT or
//! the refresh token anywhere else.

use crate::generate::ZeroString;

/// The only token endpoint kepr uses.
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Every scope kepr accepts starts with this.
pub const SCOPE_PREFIX: &str = "https://www.googleapis.com/auth/";
/// The scope `kepr gcp add` binds when none is given.
pub const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// Longest token lifetime asked for (and the JWT's validity), seconds.
pub const MAX_LIFETIME: u64 = 3600;
/// Most scopes one binding may carry.
pub const MAX_SCOPES: usize = 8;

/// A Google credential file, by its `type`.
pub enum Source {
    ServiceAccount {
        client_email: String,
        private_key: ZeroString,
    },
    AuthorizedUser {
        client_id: String,
        client_secret: ZeroString,
        refresh_token: ZeroString,
    },
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceAccount { client_email, .. } => f
                .debug_struct("ServiceAccount")
                .field("client_email", client_email)
                .field("private_key", &"<redacted>")
                .finish(),
            Self::AuthorizedUser { client_id, .. } => f
                .debug_struct("AuthorizedUser")
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .field("refresh_token", &"<redacted>")
                .finish(),
        }
    }
}

fn need<T>(v: Option<T>, field: &str) -> Result<T, String> {
    v.ok_or_else(|| format!("the credential file has no {field}"))
}

/// Parse a service-account key or an `authorized_user` file. Errors name
/// a missing field, never a value (not even the `type`).
pub fn parse_source(json: &str) -> Result<Source, String> {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "type")]
        kind: Option<String>,
        client_email: Option<String>,
        private_key: Option<ZeroString>,
        client_id: Option<String>,
        client_secret: Option<ZeroString>,
        refresh_token: Option<ZeroString>,
    }
    let raw: Raw =
        serde_json::from_str(json).map_err(|_| "not a Google credential JSON file".to_string())?;
    let text = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    let secret = |v: Option<ZeroString>| v.filter(|s| !s.trim().is_empty());
    match raw.kind.as_deref() {
        Some("service_account") => Ok(Source::ServiceAccount {
            client_email: need(text(raw.client_email), "client_email")?,
            private_key: need(secret(raw.private_key), "private_key")?,
        }),
        Some("authorized_user") => Ok(Source::AuthorizedUser {
            client_id: need(text(raw.client_id), "client_id")?,
            client_secret: need(secret(raw.client_secret), "client_secret")?,
            refresh_token: need(secret(raw.refresh_token), "refresh_token")?,
        }),
        Some(_) => Err(
            "unsupported credential type: use a service_account key or an authorized_user file"
                .into(),
        ),
        None => Err("the credential file has no type".into()),
    }
}

/// The JWT claims a service account signs: exactly iss, scope, aud, iat, exp.
pub fn jwt_claims(client_email: &str, scopes: &[String], now: u64) -> String {
    serde_json::json!({
        "iss": client_email,
        "scope": scopes.join(" "),
        "aud": TOKEN_URL,
        "iat": now,
        "exp": now + MAX_LIFETIME,
    })
    .to_string()
}

/// `application/x-www-form-urlencoded` pairs, built in one buffer sized
/// up front so no reallocation leaves a copy of a secret behind.
fn form(pairs: &[(&str, &str)]) -> ZeroString {
    let cap = pairs.iter().map(|(k, v)| 3 * (k.len() + v.len()) + 2).sum();
    let mut out = String::with_capacity(cap);
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        for (j, s) in [k, v].iter().enumerate() {
            if j == 1 {
                out.push('=');
            }
            for b in s.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        out.push(b as char)
                    }
                    _ => {
                        const HEX: &[u8; 16] = b"0123456789ABCDEF";
                        out.push('%');
                        out.push(HEX[usize::from(b >> 4)] as char);
                        out.push(HEX[usize::from(b & 15)] as char);
                    }
                }
            }
        }
    }
    ZeroString::from_string(out)
}

/// The token request for a signed service-account JWT.
pub fn jwt_grant_body(assertion: &str) -> ZeroString {
    form(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", assertion),
    ])
}

/// The token request for an `authorized_user` file; `None` for a
/// service account, which signs a JWT instead.
pub fn refresh_grant_body(s: &Source) -> Option<ZeroString> {
    let Source::AuthorizedUser {
        client_id,
        client_secret,
        refresh_token,
    } = s
    else {
        return None;
    };
    Some(form(&[
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("client_secret", client_secret.as_str()),
        ("refresh_token", refresh_token.as_str()),
    ]))
}

fn usable(token: &ZeroString) -> bool {
    !token.is_empty() && token.len() <= 8192 && token.bytes().all(|b| b.is_ascii_graphic())
}

/// `(access_token, expires_in)` from a `TOKEN_URL` reply.
pub fn parse_token_reply(body: &[u8]) -> Result<(ZeroString, u64), String> {
    #[derive(serde::Deserialize)]
    struct Reply {
        access_token: ZeroString,
        expires_in: u64,
    }
    let r: Reply = serde_json::from_slice(body).map_err(|_| "Google reply has no token")?;
    if !usable(&r.access_token) || r.expires_in == 0 {
        return Err("Google reply has no usable token".into());
    }
    Ok((r.access_token, r.expires_in))
}

/// `[a-z0-9-]+@[a-z0-9-]+.iam.gserviceaccount.com`: a service account.
pub fn valid_service_account(email: &str) -> bool {
    let word = |s: &str| {
        (1..=63).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let project = domain.strip_suffix(".iam.gserviceaccount.com");
    word(local) && project.is_some_and(word)
}

/// The IAM Credentials call that mints a token for `target`.
pub fn impersonate_url(target: &str) -> Result<String, String> {
    if !valid_service_account(target) {
        return Err("not a service account email (NAME@PROJECT.iam.gserviceaccount.com)".into());
    }
    Ok(format!(
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{target}:generateAccessToken"
    ))
}

/// Its body: the scopes and a lifetime of at most `MAX_LIFETIME`.
pub fn impersonate_body(scopes: &[String], lifetime_secs: u64) -> String {
    let secs = lifetime_secs.clamp(1, MAX_LIFETIME);
    serde_json::json!({ "scope": scopes, "lifetime": format!("{secs}s") }).to_string()
}

/// Unix seconds of `YYYY-MM-DDTHH:MM:SS[.frac]Z` (UTC only).
pub fn utc_secs(s: &str) -> Option<u64> {
    let whole = match s.get(19..20) {
        Some(".") => {
            let frac = s.get(20..s.len().checked_sub(1)?)?;
            let digits = (1..=9).contains(&frac.len()) && frac.bytes().all(|b| b.is_ascii_digit());
            if !digits || !s.ends_with('Z') {
                return None;
            }
            format!("{}Z", s.get(..19)?)
        }
        _ => s.to_string(),
    };
    crate::github_app::rfc3339_secs(&whole)
}

/// `(accessToken, expiry)` from a `generateAccessToken` reply.
pub fn parse_impersonate_reply(body: &[u8]) -> Result<(ZeroString, u64), String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Reply {
        access_token: ZeroString,
        expire_time: String,
    }
    let r: Reply = serde_json::from_slice(body).map_err(|_| "Google reply has no token")?;
    if !usable(&r.access_token) {
        return Err("Google reply has no usable token".into());
    }
    let exp = utc_secs(&r.expire_time).ok_or("Google reply has no valid expireTime")?;
    Ok((r.access_token, exp))
}

/// The `validate_binding` rule for `Inject::GcpToken`.
pub fn validate(
    host: &str,
    port: u16,
    scopes: &[String],
    impersonate: Option<&str>,
) -> Result<(), String> {
    let google = host
        .strip_suffix(".googleapis.com")
        .is_some_and(|sub| !sub.is_empty());
    if !google || port != 443 {
        return Err("a Google credential binds only *.googleapis.com hosts on port 443".into());
    }
    if !(1..=MAX_SCOPES).contains(&scopes.len()) {
        return Err(format!(
            "a Google credential needs 1 to {MAX_SCOPES} scopes"
        ));
    }
    let scope_ok = |s: &String| {
        s.strip_prefix(SCOPE_PREFIX).is_some_and(|rest| {
            !rest.is_empty()
                && rest.len() <= 128
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    };
    if !scopes.iter().all(scope_ok) {
        return Err(format!("a scope must start with {SCOPE_PREFIX}"));
    }
    match impersonate {
        Some(t) if !valid_service_account(t) => Err(
            "impersonate must be a service account email (NAME@PROJECT.iam.gserviceaccount.com)"
                .into(),
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_KEY: &str =
        "-----BEGIN PRIVATE KEY-----\nMIIfake-test-only\n-----END PRIVATE KEY-----\n";

    fn sa_json(extra: &str) -> String {
        format!(
            r#"{{"type":"service_account","project_id":"p","private_key_id":"k1",
            "private_key":{},"client_email":"bot@p.iam.gserviceaccount.com",
            "client_id":"1","token_uri":"https://oauth2.googleapis.com/token"{extra}}}"#,
            serde_json::to_string(FAKE_KEY).unwrap()
        )
    }

    const USER: &str = r#"{"type":"authorized_user","client_id":"cid.apps.googleusercontent.com",
        "client_secret":"s3cr3t-value","refresh_token":"1//refresh-value","quota_project_id":"p"}"#;

    fn scopes() -> Vec<String> {
        vec![DEFAULT_SCOPE.to_string()]
    }

    #[test]
    fn both_file_types_parse_and_debug_redacts() {
        let Source::ServiceAccount {
            client_email,
            private_key,
        } = parse_source(&sa_json("")).unwrap()
        else {
            panic!("service account expected");
        };
        assert_eq!(client_email, "bot@p.iam.gserviceaccount.com");
        assert_eq!(private_key.as_str(), FAKE_KEY);
        let user = parse_source(USER).unwrap();
        let dbg = format!("{user:?} {:?}", parse_source(&sa_json("")).unwrap());
        for secret in ["s3cr3t-value", "1//refresh-value", "MIIfake"] {
            assert!(!dbg.contains(secret), "{dbg}");
        }
        assert!(dbg.contains("cid.apps.googleusercontent.com"));
        let body = refresh_grant_body(&user).unwrap();
        assert_eq!(
            body.as_str(),
            "grant_type=refresh_token&client_id=cid.apps.googleusercontent.com\
             &client_secret=s3cr3t-value&refresh_token=1%2F%2Frefresh-value"
        );
        assert!(refresh_grant_body(&parse_source(&sa_json("")).unwrap()).is_none());
    }

    #[test]
    fn errors_name_the_field_never_a_value() {
        let no_key = sa_json("").replace("\"private_key\":", "\"other\":");
        let e = parse_source(&no_key).unwrap_err();
        assert_eq!(e, "the credential file has no private_key");
        let no_secret = USER.replace("client_secret", "x");
        assert_eq!(
            parse_source(&no_secret).unwrap_err(),
            "the credential file has no client_secret"
        );
        let typed = r#"{"type":"external_account-SECRETISH","private_key":"MIIfake"}"#;
        let e = parse_source(typed).unwrap_err();
        assert!(!e.contains("SECRETISH") && !e.contains("MIIfake"), "{e}");
        let wrong = r#"{"type":"service_account","private_key":12345678,"client_email":"a"}"#;
        assert!(!parse_source(wrong).unwrap_err().contains("12345678"));
        assert_eq!(
            parse_source("{}").unwrap_err(),
            "the credential file has no type"
        );
        assert!(parse_source("ghp_not_json").is_err());
    }

    #[test]
    fn the_files_token_uri_is_ignored() {
        let evil = sa_json("").replace(
            "https://oauth2.googleapis.com/token",
            "https://evil.example/token",
        );
        assert!(parse_source(&evil).is_ok());
        let claims: serde_json::Value =
            serde_json::from_str(&jwt_claims("bot@p.iam.gserviceaccount.com", &scopes(), 7))
                .unwrap();
        assert_eq!(claims["aud"], TOKEN_URL);
        assert!(!format!("{:?}", parse_source(&evil).unwrap()).contains("evil"));
    }

    #[test]
    fn claims_have_exactly_five_fields() {
        let two = vec![
            DEFAULT_SCOPE.to_string(),
            format!("{SCOPE_PREFIX}devstorage.read_only"),
        ];
        let c: serde_json::Value =
            serde_json::from_str(&jwt_claims("bot@p.iam.gserviceaccount.com", &two, 1000)).unwrap();
        assert_eq!(
            c,
            serde_json::json!({
                "iss": "bot@p.iam.gserviceaccount.com",
                "scope": format!("{DEFAULT_SCOPE} {SCOPE_PREFIX}devstorage.read_only"),
                "aud": TOKEN_URL,
                "iat": 1000,
                "exp": 4600,
            })
        );
        assert_eq!(
            jwt_grant_body("a.b-_.c").as_str(),
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=a.b-_.c"
        );
    }

    #[test]
    fn token_and_impersonation_replies() {
        let r = br#"{"access_token":"ya29.c.abc","expires_in":3599,"token_type":"Bearer"}"#;
        let (t, secs) = parse_token_reply(r).unwrap();
        assert_eq!((t.as_str(), secs), ("ya29.c.abc", 3599));
        for bad in [
            &br#"{"error":"invalid_grant"}"#[..],
            br#"{"access_token":"a b","expires_in":10}"#,
            br#"{"access_token":"t","expires_in":0}"#,
        ] {
            assert!(parse_token_reply(bad).is_err());
        }
        assert_eq!(utc_secs("2030-01-01T00:00:00Z"), Some(1_893_456_000));
        assert_eq!(
            utc_secs("2030-01-01T00:00:00.123456789Z"),
            Some(1_893_456_000)
        );
        for bad in [
            "2030-01-01T00:00:00+01:00",
            "2030-01-01T00:00:00.Z",
            "2030-01-01T00:00:00.1234567890Z",
            "2030-01-01T00:00:00.12a4Z",
            "2030-01-01T00:00:00.5",
            "",
        ] {
            assert_eq!(utc_secs(bad), None, "{bad}");
        }
        let r = br#"{"accessToken":"ya29.imp","expireTime":"2030-01-01T00:00:00Z"}"#;
        let (t, exp) = parse_impersonate_reply(r).unwrap();
        assert_eq!((t.as_str(), exp), ("ya29.imp", 1_893_456_000));
        assert!(parse_impersonate_reply(br#"{"accessToken":"t","expireTime":"soon"}"#).is_err());
    }

    #[test]
    fn impersonation_request() {
        let sa = "deploy@my-proj-1.iam.gserviceaccount.com";
        assert_eq!(
            impersonate_url(sa).unwrap(),
            format!("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa}:generateAccessToken")
        );
        for bad in [
            "deploy@my-proj.iam.gserviceaccount.com.evil.com",
            "Deploy@p.iam.gserviceaccount.com",
            "d@iam.gserviceaccount.com",
            "@p.iam.gserviceaccount.com",
            "d/../x@p.iam.gserviceaccount.com",
            "d@p.iam.gserviceaccount.com:x",
            "d@p@q.iam.gserviceaccount.com",
            "bot@example.com",
        ] {
            assert!(impersonate_url(bad).is_err(), "{bad}");
        }
        let b: serde_json::Value =
            serde_json::from_str(&impersonate_body(&scopes(), 7200)).unwrap();
        assert_eq!(
            b,
            serde_json::json!({"scope": [DEFAULT_SCOPE], "lifetime": "3600s"})
        );
        assert!(impersonate_body(&scopes(), 600).contains("\"600s\""));
    }

    #[test]
    fn bindings_only_on_google_api_hosts_with_auth_scopes() {
        let ok = validate("storage.googleapis.com", 443, &scopes(), None);
        assert!(ok.is_ok());
        assert!(validate(
            "www.googleapis.com",
            443,
            &scopes(),
            Some("a@b.iam.gserviceaccount.com")
        )
        .is_ok());
        assert!(validate("api.openai.com", 443, &scopes(), None).is_err());
        assert!(validate("googleapis.com", 443, &scopes(), None).is_err());
        assert!(validate("x.googleapis.com", 8443, &scopes(), None).is_err());
        assert!(validate("x.googleapis.com", 443, &[], None).is_err());
        let nine = vec![DEFAULT_SCOPE.to_string(); 9];
        assert!(validate("x.googleapis.com", 443, &nine, None).is_err());
        for bad in [
            "https://evil.example/auth/x",
            "https://www.googleapis.com/auth/",
            "https://www.googleapis.com/auth/a b",
            "cloud-platform",
        ] {
            let s = vec![bad.to_string()];
            assert!(
                validate("x.googleapis.com", 443, &s, None).is_err(),
                "{bad}"
            );
        }
        assert!(validate("x.googleapis.com", 443, &scopes(), Some("bot@example.com")).is_err());
    }
}
