//! Google API calls that would hand the agent a credential outliving its
//! session (security review of T12.08–T12.10).
//!
//! A gcloud route injects a short-lived token the agent never sees, but the
//! token's own permissions let the agent ask Google for something it can
//! keep: a service-account key file, an HMAC key, an API key, or a token or
//! signed JWT minted outside the gate. Those requests are refused here, the
//! way `sigv4_resign::mints_credentials` refuses them for AWS.

/// Does `METHOD host/path` create a credential the agent could keep?
/// `path` may carry a query string; percent-encoding and repeated slashes
/// do not change the answer.
pub fn mints_credentials(method: &str, host: &str, path: &str) -> bool {
    let post = method.eq_ignore_ascii_case("POST");
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host != "googleapis.com" && !host.ends_with(".googleapis.com") {
        return false;
    }
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let decoded = percent_decode(path);
    let seg: Vec<&str> = decoded.split('/').filter(|s| !s.is_empty()).collect();
    let is = |s: &str, want: &str| s.eq_ignore_ascii_case(want);
    let last = seg.last().copied().unwrap_or_default();
    // A service-account key: .../serviceAccounts/ID/keys or keys:upload.
    let sa_key = seg
        .windows(3)
        .any(|w| is(w[0], "serviceAccounts") && (is(w[2], "keys") || is(w[2], "keys:upload")));
    // A Cloud Storage HMAC key: .../projects/ID/hmacKeys.
    let hmac_key = seg
        .windows(3)
        .any(|w| is(w[0], "projects") && is(w[2], "hmacKeys"));
    // An API key: apikeys.googleapis.com .../keys (and :undelete).
    let api_key =
        host == "apikeys.googleapis.com" && (is(last, "keys") || is(last, "keys:undelete"));
    // Reading an API key's secret string is a read, not a POST.
    let key_string = host == "apikeys.googleapis.com" && is(last, "keyString");
    // Tokens and signatures minted outside the gate (IAM Credentials, and
    // the IAM v1 `signBlob` / `signJwt`, which sign as the account).
    let minted = [
        "generateAccessToken",
        "generateIdToken",
        "signJwt",
        "signBlob",
    ]
    .iter()
    .any(|verb| {
        last.rsplit_once(':')
            .is_some_and(|(_, v)| v.eq_ignore_ascii_case(verb))
    });
    key_string || (post && (sa_key || hmac_key || api_key || minted))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lived_credential_creation_is_refused() {
        for (host, path) in [
            (
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/bot@p.iam.gserviceaccount.com/keys",
            ),
            (
                "iam.googleapis.com",
                "/v1/projects/-/serviceAccounts/123/keys:upload",
            ),
            (
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/123/keys?alt=json",
            ),
            ("storage.googleapis.com", "/storage/v1/projects/p/hmacKeys"),
            (
                "www.googleapis.com",
                "/storage/v1/projects/p/hmacKeys?serviceAccountEmail=x",
            ),
            (
                "apikeys.googleapis.com",
                "/v2/projects/p/locations/global/keys",
            ),
            (
                "iamcredentials.googleapis.com",
                "/v1/projects/-/serviceAccounts/x:generateAccessToken",
            ),
            (
                "iamcredentials.googleapis.com",
                "/v1/projects/-/serviceAccounts/x:generateIdToken",
            ),
            (
                "iamcredentials.googleapis.com",
                "/v1/projects/-/serviceAccounts/x:signJwt",
            ),
            (
                "iamcredentials.googleapis.com",
                "/v1/projects/-/serviceAccounts/x:signBlob",
            ),
            (
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/x:signBlob",
            ),
            // Encoded or doubled separators do not hide it.
            (
                "iam.googleapis.com",
                "/v1/projects/p//serviceAccounts/1/keys",
            ),
            (
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/1%2Fkeys",
            ),
            (
                "iam.googleapis.com",
                "/v1/projects/p/%73erviceAccounts/1/keys",
            ),
            (
                "IAM.GOOGLEAPIS.COM.",
                "/v1/projects/p/serviceAccounts/1/keys",
            ),
        ] {
            assert!(mints_credentials("POST", host, path), "{host}{path}");
            assert!(mints_credentials("post", host, path), "{host}{path}");
        }
    }

    #[test]
    fn reading_an_api_keys_secret_string_is_refused_for_any_method() {
        for m in ["GET", "POST"] {
            assert!(mints_credentials(
                m,
                "apikeys.googleapis.com",
                "/v2/projects/p/locations/global/keys/k/keyString"
            ));
        }
    }

    #[test]
    fn everyday_calls_pass() {
        for (method, host, path) in [
            (
                "GET",
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/1/keys",
            ),
            (
                "GET",
                "storage.googleapis.com",
                "/storage/v1/projects/p/hmacKeys",
            ),
            (
                "DELETE",
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts/1/keys/abc",
            ),
            (
                "POST",
                "iam.googleapis.com",
                "/v1/projects/p/serviceAccounts",
            ),
            ("POST", "storage.googleapis.com", "/storage/v1/b?project=p"),
            (
                "POST",
                "compute.googleapis.com",
                "/compute/v1/projects/p/zones/z/instances",
            ),
            ("POST", "apikeys.googleapis.com", "/v2/keys:lookupKey"),
            (
                "POST",
                "example.com",
                "/v1/projects/p/serviceAccounts/1/keys",
            ),
            (
                "POST",
                "evilgoogleapis.com",
                "/v1/projects/p/serviceAccounts/1/keys",
            ),
        ] {
            assert!(
                !mints_credentials(method, host, path),
                "{method} {host}{path}"
            );
        }
    }
}
