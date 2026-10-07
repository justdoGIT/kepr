// cli_syncx/azure_kv.rs — T8.05: Azure Key Vault as a sync target.
//
//     export AZURE_ACCESS_TOKEN=$(az account get-access-token \
//         --resource https://vault.azure.net --query accessToken -o tsv)
//     kepr sync-push DB_PASS --url azure-kv:myvault/db-pass
//     kepr sync-pull DB_PASS --url azure-kv:myvault/db-pass
//
// `VAULT/SECRET`: VAULT is the vault name (→ VAULT.vault.azure.net) or a
// full Key Vault host in a sovereign cloud (….vault.azure.cn,
// ….vault.usgovcloudapi.net); SECRET is a Key Vault secret name
// (1-127 of 0-9 a-z A-Z -). Both are checked before any request: they
// become the host and the path.
//
//     push  PUT  /secrets/{SECRET}?api-version=7.4   {"value": "…"}
//     pull  GET  /secrets/{SECRET}?api-version=7.4   → {"value": "…", …}
//
// Bearer-token auth, like gcp-sm: no client-secret or certificate flow
// (that would need RSA signing). Errors carry the HTTP status and the
// provider's error code only (`error.code`, e.g. `SecretNotFound`), never
// its message or the body.

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use crate::sync::Syncer;
use crate::sync_http;

pub const API_VERSION: &str = "7.4";
const SUFFIXES: &[&str] = &[
    ".vault.azure.net",
    ".vault.azure.cn",
    ".vault.usgovcloudapi.net",
    ".vault.microsoftazure.de",
];

pub struct AzureKvSyncer {
    /// `https://HOST` (a loopback fake in tests).
    base: String,
    secret: String,
}

/// A vault name: 3-24 of a-z 0-9 -, starting with a letter, not ending
/// with or doubling a hyphen.
fn valid_vault_name(v: &str) -> bool {
    (3..=24).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && v.as_bytes()[0].is_ascii_alphabetic()
        && !v.ends_with('-')
        && !v.contains("--")
}

pub fn valid_secret_name(s: &str) -> bool {
    (1..=127).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `VAULT` or a full Key Vault host → the host name.
pub fn vault_host(vault: &str) -> Result<String, String> {
    let v = vault.to_ascii_lowercase();
    if valid_vault_name(&v) {
        return Ok(format!("{v}{}", SUFFIXES[0]));
    }
    match SUFFIXES.iter().find_map(|s| v.strip_suffix(s)) {
        Some(name) if valid_vault_name(name) => Ok(v),
        _ => Err(format!(
            "azure-kv: {vault:?} is not a vault name (3-24 of a-z 0-9 -) or a Key Vault host"
        )),
    }
}

/// The provider's error code from an Azure error body, at most 64 chars.
pub fn error_code(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v.pointer("/error/code")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .chars()
        .take(64)
        .collect()
}

pub fn read_token() -> Result<ZeroString, String> {
    match std::env::var("AZURE_ACCESS_TOKEN") {
        Ok(t) if !t.is_empty() => Ok(ZeroString::from_string(t)),
        _ => Err(
            "AZURE_ACCESS_TOKEN not set — get one with: az account get-access-token \
                  --resource https://vault.azure.net --query accessToken -o tsv"
                .into(),
        ),
    }
}

impl AzureKvSyncer {
    /// `VAULT/SECRET` (after the `azure-kv:` scheme).
    pub fn from_path(spec: &str) -> Result<Self, String> {
        let (vault, secret) = spec
            .split_once('/')
            .ok_or("azure-kv target needs VAULT/SECRET, e.g. azure-kv:myvault/db-pass")?;
        Self::at(&format!("https://{}", vault_host(vault)?), secret)
    }

    pub(super) fn at(base: &str, secret: &str) -> Result<Self, String> {
        if !valid_secret_name(secret) {
            return Err(format!(
                "azure-kv: {secret:?} is not a secret name (1-127 of 0-9 a-z A-Z -)"
            ));
        }
        Ok(Self {
            base: base.to_string(),
            secret: secret.to_string(),
        })
    }

    fn url(&self) -> String {
        format!(
            "{}/secrets/{}?api-version={API_VERSION}",
            self.base, self.secret
        )
    }

    /// The current value, `None` when the secret doesn't exist.
    pub fn fetch(&self) -> Result<Option<Zeroizing<String>>, String> {
        let token = read_token()?;
        let req = sync_http::agent()
            .get(&self.url())
            .set("Authorization", &format!("Bearer {}", token.as_str()));
        let (status, body) = sync_http::send(req, None).map_err(|e| format!("azure-kv: {e}"))?;
        let body = Zeroizing::new(body);
        match status {
            200 => {}
            404 => return Ok(None),
            s => return Err(format!("azure-kv get: HTTP {s} {}", error_code(&body))),
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| "azure-kv get: reply is not JSON")?;
        let value = v
            .get("value")
            .and_then(|x| x.as_str())
            .ok_or("azure-kv get: reply has no value")?;
        Ok(Some(Zeroizing::new(value.to_string())))
    }
}

impl Syncer for AzureKvSyncer {
    fn backend(&self) -> &'static str {
        "azure-kv"
    }

    fn push(&self, value: &str) -> Result<(), String> {
        let token = read_token()?;
        let body = Zeroizing::new(serde_json::json!({ "value": value }).to_string());
        let req = sync_http::agent()
            .put(&self.url())
            .set("Authorization", &format!("Bearer {}", token.as_str()))
            .set("Content-Type", "application/json");
        match sync_http::send(req, Some(body.as_bytes())) {
            Ok((200..=299, _)) => Ok(()),
            Ok((s, b)) => Err(format!("azure-kv set: HTTP {s} {}", error_code(&b))),
            Err(e) => Err(format!("azure-kv: {e}")),
        }
    }

    fn pull(&self) -> Result<String, String> {
        match self.fetch()? {
            Some(v) => Ok(v.as_str().to_string()),
            None => Err(format!(
                "azure-kv get: HTTP 404 SecretNotFound ({})",
                self.secret
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_syncx::testserver;

    /// Tests that read AZURE_ACCESS_TOKEN share this lock.
    pub(crate) static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_token<T>(f: impl FnOnce() -> T) -> T {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("AZURE_ACCESS_TOKEN", "tok-123");
        let out = f();
        std::env::remove_var("AZURE_ACCESS_TOKEN");
        out
    }

    #[test]
    fn push_is_a_put_of_the_value_with_the_bearer_token() {
        let (base, h) = testserver::serve(vec![(200, r#"{"value":"x","id":"i"}"#.into())]);
        let s = AzureKvSyncer::at(&base, "db-pass").unwrap();
        with_token(|| s.push("p@ss \"w\"")).unwrap();
        let req = &h.join().unwrap()[0];
        assert!(
            req.starts_with("PUT /secrets/db-pass?api-version=7.4 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("Authorization: Bearer tok-123\r\n"), "{req}");
        assert!(req.contains("Content-Type: application/json"), "{req}");
        let body = req.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v, serde_json::json!({"value": "p@ss \"w\""}));
    }

    #[test]
    fn pull_is_a_get_and_reads_value() {
        let (base, h) = testserver::serve(vec![
            (200, r#"{"value":"s3cret","id":"x","attributes":{}}"#.into()),
            (
                404,
                r#"{"error":{"code":"SecretNotFound","message":"db-pass"}}"#.into(),
            ),
        ]);
        let s = AzureKvSyncer::at(&base, "db-pass").unwrap();
        let (one, two) = with_token(|| (s.pull(), s.fetch()));
        assert_eq!(one.unwrap(), "s3cret");
        assert!(two.unwrap().is_none(), "404 is a missing secret");
        let reqs = h.join().unwrap();
        assert!(reqs[0].starts_with("GET /secrets/db-pass?api-version=7.4 HTTP/1.1\r\n"));
        assert!(reqs[0].contains("Authorization: Bearer tok-123\r\n"));
    }

    #[test]
    fn errors_keep_only_the_provider_error_code() {
        let body = r#"{"error":{"code":"Forbidden","message":"caller x has no access to hunter2",
                       "innererror":{"code":"AccessDenied"}}}"#;
        assert_eq!(error_code(body), "Forbidden");
        assert_eq!(error_code("hunter2 not json"), "");
        let (base, h) = testserver::serve(vec![(403, body.into()), (500, "hunter2".into())]);
        let s = AzureKvSyncer::at(&base, "k").unwrap();
        let (a, b) = with_token(|| (s.push("v").unwrap_err(), s.pull().unwrap_err()));
        h.join().unwrap();
        assert_eq!(a, "azure-kv set: HTTP 403 Forbidden");
        assert_eq!(b, "azure-kv get: HTTP 500 ");
    }

    #[test]
    fn targets_are_checked_before_any_request() {
        let s = AzureKvSyncer::from_path("myvault/db-pass").unwrap();
        assert_eq!(
            s.url(),
            "https://myvault.vault.azure.net/secrets/db-pass?api-version=7.4"
        );
        let cn = AzureKvSyncer::from_path("corp-kv.vault.azure.cn/x").unwrap();
        assert!(cn
            .url()
            .starts_with("https://corp-kv.vault.azure.cn/secrets/x?"));
        for bad in [
            "myvault",
            "myvault/",
            "my_vault/x",
            "ab/x",
            "1vault/x",
            "vault-/x",
            "va--ult/x",
            "evil.com/x",
            "evil.com#.vault.azure.net/x",
            "myvault/a/b",
            "myvault/a?b",
            "myvault/a%2Fb",
        ] {
            assert!(AzureKvSyncer::from_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_missing_token_is_named() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AZURE_ACCESS_TOKEN");
        let e = AzureKvSyncer::at("http://127.0.0.1:9", "k")
            .unwrap()
            .push("v")
            .unwrap_err();
        assert!(e.contains("AZURE_ACCESS_TOKEN"), "{e}");
    }
}
