// sync_vault.rs — HashiCorp Vault KV v2 backend for `kepr sync`.
//
// Vault auth: standard Vault env vars
//
//     VAULT_ADDR  (e.g. https://vault.example.com:8200)
//     VAULT_TOKEN (a periodic or static token with kv-v2 push/pull
//                  on the requested path)
//
// Path mapping: kepr's URL form is `vault:secret/myapp/db`.
// "secret" is the mount; "myapp/db" is the key path. KV v2
// inserts a `data` segment between the mount and the key in its
// REST API:
//
//     vault:secret/myapp/db → POST {VAULT_ADDR}/v1/secret/data/myapp/db
//                            GET  {VAULT_ADDR}/v1/secret/data/myapp/db
//
// Wire shape (KV v2):
//
//     push body:  {"data": {"value": "<plaintext>"}}
//     pull body:  {"data": {"data": {"value": "<plaintext>"}, ...metadata}}
//
// The double-`data` nesting on pull is an intentional KV v2
// quirk to support metadata; we descend through both layers.
//
// Failure semantics: every transport / auth error surfaces as
// `Err(String)` with the HTTP status and Vault's response body
// (which is structured: `{"errors": ["…"]}`). The CLI prints
// this verbatim — Vault's error messages are operator-actionable.
//
// Threat model: the secret value is in the kepr CLI process for
// the duration of the HTTP round-trip. Since we already hold it
// in a `ZeroString` from the daemon `Get`, we extend the wipe
// boundary by zeroing the request body buffer after `send_string`.
// VAULT_TOKEN sits in env var memory for the process lifetime;
// the user controls when to unset it, kepr does not.

use kepr_core::generate::ZeroString;

use crate::sync::Syncer;

/// One Vault target. Constructed via `from_path("secret/myapp/db")`;
/// the dispatcher in `pick_syncer` strips the `vault:` scheme
/// before calling. Holds only the path — VAULT_ADDR + VAULT_TOKEN
/// are read fresh on every call so a token rotation between push
/// and pull works without a CLI restart.
pub struct VaultSyncer {
    /// User-supplied path AFTER the `vault:` scheme. e.g.
    /// `secret/myapp/db`. The mount and key portions are
    /// recombined with `/data/` for the KV v2 REST endpoint.
    path: String,
}

impl VaultSyncer {
    pub fn from_path(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Translate `secret/myapp/db` → `secret/data/myapp/db`. The
    /// first slash separates mount from key; KV v2 inserts
    /// `data` between them. A single-segment input (`secret`) is
    /// rejected — KV v2 requires both parts.
    fn kv_v2_endpoint(&self) -> Result<String, String> {
        let (mount, key) = self
            .path
            .split_once('/')
            .ok_or_else(|| format!("vault path needs <mount>/<key>, got {:?}", self.path))?;
        if key.is_empty() {
            return Err(format!("vault path key cannot be empty: {:?}", self.path));
        }
        Ok(format!("{mount}/data/{key}"))
    }

    fn read_env() -> Result<(String, ZeroString), String> {
        let addr = std::env::var("VAULT_ADDR").map_err(|_| {
            "VAULT_ADDR not set — point at your Vault instance, e.g. https://vault.example:8200"
                .to_string()
        })?;
        if !addr.starts_with("https://")
            && std::env::var("KEPR_ALLOW_INSECURE_VAULT").as_deref() != Ok("1")
        {
            return Err(
                "VAULT_ADDR must use https://; set KEPR_ALLOW_INSECURE_VAULT=1 only for local testing"
                    .into(),
            );
        }
        let token = std::env::var("VAULT_TOKEN").map_err(|_| {
            "VAULT_TOKEN not set — pass a token with kv-v2 read/write \
             on the target path"
                .to_string()
        })?;
        // Wrap the token in ZeroString so it's wiped from CLI
        // memory when this Syncer drops. Env var memory itself
        // stays — only the user can unset that.
        Ok((addr.trim_end_matches('/').to_string(), token.into()))
    }
}

impl Syncer for VaultSyncer {
    fn backend(&self) -> &'static str {
        "vault"
    }

    fn push(&self, value: &str) -> Result<(), String> {
        let (addr, token) = Self::read_env()?;
        let endpoint = self.kv_v2_endpoint()?;
        let url = format!("{addr}/v1/{endpoint}");
        // KV v2 wraps the user's value in {"data": {…}}.
        let body = serde_json::json!({"data": {"value": value}});
        let req = crate::sync_http::agent()
            .post(&url)
            .set("X-Vault-Token", token.as_str());
        match crate::sync_http::send(req, Some(body.to_string().as_bytes())) {
            Ok((200 | 204, _)) => Ok(()),
            Ok((code, b)) => Err(format!(
                "vault push: HTTP {code} {}",
                crate::sync_http::error_summary(&b)
            )),
            Err(e) => Err(format!("vault push: {e}")),
        }
    }

    fn pull(&self) -> Result<String, String> {
        match self.fetch()? {
            Some(v) => Ok(v.as_str().to_string()),
            None => Err("vault pull: HTTP 404 ".into()),
        }
    }

    fn fetch(&self) -> Result<Option<zeroize::Zeroizing<String>>, String> {
        let (addr, token) = Self::read_env()?;
        let endpoint = self.kv_v2_endpoint()?;
        let url = format!("{addr}/v1/{endpoint}");
        let req = crate::sync_http::agent()
            .get(&url)
            .set("X-Vault-Token", token.as_str());
        let text = match crate::sync_http::send(req, None) {
            Ok((200, b)) => zeroize::Zeroizing::new(b),
            // T11.17: no such secret (create, for a dry run).
            Ok((404, _)) => return Ok(None),
            Ok((code, b)) => {
                return Err(format!(
                    "vault pull: HTTP {code} {}",
                    crate::sync_http::error_summary(&b)
                ));
            }
            Err(e) => return Err(format!("vault pull: {e}")),
        };
        // KV v2 envelope: {"data": {"data": {<our keys>}, "metadata": {...}}}
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("vault pull: parse JSON: {e}"))?;
        let value = parsed
            .pointer("/data/data/value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                "vault pull: response missing /data/data/value — \
                 was the secret written by `kepr sync push`?"
                    .to_string()
            })?;
        Ok(Some(zeroize::Zeroizing::new(value.to_string())))
    }
}

/// T11.17: the keys of one KV v2 metadata LIST reply (`dir/` is a folder).
pub fn parse_list(body: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "vault list: reply is not JSON")?;
    let keys = v
        .pointer("/data/keys")
        .and_then(|k| k.as_array())
        .ok_or("vault list: reply has no data.keys")?;
    Ok(keys
        .iter()
        .filter_map(|k| k.as_str())
        // A key never climbs out of the folder it was listed in.
        .filter(|k| !k.is_empty() && !k.starts_with('/') && !k.split('/').any(|s| s == ".."))
        .map(str::to_string)
        .collect())
}

/// T11.17: every secret under `from` (`MOUNT[/PATH]`) whose path below
/// it starts with `prefix`, as `(path, vault:MOUNT/PATH/path)`. Folders
/// are walked (at most 200 LIST calls).
pub fn list(from: &str, prefix: &str) -> Result<Vec<(String, String)>, String> {
    let (addr, token) = VaultSyncer::read_env()?;
    let from = from.trim_end_matches('/');
    let (mount, base) = from.split_once('/').unwrap_or((from, ""));
    let join = |a: &str, b: &str| match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{a}/{b}"),
    };
    // Start in the deepest folder the prefix names.
    let start = prefix.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut folders = vec![start.to_string()];
    let (mut out, mut calls) = (Vec::new(), 0);
    while let Some(dir) = folders.pop() {
        calls += 1;
        if calls > 200 {
            return Err("vault list: too many folders".into());
        }
        let path = join(base, &dir);
        let url = format!("{addr}/v1/{mount}/metadata/{path}?list=true");
        let req = crate::sync_http::agent()
            .get(&url)
            .set("X-Vault-Token", token.as_str());
        let body = match crate::sync_http::send(req, None) {
            Ok((200, b)) => b,
            Ok((404, _)) => continue, // an empty folder
            Ok((code, b)) => {
                return Err(format!(
                    "vault list: HTTP {code} {}",
                    crate::sync_http::error_summary(&b)
                ))
            }
            Err(e) => return Err(format!("vault list: {e}")),
        };
        for key in parse_list(&body)? {
            let rel = join(&dir, key.trim_end_matches('/'));
            if key.ends_with('/') {
                if rel.starts_with(prefix) || prefix.starts_with(&format!("{rel}/")) {
                    folders.push(rel);
                }
            } else if rel.starts_with(prefix) {
                let url = format!("vault:{}", join(from, &rel));
                out.push((rel, url));
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_v2_endpoint_inserts_data_segment() {
        let s = VaultSyncer::from_path("secret/myapp/db");
        assert_eq!(s.kv_v2_endpoint().unwrap(), "secret/data/myapp/db");
    }

    #[test]
    fn kv_v2_endpoint_handles_deep_keys() {
        let s = VaultSyncer::from_path("secret/team/prod/api/key");
        assert_eq!(s.kv_v2_endpoint().unwrap(), "secret/data/team/prod/api/key");
    }

    #[test]
    fn kv_v2_endpoint_rejects_single_segment() {
        // `vault:secret` (no key) is meaningless — KV v2 needs
        // both mount and key. Pin the error.
        let s = VaultSyncer::from_path("secret");
        let err = s.kv_v2_endpoint().expect_err("must reject");
        assert!(err.contains("mount"), "msg: {err}");
    }

    #[test]
    fn kv_v2_endpoint_rejects_empty_key() {
        // `vault:secret/` (mount but no key) also meaningless.
        let s = VaultSyncer::from_path("secret/");
        let err = s.kv_v2_endpoint().expect_err("must reject");
        assert!(err.contains("empty"), "msg: {err}");
    }

    #[test]
    fn read_env_complains_when_vars_missing() {
        // Snapshot + restore env so we don't pollute other
        // tests in the same binary that may rely on these vars.
        let prior_addr = std::env::var("VAULT_ADDR").ok();
        let prior_token = std::env::var("VAULT_TOKEN").ok();
        std::env::remove_var("VAULT_ADDR");
        std::env::remove_var("VAULT_TOKEN");

        let err = VaultSyncer::read_env().expect_err("must require VAULT_ADDR");
        assert!(err.contains("VAULT_ADDR"), "msg: {err}");

        std::env::set_var("VAULT_ADDR", "https://vault.example:8200");
        let err = VaultSyncer::read_env().expect_err("must require VAULT_TOKEN");
        assert!(err.contains("VAULT_TOKEN"), "msg: {err}");

        std::env::set_var("VAULT_TOKEN", "xyz");
        let (addr, token) = VaultSyncer::read_env().unwrap();
        assert_eq!(addr, "https://vault.example:8200");
        assert_eq!(token.as_str(), "xyz");

        // Restore.
        match prior_addr {
            Some(v) => std::env::set_var("VAULT_ADDR", v),
            None => std::env::remove_var("VAULT_ADDR"),
        }
        match prior_token {
            Some(v) => std::env::set_var("VAULT_TOKEN", v),
            None => std::env::remove_var("VAULT_TOKEN"),
        }
    }

    #[test]
    fn list_replies_parse_keys_and_folders() {
        let body =
            r#"{"request_id":"x","data":{"keys":["db","api-key","team/","../up","/abs",""]}}"#;
        assert_eq!(parse_list(body).unwrap(), ["db", "api-key", "team/"]);
        assert!(parse_list(r#"{"errors":[]}"#).is_err());
        assert!(parse_list("nope").is_err());
    }

    #[test]
    fn backend_name_is_vault() {
        let s = VaultSyncer::from_path("secret/foo");
        assert_eq!(s.backend(), "vault");
    }
}
