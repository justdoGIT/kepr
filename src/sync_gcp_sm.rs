// sync_gcp_sm.rs — Google Cloud Secret Manager backend for `kepr sync`.
//
// Phase 2 ζ.3. Pushes / pulls a kepr credential to / from GCP
// Secret Manager via REST. No SDK — bearer-token auth with
// `GCP_ACCESS_TOKEN`, HTTP via `ureq`. Same lean-deps stance as
// the Vault and AWS-SM backends.
//
// Auth: bearer token from a user-provided env var.
//
//     export GCP_ACCESS_TOKEN=$(gcloud auth print-access-token)
//     kepr sync-push DB_PASS --url gcp-sm:projects/myproj/secrets/db_pass
//
// Why bearer-token + env var rather than parsing a service-account
// JSON file: the JWT-from-service-account flow needs RSA signing
// (private-key bytes from the JSON, RS256 over the JWT, exchange
// against oauth2.googleapis.com/token). That's another ~200 LOC
// of crypto + an `rsa` dep. The `gcloud auth print-access-token`
// path is the developer-day-1 workflow anyway, and operators
// running on GCE / GKE can use the metadata server's bearer
// token via `curl http://metadata.google.internal/...`.
//
// Path scheme: `gcp-sm:projects/PROJECT/secrets/SECRET`. Strict
// form to avoid path-injection ambiguity. The path goes verbatim
// into the API URL after the `/v1/` prefix.
//
// Wire shape:
//
//     pull: GET /v1/{path}/versions/latest:access
//           Response: {"payload":{"data":"<base64 bytes>"}}
//
//     push: POST /v1/{path}:addVersion
//           Body: {"payload":{"data":"<base64(value)>"}}
//           If secret doesn't exist:
//             POST /v1/projects/PROJECT/secrets?secretId=SECRET
//             Body: {"replication":{"automatic":{}}}
//           Then retry addVersion.
//
// Response payload bytes are returned base64; we decode on pull
// and verify they're valid UTF-8 before handing to the daemon —
// kepr's `Request::Set` takes a `ZeroString`, so binary-only
// values would have to surface as an error.

use base64::Engine;

use crate::sync::Syncer;
use kepr_core::generate::ZeroString;

/// GCP Secret Manager API host. Versioned `/v1/`; no plans to
/// move to `/v1beta1` etc. — `/v1` is the long-term stable surface.
const GCP_SM_HOST: &str = "https://secretmanager.googleapis.com";

pub struct GcpSmSyncer {
    /// User-supplied path AFTER the `gcp-sm:` scheme. Must be
    /// `projects/PROJECT/secrets/SECRET`. Stored as-is and
    /// validated at call time so a typo on construction surfaces
    /// in the error message rather than as a 404.
    path: String,
}

impl GcpSmSyncer {
    pub fn from_path(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Validate that `self.path` is `projects/<P>/secrets/<S>`
    /// (no leading slash, exactly four segments). Returns the
    /// parsed (project, secret) tuple — useful for the
    /// CreateSecret call which needs them separately.
    fn parse_path(&self) -> Result<(String, String), String> {
        let segments: Vec<&str> = self.path.split('/').collect();
        if segments.len() != 4 || segments[0] != "projects" || segments[2] != "secrets" {
            return Err(format!(
                "gcp-sm path must be `projects/<PROJECT>/secrets/<SECRET>`, got {:?}",
                self.path
            ));
        }
        if segments[1].is_empty() || segments[3].is_empty() {
            return Err(format!(
                "gcp-sm path has empty project or secret: {:?}",
                self.path
            ));
        }
        Ok((segments[1].to_string(), segments[3].to_string()))
    }

    fn read_token() -> Result<ZeroString, String> {
        let token = std::env::var("GCP_ACCESS_TOKEN").map_err(|_| {
            "GCP_ACCESS_TOKEN not set — get one with: gcloud auth print-access-token \
             (or use the GCE/GKE metadata server)"
                .to_string()
        })?;
        Ok(ZeroString::from_string(token))
    }

    fn http_post(url: &str, token: &ZeroString, body: &[u8]) -> Result<(u16, String), String> {
        let req = crate::sync_http::agent()
            .post(url)
            .set("Authorization", &format!("Bearer {}", token.as_str()))
            .set("Content-Type", "application/json");
        crate::sync_http::send(req, Some(body)).map_err(|e| format!("gcp-sm transport: {e}"))
    }

    fn http_get(url: &str, token: &ZeroString) -> Result<(u16, String), String> {
        let req = crate::sync_http::agent()
            .get(url)
            .set("Authorization", &format!("Bearer {}", token.as_str()));
        crate::sync_http::send(req, None).map_err(|e| format!("gcp-sm transport: {e}"))
    }
}

impl Syncer for GcpSmSyncer {
    fn backend(&self) -> &'static str {
        "gcp-sm"
    }

    fn push(&self, value: &str) -> Result<(), String> {
        let (project, secret_id) = self.parse_path()?;
        let token = Self::read_token()?;
        // GCP Secret Manager wants base64-encoded payload bytes.
        // Use the standard base64 alphabet; no URL-safe variant
        // (the API doesn't accept that).
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        let body = serde_json::json!({"payload": {"data": payload_b64}});

        // Try addVersion first. Falls back to CreateSecret + retry
        // on 404 (NOT_FOUND), which is the standard GCP "secret
        // doesn't exist yet" response. Any other status surfaces
        // as-is.
        let add_url = format!("{GCP_SM_HOST}/v1/{}:addVersion", self.path);
        let (status, response) = Self::http_post(&add_url, &token, body.to_string().as_bytes())?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        if status != 404 {
            return Err(format!(
                "gcp-sm addVersion: HTTP {status} {}",
                crate::sync_http::error_summary(&response)
            ));
        }

        // Create the secret (no payload — that's a separate call)
        // then retry addVersion. The CreateSecret request body
        // configures the replication policy; `automatic` lets GCP
        // pick regions, which is the right default for a CLI-driven
        // workflow.
        let create_url =
            format!("{GCP_SM_HOST}/v1/projects/{project}/secrets?secretId={secret_id}",);
        let create_body = serde_json::json!({"replication": {"automatic": {}}});
        let (cs_status, cs_response) =
            Self::http_post(&create_url, &token, create_body.to_string().as_bytes())?;
        if !(200..300).contains(&cs_status) {
            return Err(format!(
                "gcp-sm CreateSecret: HTTP {cs_status} {}",
                crate::sync_http::error_summary(&cs_response)
            ));
        }
        // Retry the addVersion. If it still fails the secret
        // exists but our payload didn't land — surface verbatim.
        let (status2, response2) = Self::http_post(&add_url, &token, body.to_string().as_bytes())?;
        if (200..300).contains(&status2) {
            Ok(())
        } else {
            Err(format!(
                "gcp-sm addVersion (after CreateSecret): HTTP {status2} {}",
                crate::sync_http::error_summary(&response2)
            ))
        }
    }

    fn pull(&self) -> Result<String, String> {
        let _ = self.parse_path()?; // surface a path-shape error before the network round-trip
        let token = Self::read_token()?;
        let url = format!("{GCP_SM_HOST}/v1/{}/versions/latest:access", self.path);
        let (status, response) = Self::http_get(&url, &token)?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "gcp-sm access: HTTP {status} {}",
                crate::sync_http::error_summary(&response)
            ));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("gcp-sm: parse JSON: {e}"))?;
        let b64 = parsed
            .pointer("/payload/data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("gcp-sm access: response missing /payload/data: {response}"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("gcp-sm: base64 decode: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("gcp-sm: payload not valid UTF-8: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_path_stores_path_verbatim() {
        let s = GcpSmSyncer::from_path("projects/myproj/secrets/db_pass");
        assert_eq!(s.path, "projects/myproj/secrets/db_pass");
        assert_eq!(s.backend(), "gcp-sm");
    }

    #[test]
    fn parse_path_accepts_well_formed_path() {
        let s = GcpSmSyncer::from_path("projects/myproj-123/secrets/api-key");
        let (project, secret) = s.parse_path().unwrap();
        assert_eq!(project, "myproj-123");
        assert_eq!(secret, "api-key");
    }

    #[test]
    fn parse_path_rejects_short_form() {
        // A bare "secret" path (without projects/.../secrets/...)
        // is meaningless to GCP SM. Pin the rejection.
        let s = GcpSmSyncer::from_path("just-a-secret-name");
        let err = s.parse_path().expect_err("must reject");
        assert!(err.contains("projects"), "msg: {err}");
    }

    #[test]
    fn parse_path_rejects_wrong_segment_names() {
        // The user wrote `secret` (singular) instead of `secrets`.
        // GCP would 404; we surface the path-shape error first so
        // the user sees the actual problem.
        let s = GcpSmSyncer::from_path("projects/myproj/secret/foo");
        let err = s.parse_path().expect_err("must reject");
        assert!(err.contains("projects"), "msg: {err}");
    }

    #[test]
    fn parse_path_rejects_empty_components() {
        let s = GcpSmSyncer::from_path("projects//secrets/foo");
        let err = s.parse_path().expect_err("must reject");
        assert!(err.contains("empty"), "msg: {err}");
    }

    #[test]
    fn read_token_complains_when_missing() {
        // Snapshot + restore so other tests in the same binary
        // can't trip on whichever value we leave behind.
        let prior = std::env::var("GCP_ACCESS_TOKEN").ok();
        std::env::remove_var("GCP_ACCESS_TOKEN");

        let err = GcpSmSyncer::read_token().expect_err("must require token");
        assert!(err.contains("GCP_ACCESS_TOKEN"), "msg: {err}");
        assert!(
            err.contains("gcloud auth"),
            "names how to obtain one: {err}"
        );

        std::env::set_var("GCP_ACCESS_TOKEN", "ya29.AbC...");
        let token = GcpSmSyncer::read_token().unwrap();
        assert_eq!(token.as_str(), "ya29.AbC...");

        match prior {
            Some(v) => std::env::set_var("GCP_ACCESS_TOKEN", v),
            None => std::env::remove_var("GCP_ACCESS_TOKEN"),
        }
    }

    #[test]
    fn base64_round_trip_is_lossless() {
        // Pin that the base64 alphabet we use (STANDARD, with
        // padding) round-trips through GCP's wire-format
        // expectations. Test the values most likely to break:
        // empty, single byte, multi-byte UTF-8, control bytes.
        let samples: &[&[u8]] = &[
            b"",
            b"a",
            b"Hello, world!",
            "naïve résumé".as_bytes(),
            &[0x00u8, 0x01, 0x7f, 0x80, 0xff],
        ];
        for sample in samples {
            let encoded = base64::engine::general_purpose::STANDARD.encode(sample);
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .unwrap();
            assert_eq!(decoded, *sample, "round-trip lost bytes");
        }
    }
}
