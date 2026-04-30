// sync_aws_sm.rs — AWS Secrets Manager backend for `kepr sync`.
//
// Phase 2 ζ.2. Pushes / pulls a kepr credential to / from AWS
// Secrets Manager via signed REST calls. No SDK — SigV4 signing
// from `sync_aws_sigv4`, HTTP via `ureq`. Same lean-deps stance
// as the Vault backend.
//
// Auth: standard AWS env vars
//
//     AWS_ACCESS_KEY_ID
//     AWS_SECRET_ACCESS_KEY
//     AWS_REGION (or AWS_DEFAULT_REGION as fallback)
//     AWS_SESSION_TOKEN (optional, for STS / instance-profile creds)
//
// Path scheme: `aws-sm:<secret-id>` where `secret-id` is either
// the secret's friendly name (e.g. "prod/db/password") or its
// full ARN. AWS Secrets Manager accepts either form for both
// PutSecretValue and GetSecretValue.
//
// Wire shape:
//
//     push: PutSecretValue first; on ResourceNotFoundException
//           (the secret hasn't been created yet) fall back to
//           CreateSecret. Both paths leave the same end state:
//           the secret with `SecretString` = our value.
//
//     pull: GetSecretValue. Response carries `SecretString`
//           (plain) or `SecretBinary` (base64). kepr always
//           writes via SecretString, so we read SecretString
//           and reject SecretBinary as "not a kepr-written
//           value".
//
// Failure semantics: every transport / SigV4 / IAM-permission
// error surfaces as `Err(String)` with the HTTP status code and
// the AWS response body (which is structured JSON containing
// `__type` + `message`). The CLI prints it verbatim.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::sync::Syncer;
use crate::sync_aws_sigv4::{format_amz_date, sign, SigV4Input};
use kepr_core::generate::ZeroString;

pub struct AwsSmSyncer {
    secret_id: String,
}

impl AwsSmSyncer {
    pub fn from_path(secret_id: &str) -> Self {
        Self {
            secret_id: secret_id.to_string(),
        }
    }

    fn read_env() -> Result<AwsCreds, String> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            "AWS_ACCESS_KEY_ID not set — set your AWS credentials in the environment".to_string()
        })?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| "AWS_SECRET_ACCESS_KEY not set".to_string())?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .map_err(|_| {
                "AWS_REGION (or AWS_DEFAULT_REGION) not set — required to compute the SigV4 scope"
                    .to_string()
            })?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        Ok(AwsCreds {
            access_key,
            secret_key: ZeroString::from_string(secret_key),
            region,
            session_token,
        })
    }

    /// Make one SigV4-signed POST to Secrets Manager. Used by
    /// both the push and pull paths; the only difference is the
    /// `target` and the body. Returns `(status, body)` for the
    /// caller to interpret.
    fn signed_post(
        &self,
        creds: &AwsCreds,
        target: &str,
        body: &[u8],
    ) -> Result<(u16, String), String> {
        let host = format!("secretsmanager.{}.amazonaws.com", creds.region);
        let url = format!("https://{host}/");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let amz_date = format_amz_date(now);

        let input = SigV4Input {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            region: &creds.region,
            service: "secretsmanager",
            session_token: creds.session_token.as_deref(),
            method: "POST",
            host: &host,
            path: "/",
            query: "",
            amz_target: target,
            body,
            amz_date: &amz_date,
        };
        let signed = sign(&input);

        let mut req = ureq::post(&url).set("Content-Type", "application/x-amz-json-1.1");
        for (name, value) in &signed.headers {
            // ureq sets `Host` automatically from the URL — skip
            // here to avoid duplicate-header rejection.
            if name == "Host" {
                continue;
            }
            req = req.set(name, value);
        }

        let response = req.send_bytes(body);
        match response {
            Ok(r) => {
                let status = r.status();
                let body = r.into_string().unwrap_or_default();
                Ok((status, body))
            }
            Err(ureq::Error::Status(code, r)) => Ok((code, r.into_string().unwrap_or_default())),
            Err(e) => Err(format!("aws-sm transport: {e}")),
        }
    }
}

#[derive(Debug)]
struct AwsCreds {
    access_key: String,
    secret_key: ZeroString,
    region: String,
    session_token: Option<String>,
}

impl Syncer for AwsSmSyncer {
    fn backend(&self) -> &'static str {
        "aws-sm"
    }

    fn push(&self, value: &str) -> Result<(), String> {
        let creds = Self::read_env()?;
        // Try PutSecretValue first; fall back to CreateSecret on
        // ResourceNotFoundException (the secret doesn't exist
        // yet). This is the standard AWS pattern for "ensure the
        // secret has this value" — neither call alone covers
        // both the create and update cases.
        let put_body = serde_json::json!({
            "SecretId": self.secret_id,
            "SecretString": value,
        });
        let (status, body) = self.signed_post(
            &creds,
            "secretsmanager.PutSecretValue",
            put_body.to_string().as_bytes(),
        )?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        // Fall back to CreateSecret only on the specific
        // not-found error; any other 4xx is a real problem
        // (auth, IAM permissions) and should surface as-is.
        if status == 400 && body.contains("ResourceNotFoundException") {
            let create_body = serde_json::json!({
                "Name": self.secret_id,
                "SecretString": value,
            });
            let (cs_status, cs_body) = self.signed_post(
                &creds,
                "secretsmanager.CreateSecret",
                create_body.to_string().as_bytes(),
            )?;
            if (200..300).contains(&cs_status) {
                return Ok(());
            }
            return Err(format!("aws-sm CreateSecret: HTTP {cs_status} {cs_body}"));
        }
        Err(format!("aws-sm PutSecretValue: HTTP {status} {body}"))
    }

    fn pull(&self) -> Result<String, String> {
        let creds = Self::read_env()?;
        let body = serde_json::json!({"SecretId": self.secret_id});
        let (status, response) = self.signed_post(
            &creds,
            "secretsmanager.GetSecretValue",
            body.to_string().as_bytes(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!("aws-sm GetSecretValue: HTTP {status} {response}"));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("aws-sm: parse JSON: {e}"))?;
        // Prefer SecretString. SecretBinary (base64) is what AWS
        // returns when the value was written via the binary API;
        // kepr always writes via SecretString, so a Binary-only
        // response means the secret wasn't kepr-managed.
        if let Some(s) = parsed.get("SecretString").and_then(|v| v.as_str()) {
            return Ok(s.to_string());
        }
        if parsed.get("SecretBinary").is_some() {
            return Err("aws-sm: secret stored as SecretBinary, not SecretString — \
                        was it written by `kepr sync push`?"
                .to_string());
        }
        Err(format!(
            "aws-sm GetSecretValue: response missing SecretString: {response}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_path_stores_secret_id() {
        let s = AwsSmSyncer::from_path("prod/db/password");
        assert_eq!(s.secret_id, "prod/db/password");
        assert_eq!(s.backend(), "aws-sm");
    }

    #[test]
    fn from_path_accepts_arn_form() {
        // ARN-form secret IDs are also valid AWS inputs. The kepr
        // wrapper is opaque on this — we just pass through.
        let arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-AbCdEf";
        let s = AwsSmSyncer::from_path(arn);
        assert_eq!(s.secret_id, arn);
    }

    #[test]
    fn read_env_complains_when_creds_missing() {
        // Snapshot + restore so other tests in the same binary
        // can't trip on whichever set we leave behind.
        let prior_ak = std::env::var("AWS_ACCESS_KEY_ID").ok();
        let prior_sk = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
        let prior_region = std::env::var("AWS_REGION").ok();
        let prior_default_region = std::env::var("AWS_DEFAULT_REGION").ok();
        let prior_token = std::env::var("AWS_SESSION_TOKEN").ok();

        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_REGION");
        std::env::remove_var("AWS_DEFAULT_REGION");
        std::env::remove_var("AWS_SESSION_TOKEN");

        let err = AwsSmSyncer::read_env().expect_err("must require ACCESS_KEY_ID");
        assert!(err.contains("AWS_ACCESS_KEY_ID"), "msg: {err}");

        std::env::set_var("AWS_ACCESS_KEY_ID", "AKID");
        let err = AwsSmSyncer::read_env().expect_err("must require SECRET_ACCESS_KEY");
        assert!(err.contains("AWS_SECRET_ACCESS_KEY"), "msg: {err}");

        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret");
        let err = AwsSmSyncer::read_env().expect_err("must require REGION");
        assert!(err.contains("AWS_REGION"), "msg: {err}");

        std::env::set_var("AWS_REGION", "us-east-1");
        let creds = AwsSmSyncer::read_env().unwrap();
        assert_eq!(creds.access_key, "AKID");
        assert_eq!(creds.secret_key.as_str(), "secret");
        assert_eq!(creds.region, "us-east-1");
        assert!(creds.session_token.is_none());

        std::env::set_var("AWS_SESSION_TOKEN", "sts-token");
        let creds = AwsSmSyncer::read_env().unwrap();
        assert_eq!(creds.session_token.as_deref(), Some("sts-token"));

        // Restore each var.
        for (var, val) in [
            ("AWS_ACCESS_KEY_ID", prior_ak),
            ("AWS_SECRET_ACCESS_KEY", prior_sk),
            ("AWS_REGION", prior_region),
            ("AWS_DEFAULT_REGION", prior_default_region),
            ("AWS_SESSION_TOKEN", prior_token),
        ] {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }

    #[test]
    fn read_env_falls_back_to_default_region() {
        let prior_ak = std::env::var("AWS_ACCESS_KEY_ID").ok();
        let prior_sk = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
        let prior_region = std::env::var("AWS_REGION").ok();
        let prior_default = std::env::var("AWS_DEFAULT_REGION").ok();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AKID");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "secret");
        std::env::remove_var("AWS_REGION");
        std::env::set_var("AWS_DEFAULT_REGION", "eu-west-2");

        let creds = AwsSmSyncer::read_env().expect("DEFAULT_REGION fallback works");
        assert_eq!(creds.region, "eu-west-2");

        for (var, val) in [
            ("AWS_ACCESS_KEY_ID", prior_ak),
            ("AWS_SECRET_ACCESS_KEY", prior_sk),
            ("AWS_REGION", prior_region),
            ("AWS_DEFAULT_REGION", prior_default),
        ] {
            match val {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }
}
