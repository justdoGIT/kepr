// sync_aws_sm.rs — AWS Secrets Manager backend for `kepr sync`.
//
// Phase 2 ζ.2. Pushes / pulls a kepr credential to / from AWS
// Secrets Manager via signed REST calls. No SDK — SigV4 signing
// from `kepr_core::sigv4`, HTTP via `ureq`. Same lean-deps stance
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
use kepr_core::generate::ZeroString;
use kepr_core::sigv4::{format_amz_date, sign, SigV4Input};

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
        // It becomes part of the host name: `x@evil.com#` would send the
        // signed request (and the secret) somewhere else.
        if region.is_empty()
            || region.len() > 32
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(format!("AWS_REGION {region:?} is not a region name"));
        }
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

        let mut req = crate::sync_http::agent()
            .post(&url)
            .set("Content-Type", "application/x-amz-json-1.1");
        for (name, value) in &signed.headers {
            // ureq sets `Host` automatically from the URL — skip
            // here to avoid duplicate-header rejection.
            if name == "Host" {
                continue;
            }
            req = req.set(name, value);
        }

        crate::sync_http::send(req, Some(body)).map_err(|e| format!("aws-sm transport: {e}"))
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
            return Err(format!(
                "aws-sm CreateSecret: HTTP {cs_status} {}",
                crate::sync_http::error_summary(&cs_body)
            ));
        }
        Err(format!(
            "aws-sm PutSecretValue: HTTP {status} {}",
            crate::sync_http::error_summary(&body)
        ))
    }

    fn pull(&self) -> Result<String, String> {
        match self.fetch()? {
            Some(v) => Ok(v.as_str().to_string()),
            None => Err("aws-sm GetSecretValue: HTTP 400 ResourceNotFoundException".into()),
        }
    }

    fn fetch(&self) -> Result<Option<zeroize::Zeroizing<String>>, String> {
        let creds = Self::read_env()?;
        let body = serde_json::json!({"SecretId": self.secret_id});
        let (status, response) = self.signed_post(
            &creds,
            "secretsmanager.GetSecretValue",
            body.to_string().as_bytes(),
        )?;
        let response = zeroize::Zeroizing::new(response);
        // T11.17: no such secret (create, for a dry run).
        if status == 400 && error_type(&response) == NOT_FOUND {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "aws-sm GetSecretValue: HTTP {status} {}",
                crate::sync_http::error_summary(&response)
            ));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("aws-sm: parse JSON: {e}"))?;
        // Prefer SecretString. SecretBinary (base64) is what AWS
        // returns when the value was written via the binary API;
        // kepr always writes via SecretString, so a Binary-only
        // response means the secret wasn't kepr-managed.
        if let Some(s) = parsed.get("SecretString").and_then(|v| v.as_str()) {
            return Ok(Some(zeroize::Zeroizing::new(s.to_string())));
        }
        if parsed.get("SecretBinary").is_some() {
            return Err("aws-sm: secret stored as SecretBinary, not SecretString — \
                        was it written by `kepr sync push`?"
                .to_string());
        }
        Err("aws-sm GetSecretValue: response missing SecretString".into())
    }
}

const NOT_FOUND: &str = "ResourceNotFoundException";

/// The AWS error type of a JSON error body (`__type`, after any `#`).
fn error_type(body: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let t = v.get("__type").and_then(|t| t.as_str()).unwrap_or("");
    t.rsplit('#').next().unwrap_or("").to_string()
}

/// T11.17: the secret names on one ListSecrets page, and its NextToken.
pub fn parse_list(body: &str) -> Result<(Vec<String>, Option<String>), String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "aws-sm ListSecrets: reply is not JSON")?;
    let list = v
        .get("SecretList")
        .and_then(|l| l.as_array())
        .ok_or("aws-sm ListSecrets: reply has no SecretList")?;
    let names = list
        .iter()
        .filter_map(|s| s.get("Name")?.as_str())
        .map(str::to_string)
        .collect();
    let next = v
        .get("NextToken")
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    Ok((names, next))
}

/// T11.17: the ListSecrets request body for one page.
pub fn list_body(prefix: &str, next: Option<&str>) -> serde_json::Value {
    let mut b = serde_json::json!({ "MaxResults": 100 });
    if !prefix.is_empty() {
        b["Filters"] = serde_json::json!([{ "Key": "name", "Values": [prefix] }]);
    }
    if let Some(t) = next {
        b["NextToken"] = t.into();
    }
    b
}

/// T11.17: every secret whose name starts with `prefix`, as
/// `(name, aws-sm:name)`. AWS's name filter is a case-insensitive
/// prefix match; the exact prefix is checked here too.
pub fn list(prefix: &str) -> Result<Vec<(String, String)>, String> {
    let creds = AwsSmSyncer::read_env()?;
    let me = AwsSmSyncer::from_path("");
    let (mut out, mut next) = (Vec::new(), None::<String>);
    for _ in 0..50 {
        let body = list_body(prefix, next.as_deref()).to_string();
        let (status, reply) =
            me.signed_post(&creds, "secretsmanager.ListSecrets", body.as_bytes())?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "aws-sm ListSecrets: HTTP {status} {}",
                error_type(&reply)
            ));
        }
        let (names, more) = parse_list(&reply)?;
        out.extend(
            names
                .into_iter()
                .filter(|n| n.starts_with(prefix))
                .map(|n| (n.clone(), format!("aws-sm:{n}"))),
        );
        match more {
            Some(t) => next = Some(t),
            None => return Ok(out),
        }
    }
    Err("aws-sm ListSecrets: too many pages".into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static ENV_TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn list_pages_parse_names_and_next_token() {
        let body = r#"{"SecretList":[{"ARN":"arn:x","Name":"prod/db"},{"Name":"prod/api"},{"ARN":"no-name"}],
                       "NextToken":"tok2"}"#;
        let (names, next) = parse_list(body).unwrap();
        assert_eq!(names, ["prod/db", "prod/api"]);
        assert_eq!(next.as_deref(), Some("tok2"));
        assert_eq!(parse_list(r#"{"SecretList":[]}"#).unwrap(), (vec![], None));
        assert!(parse_list(r#"{"__type":"AccessDeniedException"}"#).is_err());
        assert_eq!(
            list_body("prod/", Some("tok2")),
            serde_json::json!({"MaxResults":100,"Filters":[{"Key":"name","Values":["prod/"]}],"NextToken":"tok2"})
        );
        assert_eq!(list_body("", None), serde_json::json!({"MaxResults":100}));
    }

    #[test]
    fn not_found_is_recognised_by_error_type() {
        let body = r#"{"__type":"ResourceNotFoundException","Message":"can't find hunter2"}"#;
        assert_eq!(error_type(body), NOT_FOUND);
        assert_eq!(
            error_type(r#"{"__type":"com.amazonaws#ResourceNotFoundException"}"#),
            NOT_FOUND
        );
        assert_eq!(error_type("hunter2"), "");
    }

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
        let _guard = ENV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = ENV_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
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
