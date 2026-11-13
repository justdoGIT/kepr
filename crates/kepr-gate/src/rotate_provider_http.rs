//! One-shot provider key rotation executed by kepr-gate.
//!
//! The daemon sends only credential names in `RotationConfig`. Both the
//! bootstrap and target values are resolved over the private fd3 channel; the
//! CLI never receives either value. A replacement is stored only after its
//! provider accepts an authenticated validation request.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request};
use kepr_core::gate_protocol::RotationConfig;
use kepr_core::generate::ZeroString;
use serde_json::Value;

use crate::proxy::UpstreamClient;
use crate::vault::Cache;

const MAX_REPLY: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct Spec {
    host: &'static str,
    create_path: &'static str,
    validate_path: &'static str,
    revoke_prefix: &'static str,
    key_pointer: &'static str,
    id_pointer: &'static str,
    create_body: &'static str,
}

fn spec(provider: &str) -> Option<Spec> {
    Some(match provider {
        "openrouter" => Spec {
            host: "openrouter.ai",
            create_path: "/api/v1/keys",
            validate_path: "/api/v1/key",
            revoke_prefix: "/api/v1/keys/",
            key_pointer: "/key",
            id_pointer: "/hash",
            create_body: r#"{"name":"kepr rotated key"}"#,
        },
        "venice" => Spec {
            host: "api.venice.ai",
            create_path: "/api/v1/api_keys",
            validate_path: "/api/v1/models",
            revoke_prefix: "/api/v1/api_keys/",
            key_pointer: "/data/apiKey",
            id_pointer: "/data/id",
            create_body: r#"{"apiKeyType":"INFERENCE","description":"kepr rotated key"}"#,
        },
        "openai" => Spec {
            host: "api.openai.com",
            create_path: "/v1/organization/admin_api_keys",
            validate_path: "/v1/organization/admin_api_keys",
            revoke_prefix: "/v1/organization/admin_api_keys/",
            key_pointer: "/value",
            id_pointer: "/id",
            create_body: r#"{"name":"kepr rotated key"}"#,
        },
        _ => return None,
    })
}

async fn request(
    client: &UpstreamClient,
    method: Method,
    url: &str,
    bearer: &ZeroString,
    body: Option<&'static str>,
) -> Result<(u16, ZeroString), String> {
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", bearer.as_str()))
        .map_err(|_| "provider request could not be authenticated".to_string())?;
    auth.set_sensitive(true);
    let mut builder = Request::builder()
        .method(method)
        .uri(url)
        .header(AUTHORIZATION, auth);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|_| "provider request could not be built".to_string())?;
    let response = client
        .request(request)
        .await
        .map_err(|_| "provider request failed".to_string())?;
    let status = response.status().as_u16();
    let body = Limited::new(response.into_body(), MAX_REPLY)
        .collect()
        .await
        .map_err(|_| "provider response was too large or unreadable".to_string())?
        .to_bytes();
    let body = String::from_utf8(body.to_vec())
        .map_err(|_| "provider returned a non-text response".to_string())?;
    Ok((status, ZeroString::from(body)))
}

fn extract_key(body: &str, pointer: &str) -> Result<ZeroString, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "provider returned malformed JSON".to_string())?;
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .map(ZeroString::from)
        .ok_or_else(|| "provider reply did not contain a new API key".to_string())
}

fn extract_id(body: &str, pointer: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "provider returned malformed JSON".to_string())?;
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .map(ToOwned::to_owned)
        .ok_or_else(|| "provider reply did not contain a revocation id".to_string())
}

struct Creation {
    key: ZeroString,
    id: String,
}

fn extract_creation(body: &str, spec: Spec) -> Result<Creation, String> {
    Ok(Creation {
        key: extract_key(body, spec.key_pointer)?,
        id: extract_id(body, spec.id_pointer)?,
    })
}

fn provider_url(spec: Spec, path: &str) -> String {
    format!("https://{}{}", spec.host, path)
}

async fn revoke(client: &UpstreamClient, spec: Spec, id: &str, bearer: &ZeroString) {
    let path = format!("{}{}", spec.revoke_prefix, id);
    let url = provider_url(spec, &path);
    let _ = request(client, Method::DELETE, &url, bearer, None).await;
}

fn status_error(operation: &str, status: u16) -> String {
    format!("provider {operation} rejected the request (HTTP {status})")
}

/// Run the complete create → validate → daemon commit flow.
///
/// A newly created provider key is revoked on every post-create failure. The
/// old key remains active until the daemon has durably committed the validated
/// replacement.
pub(crate) async fn run(
    cache: &Cache,
    client: &UpstreamClient,
    config: &RotationConfig,
) -> Result<(), String> {
    let spec = spec(&config.provider)
        .ok_or_else(|| "provider has no supported rotation flow".to_string())?;
    let (old, _) = cache
        .get(&config.target, spec.host, 443)
        .map_err(|_| "target credential unavailable".to_string())?;
    let (bootstrap, _) = cache
        .get(&config.bootstrap, spec.host, 443)
        .map_err(|_| "bootstrap credential unavailable".to_string())?;
    if config.provider == "openai" && !old.as_str().starts_with("sk-admin-") {
        return Err("OpenAI rotation requires an organization admin target key".into());
    }

    let (status, created) = request(
        client,
        Method::POST,
        &provider_url(spec, spec.create_path),
        &bootstrap,
        Some(spec.create_body),
    )
    .await?;
    if !(200..=299).contains(&status) {
        return Err(status_error("key creation", status));
    }
    let creation = match extract_creation(created.as_str(), spec) {
        Ok(creation) => creation,
        Err(error) => {
            if let Ok(id) = extract_id(created.as_str(), spec.id_pointer) {
                revoke(client, spec, &id, &bootstrap).await;
            }
            return Err(error);
        }
    };
    if creation.key.as_str() == old.as_str() || creation.key.as_str() == bootstrap.as_str() {
        revoke(client, spec, &creation.id, &bootstrap).await;
        return Err("provider returned an existing key instead of a replacement".into());
    }

    let validation = request(
        client,
        Method::GET,
        &provider_url(spec, spec.validate_path),
        &creation.key,
        None,
    )
    .await;
    let status = match validation {
        Ok((status, _)) => status,
        Err(_) => {
            revoke(client, spec, &creation.id, &bootstrap).await;
            return Err("provider replacement validation failed".into());
        }
    };
    if !(200..=299).contains(&status) {
        revoke(client, spec, &creation.id, &bootstrap).await;
        return Err(status_error("replacement validation", status));
    }
    if cache.rotate_commit(&config.target, &creation.key).is_err() {
        revoke(client, spec, &creation.id, &bootstrap).await;
        return Err("rotation failed: replacement could not be stored".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_specs_are_exactly_scoped() {
        assert_eq!(spec("openrouter").unwrap().host, "openrouter.ai");
        assert_eq!(spec("venice").unwrap().create_path, "/api/v1/api_keys");
        assert_eq!(
            spec("openai").unwrap().validate_path,
            "/v1/organization/admin_api_keys"
        );
        assert!(spec("moonshot").is_none());
    }

    #[test]
    fn only_declared_one_time_key_fields_are_extracted() {
        let key = extract_key(r#"{"data":{"apiKey":"new-key"}}"#, "/data/apiKey").unwrap();
        assert_eq!(key.as_str(), "new-key");
        assert!(extract_key(r#"{"data":{"apiKey":""}}"#, "/data/apiKey").is_err());
        assert!(extract_key(r#"{"key":"new-key"}"#, "/data/apiKey").is_err());
    }
    #[test]
    fn creation_requires_a_safe_revocation_identifier() {
        let spec = spec("venice").unwrap();
        let creation =
            extract_creation(r#"{"data":{"apiKey":"new-key","id":"key-123"}}"#, spec).unwrap();
        assert_eq!(creation.id, "key-123");
        assert!(extract_creation(r#"{"data":{"apiKey":"new-key","id":"bad/id"}}"#, spec).is_err());
    }
}
