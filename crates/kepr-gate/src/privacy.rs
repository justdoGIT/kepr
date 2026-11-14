//! Provider-schema privacy processing, before authentication injection.

use kepr_core::privacy::Preset;
use kepr_core::privacy::{Policy, Session};
use serde_json::Value;
use std::sync::Mutex;

#[path = "privacy_fields.rs"]
mod fields;
#[path = "privacy_schema.rs"]
mod schema;

pub struct Filter {
    session: Mutex<Option<Session>>,
    enabled: bool,
}

impl Filter {
    pub fn new(policy: Option<Policy>) -> Result<Self, String> {
        let enabled = policy.is_some();
        Ok(Self {
            session: Mutex::new(
                policy
                    .map(Session::new)
                    .transpose()
                    .map_err(str::to_owned)?,
            ),
            enabled,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn prepare(
        &self,
        path: &str,
        parts: &mut hyper::http::request::Parts,
        body: &[u8],
    ) -> Result<(Option<Vec<u8>>, usize), String> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| "privacy state unavailable")?;
        let Some(session) = guard.as_mut() else {
            return Ok((None, 0));
        };
        if session.preset() == Preset::LocalOnly {
            return Err("local-only policy forbids cloud requests".into());
        }
        if parts.method != hyper::Method::POST || parts.uri.query().is_some() {
            return Err("privacy adapter requires a POST without a query string".into());
        }
        let schema = fields::schema(path).ok_or("unsupported privacy endpoint")?;
        if body.len() > kepr_core::privacy::MAX_TEXT_BYTES {
            return Err("privacy input too large".into());
        }
        let is_json = parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next() == Some("application/json"))
            .unwrap_or(false);
        if !is_json {
            return Err("privacy adapter requires JSON content".into());
        }
        let mut request: Value =
            serde_json::from_slice(body).map_err(|_| "invalid privacy request JSON")?;
        let object = request
            .as_object_mut()
            .ok_or("privacy request must be an object")?;
        if object.keys().any(|key| !schema.contains(&key.as_str())) {
            return Err("unsupported privacy request field".into());
        }
        if object
            .get("background")
            .is_some_and(|v| v != &Value::Bool(false))
        {
            return Err("background provider processing is unsupported".into());
        }
        let mut count = 0;
        for key in ["metadata", "user", "prompt_cache_key", "safety_identifier"] {
            count += usize::from(object.remove(key).is_some());
        }
        if path.ends_with("responses") || path.ends_with("completions") {
            object.insert("store".into(), Value::Bool(false));
        }
        schema::validate(path, &request).map_err(str::to_owned)?;
        let mut nodes = 0;
        count += fields::walk(&mut request, session, 0, &mut nodes)?;
        schema::validate(path, &request).map_err(str::to_owned)?;
        let removed: Vec<_> = parts
            .headers
            .keys()
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "content-type" | "accept" | "anthropic-version"
                )
            })
            .cloned()
            .collect();
        for name in removed {
            parts.headers.remove(name);
        }
        parts
            .headers
            .insert("content-type", "application/json".parse().unwrap());
        // Admission already consumed the caller's authentication. Forwarding
        // rebuilds the bound provider header from the resolved credential.
        for value in parts.headers.values() {
            let text = value
                .to_str()
                .map_err(|_| "invalid privacy protocol header")?;
            if session.transform(text).map_err(str::to_owned)?.1 > 0 {
                return Err("personal data in a protocol header".into());
            }
        }
        if let Some(accept) = parts.headers.get("accept") {
            if !matches!(
                accept.to_str(),
                Ok("application/json" | "text/event-stream" | "*/*")
            ) {
                return Err("unsupported privacy response format".into());
            }
        }
        if let Some(version) = parts.headers.get("anthropic-version") {
            if !version.to_str().ok().is_some_and(|v| {
                v.len() == 10 && v.bytes().all(|b| b.is_ascii_digit() || b == b'-')
            }) {
                return Err("invalid provider protocol version".into());
            }
        }
        let encoded = serde_json::to_vec(&request).map_err(|_| "cannot encode privacy request")?;
        if encoded.len() > kepr_core::privacy::MAX_TEXT_BYTES {
            return Err("transformed privacy request too large".into());
        }
        Ok((Some(encoded), count))
    }
}

#[cfg(test)]
#[path = "privacy_tests.rs"]
mod tests;
