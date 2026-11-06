//! Redact key-shaped conversation text before the final DLP check.

use serde_json::Value;

pub fn prepare(path: &str, body: &[u8]) -> (Vec<u8>, usize) {
    if !matches!(
        path,
        "/v1/responses"
            | "/responses"
            | "/v1/messages"
            | "/v1/chat/completions"
            | "/chat/completions"
    ) {
        return (body.to_vec(), 0);
    }
    let Ok(mut request) = serde_json::from_slice::<Value>(body) else {
        return (body.to_vec(), 0);
    };
    let mut count = text_field(&mut request, "instructions");
    count += content_field(&mut request, "system");
    for field in ["input", "messages"] {
        if let Some(items) = request.get_mut(field) {
            match items {
                Value::String(_) => count += text(items),
                Value::Array(items) => {
                    for item in items {
                        count += item_text(item);
                    }
                }
                _ => {}
            }
        }
    }
    if count == 0 {
        return (body.to_vec(), 0);
    }
    (
        serde_json::to_vec(&request).expect("JSON value serializes"),
        count,
    )
}

fn text(value: &mut Value) -> usize {
    let Value::String(s) = value else { return 0 };
    let (clean, count) = kepr_core::redact::text(s);
    if count > 0 {
        *s = clean;
    }
    count
}

fn text_field(value: &mut Value, field: &str) -> usize {
    value.get_mut(field).map(text).unwrap_or(0)
}

fn content_field(value: &mut Value, field: &str) -> usize {
    value.get_mut(field).map(content).unwrap_or(0)
}

fn content(value: &mut Value) -> usize {
    match value {
        Value::String(_) => text(value),
        Value::Array(parts) => parts
            .iter_mut()
            .map(|p| {
                match p["type"].as_str() {
                    Some("text" | "input_text" | "output_text" | "summary_text") => {
                        text_field(p, "text")
                    }
                    Some("thinking") if p["signature"].is_null() => text_field(p, "thinking"),
                    Some("tool_result") => content_field(p, "content"),
                    _ => 0, // Images, signatures and encrypted state are opaque.
                }
            })
            .sum(),
        _ => 0,
    }
}

fn item_text(item: &mut Value) -> usize {
    match item["type"].as_str() {
        Some("function_call") => text_field(item, "arguments"),
        Some("custom_tool_call") => text_field(item, "input"),
        Some("function_call_output" | "custom_tool_call_output") => content_field(item, "output"),
        Some("reasoning") => content_field(item, "summary"),
        Some("message") | None if item.get("role").is_some() => {
            let mut count = content_field(item, "content");
            if let Some(calls) = item.get_mut("tool_calls").and_then(Value::as_array_mut) {
                for call in calls {
                    if let Some(function) = call.get_mut("function") {
                        count += text_field(function, "arguments");
                    }
                }
            }
            count
        }
        _ => 0,
    }
}

/// Canary screening happens first in proxy.rs. Stored credentials must be
/// refused on the original bytes, even when another field can be redacted.
pub fn checked(
    path: &str,
    parts: &hyper::http::request::Parts,
    body: &[u8],
    secrets: &[(String, kepr_core::generate::ZeroString)],
) -> Result<(Vec<u8>, usize), String> {
    if let crate::dlp::Verdict::StoredSecret(_) = crate::dlp::scan(body, secrets) {
        return Err(crate::dlp::check(parts, body, secrets).expect("stored secret is blocked"));
    }
    let (clean, count) = prepare(path, body);
    if let Some(reason) = crate::dlp::check(parts, &clean, secrets) {
        return Err(reason);
    }
    Ok((clean, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_history_is_redacted_without_changing_call_ids() {
        let token = format!("sk-proj-{}", "a".repeat(24));
        let body = json!({"input":[{"type":"function_call_output", "call_id":"call_example", "output":token}], "model":"test"});
        let (out, count) = prepare("/v1/responses", &serde_json::to_vec(&body).unwrap());
        assert!(count > 0);
        assert!(!crate::dlp::looks_like_key(&out));
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["input"][0]["call_id"], "call_example");
    }

    #[test]
    fn unrelated_apis_and_opaque_data_are_unchanged() {
        let body = br#"{"input":[{"type":"reasoning","encrypted_content":"opaque"}],"metadata":{"note":"keep"}}"#;
        assert_eq!(prepare("/v1/files", body), (body.to_vec(), 0));
        assert_eq!(prepare("/v1/responses", body), (body.to_vec(), 0));
    }

    #[test]
    fn stored_values_headers_and_metadata_still_block() {
        let token = format!("sk-proj-{}", "a".repeat(24));
        let secrets = vec![(
            "TEST_KEY".into(),
            kepr_core::generate::ZeroString::from_string(token.clone()),
        )];
        let (parts, _) = hyper::Request::post("/v1/responses")
            .body(())
            .unwrap()
            .into_parts();
        let body = serde_json::to_vec(&json!({"input":token})).unwrap();
        assert!(checked("/v1/responses", &parts, &body, &secrets).is_err());
        assert!(checked("/v1/responses", &parts, &body, &[]).is_ok());
        let body = serde_json::to_vec(&json!({"metadata":{"key":token}})).unwrap();
        assert!(checked("/v1/responses", &parts, &body, &[]).is_err());
        for name in ["x-note", "content-encoding"] {
            let value = if name == "x-note" {
                token.as_str()
            } else {
                "gzip"
            };
            let (parts, _) = hyper::Request::post("/v1/responses")
                .header(name, value)
                .body(())
                .unwrap()
                .into_parts();
            let body = serde_json::to_vec(&json!({"input":token})).unwrap();
            assert!(checked("/v1/responses", &parts, &body, &[]).is_err());
        }
    }

    #[test]
    fn signatures_and_history_links_survive_redaction() {
        let token = format!("sk-proj-{}", "a".repeat(24));
        let body = json!({"previous_response_id":"resp_saved", "input":[
            {"type":"message", "id":"msg_saved", "role":"assistant", "phase":"commentary", "content":[{"type":"output_text", "text":token}]},
            {"type":"reasoning", "id":"rs_saved", "encrypted_content":"opaque", "summary":[]}
        ]});
        let (out, count) = prepare("/v1/responses", &serde_json::to_vec(&body).unwrap());
        assert_eq!(count, 1);
        let clean: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(clean["previous_response_id"], body["previous_response_id"]);
        assert_eq!(clean["input"][1], body["input"][1]);
        assert_eq!(clean["input"][0]["id"], "msg_saved");
        assert_eq!(clean["input"][0]["phase"], "commentary");
    }

    #[test]
    fn signed_thinking_is_refused_instead_of_invalidating_its_signature() {
        let token = format!("sk-proj-{}", "a".repeat(24));
        let body = serde_json::to_vec(&json!({"messages":[{"role":"assistant", "content":[
            {"type":"thinking", "thinking":token, "signature":"opaque"}
        ]}]}))
        .unwrap();
        let (parts, _) = hyper::Request::post("/v1/messages")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(prepare("/v1/messages", &body), (body.clone(), 0));
        assert!(checked("/v1/messages", &parts, &body, &[]).is_err());
    }
}
