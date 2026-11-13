use super::*;
use hyper::{Method, Request};
use serde_json::{json, Value};

fn parts() -> hyper::http::request::Parts {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .header("user-agent", "personal-machine")
        .header("x-forwarded-for", "192.168.1.4")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[test]
fn sec_007_masks_text_and_removes_optional_metadata() {
    let f = Filter::new(Some(Policy::default())).unwrap();
    let bytes = serde_json::to_vec(&json!({"model":"test", "input":"alice@example.invalid",
        "metadata":{"email":"alice@example.invalid"}, "user":"alice", "store":true}))
    .unwrap();
    let mut p = parts();
    let (body, count) = f.prepare("/v1/responses", &mut p, &bytes).unwrap();
    let body = body.unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert!(count > 0);
    assert!(!String::from_utf8(body)
        .unwrap()
        .contains("alice@example.invalid"));
    assert!(v.get("metadata").is_none());
    assert!(v.get("user").is_none());
    assert_eq!(v["store"], false);
    assert!(!p.headers.contains_key("user-agent"));
    assert!(!p.headers.contains_key("x-forwarded-for"));
}

#[test]
fn sec_007_caller_authentication_headers_are_removed_before_reinjection() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    for name in [
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "cf-aig-authorization",
    ] {
        let mut request = parts();
        request
            .headers
            .insert(name, "alice@example.invalid".parse().unwrap());
        filter
            .prepare(
                "/v1/responses",
                &mut request,
                br#"{"model":"test","input":"safe"}"#,
            )
            .unwrap();
        assert!(
            !request.headers.contains_key(name),
            "caller authentication header survived privacy processing"
        );
    }
}

#[test]
fn sec_007_retained_protocol_headers_cannot_contain_configured_identifiers() {
    let filter = Filter::new(Some(Policy {
        identifiers: vec!["1990-01-01".into()],
        ..Policy::default()
    }))
    .unwrap();
    let mut request = parts();
    request
        .headers
        .insert("anthropic-version", "1990-01-01".parse().unwrap());
    assert!(filter
        .prepare(
            "/v1/messages",
            &mut request,
            br#"{"model":"test","messages":[]}"#
        )
        .is_err());
}

#[test]
fn sec_007_refuses_unknown_schema_opaque_state_and_media() {
    let f = Filter::new(Some(Policy::default())).unwrap();
    for v in [
        json!({"model":"test", "unknown":{"data":"private"}}),
        json!({"model":"test", "previous_response_id":"resp_example"}),
        json!({"input":[{"type":"reasoning", "encrypted_content":"opaque"}]}),
        json!({"input":[{"type":"input_image", "image_url":"https://example.invalid/x"}]}),
    ] {
        assert!(f
            .prepare(
                "/v1/responses",
                &mut parts(),
                &serde_json::to_vec(&v).unwrap()
            )
            .is_err());
    }
    assert!(f
        .prepare("/v1/files", &mut parts(), b"raw attachment")
        .is_err());
    assert!(f
        .prepare("/v1/responses", &mut parts(), b"not JSON")
        .is_err());
}

#[test]
fn sec_007_preserves_call_links_and_parses_nested_arguments() {
    let f = Filter::new(Some(Policy::default())).unwrap();
    let body = json!({"model":"test", "input":[{"type":"function_call", "id":"fc_example",
        "call_id":"call_example", "name":"lookup", "arguments":"{\"email\":\"alice@example.invalid\"}"}]});
    let (bytes, _) = f
        .prepare(
            "/v1/responses",
            &mut parts(),
            &serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes.unwrap()).unwrap();
    assert_eq!(v["input"][0]["id"], "fc_example");
    assert_eq!(v["input"][0]["call_id"], "call_example");
    let args: Value = serde_json::from_str(v["input"][0]["arguments"].as_str().unwrap()).unwrap();
    assert!(!args["email"].as_str().unwrap().contains('@'));
}

#[test]
fn sec_007_masks_data_ids_and_preserves_only_protocol_references() {
    let filter = Filter::new(Some(Policy {
        identifiers: vec!["Example Person".into()],
        ..Policy::default()
    }))
    .unwrap();
    let body = json!({"model":"test", "input":[{"type":"function_call", "id":"fc_example",
        "call_id":"call_example", "name":"lookup", "arguments":
        "{\"id\":\"alice@example.invalid\",\"model\":\"Example Person\",\"name\":\"Example Person\"}"}]});
    let (bytes, _) = filter
        .prepare(
            "/v1/responses",
            &mut parts(),
            &serde_json::to_vec(&body).unwrap(),
        )
        .expect("personal fields in tool arguments are data");
    let value: Value = serde_json::from_slice(&bytes.unwrap()).unwrap();
    assert_eq!(value["input"][0]["id"], "fc_example");
    assert_eq!(value["input"][0]["call_id"], "call_example");
    let args = value["input"][0]["arguments"].as_str().unwrap();
    assert!(!args.contains("alice@example.invalid"));
    assert!(!args.contains("Example Person"));
}

#[test]
fn sec_007_encoded_protocol_references_are_refused_without_rewriting() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let body = json!({"model":"test", "input":[{"type":"function_call",
        "id":URL_SAFE_NO_PAD.encode("alice@example.invalid"),
        "call_id":"call_example", "name":"lookup", "arguments":"{}"}]});
    assert!(filter
        .prepare(
            "/v1/responses",
            &mut parts(),
            &serde_json::to_vec(&body).unwrap()
        )
        .is_err());
}

#[test]
fn sec_007_refuses_unreviewed_nested_content_and_provider_tools() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    for (path, body) in [
        (
            "/v1/messages",
            json!({"model":"test", "messages":[], "tools":[
            {"type":"web_search_20250305", "name":"web_search"}]}),
        ),
        (
            "/v1/messages",
            json!({"model":"test", "messages":[{"role":"user", "content":[
                {"type":"document", "source":{"type":"url", "url":"https://example.invalid/private"}}
            ]}]}),
        ),
        (
            "/v1/chat/completions",
            json!({"model":"test", "messages":[{"role":"user", "content":[
                {"type":"future_media", "text":"opaque"}
            ]}]}),
        ),
        (
            "/v1/responses",
            json!({"model":"test", "input":[{"type":"future_tool_call",
            "payload":"opaque"}]}),
        ),
        (
            "/v1/responses",
            json!({"model":"test", "input":[], "tools":[
            {"type":"function", "name":"lookup", "remote_url":"https://example.invalid/private"}]}),
        ),
    ] {
        assert!(
            filter
                .prepare(path, &mut parts(), &serde_json::to_vec(&body).unwrap())
                .is_err(),
            "unreviewed nested schema must be refused"
        );
    }
}

#[test]
fn sec_007_disabled_filter_does_not_claim_privacy() {
    let f = Filter::new(None).unwrap();
    assert_eq!(
        f.prepare("/custom", &mut parts(), b"legacy").unwrap(),
        (None, 0)
    );
}

#[test]
fn sec_007_provider_chat_paths_mask_text_and_refuse_media() {
    for path in [
        "/api/v1/chat/completions",
        "/openai/v1/chat/completions",
        "/inference/v1/chat/completions",
    ] {
        let filter = Filter::new(Some(Policy::default())).unwrap();
        let body = json!({
            "model": "test",
            "messages": [{"role": "user", "content": "Contact alice@example.invalid"}],
            "user": "private-user",
            "metadata": {"email": "alice@example.invalid"}
        });
        let mut request = parts();
        let (masked, count) = filter
            .prepare(path, &mut request, &serde_json::to_vec(&body).unwrap())
            .expect("reviewed provider Chat endpoint");
        let masked = masked.unwrap();
        assert!(count > 0);
        assert!(!String::from_utf8_lossy(&masked).contains("alice@example.invalid"));
        let value: Value = serde_json::from_slice(&masked).unwrap();
        assert!(value.get("metadata").is_none());
        assert!(value.get("user").is_none());
        assert_eq!(value["store"], false);
        assert!(!request.headers.contains_key("user-agent"));
        let media = json!({"model": "test", "messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "https://example.invalid/image"}}
        ]}]});
        assert!(filter
            .prepare(path, &mut parts(), &serde_json::to_vec(&media).unwrap())
            .is_err());
    }
    let filter = Filter::new(Some(Policy::default())).unwrap();
    assert!(filter
        .prepare("/api/v1/files", &mut parts(), b"{}")
        .is_err());
}

#[test]
fn sec_007_local_only_and_poison_fail_closed() {
    let policy = Policy {
        preset: kepr_core::privacy::Preset::LocalOnly,
        ..Policy::default()
    };
    let f = Filter::new(Some(policy)).unwrap();
    assert!(f.prepare("/v1/responses", &mut parts(), b"{}").is_err());
    let f = Filter::new(Some(Policy::default())).unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _guard = f.session.lock().unwrap();
        panic!("fixture");
    });
    assert!(f.prepare("/v1/responses", &mut parts(), b"{}").is_err());
}
