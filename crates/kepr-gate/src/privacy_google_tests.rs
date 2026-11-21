use super::*;
use hyper::{Method, Request};
use serde_json::json;

fn parts(path: &str, query: &str) -> hyper::http::request::Parts {
    Request::builder()
        .method(Method::POST)
        .uri(format!("/google{path}{query}"))
        .header("content-type", "application/json")
        .header("x-goog-api-key", "kepr-ph-test")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn text_request() -> Value {
    json!({"contents": [{"role": "user", "parts": [{"text": "alice@example.invalid"}]}]})
}

#[test]
fn sec_007_google_generate_and_stream_scrub_all_text_fields() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    for version in ["v1", "v1beta"] {
        for (method, query) in [
            ("generateContent", ""),
            ("streamGenerateContent", "?alt=sse"),
        ] {
            let path = format!("/{version}/models/gemini-test:{method}");
            let body = json!({
                "contents": [
                    {"role": "user", "parts": [{"text": "alice@example.invalid"}]},
                    {"role": "model", "parts": [{"thought": true, "text": "alice@example.invalid"}]}
                ],
                "systemInstruction": {"parts": [{"text": "alice@example.invalid"}]},
                "generationConfig": {
                    "stopSequences": ["alice@example.invalid"],
                    "temperature": 0.5, "maxOutputTokens": 64,
                    "responseMimeType": "application/json",
                    "responseSchema": {"type": "OBJECT", "description": "alice@example.invalid"},
                    "thinkingConfig": {"thinkingBudget": 0, "includeThoughts": false},
                    "responseModalities": ["TEXT"]
                },
                "safetySettings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"}]
            });
            let mut request = parts(&path, query);
            let (masked, count) = filter
                .prepare(&path, &mut request, &serde_json::to_vec(&body).unwrap())
                .unwrap();
            let masked = masked.unwrap();
            assert!(count >= 5);
            assert!(!String::from_utf8_lossy(&masked).contains("alice@example.invalid"));
            let value: Value = serde_json::from_slice(&masked).unwrap();
            assert_eq!(
                value["generationConfig"]["responseSchema"]["type"],
                "OBJECT"
            );
            assert_eq!(value["contents"][1]["parts"][0]["thought"], true);
            assert_eq!(
                request.uri.query(),
                (!query.is_empty()).then_some("alt=sse")
            );
            assert!(!request.headers.contains_key("x-goog-api-key"));
        }
    }
}

#[test]
fn sec_007_google_function_data_is_scrubbed_without_rewriting_call_links() {
    let filter = Filter::new(Some(Policy {
        identifiers: vec!["Example Person".into()],
        ..Policy::default()
    }))
    .unwrap();
    let path = "/v1beta/models/gemini-test:streamGenerateContent";
    for schema_key in ["parameters", "parametersJsonSchema"] {
        let mut body = json!({
            "contents": [
                {"role": "model", "parts": [{"functionCall": {
                    "id": "call_example", "name": "lookup", "args": {
                        "id": "alice@example.invalid", "model": "Example Person",
                        "name": "Example Person", "type": "Example Person",
                        "nested": [{"text": "alice@example.invalid"}]
                    }
                }}]},
                {"role": "user", "parts": [{"functionResponse": {
                    "id": "call_example", "name": "lookup", "response": {
                        "id": "alice@example.invalid", "model": "Example Person",
                        "name": "Example Person", "type": "Example Person"
                    }
                }}]}
            ],
            "tools": [{"functionDeclarations": [{
                "name": "lookup", "description": "Example Person",
                "responseJsonSchema": {"type": "object", "description": "alice@example.invalid"}
            }]}],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["lookup"]}}
        });
        body["tools"][0]["functionDeclarations"][0][schema_key] = json!({
            "type": "object", "properties": {"name": {"type": "string", "description": "Example Person"}},
            "required": ["name"]
        });
        let (masked, count) = filter
            .prepare(
                path,
                &mut parts(path, "?alt=sse"),
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
        let masked = masked.unwrap();
        assert!(count >= 10);
        let text = String::from_utf8_lossy(&masked);
        assert!(!text.contains("alice@example.invalid"));
        assert!(!text.contains("Example Person"));
        let value: Value = serde_json::from_slice(&masked).unwrap();
        for (index, field) in [(0, "functionCall"), (1, "functionResponse")] {
            assert_eq!(
                value["contents"][index]["parts"][0][field]["id"],
                "call_example"
            );
            assert_eq!(
                value["contents"][index]["parts"][0][field]["name"],
                "lookup"
            );
        }
        assert_eq!(
            value["tools"][0]["functionDeclarations"][0][schema_key]["required"][0],
            "name"
        );
        assert_eq!(
            value["toolConfig"]["functionCallingConfig"]["allowedFunctionNames"][0],
            "lookup"
        );
    }
}

#[test]
fn sec_007_google_rejects_unknown_opaque_media_and_unreviewed_tools() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    let path = "/v1beta/models/gemini-test:generateContent";
    let mut cases = vec![
        json!({}),
        json!({"contents": []}),
        json!({"contents": "text"}),
    ];
    for field in [
        "cachedContent",
        "continuationToken",
        "labels",
        "tool_config",
        "unknown",
    ] {
        let mut value = text_request();
        value[field] = json!("opaque");
        cases.push(value);
    }
    for part in [
        json!({"text": "safe", "thoughtSignature": "opaque"}),
        json!({"thoughtSignature": "opaque"}),
        json!({"inlineData": {"mimeType": "image/png", "data": "opaque"}}),
        json!({"fileData": {"fileUri": "https://example.invalid/private"}}),
        json!({"executableCode": {"language": "PYTHON", "code": "print(1)"}}),
        json!({"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": "safe"}}),
        json!({"toolCall": {"name": "remote"}}),
        json!({"text": "safe", "futureField": "opaque"}),
        json!({"text": "safe", "functionCall": {"name": "lookup"}}),
        json!({"text": 42}),
        json!({"functionCall": {"name": "lookup", "args": "opaque"}}),
        json!({"functionResponse": {"name": "lookup", "response": {}, "parts": []}}),
        json!({"functionResponse": {"name": "lookup", "response": "opaque"}}),
        json!({"functionCall": {"name": "lookup", "id": "alice@example.invalid"}}),
    ] {
        cases.push(json!({"contents": [{"role": "user", "parts": [part]}]}));
    }
    for extra in [
        json!({"tools": [{"googleSearch": {}}]}),
        json!({"tools": [{"codeExecution": {}}]}),
        json!({"tools": [{"functionDeclarations": [{"name": "lookup", "remote_url": "opaque"}]}]}),
        json!({"toolConfig": {"retrievalConfig": {}}}),
        json!({"toolConfig": {"functionCallingConfig": {"futureField": true}}}),
        json!({"generationConfig": {"futureField": "opaque"}}),
        json!({"generationConfig": {"speechConfig": {}}}),
        json!({"generationConfig": {"responseModalities": ["IMAGE"]}}),
        json!({"generationConfig": {"thinkingConfig": {"futureField": "opaque"}}}),
        json!({"generationConfig": {"maxOutputTokens": "opaque"}}),
        json!({"systemInstruction": {"parts": [{"functionCall": {"name": "lookup"}}]}}),
        json!({"safetySettings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE", "unknown": true}]}),
    ] {
        let mut value = text_request();
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        cases.push(value);
    }
    for value in cases {
        assert!(
            filter
                .prepare(
                    path,
                    &mut parts(path, ""),
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn sec_007_google_only_allows_exact_sse_query_on_stream_endpoint() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    let body = serde_json::to_vec(&text_request()).unwrap();
    for path in [
        "/v1beta/models/gemini-test:streamGenerateContent",
        "/v1/models/gemini-test:streamGenerateContent",
    ] {
        for query in ["", "?alt=sse"] {
            filter
                .prepare(path, &mut parts(path, query), &body)
                .unwrap();
        }
        for query in [
            "?",
            "?key=kepr-ph-test",
            "?alt=json",
            "?alt=sse&key=kepr-ph-test",
            "?alt=sse&user=private",
            "?alt=sse&alt=sse",
            "?alt=sse&",
            "?alt=%73se",
            "?%61lt=sse",
            "?ALT=sse",
            "?alt=sse;key=kepr-ph-test",
            "?unknown=value",
        ] {
            assert!(
                filter
                    .prepare(path, &mut parts(path, query), &body)
                    .is_err(),
                "accepted {query}"
            );
        }
    }
    for path in [
        "/v1beta/models/gemini-test:generateContent",
        "/v1/models/gemini-test:generateContent",
        "/v1/chat/completions",
        "/v1/responses",
        "/v1/messages",
    ] {
        assert!(filter
            .prepare(path, &mut parts(path, "?alt=sse"), &body)
            .is_err());
    }
    let path = "/v1beta/models/gemini-test:streamGenerateContent";
    let mut request = parts(path, "?alt=sse");
    request.method = Method::GET;
    assert!(filter.prepare(path, &mut request, &body).is_err());
}

#[test]
fn sec_007_google_rejects_unreviewed_paths_and_personal_model_names() {
    let filter = Filter::new(Some(Policy::default())).unwrap();
    for path in [
        "/v1beta/models",
        "/v1beta/models/",
        "/v1beta/models/:generateContent",
        "/v1beta/models/gemini-test:countTokens",
        "/v1beta/models/gemini-test:embedContent",
        "/v1beta/models/gemini-test/other:generateContent",
        "/v1beta/models/..:generateContent",
        "/v1beta/models/%61lice:streamGenerateContent",
        "/v1alpha/models/gemini-test:generateContent",
        "/v1beta/models/gemini-test:generateContent/extra",
    ] {
        assert!(
            filter
                .prepare(path, &mut parts(path, "?alt=sse"), b"{}")
                .is_err(),
            "accepted {path}"
        );
        assert!(fields::schema(path).is_none());
    }
    let filter = Filter::new(Some(Policy {
        identifiers: vec!["private-model".into()],
        ..Policy::default()
    }))
    .unwrap();
    let path = "/v1beta/models/private-model:generateContent";
    assert!(filter
        .prepare(
            path,
            &mut parts(path, ""),
            &serde_json::to_vec(&text_request()).unwrap()
        )
        .is_err());
    let _: &'static [&'static str] =
        fields::schema("/v1beta/models/gemini-test:generateContent").unwrap();
}
