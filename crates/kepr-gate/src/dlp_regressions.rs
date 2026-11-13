//! Outbound screening must cover the same session secrets as response masking.
use super::*;
use base64::Engine;

fn session_value(value: &str) -> Vec<(String, ZeroString)> {
    vec![("SESSION_FIXTURE".into(), ZeroString::from(value))]
}

#[test]
fn structured_secret_fields_are_screened_without_matching_record_metadata() {
    let secret = ["fixture-", "private/", "value+123"].concat();
    for field in [
        "password",
        "pending_password",
        "secret_access_key",
        "session_token",
        "private_key",
        "client_secret",
        "refresh_token",
        "token",
    ] {
        let mut record = serde_json::json!({
            "user": "fixture-user-name", "database": "fixture-database-name"
        });
        record[field] = serde_json::Value::String(secret.clone());
        let secrets = session_value(&record.to_string());
        assert!(matches!(
            scan(secret.as_bytes(), &secrets),
            Verdict::StoredSecret(_)
        ));
        assert_eq!(scan(b"fixture-user-name", &secrets), Verdict::Clean);
        assert_eq!(scan(b"fixture-database-name", &secrets), Verdict::Clean);
    }
}

#[test]
fn whole_structured_records_are_screened_after_base64_encoding() {
    use base64::engine::general_purpose::STANDARD;
    let secret = ["fixture-", "private-value"].concat();
    let record = serde_json::json!({"password":secret}).to_string();
    let encoded = STANDARD.encode(record.as_bytes());
    assert!(matches!(
        scan(encoded.as_bytes(), &session_value(&record)),
        Verdict::StoredSecret(_)
    ));
}

#[test]
fn encoded_session_secrets_are_screened_in_body_headers_and_uri() {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let secret = ["fixture-", "private/", "value+123"].concat();
    let secrets = session_value(&secret);
    let mut variants = vec![
        secret.replace('/', "%2F").replace('+', "%2B"),
        secret.replace('/', "%2f").replace('+', "%2b"),
        secret.replace('/', "%2f").replace('+', "%2B"),
    ];
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        variants.push(engine.encode(secret.as_bytes()));
    }
    for encoded in variants {
        assert!(matches!(
            scan(encoded.as_bytes(), &secrets),
            Verdict::StoredSecret(_)
        ));
        for uri in [
            "/v1/responses".to_string(),
            format!("/v1/responses?note={encoded}"),
        ] {
            let mut request = hyper::Request::post(&uri);
            if uri == "/v1/responses" {
                request = request.header("x-fixture", &encoded);
            }
            let (parts, _) = request.body(()).unwrap().into_parts();
            assert!(check(&parts, b"{}", &secrets).is_some());
        }
    }
}

#[test]
fn json_surrogate_pairs_cannot_hide_a_session_secret() {
    let secret = ["fixture-", "\u{1f642}", "-value"].concat();
    let encoded: String = secret
        .encode_utf16()
        .map(|u| format!("\\u{u:04x}"))
        .collect();
    let body = format!("{{\"input\":\"{encoded}\"}}");
    assert!(matches!(
        scan(body.as_bytes(), &session_value(&secret)),
        Verdict::StoredSecret(_)
    ));
}

#[test]
fn encoded_short_values_and_values_outside_this_session_remain_unmatched() {
    use base64::engine::general_purpose::STANDARD;
    let short = ["ab", "cde"].concat();
    let encoded = STANDARD.encode(short.as_bytes());
    for value in [
        short.clone(),
        serde_json::json!({"password":short}).to_string(),
    ] {
        assert_eq!(
            scan(encoded.as_bytes(), &session_value(&value)),
            Verdict::Clean
        );
    }
    let unresolved = ["unresolved-", "fixture-value"].concat();
    assert_eq!(scan(unresolved.as_bytes(), &[]), Verdict::Clean);
    assert_eq!(scan(b"kepr-ph-session-fixture", &[]), Verdict::Clean);
}

#[test]
fn duplicate_encoding_headers_cannot_hide_compression() {
    let mut request = hyper::Request::post("/v1/responses").body(()).unwrap();
    request
        .headers_mut()
        .append("content-encoding", "identity".parse().unwrap());
    request
        .headers_mut()
        .append("content-encoding", "gzip".parse().unwrap());
    let (parts, _) = request.into_parts();
    assert!(check(&parts, b"uninspected bytes", &[]).is_some());
}
