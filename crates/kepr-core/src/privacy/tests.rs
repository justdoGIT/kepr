use super::*;

#[test]
fn sec_006_email_is_consistent_and_session_scoped() {
    let mut a = Session::new(Policy::default()).unwrap();
    let original = "Mail alice@example.invalid and alice@example.invalid.";
    let (masked, count) = a.transform(original).unwrap();
    assert_eq!(count, 2);
    assert!(!masked.contains("alice@example.invalid"));
    let (again, _) = a.transform("alice@example.invalid").unwrap();
    assert_eq!(masked.matches(&again).count(), 2);
    let mut b = Session::new(Policy::default()).unwrap();
    assert_ne!(again, b.transform("alice@example.invalid").unwrap().0);
}

#[test]
fn sec_006_private_paths_ips_and_international_phone_are_masked() {
    let mut s = Session::new(Policy::default()).unwrap();
    let text = "Call +1 (202) 555-0100, host 192.168.1.4, file /home/alice/mail/inbox.";
    let (masked, count) = s.transform(text).unwrap();
    assert!(count >= 3);
    for private in ["555-0100", "192.168.1.4", "/home/alice"] {
        assert!(!masked.contains(private));
    }
}

#[test]
fn sec_006_configured_literals_and_unicode_mail_are_masked() {
    let p = Policy {
        identifiers: vec!["Example Person".into()],
        ..Policy::default()
    };
    let mut s = Session::new(p).unwrap();
    let (masked, count) = s
        .transform("Example Person writes to álîce@example.invalid")
        .unwrap();
    assert_eq!(count, 2);
    assert!(!masked.contains("Example Person"));
    assert!(!masked.contains("álîce"));
}

#[test]
fn sec_006_invalid_policy_and_oversize_input_are_refused() {
    let p = Policy {
        version: 2,
        ..Policy::default()
    };
    assert!(Session::new(p).is_err());
    let mut s = Session::new(Policy::default()).unwrap();
    assert!(s.transform(&"a".repeat(MAX_TEXT_BYTES + 1)).is_err());
}

#[test]
fn sec_006_pseudonym_growth_cannot_exceed_the_output_limit() {
    let mut session = Session::new(Policy::default()).unwrap();
    let suffix = " alice@example.invalid";
    let input = format!("{}{suffix}", "#".repeat(MAX_TEXT_BYTES - suffix.len()));
    assert_eq!(input.len(), MAX_TEXT_BYTES);
    assert_eq!(
        session.transform(&input).err(),
        Some("transformed privacy text too large")
    );
}

#[test]
fn sec_006_preserves_nonpersonal_source_and_never_restores_tokens() {
    let mut s = Session::new(Policy::default()).unwrap();
    let source = "fn add(a: i32, b: i32) -> i32 { a + b }";
    assert_eq!(s.transform(source).unwrap(), (source.into(), 0));
    let (token, _) = s.transform("alice@example.invalid").unwrap();
    assert_eq!(
        s.transform(&format!("https://example.invalid/{token}"))
            .unwrap()
            .0,
        format!("https://example.invalid/{token}")
    );
}

#[test]
fn sec_006_encoded_personal_data_is_refused_without_rewriting_it() {
    use base64::{engine::general_purpose as b64, Engine};
    let percent = |text: &str| {
        text.as_bytes()
            .iter()
            .map(|b| format!("%{b:02X}"))
            .collect::<String>()
    };
    let escaped = |text: &str| {
        text.chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect::<String>()
    };
    for original in [
        "alice@example.invalid",
        "/home/alice/private",
        "+1 (202) 555-0100",
        "192.168.1.4",
        "Example Person",
    ] {
        for encoded in [
            percent(original),
            escaped(original),
            b64::STANDARD.encode(original),
            b64::STANDARD_NO_PAD.encode(original),
            b64::URL_SAFE.encode(original),
            b64::URL_SAFE_NO_PAD.encode(original),
            b64::STANDARD.encode(percent(original)),
            percent(&b64::STANDARD.encode(original)),
            escaped(&b64::URL_SAFE.encode(original)),
        ] {
            let policy = Policy {
                identifiers: vec!["Example Person".into()],
                ..Policy::default()
            };
            let mut session = Session::new(policy).unwrap();
            assert!(
                session.transform(&encoded).is_err(),
                "encoded personal data escaped screening"
            );
        }
    }
}

#[test]
fn sec_006_benign_encodings_preserve_source_and_excessive_depth_is_refused() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut session = Session::new(Policy::default()).unwrap();
    for input in [
        r#"fn sample() { let text = "safe\n"; }"#,
        "See https://example.invalid/docs%20guide and YWJjZGVmZ2g=",
        r"Examples: 100% safe and \u0061",
    ] {
        assert_eq!(session.transform(input).unwrap(), (input.into(), 0));
    }
    let mut encoded = "ordinary text".to_string();
    for _ in 0..5 {
        encoded = STANDARD.encode(encoded);
    }
    assert!(session.transform(&encoded).is_err());
}

#[test]
fn sec_004_privacy_accepts_omp_routes_only_for_inspected_provider_hosts() {
    use crate::gate_protocol::GateRoute;
    let policy = Policy::default();
    for host in [
        "api.openai.com",
        "api.anthropic.com",
        "gateway.ai.cloudflare.com",
        "api.fireworks.ai",
        "api.moonshot.cn",
        "api.venice.ai",
    ] {
        let provider = crate::http_route::key(host, "WORK").unwrap();
        let route = GateRoute {
            provider: provider.clone(),
            cred: "WORK".into(),
            slot: 0,
            target: None,
        };
        assert!(
            supports_provider(&provider),
            "inspected OMP host was rejected"
        );
        assert!(policy.validate_routes(&[route], false).is_ok());
    }
    for host in [
        "api.github.com",
        "uninspected.example.invalid",
        "api.openai.com.attacker.invalid",
    ] {
        let provider = crate::http_route::key(host, "WORK").unwrap();
        assert!(!supports_provider(&provider));
        assert!(policy
            .validate_routes(
                &[GateRoute {
                    provider,
                    cred: "WORK".into(),
                    slot: 0,
                    target: None
                }],
                false
            )
            .is_err());
    }
    assert!(!supports_provider("https+api.openai.com+../WORK"));
}
