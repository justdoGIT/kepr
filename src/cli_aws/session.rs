// session.rs — AWS keys in an agent session (T2.02), the harness side.
//
// A sealed AWS key (bound with `--for HOST:sigv4`) gets an `aws:<NAME>`
// gate route. The harness sees only a placeholder pair: access key id
// `KEPRPH…` and the session placeholder as the secret; the gate checks
// the SDK's signature with it and signs again with the real key. Real
// AWS variables and profiles are not inherited.

use std::collections::HashMap;

use kepr_core::gate_protocol::{aws_route_key, GateRoute};
use kepr_core::protocol::CredInfo;
use kepr_core::sigv4_req::placeholder_access_key_id;

/// Variables the harness must not inherit when the session has AWS keys.
const AWS_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CA_BUNDLE",
];

/// Prefix of the per-key placeholder variables (`KEPR_AWS_<NAME>`),
/// read by `kepr aws credential-process NAME` inside the session.
pub const PH_VAR_PREFIX: &str = "KEPR_AWS_";

/// One route per sealed SigV4 key, after the routes already chosen.
pub fn routes(existing: &[GateRoute], sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut slot = existing.iter().map(|r| r.slot + 1).max().unwrap_or(0);
    let mut names: Vec<&str> = sealed
        .iter()
        .filter(|c| c.aws_sigv4 == Some(true))
        .map(|c| c.name.as_str())
        .collect();
    names.sort_unstable();
    names
        .into_iter()
        .map(|n| {
            slot += 1;
            GateRoute {
                provider: aws_route_key(n),
                cred: n.to_string(),
                slot: slot - 1,
                target: None,
            }
        })
        .collect()
}

/// `(NAME, placeholder)` of the session's AWS routes, by name.
pub fn placeholders(ph: &HashMap<String, String>) -> Vec<(&str, &str)> {
    let mut v: Vec<(&str, &str)> = ph
        .iter()
        .filter_map(|(k, p)| Some((k.strip_prefix("aws:")?, p.as_str())))
        .collect();
    v.sort_unstable();
    v
}

/// Whether the inherited variable `var` is replaced in this session.
pub fn shadowed(ph: &HashMap<String, String>, var: &str) -> bool {
    !placeholders(ph).is_empty() && AWS_VARS.contains(&var)
}

/// The placeholder pair (first key by name) and one `KEPR_AWS_<NAME>`
/// per key; `AWS_CA_BUNDLE` follows the egress CA bundle in `env`.
pub fn env(ph: &HashMap<String, String>, env: &[(String, String)]) -> Vec<(String, String)> {
    let keys = placeholders(ph);
    let mut out: Vec<(String, String)> = keys
        .iter()
        .map(|(n, p)| (format!("{PH_VAR_PREFIX}{n}"), p.to_string()))
        .collect();
    if let Some((_, p)) = keys.first() {
        out.push(("AWS_ACCESS_KEY_ID".into(), placeholder_access_key_id(p)));
        out.push(("AWS_SECRET_ACCESS_KEY".into(), p.to_string()));
        if let Some((_, b)) = env.iter().find(|(k, _)| k == "SSL_CERT_FILE") {
            out.push(("AWS_CA_BUNDLE".into(), b.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, sigv4: bool) -> CredInfo {
        CredInfo {
            name: name.into(),
            sealed: Some(true),
            aws_sigv4: sigv4.then_some(true),
            ..Default::default()
        }
    }

    #[test]
    fn a_route_per_sealed_aws_key_after_the_others() {
        let existing = vec![GateRoute {
            provider: "anthropic".into(),
            cred: "ANTHROPIC_API_KEY".into(),
            slot: 0,
            target: None,
        }];
        let r = routes(
            &existing,
            &[
                cred("PROD_AWS", true),
                cred("ANTHROPIC_API_KEY", false),
                cred("DEV_AWS", true),
            ],
        );
        let got: Vec<(&str, u16)> = r.iter().map(|r| (r.provider.as_str(), r.slot)).collect();
        assert_eq!(got, [("aws:DEV_AWS", 1), ("aws:PROD_AWS", 2)]);
        let mut all = existing.clone();
        all.extend(r);
        assert!(kepr_core::gate_protocol::validate_routes(&all).is_ok());
    }

    #[test]
    fn the_harness_gets_a_placeholder_pair_and_never_the_real_variables() {
        let ph: HashMap<String, String> = [
            ("aws:PROD_AWS".to_string(), "kepr-ph-b".to_string()),
            ("aws:DEV_AWS".to_string(), "kepr-ph-a".to_string()),
            ("github".to_string(), "kepr-ph-g".to_string()),
        ]
        .into();
        let egress = vec![("SSL_CERT_FILE".to_string(), "/run/x/ca.pem".to_string())];
        let e = env(&ph, &egress);
        let get = |k: &str| e.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("AWS_SECRET_ACCESS_KEY"), Some("kepr-ph-a"));
        assert_eq!(
            get("AWS_ACCESS_KEY_ID").map(str::to_string),
            Some(placeholder_access_key_id("kepr-ph-a"))
        );
        assert_eq!(get("KEPR_AWS_PROD_AWS"), Some("kepr-ph-b"));
        assert_eq!(get("AWS_CA_BUNDLE"), Some("/run/x/ca.pem"));
        assert!(shadowed(&ph, "AWS_SESSION_TOKEN") && shadowed(&ph, "AWS_PROFILE"));
        assert!(!shadowed(&ph, "PATH"));
        let none: HashMap<String, String> = HashMap::new();
        assert!(!shadowed(&none, "AWS_PROFILE") && env(&none, &egress).is_empty());
    }
}
