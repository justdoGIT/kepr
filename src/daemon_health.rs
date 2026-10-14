// daemon_health.rs — `kepr health` (agent vault P6.4): weak, reused and
// old credentials, plus a k-anonymity breach check. Everything that
// needs a value runs here; replies carry only flags. T11.11 policy rules
// (kepr_core::health_policy); T11.23 ignored findings (daemon_recordsx).
//
// Breach check (Have I Been Pwned "range" model): `Health` returns the
// first 5 hex digits of each readable value's SHA-1. The CLI downloads
// the public list of hash suffixes for that prefix and sends them back
// in `BreachCheck`; the daemon answers yes/no. Neither the value nor its
// full hash leaves the daemon, and the network request carries 20 bits.
// Sealed credentials and SSH keys get no prefix and no breach check.

use std::collections::HashMap;

use kepr_core::health_policy::HealthPolicy;
use kepr_core::protocol::{KeyHealth, Response};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::store::validate_name;
use crate::{crypto, daemon_cache, expiry};

/// Entropy (bits) below which a value is reported as weak.
const WEAK_BITS: f64 = 50.0;
const SHORT_LEN: usize = 12;
const DEFAULT_MAX_AGE_DAYS: u32 = 365;
const MAX_SUFFIXES: usize = 4096;
const COMMON: &[&str] = &[
    "password", "123456", "12345678", "qwerty", "letmein", "admin", "welcome", "iloveyou",
    "monkey", "dragon", "changeme", "secret", "abc123", "passw0rd", "default", "test",
];

/// Rough entropy: length × log2(size of the character classes used).
fn entropy_bits(v: &str) -> f64 {
    let mut pool = 0u32;
    let has = |f: fn(char) -> bool| v.chars().any(f);
    if has(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if has(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if has(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if has(|c| c.is_ascii_punctuation() || c == ' ') {
        pool += 33;
    }
    if has(|c| !c.is_ascii()) {
        pool += 100;
    }
    if pool == 0 {
        return 0.0;
    }
    v.chars().count() as f64 * f64::from(pool).log2()
}

/// Issues found in one value on its own (no reuse, no age).
fn value_issues(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = v.to_ascii_lowercase();
    if COMMON
        .iter()
        .any(|c| lower == *c || lower.trim_end_matches(char::is_numeric) == *c)
    {
        out.push("common password".to_string());
    } else if entropy_bits(v) < WEAK_BITS {
        out.push("weak (easy to guess)".to_string());
    }
    if v.chars().count() < SHORT_LEN {
        out.push(format!("short (under {SHORT_LEN} characters)"));
    }
    out
}

fn sha1_hex(v: &str) -> String {
    hex::encode_upper(Sha1::digest(v.as_bytes()))
}

/// Days since the value was last written: the record's write time on the
/// image backend, the file's mtime otherwise.
fn file_age_days(path: &std::path::Path) -> Option<u64> {
    if let Some((_, updated)) = crate::daemon_vault::stat(path) {
        return Some(days_since(updated, crate::expiry::now_unix()));
    }
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(modified.elapsed().ok()?.as_secs() / 86_400)
}

fn days_since(then_unix: u64, now_unix: u64) -> u64 {
    now_unix.saturating_sub(then_unix) / 86_400
}

fn audit_ok(op: &'static str, uid: u32, username: &str, name: Option<&str>) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: AuditResult::Ok,
    });
}

pub fn handle_health(
    uid: u32,
    username: &str,
    max_age_days: Option<u32>,
    policy: Option<&HealthPolicy>,
) -> Response {
    // T11.11: the caller's hygiene rules (health_policy.rs).
    if let Some(Err(e)) = policy.map(HealthPolicy::validate) {
        return Response::fail(format!("health policy: {e}"));
    }
    let max_age = u64::from(max_age_days.unwrap_or(DEFAULT_MAX_AGE_DAYS));
    let mut items = Vec::new();
    // value digest → names, for reuse detection (digests never leave).
    let mut seen: HashMap<[u8; 32], Vec<String>> = HashMap::new();
    for (name, path) in daemon_cache::list_for_uid(uid) {
        let meta = expiry::read_meta(&expiry::meta_path_for(&path))
            .and_then(Result::ok)
            .unwrap_or_default();
        if meta.ssh.is_some() || meta.share_key.is_some() {
            continue;
        }
        let mut issues = Vec::new();
        let mut hibp_prefix = None;
        let rules = policy.map(|p| p.rules_for(meta.tags.as_deref().unwrap_or_default()));
        // Values the caller can't `Get` (sealed, consent or FIDO2 gated)
        // are never analysed: "same value as SEALED_KEY" or "weak" would
        // let a caller test guesses against them.
        let gated = meta.sealed == Some(true)
            || meta.requires_consent == Some(true)
            || meta.requires_fido2 == Some(true)
            || meta.requires_reauth == Some(true); // T11.14
        match (!gated).then(|| crypto::default_backend().decrypt(uid, &name)) {
            None => {}
            Some(Ok(v)) => {
                issues.extend(value_issues(v.as_str()));
                issues.extend(rules.iter().flat_map(|r| r.value_violations(v.as_str())));
                seen.entry(Sha256::digest(v.as_bytes()).into())
                    .or_default()
                    .push(name.clone());
                hibp_prefix = Some(sha1_hex(v.as_str())[..5].to_string());
            }
            Some(Err(_)) => issues.push("unreadable".to_string()),
        }
        issues.extend(crate::daemon_platform::pki::health_issues(
            &meta,
            expiry::now_unix(),
        )); // T10.10
        let age_days = file_age_days(&path).unwrap_or(0);
        if age_days > max_age {
            issues.push(format!("not changed in {age_days} days"));
        }
        issues.extend(rules.and_then(|r| r.age_violation(age_days)));
        if meta
            .expires_at_unix
            .is_some_and(|t| t <= expiry::now_unix())
        {
            issues.push("expired".to_string());
        }
        items.push(KeyHealth {
            name,
            issues,
            age_days,
            hibp_prefix,
            ignored: Vec::new(),
            ignore: meta.health_ignore.unwrap_or_default(), // T11.23
        });
    }
    for names in seen.values().filter(|n| n.len() > 1) {
        for item in items.iter_mut().filter(|i| names.contains(&i.name)) {
            let others: Vec<&str> = names
                .iter()
                .filter(|n| **n != item.name)
                .map(String::as_str)
                .collect();
            item.issues
                .push(format!("same value as {}", others.join(", ")));
        }
    }
    items
        .iter_mut()
        .for_each(crate::daemon_recordsx::apply_health_ignores);
    audit_ok("health", uid, username, None);
    Response::HealthOk { items }
}

/// Is the value of `name` among `suffixes` (hash suffixes after the
/// 5-digit prefix, each at least 10 hex digits)?
fn breached(value: &str, suffixes: &[String]) -> Result<bool, String> {
    if suffixes.len() > MAX_SUFFIXES {
        return Err("too many suffixes".into());
    }
    let ok = |s: &String| (10..=35).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !suffixes.iter().all(ok) {
        return Err("suffixes must be 10-35 hex digits".into());
    }
    let full = sha1_hex(value);
    let mine = &full[5..];
    Ok(suffixes
        .iter()
        .any(|s| mine.starts_with(&s.to_ascii_uppercase())))
}

pub fn handle_breach_check(uid: u32, username: &str, name: &str, suffixes: &[String]) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|_| {
        let meta = expiry::read_meta(&expiry::meta_path_for(&crate::store::cred_path(
            uid, &upper,
        )))
        .transpose()
        .map_err(|_| "credential unavailable".to_string())?
        .unwrap_or_default();
        // The caller picks the suffixes, so this is a guess oracle: only
        // for values the caller could `Get` without a prompt anyway.
        if meta.sealed == Some(true)
            || meta.ssh.is_some()
            || meta.share_key == Some(true)
            || meta.requires_consent == Some(true)
            || meta.requires_fido2 == Some(true)
            || meta.requires_reauth == Some(true)
        // T11.14
        {
            return Err("credential unavailable".to_string());
        }
        let v = crypto::default_backend()
            .decrypt(uid, &upper)
            .map_err(|e| crypto::sanitize_lookup_error(&e))?;
        breached(v.as_str(), suffixes)
    });
    audit::log(&AuditEvent {
        op: "breach-check",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(breached) => Response::BreachOk {
            name: upper,
            breached,
        },
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_weak_common_and_short_values() {
        assert!(value_issues("password1")[0].contains("common"));
        assert!(value_issues("aaaaaaaa").iter().any(|i| i.contains("weak")));
        assert!(value_issues("abc").iter().any(|i| i.contains("short")));
        assert!(value_issues("sk-ant-api03-Xq8vLm2PzR7tY4nB6wK0").is_empty());
        assert!(value_issues("").iter().any(|i| i.contains("weak")));
    }

    fn issues(
        uid: u32,
        max_age: Option<u32>,
        p: Option<&HealthPolicy>,
    ) -> Vec<(String, Vec<String>)> {
        match handle_health(uid, "t", max_age, p) {
            Response::HealthOk { items } => items.into_iter().map(|i| (i.name, i.issues)).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn days_since_counts_whole_days_and_never_underflows() {
        assert_eq!(days_since(1_000, 1_000 + 86_399), 0);
        assert_eq!(days_since(1_000, 1_000 + 120 * 86_400 + 5), 120);
        assert_eq!(days_since(2_000, 1_000), 0);
    }

    fn age(uid: u32, name: &str, days: u64) {
        let f = std::fs::File::options()
            .write(true)
            .open(crate::store::cred_path(uid, name))
            .unwrap();
        let then =
            std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400 + 60);
        f.set_modified(then).unwrap();
    }

    #[test]
    fn period_and_policy_rules_are_reported() {
        use crate::daemon_store::testkit;
        use kepr_core::health_policy::HealthRules;
        let uid = testkit::uid();
        testkit::set(uid, "OLD", "Qz8#vR2!mX9$pL4&kT6@");
        testkit::set(uid, "PROD_KEY", "Qz8#vR2!mX9$pL4&kT6@wY3*");
        testkit::set_sealed(uid, "SEALED", "short");
        let tag = kepr_core::protocol_store::StoreRequest::Organize {
            name: "PROD_KEY".into(),
            add_tags: vec!["prod".into()],
            remove_tags: vec![],
            folder: None,
        };
        assert!(crate::daemon_store::dispatch(uid, 0, "t", tag).is_success());
        age(uid, "OLD", 120);
        age(uid, "SEALED", 120);
        // --period 90: unchanged for longer than 90 days.
        let got = issues(uid, Some(90), None);
        let of = |n: &str| got.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert!(of("OLD")
            .iter()
            .any(|i| i.starts_with("not changed in 120 days")));
        assert!(of("PROD_KEY").is_empty());
        let policy = HealthPolicy {
            all: HealthRules {
                min_length: Some(16),
                classes: vec![],
                max_age_days: Some(100),
            },
            tags: std::collections::BTreeMap::from([(
                "prod".into(),
                HealthRules {
                    min_length: Some(32),
                    classes: vec!["upper".into()],
                    max_age_days: None,
                },
            )]),
        };
        let got = issues(uid, None, Some(&policy));
        let of = |n: &str| got.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert_eq!(of("OLD"), ["policy: older than 100 days"]);
        assert_eq!(of("PROD_KEY"), ["policy: shorter than 32 characters"]);
        // A sealed value is never measured, but its age still counts.
        assert_eq!(of("SEALED"), ["policy: older than 100 days"]);
        let bad = HealthPolicy {
            all: HealthRules {
                min_length: Some(0),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!handle_health(uid, "t", None, Some(&bad)).is_success());
    }

    #[test]
    fn breach_matches_by_suffix_prefix() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let suf = |s: &str| vec![s.to_string()];
        assert!(breached("password", &suf("1E4C9B93F3F0682250B6CF8331B7EE68FD8")).unwrap());
        assert!(breached("password", &suf("1e4c9b93f3")).unwrap());
        assert!(!breached("password", &suf("0000000000")).unwrap());
        assert!(breached("password", &suf("1E4C")).is_err());
        assert!(breached("password", &suf("zzzzzzzzzz")).is_err());
        assert_eq!(&sha1_hex("password")[..5], "5BAA6");
    }
}
