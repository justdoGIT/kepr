//! Explicit migration; normal lookups never fall back to ambiguous old names.
use super::{client, host_to_kepr_name, in_session, process_env, GitCred};
use kepr_core::{
    generate::ZeroString,
    protocol::{Request, Response},
};
use std::{collections::HashMap, process::ExitCode};

pub(super) fn matches(value: &ZeroString, host: &str, protocol: &str) -> bool {
    serde_json::from_str::<GitCred>(value.as_str()).is_ok_and(|c| {
        c.host.eq_ignore_ascii_case(host) && c.protocol == protocol && !protocol.is_empty()
    })
}
fn legacy_names(host: &str) -> [String; 2] {
    let host = host.to_ascii_lowercase();
    let mapped: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    [
        format!("GIT_{mapped}"),
        format!("GIT_{mapped}_HOST_{}", hex::encode_upper(host.as_bytes())),
    ]
}
fn migrate(
    input: &HashMap<String, String>,
    mut send: impl FnMut(&Request) -> Result<Response, String>,
) -> Result<(), String> {
    let host = input
        .get("host")
        .filter(|h| !h.is_empty())
        .ok_or("host required")?;
    let protocol = input
        .get("protocol")
        .filter(|p| p.as_str() == "https")
        .ok_or("HTTPS protocol required")?;
    let dest = host_to_kepr_name(host);
    let Response::ListOk { credentials, .. } = send(&Request::List)? else {
        return Err("could not list migration targets".into());
    };
    if credentials.iter().any(|c| c.name == dest) {
        return Err("destination already exists; nothing changed".into());
    }
    for name in legacy_names(host) {
        let Some(info) = credentials.iter().find(|c| c.name == name) else {
            continue;
        };
        if info.expires_at.is_some()
            || info.requires_reauth == Some(true)
            || info.sealed == Some(true)
        {
            return Err(
                "protected or expiring legacy credential requires explicit re-enrolment".into(),
            );
        }
        let Response::GetOk { value, .. } = send(&Request::Get {
            name: name.clone(),
            fido2_assertion: None,
        })?
        else {
            return Err("legacy credential unavailable".into());
        };
        if !matches(&value, host, protocol) {
            continue;
        }
        let req = Request::Set {
            name: dest.clone(),
            value: Some(value),
            generate: None,
            ttl_secs: None,
            requires_consent: info.requires_consent,
            requires_fido2: info.requires_fido2,
            sealed: None,
            bindings: None,
        };
        if !matches!(send(&req)?, Response::SetOk { .. }) {
            return Err("migration write failed".into());
        }
        // Keep the old entry for rollback: the wire API has no compare-and-delete.
        // Removing it here could delete a concurrent update or a colliding login.
        return Ok(());
    }
    Err("no matching structured legacy login; nothing changed".into())
}
pub(super) fn run(input: HashMap<String, String>) -> ExitCode {
    if in_session(&process_env) {
        return ExitCode::FAILURE;
    }
    match migrate(&input, client::send_request) {
        Ok(()) => {
            eprintln!("Git login migrated; legacy entry retained for rollback. Stop concurrent credential writers during migration.");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("Git migration refused: {reason}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_checks_reject_other_hosts_protocols_and_raw_values() {
        let value = ZeroString::from_string(serde_json::json!({"host":"foo-bar.example", "protocol":"https", "username":"u", "password":"synthetic"}).to_string());
        assert!(matches(&value, "FOO-BAR.EXAMPLE", "https"));
        assert!(!matches(&value, "foo.bar.example", "https"));
        assert!(!matches(&value, "foo-bar.example", "http"));
        assert!(!matches(
            &ZeroString::from("synthetic"),
            "foo-bar.example",
            "https"
        ));
    }
    #[test]
    fn refuses_an_existing_destination() {
        let input = HashMap::from([
            ("host".into(), "foo-bar.example".into()),
            ("protocol".into(), "https".into()),
        ]);
        let mut calls = 0;
        assert!(migrate(&input, |_| {
            calls += 1;
            Ok(Response::ListOk {
                credentials: vec![kepr_core::protocol::CredInfo {
                    name: host_to_kepr_name("foo-bar.example"),
                    ..Default::default()
                }],
                count: 1,
            })
        })
        .is_err());
        assert_eq!(calls, 1);
    }
    #[test]
    fn migration_copies_only_the_verified_host_and_retains_rollback() {
        for actual_host in ["foo-bar.example", "other.example"] {
            let host = "foo-bar.example";
            let old = legacy_names(host)[0].clone();
            let input = HashMap::from([
                ("host".into(), host.into()),
                ("protocol".into(), "https".into()),
            ]);
            let mut wrote = false;
            let result = migrate(&input, |request| {
                match request {
                Request::List => Ok(Response::ListOk { credentials: vec![kepr_core::protocol::CredInfo {name:old.clone(),..Default::default()}],count:1 }),
                Request::Get { name, .. } => Ok(Response::GetOk { name:name.clone(), value:ZeroString::from_string(serde_json::json!({"host":actual_host,"protocol":"https","username":"u","password":"synthetic"}).to_string()) }),
                Request::Set { name, value:Some(value), .. } => {
                    assert!(matches(value, host, "https"));
                    assert_eq!(name, &host_to_kepr_name(host));
                    wrote = true;
                    Ok(Response::SetOk {name:name.clone(),cred_name:String::new(),password_protected:true})
                }
                _ => panic!("migration must not delete or overwrite an unrelated login"),
            }
            });
            assert_eq!(result.is_ok(), actual_host == host);
            assert_eq!(wrote, actual_host == host);
        }
    }
}
