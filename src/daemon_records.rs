// daemon_records.rs — typed records (agent vault P5.1): one credential
// holding several named fields (login, card, database, …). The value is
// a JSON object of string fields, encrypted like any other value; the
// type lives in `.meta` `record_type` and shows in `kepr list`. Fields
// are read client-side after a normal `Get` (`kepr record get`,
// `kepr://NAME/field`), so every Get policy (consent, FIDO2, expiry)
// applies to records unchanged.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::record_types;

use crate::daemon_handlers::{handle_set, SetFlags};

const MAX_FIELDS: usize = 64;

/// Check the type and that `fields` is a JSON object of 1..=64 fields
/// with lower-case names (values: daemon_recordsx/fields.rs). The type is
/// a built-in or a well-formed user type name (T11.7: user types live in
/// the caller's config, so only their name reaches the daemon).
pub fn validate(record_type: &str, fields: &str) -> Result<(), String> {
    if !record_types::is_builtin(record_type) {
        record_types::valid_type_name(record_type).map_err(|e| {
            let names: Vec<&str> = record_types::builtin_names().collect();
            format!("{e} (built-in types: {})", names.join(", "))
        })?;
    }
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(fields).map_err(|_| "record fields must be a JSON object")?;
    if obj.is_empty() || obj.len() > MAX_FIELDS {
        return Err(format!("a record needs 1-{MAX_FIELDS} fields"));
    }
    for (k, v) in &obj {
        if !record_types::valid_field_name(k) {
            return Err(format!(
                "field name {k:?}: use 1-32 of a-z, 0-9, underscore"
            ));
        }
        crate::daemon_recordsx::check_field(k, v)?; // T5.05: lists, structured, custom
    }
    Ok(())
}

/// P7.1: the binding a sealed `database` record gets: its own host:port,
/// logged in to by the gate's PostgreSQL proxy.
pub fn db_binding(fields: &str) -> Result<kepr_core::binding::Binding, String> {
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(fields).map_err(|_| "record fields must be a JSON object")?;
    let get = |k: &str| obj.get(k).and_then(|v| v.as_str()).unwrap_or("");
    for k in ["host", "user", "password", "database"] {
        if get(k).is_empty() {
            return Err(format!("a sealed database record needs a {k} field"));
        }
    }
    if !matches!(get("sslmode"), "" | "verify-full" | "disable") {
        return Err("sslmode must be verify-full (default) or disable".into());
    }
    let (inject, default_port) = kepr_core::binding::Inject::for_db_kind(get("kind"))
        .ok_or("kind must be postgres, mysql or redis")?;
    let port = match get("port") {
        "" => default_port,
        p => p.parse().map_err(|_| "port must be a number")?,
    };
    let b = kepr_core::binding::Binding {
        host: get("host").to_ascii_lowercase(),
        port,
        inject,
    };
    kepr_core::binding::validate_binding(&b)?;
    Ok(b)
}

/// T13.04: the binding a sealed `kube` record gets: its API server's
/// DNS name and port, where the gate sends the token as a bearer.
pub fn kube_binding(fields: &str) -> Result<kepr_core::binding::Binding, String> {
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(fields).map_err(|_| "record fields must be a JSON object")?;
    let get = |k: &str| obj.get(k).and_then(|v| v.as_str()).unwrap_or("");
    if get("token").is_empty() {
        return Err("a sealed kube record needs a token field".into());
    }
    let ca = get("ca_pem");
    if !ca.is_empty() && !ca.contains("-----BEGIN CERTIFICATE-----") {
        return Err("ca_pem must be PEM certificates".into());
    }
    let (host, port) = kepr_core::binding::kube_server(get("server"))?;
    let b = kepr_core::binding::Binding {
        host,
        port,
        inject: kepr_core::binding::Inject::KubeToken,
    };
    kepr_core::binding::validate_binding(&b)?;
    Ok(b)
}

pub fn handle_record_set(
    uid: u32,
    username: &str,
    name: &str,
    (record_type, fields): (&str, &ZeroString),
    (requires_consent, seal): (Option<bool>, bool),
) -> Response {
    if let Err(e) = validate(record_type, fields.as_str())
        .and_then(|()| crate::daemon_recordsx::check_links(uid, name, fields.as_str()))
    {
        return Response::fail(e);
    }
    let bindings = match (seal, record_type) {
        (false, _) => None,
        (true, "database") => match db_binding(fields.as_str()) {
            Ok(b) => Some(vec![b]),
            Err(e) => return Response::fail(e),
        },
        (true, "kube") => match kube_binding(fields.as_str()) {
            Ok(b) => Some(vec![b]),
            Err(e) => return Response::fail(e),
        },
        (true, _) => return Response::fail("only database and kube records can be sealed"),
    };
    let flags = SetFlags {
        requires_consent,
        record_type: Some(record_type.to_string()),
        sealed: seal.then_some(true),
        bindings,
        ..Default::default()
    };
    handle_set(uid, username, name, Some(fields.as_str()), None, flags)
}

/// P7.2: `begin` puts a random `pending_password` into a sealed database
/// record, `commit` makes it the password, `abort` drops it. The value is
/// re-stored with its existing policy (seal, binding, consent); nothing is
/// returned. The gate performs the actual ALTER ROLE in between.
pub fn handle_db_rotate(uid: u32, username: &str, name: &str, phase: &str) -> Response {
    let upper = name.to_uppercase();
    let r = (|| -> Result<(), String> {
        crate::store::validate_name(name)?;
        let meta = crate::expiry::read_meta(&crate::expiry::meta_path_for(
            &crate::store::cred_path(uid, &upper),
        ))
        .and_then(Result::ok)
        .unwrap_or_default();
        if meta.sealed != Some(true) || meta.record_type.as_deref() != Some("database") {
            return Err("only sealed database logins (kepr agent add-db) can be rotated".into());
        }
        let value = crate::crypto::default_backend()
            .decrypt(uid, &upper)
            .map_err(|e| crate::crypto::sanitize_lookup_error(&e))?;
        let mut obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(value.as_str()).map_err(|_| "damaged database record")?;
        match phase {
            // An unfinished rotation keeps its pending password: the
            // server may already have it.
            "begin" if obj.contains_key("pending_password") => return Ok(()),
            "begin" => {
                let p = kepr_core::generate::generate_secret(kepr_core::generate::GenKind::Base62)?;
                obj.insert("pending_password".into(), p.as_str().into());
            }
            "commit" => {
                let p = obj
                    .remove("pending_password")
                    .ok_or("no rotation pending")?;
                obj.insert("password".into(), p);
            }
            "abort" => {
                obj.remove("pending_password")
                    .ok_or("no rotation pending")?;
            }
            _ => return Err("phase must be begin, commit or abort".into()),
        }
        let json = ZeroString::from_string(serde_json::Value::Object(obj).to_string());
        let flags = SetFlags {
            requires_consent: meta.requires_consent,
            sealed: Some(true),
            bindings: meta.bindings,
            record_type: meta.record_type,
            ..Default::default()
        };
        match handle_set(uid, username, &upper, Some(json.as_str()), None, flags) {
            Response::SetOk { .. } => Ok(()),
            Response::Err { error } => Err(error),
            _ => Err("unexpected store reply".into()),
        }
    })();
    crate::audit::log(&crate::audit::AuditEvent {
        op: "db-rotate",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(()) => crate::audit::AuditResult::Ok,
            Err(e) => crate::audit::AuditResult::Fail(format!("{phase}: {e}")),
        },
    });
    match r {
        Ok(()) => Response::DbRotateOk {
            name: upper,
            phase: phase.into(),
        },
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kube_record_binds_its_api_server() {
        let rec = |server: &str| format!(r#"{{"server":"{server}","token":"t"}}"#);
        let b = kube_binding(&rec("https://API.cluster.example.com:6443/")).unwrap();
        assert_eq!((b.host.as_str(), b.port), ("api.cluster.example.com", 6443));
        assert_eq!(b.inject, kepr_core::binding::Inject::KubeToken);
        assert_eq!(
            kube_binding(&rec("https://k8s.example.com")).unwrap().port,
            443
        );
        for bad in [
            "http://k8s.example.com",
            "https://10.0.0.1:6443",
            "https://user@k8s.example.com",
            "https://",
            "https://k8s.example.com:notaport",
        ] {
            assert!(kube_binding(&rec(bad)).is_err(), "{bad}");
        }
        assert!(
            kube_binding(r#"{"server":"https://k8s.example.com"}"#).is_err(),
            "no token"
        );
        let bad_ca = r#"{"server":"https://k8s.example.com","token":"t","ca_pem":"nope"}"#;
        assert!(kube_binding(bad_ca).is_err());
    }

    #[test]
    fn database_binding_comes_from_the_record() {
        let b = db_binding(r#"{"host":"DB.Example.com","user":"u","password":"p","database":"d"}"#)
            .unwrap();
        assert_eq!((b.host.as_str(), b.port), ("db.example.com", 5432));
        assert_eq!(b.inject, kepr_core::binding::Inject::Postgres);
        assert!(db_binding(r#"{"host":"db.example.com","user":"u","password":"p"}"#).is_err());
        assert!(db_binding(r#"{"host":"db","user":"u","password":"p","database":"d"}"#).is_err());
        assert!(db_binding(
            r#"{"host":"db.example.com","port":"x","user":"u","password":"p","database":"d"}"#
        )
        .is_err());
        assert!(db_binding(
            r#"{"host":"db.example.com","user":"u","password":"p","database":"d","sslmode":"prefer"}"#
        )
        .is_err());
    }

    #[test]
    fn database_kind_picks_the_proxy_and_default_port() {
        let b = db_binding(
            r#"{"kind":"redis","host":"cache.example.com","user":"default","password":"p","database":"0"}"#,
        )
        .unwrap();
        assert_eq!(b.port, 6379);
        assert_eq!(b.inject, kepr_core::binding::Inject::Redis);
        assert!(db_binding(
            r#"{"kind":"oracle","host":"db.example.com","user":"u","password":"p","database":"d"}"#
        )
        .is_err());
    }

    #[test]
    fn validates_type_and_fields() {
        assert!(validate("login", r#"{"username":"me","password":"p"}"#).is_ok());
        assert!(validate("Nope", r#"{"a":"b"}"#).is_err());
        assert!(validate("a b", r#"{"a":"b"}"#).is_err());
        // T11.7: a user type's name.
        assert!(validate("wifi", r#"{"ssid":"home"}"#).is_ok());
        assert!(validate("login", "[]").is_err());
        assert!(validate("login", "{}").is_err());
        assert!(validate("login", r#"{"User":"x"}"#).is_err());
        assert!(validate("login", r#"{"port":5432}"#).is_err());
        assert!(validate("login", r#"{"url":["a","b"],"custom":{"Q/A":"x"}}"#).is_ok());
        let many: String = (0..65)
            .map(|i| format!("\"f{i}\":\"v\""))
            .collect::<Vec<_>>()
            .join(",");
        assert!(validate("custom", &format!("{{{many}}}")).is_err());
    }
}
