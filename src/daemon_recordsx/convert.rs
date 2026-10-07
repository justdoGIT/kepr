// daemon_recordsx/convert.rs — T11.7 `kepr record convert NAME TYPE`.
//
// The value never leaves the daemon: it is decrypted here, its fields
// re-shaped for the new type and stored again through `handle_set` with
// the record's own policy (consent, FIDO2, remaining TTL); tags, folder
// and attachments carry over and the old value goes to history, so
// `kepr restore` undoes a convert. Sealed records, SSH and share keys
// and aliases are refused.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_records::RecordsResponse;
use kepr_core::record_types::{valid_field_name, MAX_TYPE_FIELDS};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_set, SetFlags};
use crate::store::{cred_exists, cred_path, validate_name};
use crate::{crypto, expiry};

/// Record fields whose strings are wiped on drop.
struct Fields(Map<String, Value>);

impl Drop for Fields {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                Value::Object(o) => o.values_mut().for_each(wipe),
                _ => {}
            }
        }
        self.0.values_mut().for_each(wipe);
    }
}

/// `label`, or `label (2)`, `label (3)`, … if `custom` has it already.
fn free_label(custom: &Map<String, Value>, label: &str) -> String {
    (1..)
        .map(|n| match n {
            1 => label.to_string(),
            n => format!("{label} ({n})"),
        })
        .find(|l| !custom.contains_key(l))
        .unwrap_or_default()
}

/// Re-shape `obj` for a type with `fields`: custom fields named like one
/// of them become fields, fields not among them become custom fields.
/// Returns (moved to custom, promoted from custom).
pub fn remap(obj: &mut Map<String, Value>, fields: &[String]) -> (Vec<String>, Vec<String>) {
    if fields.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let mut custom = match obj.remove("custom") {
        Some(Value::Object(o)) => o,
        // A legacy plain-string `custom` keeps its value under that label.
        Some(other) => Map::from_iter([("custom".to_string(), other)]),
        None => Map::new(),
    };
    let mut promoted = Vec::new();
    for f in fields {
        if !obj.contains_key(f) {
            if let Some(v) = custom.remove(f) {
                obj.insert(f.clone(), v);
                promoted.push(f.clone());
            }
        }
    }
    let moved: Vec<String> = obj
        .keys()
        .filter(|k| !fields.contains(k))
        .cloned()
        .collect();
    for k in &moved {
        if let Some(v) = obj.remove(k) {
            custom.insert(free_label(&custom, k), v);
        }
    }
    if !custom.is_empty() {
        obj.insert("custom".into(), Value::Object(custom));
    }
    (moved, promoted)
}

fn convert(
    uid: u32,
    username: &str,
    upper: &str,
    record_type: &str,
    fields: &[String],
) -> Result<RecordsResponse, String> {
    if fields.len() > MAX_TYPE_FIELDS || !fields.iter().all(|f| valid_field_name(f)) {
        return Err("the type's field names must be 1-32 of a-z, 0-9, underscore".into());
    }
    let _lock = crate::daemon_credlock::lock(uid, upper);
    const GONE: &str = "credential unavailable";
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .transpose()
        .map_err(|_| GONE.to_string())?
        .unwrap_or_default();
    if meta.alias_of.is_some() {
        return Err(format!("{upper} is an alias: convert the record it names"));
    }
    if meta.sealed == Some(true) || meta.ssh.is_some() || meta.share_key.is_some() {
        return Err(GONE.into());
    }
    let now = expiry::now_unix();
    if !cred_exists(uid, upper) || meta.expires_at_unix.is_some_and(|t| t <= now) {
        return Err(GONE.into());
    }
    if meta.record_type.is_none() {
        return Err(format!("{upper} is not a record (see: kepr record add)"));
    }
    let value = crypto::default_backend()
        .decrypt(uid, upper)
        .map_err(|e| crypto::sanitize_lookup_error(&e))?;
    let mut obj = Fields(serde_json::from_str(value.as_str()).map_err(|_| "damaged record")?);
    let (moved, promoted) = remap(&mut obj.0, fields);
    let json = ZeroString::from_string(Value::Object(std::mem::take(&mut obj.0)).to_string());
    crate::daemon_records::validate(record_type, json.as_str())?;
    let flags = SetFlags {
        ttl_secs: meta.expires_at_unix.map(|t| t - now),
        requires_consent: meta.requires_consent,
        requires_fido2: meta.requires_fido2,
        record_type: Some(record_type.to_string()),
        ..Default::default()
    };
    match handle_set(uid, username, upper, Some(json.as_str()), None, flags) {
        Response::SetOk { .. } => {}
        Response::Err { error } => return Err(error),
        _ => return Err("unexpected store reply".into()),
    }
    // Field names of a gated record are not shown without its prompt.
    let gated = meta.requires_consent == Some(true) || meta.requires_fido2 == Some(true);
    let (moved, promoted) = match gated {
        true => (Vec::new(), Vec::new()),
        false => (moved, promoted),
    };
    Ok(RecordsResponse::RecordConvertOk {
        name: upper.to_string(),
        record_type: record_type.to_string(),
        moved,
        promoted,
        gated,
    })
}

pub fn handle_convert(
    uid: u32,
    username: &str,
    name: &str,
    record_type: &str,
    fields: &[String],
) -> Response {
    let upper = name.to_uppercase();
    let r = validate_name(name).and_then(|()| convert(uid, username, &upper, record_type, fields));
    audit::log(&AuditEvent {
        op: "record-convert",
        name: Some(&upper),
        uid,
        username,
        result: match &r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
    match r {
        Ok(ok) => Response::Records(ok),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::protocol::Request;
    use serde_json::json;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn remap_keeps_matches_and_moves_the_rest_to_custom() {
        let mut obj = json!({
            "username": "me", "password": "p", "url": ["a", "b"],
            "custom": {"host": "h", "url": "taken"}
        });
        let obj = obj.as_object_mut().unwrap();
        let (moved, promoted) = remap(obj, &names(&["host", "port", "user", "password"]));
        assert_eq!(moved, ["url", "username"]);
        assert_eq!(promoted, ["host"]);
        assert_eq!(
            Value::Object(obj.clone()),
            json!({"password": "p", "host": "h",
                   "custom": {"url": "taken", "url (2)": ["a", "b"], "username": "me"}})
        );
        // An any-fields type changes nothing.
        let before = obj.clone();
        assert_eq!(remap(obj, &[]), (vec![], vec![]));
        assert_eq!(*obj, before);
    }

    fn record(uid: u32, name: &str, rtype: &str, fields: &str, consent: Option<bool>) {
        let r = crate::daemon_records::handle_record_set(
            uid,
            "t",
            name,
            (rtype, &ZeroString::from_string(fields.into())),
            (consent, false),
        );
        assert!(r.is_success(), "{r:?}");
    }

    #[test]
    fn convert_keeps_unmatched_fields_policy_and_history() {
        let uid = testkit::uid();
        record(
            uid,
            "L",
            "login",
            r#"{"username":"me","password":"p","url":"u"}"#,
            None,
        );
        let tag = kepr_core::protocol_store::StoreRequest::Organize {
            name: "L".into(),
            add_tags: vec!["work".into()],
            remove_tags: vec![],
            folder: None,
        };
        assert!(crate::daemon_store::dispatch(uid, 0, "t", tag).is_success());
        let r = handle_convert(
            uid,
            "t",
            "l",
            "server",
            &names(&["host", "user", "password"]),
        );
        let Response::Records(RecordsResponse::RecordConvertOk { moved, .. }) = r else {
            panic!("{r:?}");
        };
        assert_eq!(moved, ["url", "username"]);
        let v = crypto::default_backend().decrypt(uid, "L").unwrap();
        let got: Value = serde_json::from_str(v.as_str()).unwrap();
        assert_eq!(
            got,
            json!({"password": "p", "custom": {"url": "u", "username": "me"}})
        );
        let m = testkit::meta(uid, "L");
        assert_eq!(m.record_type.as_deref(), Some("server"));
        assert_eq!(m.tags, Some(vec!["work".to_string()]));
        assert!(
            crate::store::cred_exists(uid, "L~0"),
            "old value kept in history"
        );
        // And back: the custom fields named like login fields return.
        let r = handle_convert(
            uid,
            "t",
            "L",
            "login",
            &names(&["username", "password", "url"]),
        );
        assert!(r.is_success(), "{r:?}");
        let v = crypto::default_backend().decrypt(uid, "L").unwrap();
        let got: Value = serde_json::from_str(v.as_str()).unwrap();
        assert_eq!(got, json!({"username": "me", "password": "p", "url": "u"}));
    }

    #[test]
    fn convert_refuses_what_it_must_not_touch_and_hides_gated_names() {
        let uid = testkit::uid();
        testkit::set(uid, "PLAIN", "v");
        testkit::set_sealed(uid, "SEALED", "v");
        record(uid, "C", "login", r#"{"username":"me"}"#, Some(true));
        for (name, rtype, what) in [
            ("PLAIN", "server", "not a record"),
            ("SEALED", "server", "credential unavailable"),
            ("NOPE", "server", "credential unavailable"),
            ("C", "Bad Type", "type name"),
            ("../x", "server", "invalid character"),
        ] {
            let r = handle_convert(uid, "t", name, rtype, &names(&["host"]));
            let Response::Err { error } = r else {
                panic!("{name}: {r:?}");
            };
            assert!(error.contains(what), "{name}: {error}");
        }
        let r = handle_convert(uid, "t", "C", "server", &names(&["host"]));
        let Response::Records(RecordsResponse::RecordConvertOk { moved, gated, .. }) = r else {
            panic!("{r:?}");
        };
        assert!(gated && moved.is_empty());
        assert_eq!(testkit::meta(uid, "C").requires_consent, Some(true));
        // The request type routes through the batch.
        let req: Request = serde_json::from_value(json!({
            "cmd": "record_convert", "name": "C", "record_type": "login"
        }))
        .unwrap();
        assert!(matches!(req, Request::Records(_)));
    }
}
