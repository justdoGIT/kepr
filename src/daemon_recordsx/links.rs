// daemon_recordsx/links.rs — T11.6 linked records. A field value (or a
// list item, or a custom field) `{"ref": "OTHER"}` links to the record
// OTHER; `kepr://NAME/field/...` follows it client-side, one Get per
// record, so every Get policy applies to the target unchanged.
//
// On write the daemon refuses a link to the record itself and to a
// credential no Get can read (sealed, an SSH key, the share key, or an
// alias of one): such a link could never resolve. Longer cycles are
// refused when a reference is resolved.

use serde_json::{Map, Value};

use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

/// The name a `{"ref": "NAME"}` value links to.
pub fn link_of(v: &Value) -> Option<&str> {
    match v.as_object() {
        Some(o) if o.len() == 1 => o.get("ref").and_then(Value::as_str),
        _ => None,
    }
}

/// Every link in a record: field values, list items and custom fields.
fn links(obj: &Map<String, Value>) -> Vec<&str> {
    let mut values: Vec<&Value> = Vec::new();
    for (k, v) in obj {
        match (k.as_str(), v.as_object()) {
            // `custom` is an object of labelled values (fields.rs).
            ("custom", Some(c)) => values.extend(c.values()),
            _ => values.push(v),
        }
    }
    values
        .into_iter()
        .flat_map(|v| match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        })
        .filter_map(link_of)
        .collect()
}

fn meta(uid: u32, name: &str) -> CredMeta {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name)))
        .and_then(Result::ok)
        .unwrap_or_default()
}

fn unreadable(m: &CredMeta) -> bool {
    m.sealed == Some(true) || m.ssh.is_some() || m.share_key == Some(true)
}

/// Check the links of record `name` (fields already validated as JSON).
pub fn check_links(uid: u32, name: &str, fields: &str) -> Result<(), String> {
    let obj: Map<String, Value> =
        serde_json::from_str(fields).map_err(|_| "record fields must be a JSON object")?;
    let me = name.to_uppercase();
    for target in links(&obj) {
        validate_name(target).map_err(|e| format!("link to {target:?}: {e}"))?;
        let target = target.to_uppercase();
        if target == me {
            return Err(format!("{me} cannot link to itself"));
        }
        let m = meta(uid, &target);
        let via_alias = m.alias_of.as_deref().map(|a| meta(uid, &a.to_uppercase()));
        if unreadable(&m) || via_alias.as_ref().is_some_and(unreadable) {
            return Err(format!(
                "cannot link to {target}: it can never be read (sealed or a key)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use serde_json::json;

    #[test]
    fn finds_links_in_fields_lists_and_custom_fields() {
        let obj = json!({
            "billing": {"ref": "HOME"},
            "others": ["x", {"ref": "A"}, {"ref": "B", "note": "not a link"}],
            "custom": {"Bank": {"ref": "C"}, "pins": [{"ref": "D"}]},
            "plain": "E"
        });
        let mut got = links(obj.as_object().unwrap());
        got.sort_unstable();
        assert_eq!(got, ["A", "C", "D", "HOME"]);
    }

    #[test]
    fn refuses_self_links_and_unreadable_targets() {
        let uid = testkit::uid();
        testkit::set(uid, "HOME", r#"{"city":"Oslo"}"#);
        testkit::set_sealed(uid, "SEALED", "s3cret");
        assert!(check_links(uid, "card", r#"{"billing":{"ref":"HOME"}}"#).is_ok());
        // A dangling link is allowed: the target may be added later.
        assert!(check_links(uid, "CARD", r#"{"billing":{"ref":"LATER"}}"#).is_ok());
        for (fields, what) in [
            (r#"{"me":{"ref":"card"}}"#, "CARD cannot link to itself"),
            (r#"{"x":[{"ref":"SEALED"}]}"#, "cannot link to SEALED"),
            (r#"{"custom":{"x":{"ref":"../x"}}}"#, "invalid character"),
        ] {
            let e = check_links(uid, "CARD", fields).unwrap_err();
            assert!(e.contains(what), "{fields}: {e}");
        }
    }
}
