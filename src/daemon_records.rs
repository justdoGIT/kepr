// daemon_records.rs — typed records (agent vault P5.1): one credential
// holding several named fields (login, card, database, …). The value is
// a JSON object of string fields, encrypted like any other value; the
// type lives in `.meta` `record_type` and shows in `kepr list`. Fields
// are read client-side after a normal `Get` (`kepr record get`,
// `kepr://NAME/field`), so every Get policy (consent, FIDO2, expiry)
// applies to records unchanged.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;

use crate::daemon_handlers::{handle_set, SetFlags};

/// Known record types and the fields `kepr record add` asks for.
pub const TYPES: &[(&str, &[&str])] = &[
    ("login", &["username", "password", "url", "totp"]),
    ("card", &["holder", "number", "expiry", "cvv", "pin"]),
    (
        "database",
        &["host", "port", "user", "password", "database"],
    ),
    ("server", &["host", "port", "user", "password"]),
    ("api", &["key", "secret", "url"]),
    ("note", &["text"]),
    ("custom", &[]),
];
const MAX_FIELDS: usize = 64;

fn valid_field_name(k: &str) -> bool {
    (1..=32).contains(&k.len())
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Check the type and that `fields` is a JSON object of 1..=64 string
/// fields with lower-case names.
pub fn validate(record_type: &str, fields: &str) -> Result<(), String> {
    if !TYPES.iter().any(|(t, _)| *t == record_type) {
        let names: Vec<&str> = TYPES.iter().map(|(t, _)| *t).collect();
        return Err(format!(
            "unknown record type; use one of: {}",
            names.join(", ")
        ));
    }
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(fields).map_err(|_| "record fields must be a JSON object")?;
    if obj.is_empty() || obj.len() > MAX_FIELDS {
        return Err(format!("a record needs 1-{MAX_FIELDS} fields"));
    }
    for (k, v) in &obj {
        if !valid_field_name(k) {
            return Err(format!(
                "field name {k:?}: use 1-32 of a-z, 0-9, underscore"
            ));
        }
        if !v.is_string() {
            return Err(format!("field {k}: values must be strings"));
        }
    }
    Ok(())
}

pub fn handle_record_set(
    uid: u32,
    username: &str,
    name: &str,
    record_type: &str,
    fields: &ZeroString,
    requires_consent: Option<bool>,
) -> Response {
    if let Err(e) = validate(record_type, fields.as_str()) {
        return Response::fail(e);
    }
    let flags = SetFlags {
        requires_consent,
        record_type: Some(record_type.to_string()),
        ..Default::default()
    };
    handle_set(uid, username, name, Some(fields.as_str()), None, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_type_and_fields() {
        assert!(validate("login", r#"{"username":"me","password":"p"}"#).is_ok());
        assert!(validate("nope", r#"{"a":"b"}"#).is_err());
        assert!(validate("login", "[]").is_err());
        assert!(validate("login", "{}").is_err());
        assert!(validate("login", r#"{"User":"x"}"#).is_err());
        assert!(validate("login", r#"{"port":5432}"#).is_err());
        let many: String = (0..65)
            .map(|i| format!("\"f{i}\":\"v\""))
            .collect::<Vec<_>>()
            .join(",");
        assert!(validate("custom", &format!("{{{many}}}")).is_err());
    }
}
