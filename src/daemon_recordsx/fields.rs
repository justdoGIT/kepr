// daemon_recordsx/fields.rs — T5.05: the shapes a record field's value
// may take, so `kepr://NAME/field[i][sub]` and `/custom_field/LABEL`
// have something to index:
//
//   "text"                                 a string
//   {"first": "Ada", "last": "L"}          a structured value (strings)
//   ["a", {"type": "work", ...}, ...]      a list of either
//   "custom": {"Any label": <any of the above>, ...}   custom fields
//
// Nothing nests deeper. Property names are 1-32 of A-Z a-z 0-9 _ -;
// custom labels 1-128 characters, no control characters.

use serde_json::Value;

const MAX_ITEMS: usize = 64;
const MAX_PROPS: usize = 32;
const MAX_CUSTOM: usize = 64;

fn valid_prop(p: &str) -> bool {
    (1..=32).contains(&p.len())
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn structured(o: &serde_json::Map<String, Value>) -> Result<(), String> {
    if o.is_empty() || o.len() > MAX_PROPS {
        return Err(format!("a structured value needs 1-{MAX_PROPS} properties"));
    }
    for (p, v) in o {
        if !valid_prop(p) {
            return Err(format!(
                "property {p:?}: use 1-32 of A-Z, a-z, 0-9, _ and -"
            ));
        }
        if !v.is_string() {
            return Err(format!("property {p}: values must be strings"));
        }
    }
    Ok(())
}

/// A string, a structured value, or a list of 1-64 of those.
pub fn check_value(v: &Value) -> Result<(), String> {
    match v {
        Value::String(_) => Ok(()),
        Value::Object(o) => structured(o),
        Value::Array(a) if a.is_empty() || a.len() > MAX_ITEMS => {
            Err(format!("a list needs 1-{MAX_ITEMS} items"))
        }
        Value::Array(a) => a.iter().try_for_each(|item| match item {
            Value::String(_) => Ok(()),
            Value::Object(o) => structured(o),
            _ => Err("list items must be strings or structured values".into()),
        }),
        _ => Err("values must be strings, lists or structured values".into()),
    }
}

/// `custom`: a string (as any field) or an object of labelled values.
pub fn check_custom(v: &Value) -> Result<(), String> {
    let Value::Object(o) = v else {
        return check_value(v);
    };
    if o.is_empty() || o.len() > MAX_CUSTOM {
        return Err(format!("custom needs 1-{MAX_CUSTOM} labelled fields"));
    }
    for (label, v) in o {
        if label.is_empty() || label.chars().count() > 128 || label.chars().any(char::is_control) {
            return Err(format!(
                "custom label {label:?}: 1-128 characters, no control characters"
            ));
        }
        check_value(v).map_err(|e| format!("custom {label:?}: {e}"))?;
    }
    Ok(())
}

/// One top-level field of a record.
pub fn check_field(name: &str, v: &Value) -> Result<(), String> {
    match name {
        "custom" => check_custom(v),
        _ => check_value(v).map_err(|e| format!("field {name}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_strings_lists_structured_and_custom() {
        for (k, v) in [
            ("url", json!("https://x")),
            ("url", json!(["a", "b"])),
            ("phone", json!([{"type": "work", "number": "1"}, "2"])),
            ("name", json!({"first": "Ada", "last-name": "L"})),
            ("custom", json!({"Q/A [1]": "x", "pins": ["1", "2"]})),
            ("custom", json!("legacy string")),
        ] {
            assert!(check_field(k, &v).is_ok(), "{k}: {v}");
        }
    }

    #[test]
    fn refuses_numbers_nesting_and_bad_names() {
        for (k, v) in [
            ("port", json!(5432)),
            ("url", json!([])),
            ("url", json!([["nested"]])),
            ("name", json!({"first": {"deep": "x"}})),
            ("name", json!({"bad prop": "x"})),
            ("name", json!({})),
            ("custom", json!({"a\nb": "x"})),
            ("custom", json!({"": "x"})),
            ("custom", json!({"ok": 1})),
            (
                "url",
                json!((0..65).map(|i| i.to_string()).collect::<Vec<_>>()),
            ),
        ] {
            assert!(check_field(k, &v).is_err(), "{k}: {v}");
        }
    }
}
