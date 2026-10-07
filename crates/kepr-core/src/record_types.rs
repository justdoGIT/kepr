// record_types.rs — typed-record schemas (P5.1, T11.7, T11.8): the
// built-in types and the shape of user types, which the CLI loads from
// `~/.config/kepr/types/*.toml`:
//
//   name = "wifi"
//   fields = [
//     { name = "ssid", type = "text", required = true },
//     { name = "password", type = "secret" },        # masked by default
//     { name = "router", type = "ref" },             # a link (T11.6)
//   ]
//
// A type with no fields accepts any fields (`custom`). Types describe
// what `kepr record add` asks for, requires and masks; the daemon checks
// only the type name and the value's shape, so user types never need to
// reach it.

use serde::{Deserialize, Serialize};

/// Field kinds. `secret` fields are masked unless the type says otherwise;
/// a `ref` field holds a link `{"ref": "OTHER"}` (T11.6).
pub const KINDS: &[&str] = &[
    "text",
    "secret",
    "multiline",
    "url",
    "email",
    "phone",
    "date",
    "number",
    "ref",
];
/// Most fields a type may declare (a record holds at most 64).
pub const MAX_TYPE_FIELDS: usize = 64;

fn text() -> String {
    "text".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSpec {
    pub name: String,
    #[serde(rename = "type", default = "text")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    /// Hidden by `kepr record show` unless `--reveal`; default: `secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
}

impl FieldSpec {
    pub fn masked(&self) -> bool {
        self.masked.unwrap_or(self.kind == "secret")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordType {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<FieldSpec>,
}

impl RecordType {
    pub fn field(&self, name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Name, field names and kinds well-formed; no field twice.
    pub fn validate(&self) -> Result<(), String> {
        valid_type_name(&self.name)?;
        if self.fields.len() > MAX_TYPE_FIELDS {
            return Err(format!("at most {MAX_TYPE_FIELDS} fields"));
        }
        for (i, f) in self.fields.iter().enumerate() {
            if !valid_field_name(&f.name) || f.name == "custom" {
                return Err(format!(
                    "field {:?}: use 1-32 of a-z, 0-9, underscore (not `custom`)",
                    f.name
                ));
            }
            if !KINDS.contains(&f.kind.as_str()) {
                return Err(format!(
                    "field {}: unknown type {:?}; use one of: {}",
                    f.name,
                    f.kind,
                    KINDS.join(", ")
                ));
            }
            if self.fields[..i].iter().any(|g| g.name == f.name) {
                return Err(format!("field {} is declared twice", f.name));
            }
        }
        Ok(())
    }
}

/// A record field name: 1-32 of a-z, 0-9, underscore.
pub fn valid_field_name(k: &str) -> bool {
    (1..=32).contains(&k.len())
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A type name: a lower-case letter, then up to 31 of a-z, 0-9, `_`, `-`.
pub fn valid_type_name(t: &str) -> Result<(), String> {
    let ok = (1..=32).contains(&t.len())
        && t.starts_with(|c: char| c.is_ascii_lowercase())
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "type name {t:?}: a-z first, then up to 31 of a-z, 0-9, _ and -"
        ))
    }
}

/// (type, [(field, kind, masked)]) — every built-in field is optional.
type Builtin = (&'static str, &'static [(&'static str, &'static str, bool)]);

const BUILTINS: &[Builtin] = &[
    (
        "login",
        &[
            ("username", "text", false),
            ("password", "secret", true),
            ("url", "url", false),
            ("totp", "secret", true),
        ],
    ),
    (
        "card",
        &[
            ("holder", "text", false),
            ("number", "secret", true),
            ("expiry", "date", false),
            ("cvv", "secret", true),
            ("pin", "secret", true),
        ],
    ),
    (
        "database",
        &[
            ("host", "text", false),
            ("port", "number", false),
            ("user", "text", false),
            ("password", "secret", true),
            ("database", "text", false),
        ],
    ),
    (
        "server",
        &[
            ("host", "text", false),
            ("port", "number", false),
            ("user", "text", false),
            ("password", "secret", true),
        ],
    ),
    (
        "api",
        &[
            ("key", "secret", true),
            ("secret", "secret", true),
            ("url", "url", false),
        ],
    ),
    ("note", &[("text", "multiline", true)]),
    ("custom", &[]),
];

/// Names of the built-in types, in display order.
pub fn builtin_names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|(t, _)| *t)
}

pub fn is_builtin(t: &str) -> bool {
    builtin_names().any(|b| b == t)
}

/// The built-in types.
pub fn builtins() -> Vec<RecordType> {
    BUILTINS
        .iter()
        .map(|(name, fields)| RecordType {
            name: (*name).into(),
            fields: fields
                .iter()
                .map(|(f, kind, masked)| FieldSpec {
                    name: (*f).into(),
                    kind: (*kind).into(),
                    required: false,
                    masked: (*masked != (*kind == "secret")).then_some(*masked),
                })
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_valid_and_keep_their_order() {
        let all = builtins();
        let names: Vec<&str> = all.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            ["login", "card", "database", "server", "api", "note", "custom"]
        );
        for t in &all {
            t.validate().unwrap();
        }
        let login = &all[0];
        assert!(login.field("password").unwrap().masked());
        assert!(!login.field("username").unwrap().masked());
        let note = all.iter().find(|t| t.name == "note").unwrap();
        assert!(note.field("text").unwrap().masked());
        assert!(is_builtin("card") && !is_builtin("wifi"));
    }

    #[test]
    fn type_names_and_fields_are_checked() {
        let t = |name: &str, fields: &[(&str, &str)]| RecordType {
            name: name.into(),
            fields: fields
                .iter()
                .map(|(n, k)| FieldSpec {
                    name: (*n).into(),
                    kind: (*k).into(),
                    required: false,
                    masked: None,
                })
                .collect(),
        };
        assert!(t("wifi", &[("ssid", "text"), ("password", "secret")])
            .validate()
            .is_ok());
        for (bad, what) in [
            (t("Wifi", &[]), "type name"),
            (t("1x", &[]), "type name"),
            (t("wifi", &[("SSID", "text")]), "field \"SSID\""),
            (t("wifi", &[("custom", "text")]), "not `custom`"),
            (t("wifi", &[("a", "blob")]), "unknown type \"blob\""),
            (t("wifi", &[("a", "text"), ("a", "url")]), "declared twice"),
        ] {
            let e = bad.validate().unwrap_err();
            assert!(e.contains(what), "{bad:?}: {e}");
        }
    }
}
