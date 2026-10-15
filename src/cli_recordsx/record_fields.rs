// cli_recordsx/record_fields.rs — building and showing a record's fields
// for `kepr record add | show | template` (record_add.rs): the `--field`
// / `--custom` / `--ref` slots (P5.1, T5.05, T11.6) and the T11.8 field
// options: required fields, masked fields, templates and `--from-file`.

use kepr_core::record_types::RecordType;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use super::resolve::{link_of, Record};

/// Where one `--field` / `--custom` / `--ref` value goes.
pub enum Slot {
    Field(String),
    Item(String),
    Custom(String),
}

impl Slot {
    pub fn key(&self) -> &str {
        let (Slot::Field(k) | Slot::Item(k) | Slot::Custom(k)) = self;
        k
    }
}

pub fn put(map: &mut Map<String, Value>, slot: &Slot, v: Value) {
    match slot {
        Slot::Field(k) => {
            map.insert(k.clone(), v);
        }
        Slot::Item(k) => match map.entry(k.clone()).or_insert(Value::Array(Vec::new())) {
            Value::Array(a) => a.push(v),
            other => *other = Value::Array(vec![std::mem::take(other), v]),
        },
        Slot::Custom(label) => {
            let c = map
                .entry("custom")
                .or_insert_with(|| Value::Object(Map::new()));
            if !c.is_object() {
                *c = Value::Object(Map::new());
            }
            if let Value::Object(o) = c {
                o.insert(label.clone(), v);
            }
        }
    }
}

/// `k=v`, `k[]=v` (list item) or, for `--custom`, `LABEL=v`; `--ref`
/// takes `k=OTHER` / `k[]=OTHER` and is never asked for.
pub fn slot_of(flag: &str, arg: &str) -> Option<(Slot, Option<Value>)> {
    let (k, v) = arg.split_once('=')?;
    let v = match flag {
        "--ref" if v.is_empty() || v == "-" => return None,
        "--ref" => Some(json!({ "ref": v.to_uppercase() })),
        _ => (v != "-").then(|| Value::String(v.to_string())),
    };
    let slot = match (flag, k.strip_suffix("[]")) {
        ("--custom", _) => Slot::Custom(k.to_string()),
        (_, Some(list)) => Slot::Item(list.to_string()),
        _ => Slot::Field(k.to_string()),
    };
    Some((slot, v))
}

/// `kepr record template TYPE`: every field of the type, empty (a `ref`
/// field as an empty link), under the type's name.
pub fn template(t: &RecordType) -> Value {
    let fields: Map<String, Value> = t
        .fields
        .iter()
        .map(|f| {
            let empty = match f.kind.as_str() {
                "ref" => json!({ "ref": "" }),
                _ => json!(""),
            };
            (f.name.clone(), empty)
        })
        .collect();
    json!({ "type": t.name, "fields": fields })
}

/// A `--from-file` document: a template (`{"type": T, "fields": {...}}`)
/// or a bare object of fields. Returns the type it names, if any.
pub fn from_file(text: &str) -> Result<(Option<String>, Record), String> {
    let mut obj = Record::parse(text)
        .map_err(|_| "the file must hold a JSON object (see: kepr record template TYPE)")?;
    let wrapped = obj.0.len() == 2
        && obj.0.get("type").is_some_and(Value::is_string)
        && obj.0.get("fields").is_some_and(Value::is_object);
    if !wrapped {
        return Ok((None, obj));
    }
    let rtype = obj
        .0
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_string);
    let fields = match obj.0.remove("fields") {
        Some(Value::Object(f)) => f,
        _ => Map::new(),
    };
    Ok((rtype, Record(fields)))
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.iter().all(is_empty),
        Value::Object(o) => o.values().all(is_empty),
        Value::Null => true,
        _ => false,
    }
}

/// Drop fields left empty (from a template), and turn a plain name given
/// for a `ref` field of `t` into a link.
pub fn tidy(fields: &mut Map<String, Value>, t: &RecordType) {
    if let Some(Value::Object(c)) = fields.get_mut("custom") {
        c.retain(|_, v| !is_empty(v));
    }
    fields.retain(|_, v| !is_empty(v));
    for f in t.fields.iter().filter(|f| f.kind == "ref") {
        if let Some(v) = fields.get_mut(&f.name) {
            let link = |v: &mut Value| {
                if let Value::String(s) = v {
                    *v = json!({ "ref": s.to_uppercase() });
                }
            };
            match v {
                Value::Array(a) => a.iter_mut().for_each(link),
                other => link(other),
            }
        }
    }
}

/// The required fields of `t` that `fields` lacks (or leaves empty).
pub fn missing(fields: &Map<String, Value>, t: &RecordType) -> Vec<String> {
    t.fields
        .iter()
        .filter(|f| f.required && fields.get(&f.name).is_none_or(is_empty))
        .map(|f| f.name.clone())
        .collect()
}

/// `kepr record show` lines. Fields the type marks masked, fields it
/// doesn't know and custom fields are starred unless `reveal`; links
/// always show where they point.
pub fn render(rec: &Record, t: Option<&RecordType>, reveal: bool) -> Vec<Zeroizing<String>> {
    let line = |k: &str, v: &Value, masked: bool| {
        if let Some(target) = link_of(v) {
            return Zeroizing::new(format!("{k}: -> {target}"));
        }
        let text = Zeroizing::new(match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
        Zeroizing::new(match masked && !reveal {
            true => format!("{k}: {}", "*".repeat(text.chars().count().clamp(1, 12))),
            false => format!("{k}: {}", text.as_str()),
        })
    };
    let mut out = Vec::new();
    for (k, v) in &rec.0 {
        match (k.as_str(), v.as_object()) {
            ("custom", Some(c)) => {
                for (label, cv) in c {
                    out.push(line(&format!("custom_field/{label}"), cv, true));
                }
            }
            _ => {
                let masked = t.and_then(|t| t.field(k)).is_none_or(|f| f.masked());
                out.push(line(k, v, masked));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::record_types::{self, FieldSpec};

    fn wifi() -> RecordType {
        let f = |name: &str, kind: &str, required: bool| FieldSpec {
            name: name.into(),
            kind: kind.into(),
            required,
            masked: None,
        };
        RecordType {
            name: "wifi".into(),
            fields: vec![
                f("ssid", "text", true),
                f("password", "secret", true),
                f("router", "ref", false),
            ],
        }
    }

    #[test]
    fn field_flags_build_lists_and_custom_fields() {
        let mut m = Map::new();
        for (flag, arg) in [
            ("--field", "user=me"),
            ("--field", "url[]=a"),
            ("--field", "url[]=b"),
            ("--custom", "Q/A [1]=x=y"),
            ("--field", "one[]=1"),
            ("--field", "user=you"),
        ] {
            let (slot, v) = slot_of(flag, arg).unwrap();
            put(&mut m, &slot, v.unwrap());
        }
        assert_eq!(
            Value::Object(m).to_string(),
            r#"{"custom":{"Q/A [1]":"x=y"},"one":["1"],"url":["a","b"],"user":"you"}"#
        );
        // T11.6: links.
        let mut m = Map::new();
        for arg in ["billing=home", "cards[]=A", "cards[]=B"] {
            let (slot, v) = slot_of("--ref", arg).unwrap();
            put(&mut m, &slot, v.unwrap());
        }
        assert_eq!(
            Value::Object(m).to_string(),
            r#"{"billing":{"ref":"HOME"},"cards":[{"ref":"A"},{"ref":"B"}]}"#
        );
        assert!(slot_of("--ref", "billing=-").is_none());
        assert!(slot_of("--ref", "billing=").is_none());
        assert!(slot_of("--field", "novalue").is_none());
        assert!(slot_of("--field", "k=-").unwrap().1.is_none());
    }

    #[test]
    fn template_matches_the_type_and_reads_back() {
        for t in record_types::builtins().into_iter().chain([wifi()]) {
            let tpl = template(&t);
            assert_eq!(tpl["type"], json!(t.name));
            let keys: Vec<&String> = tpl["fields"].as_object().unwrap().keys().collect();
            let mut want: Vec<&String> = t.fields.iter().map(|f| &f.name).collect();
            want.sort();
            assert_eq!(keys, want, "{}", t.name);
            let (rtype, mut rec) = from_file(&tpl.to_string()).unwrap();
            assert_eq!(rtype.as_deref(), Some(t.name.as_str()));
            tidy(&mut rec.0, &t);
            assert!(rec.0.is_empty(), "an untouched template adds nothing");
        }
        assert_eq!(template(&wifi())["fields"]["router"], json!({"ref": ""}));
    }

    #[test]
    fn from_file_takes_a_template_or_bare_fields() {
        let (t, rec) = from_file(r#"{"type":"wifi","fields":{"ssid":"home"}}"#).unwrap();
        assert_eq!((t.as_deref(), rec.0.len()), (Some("wifi"), 1));
        let (t, rec) = from_file(r#"{"ssid":"home","type":"x"}"#).unwrap();
        assert_eq!((t, rec.0.len()), (None, 2));
        assert!(from_file("[1]").err().unwrap().contains("JSON object"));
    }

    #[test]
    fn tidy_links_ref_fields_and_missing_names_required_ones() {
        let t = wifi();
        let mut m = json!({"ssid": "home", "password": "", "router": "rtr",
                           "custom": {"a": "", "b": "x"}})
        .as_object()
        .cloned()
        .unwrap();
        tidy(&mut m, &t);
        assert_eq!(
            Value::Object(m.clone()),
            json!({"ssid": "home", "router": {"ref": "RTR"}, "custom": {"b": "x"}})
        );
        assert_eq!(missing(&m, &t), ["password"]);
        m.insert("password".into(), json!("p"));
        assert!(missing(&m, &t).is_empty());
        assert_eq!(missing(&Map::new(), &t), ["ssid", "password"]);
    }

    #[test]
    fn show_masks_what_the_type_masks() {
        let rec = Record(
            json!({"username": "me", "password": "pw", "extra": "e",
                   "billing": {"ref": "HOME"}, "custom": {"Q": "a"}})
            .as_object()
            .cloned()
            .unwrap(),
        );
        let login = record_types::builtins().remove(0);
        let lines = |t: Option<&RecordType>, reveal| -> Vec<String> {
            render(&rec, t, reveal)
                .iter()
                .map(|l| l.as_str().to_string())
                .collect()
        };
        assert_eq!(
            lines(Some(&login), false),
            [
                "billing: -> HOME",
                "custom_field/Q: *",
                "extra: *",
                "password: **",
                "username: me"
            ]
        );
        assert!(lines(None, false).contains(&"username: **".to_string()));
        assert!(lines(Some(&login), true).contains(&"password: pw".to_string()));
    }
}
