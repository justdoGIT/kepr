// cli_recordsx/resolve.rs — T5.05: what a parsed `kepr://` notation
// stands for. Values come from a `Source`; the daemon's (`Daemon`) uses
// `Get` and `AttachGet`, so seal, consent, FIDO2, expiry and aliases
// (T11.5: `kepr://ALIAS/field` reads the target) apply unchanged.
// `Cached` fetches each credential and each attachment once, so a gated
// record prompts once however often a template names it.
//
// Record values are JSON objects. A field is a string, an object of
// strings (a structured value such as `name: {first, last}`) or an array
// of either; `custom` holds the custom fields, keyed by free-text label.

use std::cell::RefCell;
use std::collections::HashMap;

use kepr_core::generate::ZeroString;
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::notation::{Index, Notation, Sel};

/// The error for a field reference into a value that is not a record.
pub const NOT_A_RECORD: &str = "not a record (use kepr get)";

pub trait Source {
    fn value(&self, name: &str) -> Result<ZeroString, String>;
    fn file(&self, name: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// The daemon, through the normal CLI transport.
pub struct Daemon;

impl Source for Daemon {
    fn value(&self, name: &str) -> Result<ZeroString, String> {
        use crate::cli_exec::CredFetcher;
        crate::cli_exec::DaemonFetcher.fetch(name)
    }
    fn file(&self, name: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        super::attach::download(name, file)
    }
}

type Files = HashMap<(String, String), Zeroizing<Vec<u8>>>;

/// One fetch per credential and per attachment.
pub struct Cached<'a> {
    src: &'a dyn Source,
    values: RefCell<HashMap<String, ZeroString>>,
    files: RefCell<Files>,
}

impl<'a> Cached<'a> {
    pub fn new(src: &'a dyn Source) -> Self {
        Cached {
            src,
            values: RefCell::default(),
            files: RefCell::default(),
        }
    }
}

impl Source for Cached<'_> {
    fn value(&self, name: &str) -> Result<ZeroString, String> {
        let mut values = self.values.borrow_mut();
        if !values.contains_key(name) {
            values.insert(name.to_string(), self.src.value(name)?);
        }
        Ok(ZeroString::from_string(values[name].as_str().to_string()))
    }
    fn file(&self, name: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let key = (name.to_string(), file.to_string());
        let mut files = self.files.borrow_mut();
        if !files.contains_key(&key) {
            let bytes = self.src.file(name, file)?;
            files.insert(key.clone(), bytes);
        }
        Ok(Zeroizing::new(files[&key].to_vec()))
    }
}

/// A parsed record whose string values are wiped when it is dropped.
pub struct Record(pub Map<String, Value>);

impl Drop for Record {
    fn drop(&mut self) {
        self.0.values_mut().for_each(wipe);
    }
}

fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

impl Record {
    pub fn parse(value: &str) -> Result<Record, String> {
        serde_json::from_str(value)
            .map(Record)
            .map_err(|_| NOT_A_RECORD.to_string())
    }
}

/// The text `n` stands for. Attachments must be UTF-8 here (inject,
/// exec and resolve all produce text); `kepr attach get` saves any file.
pub fn resolve(n: &Notation, src: &dyn Source) -> Result<ZeroString, String> {
    match &n.sel {
        Sel::Whole => src.value(&n.name),
        Sel::File(f) => {
            let bytes = src.file(&n.name, f)?;
            match std::str::from_utf8(&bytes) {
                Ok(s) => Ok(ZeroString::from_string(s.to_string())),
                Err(_) => Err(format!(
                    "attachment {f} is not text; save it with kepr attach get"
                )),
            }
        }
        sel => select(&Record::parse(src.value(&n.name)?.as_str())?, sel),
    }
}

/// A field or custom field of `rec`, indexed.
pub fn select(rec: &Record, sel: &Sel) -> Result<ZeroString, String> {
    let (v, what, index) = match sel {
        Sel::Field { field, index } => (rec.0.get(field), field, index),
        Sel::Custom { label, index } => (
            rec.0
                .get("custom")
                .and_then(Value::as_object)
                .and_then(|c| c.get(label)),
            label,
            index,
        ),
        Sel::Whole | Sel::File(_) => return Err("not a field reference".into()),
    };
    let v = v.ok_or_else(|| match sel {
        Sel::Custom { .. } => format!("no custom field {what:?}"),
        _ => format!("no field {what:?}"),
    })?;
    apply(v, index)
        .map(ZeroString::from_string)
        .map_err(|e| format!("{what}: {e}"))
}

/// A non-array value is an array of one.
fn items(v: &Value) -> &[Value] {
    match v {
        Value::Array(a) => a,
        other => std::slice::from_ref(other),
    }
}

/// A string as itself; anything structured as compact JSON.
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn item(v: &Value, i: usize) -> Result<&Value, String> {
    let all = items(v);
    all.get(i)
        .ok_or_else(|| format!("no item {i} (it has {})", all.len()))
}

fn prop<'v>(item: &'v Value, i: usize, p: &str) -> Result<&'v Value, String> {
    item.as_object()
        .and_then(|o| o.get(p))
        .ok_or_else(|| format!("item {i} has no property {p:?}"))
}

fn apply(v: &Value, index: &Index) -> Result<String, String> {
    Ok(match index {
        Index::None => text(item(v, 0)?),
        Index::At(i) => text(item(v, *i)?),
        Index::All => Value::Array(items(v).to_vec()).to_string(),
        Index::Prop(p) => text(prop(item(v, 0)?, 0, p)?),
        Index::AtProp(i, p) => text(prop(item(v, *i)?, *i, p)?),
        Index::AllProp(p) => {
            let all = items(v)
                .iter()
                .enumerate()
                .map(|(i, it)| prop(it, i, p).cloned())
                .collect::<Result<Vec<_>, _>>()?;
            Value::Array(all).to_string()
        }
    })
}

#[cfg(test)]
pub mod tests {
    use super::super::notation::parse;
    use super::*;

    /// A fixture source: `R` is a record with array, structured and
    /// custom fields; `PLAIN` a plain value; `R` has two attachments.
    pub struct Fixture {
        pub fetches: std::cell::Cell<u32>,
    }

    pub const RECORD: &str = r#"{
        "login": "me",
        "url": ["https://a.example", "https://b.example"],
        "phone": [{"type": "work", "number": "111"}, {"type": "home", "number": "222"}],
        "name": {"first": "Ada", "last": "L"},
        "custom": {"Q/A [1]": "answer", "pins": ["1", "2"]}
    }"#;

    impl Source for Fixture {
        fn value(&self, name: &str) -> Result<ZeroString, String> {
            self.fetches.set(self.fetches.get() + 1);
            match name {
                "R" => Ok(RECORD.into()),
                "PLAIN" => Ok("https://x".into()),
                _ => Err("credential unavailable".into()),
            }
        }
        fn file(&self, name: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String> {
            match (name, file) {
                ("R", "notes.txt") => Ok(Zeroizing::new(b"line one\n".to_vec())),
                ("R", "key.bin") => Ok(Zeroizing::new(vec![0xff, 0xfe, 0])),
                _ => Err("no attachment".into()),
            }
        }
    }

    pub fn fixture() -> Fixture {
        Fixture {
            fetches: std::cell::Cell::new(0),
        }
    }

    fn get(text: &str) -> Result<String, String> {
        let n = parse(text)?;
        resolve(&n, &fixture()).map(|v| v.as_str().to_string())
    }

    #[test]
    fn resolves_fields_indexes_and_custom_fields() {
        for (text, want) in [
            ("kepr://R/login", "me"),
            ("kepr://R/url", "https://a.example"),
            ("kepr://R/url[1]", "https://b.example"),
            (
                "kepr://R/url[]",
                r#"["https://a.example","https://b.example"]"#,
            ),
            ("kepr://R/phone[1][number]", "222"),
            ("kepr://R/phone[type]", "work"),
            ("kepr://R/phone[][number]", r#"["111","222"]"#),
            ("kepr://R/phone[0]", r#"{"number":"111","type":"work"}"#),
            ("kepr://R/name[first]", "Ada"),
            ("kepr://R/login[0]", "me"),
            (r"kepr://R/custom_field/Q\/A \[1\]", "answer"),
            ("kepr://R/custom_field/pins[1]", "2"),
            ("kepr://R/custom_field/pins[]", r#"["1","2"]"#),
            ("kepr://PLAIN", "https://x"),
            ("kepr://R/file/notes.txt", "line one\n"),
        ] {
            assert_eq!(get(text).as_deref(), Ok(want), "{text}");
        }
    }

    #[test]
    fn resolution_errors_say_what_is_missing() {
        for (text, what) in [
            ("kepr://R/nope", "no field \"nope\""),
            ("kepr://R/url[5]", "url: no item 5 (it has 2)"),
            ("kepr://R/phone[0][fax]", "has no property \"fax\""),
            ("kepr://R/url[0][x]", "has no property"),
            ("kepr://R/custom_field/Q", "no custom field \"Q\""),
            ("kepr://PLAIN/url", NOT_A_RECORD),
            ("kepr://R/file/key.bin", "not text"),
            ("kepr://R/file/none", "no attachment"),
            ("kepr://NOPE", "credential unavailable"),
        ] {
            let e = get(text).unwrap_err();
            assert!(e.contains(what), "{text}: {e}");
        }
    }

    #[test]
    fn cached_source_fetches_once() {
        let f = fixture();
        let c = Cached::new(&f);
        for t in ["kepr://R/login", "kepr://R/url[1]", "kepr://R"] {
            resolve(&parse(t).unwrap(), &c).unwrap();
        }
        assert_eq!(f.fetches.get(), 1);
        assert!(c.value("NOPE").is_err());
        assert_eq!(c.file("R", "notes.txt").unwrap().as_slice(), b"line one\n");
    }

    #[test]
    fn record_wipes_its_strings() {
        let mut v: Value = serde_json::from_str(r#"{"a":["xy",{"b":"zz"}]}"#).unwrap();
        wipe(&mut v);
        assert_eq!(v["a"][0], Value::String(String::new()));
        assert_eq!(v["a"][1]["b"], Value::String(String::new()));
    }
}
