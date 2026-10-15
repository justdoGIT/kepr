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
// T11.6: a structured value `{"ref": "OTHER"}` links to the record OTHER;
// `kepr://NAME/field/...` follows it (each record read with its own Get,
// so a sealed or gated target is refused or prompts as usual), and a
// path that comes back to a record it already read is refused.

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
    let (name, sel) = follow(n, src)?;
    match sel {
        Sel::Whole => src.value(&name),
        Sel::File(f) => {
            let bytes = src.file(&name, f)?;
            match std::str::from_utf8(&bytes) {
                Ok(s) => Ok(ZeroString::from_string(s.to_string())),
                Err(_) => Err(format!(
                    "attachment {f} is not text; save it with kepr attach get"
                )),
            }
        }
        sel => select(&Record::parse(src.value(&name)?.as_str())?, sel),
    }
}

/// T11.6: the record and selection `n` ends at, after its links
/// (`kepr://CARD/billing/city`: HOME_ADDRESS and `city`).
pub fn follow<'n>(n: &'n Notation, src: &dyn Source) -> Result<(String, &'n Sel), String> {
    let mut path = vec![n.name.clone()];
    let mut sel = &n.sel;
    for next in &n.links {
        let here = &path[path.len() - 1];
        let target = link(&Record::parse(src.value(here)?.as_str())?, sel)?;
        let cycle = path.contains(&target);
        path.push(target);
        if cycle {
            return Err(format!("reference cycle: {}", path.join(" -> ")));
        }
        sel = next;
    }
    Ok((path.pop().unwrap_or_default(), sel))
}

/// The name a `{"ref": "NAME"}` value links to.
pub fn link_of(v: &Value) -> Option<&str> {
    match v.as_object() {
        Some(o) if o.len() == 1 => o.get("ref").and_then(Value::as_str),
        _ => None,
    }
}

/// The record the selected item of `rec` links to.
fn link(rec: &Record, sel: &Sel) -> Result<String, String> {
    let (v, what, index) = field(rec, sel)?;
    let one = match index {
        Index::None => item(v, 0),
        Index::At(i) => item(v, *i),
        _ => return Err(format!("{what}: a link is one item ({what} or {what}[i])")),
    }
    .map_err(|e| format!("{what}: {e}"))?;
    let target = link_of(one).ok_or_else(|| format!("{what} is not a link to another record"))?;
    let ok = (1..=128).contains(&target.len())
        && target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        return Err(format!("{what} links to an invalid name"));
    }
    Ok(target.to_uppercase())
}

/// The value a field or custom-field selection names, its label and index.
fn field<'r>(rec: &'r Record, sel: &'r Sel) -> Result<(&'r Value, &'r str, &'r Index), String> {
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
    Ok((v, what, index))
}

/// A field or custom field of `rec`, indexed.
pub fn select(rec: &Record, sel: &Sel) -> Result<ZeroString, String> {
    let (v, what, index) = field(rec, sel)?;
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

    /// T11.6: CARD links to HOME (and back), to R by a list, to a
    /// sealed record (whose Get the daemon refuses) and to itself.
    pub const CARD: &str = r#"{
        "number": "4111",
        "billing": {"ref": "HOME"},
        "others": ["x", {"ref": "R"}],
        "custom": {"Bank/1": {"ref": "SEALED"}},
        "me": {"ref": "card"},
        "bad": {"ref": "../x"}
    }"#;
    pub const HOME: &str = r#"{"city": "Oslo", "owner": {"ref": "CARD"}}"#;

    impl Source for Fixture {
        fn value(&self, name: &str) -> Result<ZeroString, String> {
            self.fetches.set(self.fetches.get() + 1);
            match name {
                "R" => Ok(RECORD.into()),
                "CARD" => Ok(CARD.into()),
                "HOME" => Ok(HOME.into()),
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
    fn links_resolve_one_hop_and_refuse_cycles_and_sealed_targets() {
        for (text, want) in [
            ("kepr://CARD/billing/city", "Oslo"),
            ("kepr://card/others[1]/login", "me"),
            ("kepr://CARD/others[1]/url[1]", "https://b.example"),
            ("kepr://CARD/billing/file/notes.txt", "no attachment"),
            ("kepr://CARD/billing", r#"{"ref":"HOME"}"#),
            ("kepr://CARD/billing[ref]", "HOME"),
        ] {
            let got = get(text).unwrap_or_else(|e| e);
            assert_eq!(got, want, "{text}");
        }
        for (text, what) in [
            (
                "kepr://CARD/billing/owner/number",
                "reference cycle: CARD -> HOME -> CARD",
            ),
            ("kepr://CARD/me/number", "reference cycle: CARD -> CARD"),
            (
                r"kepr://CARD/custom_field/Bank\/1/x",
                "credential unavailable",
            ),
            ("kepr://CARD/number/x", "number is not a link"),
            ("kepr://CARD/others/x", "others is not a link"),
            ("kepr://CARD/others[]/x", "a link is one item"),
            ("kepr://CARD/others[5]/x", "no item 5"),
            ("kepr://CARD/bad/x", "invalid name"),
            ("kepr://CARD/nope/x", "no field \"nope\""),
        ] {
            let e = get(text).unwrap_err();
            assert!(e.contains(what), "{text}: {e}");
        }
        // The sealed target is never fetched past its refusal, and each
        // record is read once per hop.
        let f = fixture();
        resolve(&parse("kepr://CARD/billing/city").unwrap(), &f).unwrap();
        assert_eq!(f.fetches.get(), 2);
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
