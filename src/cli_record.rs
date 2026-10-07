// cli_record.rs — typed records (agent vault P5.1).
//
//   kepr record add NAME --type T [--field k=v | --field k=-]... [--requires-consent]
//       `k=-` (or a type's standard field left out) is prompted for, hidden.
//       `--field k[]=v` appends to a list, `--custom LABEL=v` sets a
//       custom field (T5.05).
//   kepr record show NAME [--reveal]     field names (values masked unless --reveal)
//   kepr record get NAME FIELD           one field's value, raw; FIELD is
//       anything after `kepr://NAME/` (url[1], custom_field/LABEL, ...)
//   kepr record types                    known types and their standard fields
//
// `kepr://NAME/field` in `kepr inject` templates reads one field.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use serde_json::{Map, Value};

use crate::cli_input::read_masked;
use crate::cli_recordsx::notation;
use crate::cli_recordsx::resolve::{self, Record};
use crate::cli_ui;
use crate::client;

/// Same list as the daemon's (daemon_records::TYPES); the daemon re-checks.
const TYPES: &[(&str, &[&str])] = &[
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
const USAGE: &str = "usage: kepr record add NAME --type T [--field k=v | k[]=v]... [--custom LABEL=v]... | show NAME [--reveal] | get NAME FIELD | types";

/// Where one `--field` / `--custom` value goes.
enum Slot {
    Field(String),
    Item(String),
    Custom(String),
}

fn put(map: &mut Map<String, Value>, slot: &Slot, v: String) {
    let v = Value::String(v);
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

/// `k=v`, `k[]=v` (list item) or, for `--custom`, `LABEL=v`.
fn slot_of(flag: &str, arg: &str) -> Option<(Slot, Option<String>)> {
    let (k, v) = arg.split_once('=')?;
    let v = (v != "-").then(|| v.to_string());
    let slot = match (flag, k.strip_suffix("[]")) {
        ("--custom", _) => Slot::Custom(k.to_string()),
        (_, Some(list)) => Slot::Item(list.to_string()),
        _ => Slot::Field(k.to_string()),
    };
    Some((slot, v))
}

fn get_value(name: &str) -> Result<ZeroString, String> {
    use crate::cli_exec::CredFetcher;
    crate::cli_exec::DaemonFetcher.fetch(&name.to_uppercase())
}

fn add(args: &[String]) -> Response {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')) else {
        return Response::fail(USAGE);
    };
    let mut rtype = None;
    let mut given: Vec<(Slot, Option<String>)> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--type" => rtype = args.get(i + 1).cloned(),
            f @ ("--field" | "--custom") => match args.get(i + 1).and_then(|a| slot_of(f, a)) {
                Some(s) => given.push(s),
                None => {
                    return Response::fail(format!("{f} needs key=value (or key=- to be asked)"))
                }
            },
            "--requires-consent" => {
                i += 1;
                continue;
            }
            other => return Response::fail(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 2;
    }
    let Some(rtype) = rtype else {
        return Response::fail("--type is required (see: kepr record types)");
    };
    let standard = TYPES
        .iter()
        .find(|(t, _)| *t == rtype)
        .map_or(&[][..], |(_, f)| *f);
    // Wiped on drop, like the JSON text built from it.
    let mut fields = Record(Map::new());
    for (slot, v) in given {
        let v = v.unwrap_or_else(|| {
            let (Slot::Field(k) | Slot::Item(k) | Slot::Custom(k)) = &slot;
            read_masked(&format!("  {k}: ")).as_str().to_string()
        });
        put(&mut fields.0, &slot, v);
    }
    if fields.0.is_empty() {
        for k in standard {
            let v = read_masked(&format!("  {k} (blank to skip): "));
            if !v.as_str().is_empty() {
                put(
                    &mut fields.0,
                    &Slot::Field(k.to_string()),
                    v.as_str().to_string(),
                );
            }
        }
    }
    let json = ZeroString::from_string(serde_json::to_string(&fields.0).unwrap_or_default());
    let consent = args
        .iter()
        .any(|a| a == "--requires-consent")
        .then_some(true);
    let r = client::send_request(&Request::RecordSet {
        name: name.to_uppercase(),
        record_type: rtype.clone(),
        fields: json,
        requires_consent: consent,
        seal: false,
    })
    .unwrap_or_else(Response::fail);
    if let Response::SetOk { name, .. } = &r {
        cli_ui::ok(&format!(
            "{name}: {rtype} record with {} field(s)",
            fields.0.len()
        ));
    }
    r
}

fn show(name: &str, reveal: bool) -> Response {
    let value = match get_value(name) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let rec = match Record::parse(value.as_str()) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    for (k, v) in &rec.0 {
        let v = zeroize::Zeroizing::new(match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
        let v = v.as_str();
        if reveal {
            println!("{k}: {v}");
        } else {
            println!("{k}: {}", "*".repeat(v.chars().count().min(12)));
        }
    }
    Response::Pong
}

pub fn cmd_record(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    match (args.first().map(String::as_str), rest) {
        (Some("add"), _) => add(rest),
        (Some("show"), [name, ..]) => show(name, rest.iter().any(|a| a == "--reveal")),
        (Some("get"), [name, field]) => {
            let n = notation::parse(&format!("{}{name}/{field}", notation::PREFIX));
            match n.and_then(|n| resolve::resolve(&n, &resolve::Daemon)) {
                Ok(v) => {
                    println!("{}", v.as_str());
                    Response::Pong
                }
                Err(e) => Response::fail(e),
            }
        }
        (Some("types"), _) => {
            for (t, f) in TYPES {
                println!(
                    "{t:<9} {}",
                    if f.is_empty() {
                        "(any fields)".to_string()
                    } else {
                        f.join(", ")
                    }
                );
            }
            Response::Pong
        }
        _ => Response::fail(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(slot_of("--field", "novalue").is_none());
        assert!(slot_of("--field", "k=-").unwrap().1.is_none());
    }

    #[test]
    fn type_table_matches_the_daemon() {
        let names: Vec<&str> = TYPES.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            names,
            ["login", "card", "database", "server", "api", "note", "custom"]
        );
    }
}
