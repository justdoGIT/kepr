// cli_record.rs — typed records (agent vault P5.1).
//
//   kepr record add NAME --type T [--field k=v | --field k=-]... [--requires-consent]
//       `k=-` (or a type's standard field left out) is prompted for, hidden.
//   kepr record show NAME [--reveal]     field names (values masked unless --reveal)
//   kepr record get NAME FIELD           one field's value, raw
//   kepr record types                    known types and their standard fields
//
// `kepr://NAME/field` in `kepr inject` templates reads one field.

use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use zeroize::Zeroizing;

use crate::cli_input::read_masked;
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
const USAGE: &str = "usage: kepr record add NAME --type T [--field k=v]... | show NAME [--reveal] | get NAME FIELD | types";

/// One field of a record value (a JSON object of strings).
pub fn field_of(value: &str, field: &str) -> Result<ZeroString, String> {
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(value).map_err(|_| "not a record (use kepr get)".to_string())?;
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(|s| ZeroString::from_string(s.to_string()))
        .ok_or_else(|| format!("no field {field:?}"))
}

fn get_value(name: &str) -> Result<ZeroString, String> {
    match client::send_request(&Request::Get {
        name: name.to_uppercase(),
        fido2_assertion: None,
    })? {
        Response::GetOk { value, .. } => Ok(value),
        Response::Err { error } => Err(error),
        _ => Err("this credential needs a FIDO2 touch; use kepr get".into()),
    }
}

fn add(args: &[String]) -> Response {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')) else {
        return Response::fail(USAGE);
    };
    let mut rtype = None;
    let mut given: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--type" => rtype = args.get(i + 1).cloned(),
            "--field" => match args.get(i + 1).and_then(|f| f.split_once('=')) {
                Some((k, "-")) => given.push((k.to_string(), None)),
                Some((k, v)) => given.push((k.to_string(), Some(v.to_string()))),
                None => return Response::fail("--field needs key=value (or key=- to be asked)"),
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
    let mut fields: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for (k, v) in &given {
        let v = v
            .clone()
            .unwrap_or_else(|| read_masked(&format!("  {k}: ")).as_str().to_string());
        fields.insert(k.clone(), Zeroizing::new(v));
    }
    if given.is_empty() {
        for k in standard {
            let v = read_masked(&format!("  {k} (blank to skip): "));
            if !v.as_str().is_empty() {
                fields.insert(k.to_string(), Zeroizing::new(v.as_str().to_string()));
            }
        }
    }
    let map: serde_json::Map<String, serde_json::Value> = fields
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.to_string())))
        .collect();
    let json = ZeroString::from_string(serde_json::Value::Object(map).to_string());
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
            fields.len()
        ));
    }
    r
}

fn show(name: &str, reveal: bool) -> Response {
    let value = match get_value(name) {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let obj: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(value.as_str())
    {
        Ok(o) => o,
        Err(_) => return Response::fail("not a record (use kepr get)"),
    };
    for (k, v) in &obj {
        let v = v.as_str().unwrap_or_default();
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
            match get_value(name).and_then(|v| field_of(v.as_str(), field)) {
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
    fn reads_one_field() {
        let v = r#"{"username":"me","password":"p w"}"#;
        assert_eq!(field_of(v, "password").unwrap().as_str(), "p w");
        assert!(field_of(v, "url").is_err());
        assert!(field_of("plain", "x").is_err());
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
