// cli_recordsx/record_add.rs — `kepr record add | show | template`
// (P5.1; moved from cli_record.rs, which dispatches here).
//
//   record add KEY [--type T] [--from-file F | --clone OTHER]
//              [--field k=v|k=-|k[]=v]... [--custom LABEL=v]... [--ref k=OTHER]...
//              [--requires-consent]
//       T11.8: fields start from F (a `record template` filled in, or a
//       bare JSON object) or from OTHER's fields (read with a normal get;
//       its attachments and history stay with it); flags then add or
//       replace fields. The type comes from --type, else F or OTHER. The
//       type's required fields must be present.
//   record show KEY [--reveal]    masked fields starred (T11.8: per type)
//   record template TYPE          the JSON skeleton --from-file reads

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::record_types::RecordType;
use serde_json::{Map, Value};

use super::record_fields::{from_file, missing, put, render, slot_of, template, tidy, Slot};
use super::resolve::{Daemon, Record, Source};
use super::types;
use crate::cli_input::read_masked;
use crate::{cli_ui, client};

const USAGE: &str = "usage: kepr record add KEY [--type T] [--from-file F | --clone OTHER] \
                     [--field k=v|k[]=v]... [--custom LABEL=v]... [--ref k=OTHER]... [--requires-consent]";

#[derive(Default)]
struct AddArgs {
    rtype: Option<String>,
    given: Vec<(Slot, Option<Value>)>,
    from_file: Option<String>,
    clone: Option<String>,
    consent: bool,
}

fn parse(args: &[String]) -> Result<AddArgs, String> {
    let mut a = AddArgs::default();
    let mut i = 0;
    while i < args.len() {
        let next = || {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--type" => a.rtype = Some(next()?),
            "--from-file" => a.from_file = Some(next()?),
            "--clone" => a.clone = Some(next()?.to_uppercase()),
            f @ ("--field" | "--custom" | "--ref") => {
                match args.get(i + 1).and_then(|v| slot_of(f, v)) {
                    Some(s) => a.given.push(s),
                    None => return Err(format!("{f} needs key=value (or key=- to be asked)")),
                }
            }
            "--requires-consent" => {
                a.consent = true;
                i += 1;
                continue;
            }
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
        i += 2;
    }
    if a.from_file.is_some() && a.clone.is_some() {
        return Err("use --from-file or --clone, not both".into());
    }
    Ok(a)
}

/// The record type `name` has, from the listing (no value is read).
fn record_type_of(name: &str) -> Option<String> {
    match client::send_request(&Request::List) {
        Ok(Response::ListOk { credentials, .. }) => credentials
            .into_iter()
            .find(|c| c.name == name)
            .and_then(|c| c.record_type),
        _ => None,
    }
}

/// The fields a clone starts from: OTHER's, read like `kepr record show`.
pub fn clone_fields(src: &dyn Source, other: &str) -> Result<Record, String> {
    Record::parse(src.value(other)?.as_str()).map_err(|_| format!("{other} is not a record"))
}

/// Fields from flags (prompting for `k=-`), or the type's fields, asked.
fn ask(fields: &mut Map<String, Value>, given: Vec<(Slot, Option<Value>)>, t: &RecordType) {
    let started = !fields.is_empty() || !given.is_empty();
    for (slot, v) in given {
        let v = v.unwrap_or_else(|| {
            Value::String(
                read_masked(&format!("  {}: ", slot.key()))
                    .as_str()
                    .to_string(),
            )
        });
        put(fields, &slot, v);
    }
    if started {
        return;
    }
    for f in &t.fields {
        let hint = match (f.required, f.kind.as_str()) {
            (true, "ref") => "record name, required",
            (true, _) => "required",
            (false, "ref") => "record name, blank to skip",
            (false, _) => "blank to skip",
        };
        let v = read_masked(&format!("  {} ({hint}): ", f.name));
        if !v.as_str().is_empty() {
            put(
                fields,
                &Slot::Field(f.name.clone()),
                Value::String(v.as_str().to_string()),
            );
        }
    }
}

pub fn cmd_add(args: &[String]) -> Response {
    let Some(name) = args.first().filter(|a| !a.starts_with('-')) else {
        return Response::fail(USAGE);
    };
    match add(&name.to_uppercase(), &args[1..]) {
        Ok(r) => r,
        Err(e) => Response::fail(e),
    }
}

fn add(name: &str, args: &[String]) -> Result<Response, String> {
    let a = parse(args)?;
    // Wiped on drop, like the JSON text built from it.
    let (from_type, mut fields) = match (&a.from_file, &a.clone) {
        (Some(f), _) => from_file(&std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?)?,
        (_, Some(other)) => (record_type_of(other), clone_fields(&Daemon, other)?),
        _ => (None, Record(Map::new())),
    };
    let rtype = a
        .rtype
        .or(from_type)
        .ok_or("--type is required (see: kepr record types)")?;
    let t = types::find(&rtype)?;
    ask(&mut fields.0, a.given, &t);
    tidy(&mut fields.0, &t);
    let lacking = missing(&fields.0, &t);
    if !lacking.is_empty() {
        return Err(format!(
            "a {rtype} record needs {} (add --field NAME=VALUE)",
            lacking.join(", ")
        ));
    }
    let json = ZeroString::from_string(serde_json::to_string(&fields.0).unwrap_or_default());
    let r = client::send_request(&Request::RecordSet {
        name: name.to_string(),
        record_type: rtype.clone(),
        fields: json,
        requires_consent: a.consent.then_some(true),
        seal: false,
    })
    .unwrap_or_else(Response::fail);
    if let Response::SetOk { name, .. } = &r {
        cli_ui::ok(&format!(
            "{name}: {rtype} record with {} field(s)",
            fields.0.len()
        ));
    }
    Ok(r)
}

pub fn cmd_show(name: &str, reveal: bool) -> Response {
    let name = name.to_uppercase();
    let rec = match Daemon.value(&name).and_then(|v| Record::parse(v.as_str())) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let t = record_type_of(&name).and_then(|t| types::all().into_iter().find(|x| x.name == t));
    for line in render(&rec, t.as_ref(), reveal) {
        println!("{}", line.as_str());
    }
    Response::Pong
}

pub fn cmd_template(args: &[String]) -> Response {
    let [rtype] = args else {
        return Response::fail("usage: kepr record template TYPE");
    };
    match types::find(rtype) {
        Ok(t) => {
            let text = serde_json::to_string_pretty(&template(&t)).unwrap_or_default();
            println!("{text}");
            Response::Pong
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolve::tests::fixture;
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_sources_and_flags() {
        let a = parse(&args(&[
            "--clone",
            "other",
            "--field",
            "url=x",
            "--requires-consent",
        ]))
        .unwrap();
        assert_eq!(a.clone.as_deref(), Some("OTHER"));
        assert!(a.consent && a.from_file.is_none() && a.given.len() == 1);
        let e = parse(&args(&["--clone", "A", "--from-file", "f"]))
            .err()
            .unwrap();
        assert!(e.contains("not both"));
        assert!(parse(&args(&["--type"]))
            .err()
            .unwrap()
            .contains("needs a value"));
        assert!(parse(&args(&["--bogus"]))
            .err()
            .unwrap()
            .contains("unexpected"));
    }

    #[test]
    fn a_clone_starts_from_the_other_records_fields() {
        let src = fixture();
        let mut rec = clone_fields(&src, "R").unwrap();
        let login = kepr_core::record_types::builtins().remove(0);
        ask(
            &mut rec.0,
            vec![slot_of("--field", "login=you").unwrap()],
            &login,
        );
        assert_eq!(rec.0["login"], "you");
        assert_eq!(rec.0["url"][1], "https://b.example");
        assert!(rec.0.contains_key("custom"));
        assert!(clone_fields(&src, "PLAIN")
            .err()
            .unwrap()
            .contains("not a record"));
        assert_eq!(
            clone_fields(&src, "SEALED").err().unwrap(),
            "credential unavailable"
        );
    }
}
