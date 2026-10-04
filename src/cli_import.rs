// cli_import.rs — `kepr import FILE [--format auto|csv|json|env]
// [--prefix P] [--seal] [--overwrite] [--yes]` (agent vault P10.2).
//
// Shows the plan (names only, never values) and stores nothing without
// --yes. Names already in kepr, or repeated within the file, are
// skipped unless --overwrite. --seal stores values that look like a
// known provider's API key write-only, bound to that provider, the way
// `kepr agent add` does.

use std::collections::HashSet;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::providers;
use zeroize::Zeroizing;

use crate::cli_import_parse::{self, Entry};
use crate::{cli_ui, client};

pub struct Opts<'a> {
    pub format: &'a str,
    pub prefix: Option<&'a str>,
    pub seal: bool,
    pub overwrite: bool,
    pub yes: bool,
}

fn existing_names() -> HashSet<String> {
    match client::send_request(&Request::List) {
        Ok(Response::ListOk { credentials, .. }) => {
            credentials.into_iter().map(|c| c.name).collect()
        }
        _ => HashSet::new(),
    }
}

/// Same rule as the daemon's `validate_name` (it re-checks).
fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Entries to store and `(name, reason)` pairs skipped.
pub fn plan(
    entries: Vec<Entry>,
    existing: &HashSet<String>,
    overwrite: bool,
) -> (Vec<Entry>, Vec<(String, &'static str)>) {
    let (mut keep, mut skipped, mut seen) = (Vec::new(), Vec::new(), HashSet::new());
    for e in entries {
        if !valid_name(&e.name) {
            skipped.push((e.name, "not a valid credential name"));
        } else if !seen.insert(e.name.clone()) {
            skipped.push((e.name, "appears more than once in the file"));
        } else if existing.contains(&e.name) && !overwrite {
            skipped.push((e.name, "already in kepr (use --overwrite)"));
        } else {
            keep.push(e);
        }
    }
    (keep, skipped)
}

fn store(e: &Entry, seal: bool) -> Result<bool, String> {
    let provider = seal
        .then(|| providers::detect(None, e.value.as_str()))
        .flatten();
    let req = Request::Set {
        name: e.name.clone(),
        value: Some(ZeroString::from_string(e.value.as_str().to_string())),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
        requires_fido2: None,
        sealed: provider.map(|_| true),
        bindings: provider.map(|p| vec![p.binding()]),
    };
    match client::send_request(&req)? {
        Response::SetOk { .. } => Ok(provider.is_some()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

pub fn cmd_import(file: &str, o: &Opts) -> Response {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => Zeroizing::new(t),
        Err(e) => return Response::fail(format!("{file}: {e}")),
    };
    let entries = match cli_import_parse::parse(o.format, file, &text) {
        Ok(e) => e,
        Err(e) => return Response::fail(e),
    };
    import_entries(entries, o, Some(file))
}

/// Plan, print, and (with --yes) store `entries`. `file` is the export
/// to remind the user to delete.
pub fn import_entries(mut entries: Vec<Entry>, o: &Opts, file: Option<&str>) -> Response {
    if let Some(p) = o.prefix {
        let p = cli_import_parse::kepr_name(p);
        for e in &mut entries {
            e.name = format!("{p}_{}", e.name);
        }
    }
    let (keep, skipped) = plan(entries, &existing_names(), o.overwrite);
    for e in &keep {
        let sealed = o.seal && providers::detect(None, e.value.as_str()).is_some();
        println!("{}{}", e.name, if sealed { "  (sealed)" } else { "" });
    }
    for (name, why) in &skipped {
        cli_ui::warn(&format!("skipping {name}: {why}"));
    }
    if keep.is_empty() {
        return Response::fail("nothing to import");
    }
    if !o.yes {
        cli_ui::info(&format!(
            "{} credential(s) to import; re-run with --yes",
            keep.len()
        ));
        return Response::Pong;
    }
    let (mut stored, mut sealed) = (0, 0);
    for e in &keep {
        match store(e, o.seal) {
            Ok(s) => {
                stored += 1;
                sealed += usize::from(s);
            }
            Err(err) => cli_ui::err(&format!("{}: {err}", e.name)),
        }
    }
    cli_ui::ok(&format!("imported {stored} credential(s), {sealed} sealed"));
    if let Some(file) = file {
        cli_ui::warn(&format!(
            "{file} holds every value in plain text; delete it (shred -u {file})"
        ));
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str) -> Entry {
        Entry {
            name: name.into(),
            value: ZeroString::from_string("v".into()),
        }
    }

    #[test]
    fn plan_skips_duplicates_existing_and_invalid() {
        let existing: HashSet<String> = ["OLD".to_string()].into();
        let (keep, skipped) = plan(vec![e("A"), e("A"), e("OLD"), e("")], &existing, false);
        assert_eq!(
            keep.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["A"]
        );
        assert_eq!(skipped.len(), 3);
        let (keep, _) = plan(vec![e("OLD")], &existing, true);
        assert_eq!(keep.len(), 1);
    }
}
