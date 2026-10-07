// cli_recordsx/refs.rs — T5.06: `kepr://` references outside templates.
//
//   kepr exec --env DB_URL=kepr://DB/url,API_KEY -- cmd   (also kepr env, --memfd)
//   .kepr.toml  [env.map]  DB_URL = "kepr://DB/url"      (cli_manifest.rs)
//   kepr resolve kepr://NAME/...                          print what it stands for
//
// An `--env` entry is either a credential NAME (exported as $NAME, as
// before) or `VAR=kepr://…`. A comma inside a reference is written `\,`.
// Every value still comes from the daemon's `Get` / `AttachGet`, so a
// sealed credential is refused here exactly as by `kepr get`.

use std::io::Write;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use zeroize::Zeroizing;

use super::notation::{self, Sel};
use super::resolve::{self, Source};
use crate::cli_exec::CredFetcher;

/// A `CredFetcher` as a `Source`; attachments come from the daemon.
pub struct Fetched<'a, F: CredFetcher>(pub &'a F);

impl<F: CredFetcher> Source for Fetched<'_, F> {
    fn value(&self, name: &str) -> Result<ZeroString, String> {
        self.0.fetch(name)
    }
    fn file(&self, name: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        super::attach::download(name, file)
    }
}

/// An environment variable name: [A-Za-z_][A-Za-z0-9_]*.
pub fn valid_var(v: &str) -> bool {
    let mut b = v.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Split an `--env` list on commas, except escaped ones (`\,` stays in
/// the entry; the notation parser unescapes it).
pub fn split_entries(csv: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = csv.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push(c);
                cur.extend(chars.next());
            }
            ',' => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// The variable and notation of a `VAR=kepr://…` entry; `None` for a
/// plain credential name.
fn split_ref(entry: &str) -> Result<Option<(&str, notation::Notation)>, String> {
    let Some((var, r)) = entry.split_once('=') else {
        return Ok(None);
    };
    if !valid_var(var) {
        return Err(format!(
            "{var:?}: an environment variable name is A-Z, a-z, 0-9 and _"
        ));
    }
    Ok(Some((var, notation::parse(r)?)))
}

/// Check an entry without fetching anything (manifest load).
pub fn check_entry(entry: &str) -> Result<(), String> {
    split_ref(entry).map(|_| ())
}

/// `(variable, value)` for one entry: `NAME` (upper-cased) or
/// `VAR=kepr://…`.
pub fn entry(entry: &str, src: &dyn Source) -> Result<(String, ZeroString), String> {
    match split_ref(entry)? {
        None => {
            let upper = entry.to_uppercase();
            let v = src
                .value(&upper)
                .map_err(|e| format!("cannot resolve {upper}: {e}"))?;
            Ok((upper, v))
        }
        Some((var, n)) => {
            let v = resolve::resolve(&n, src).map_err(|e| {
                let r = &entry[var.len() + 1..];
                format!("cannot resolve {var} ({r}): {e}")
            })?;
            Ok((var.to_string(), v))
        }
    }
}

/// Every entry, in order, with one fetch per credential (a gated record
/// named by several references prompts once).
pub fn entries<F: CredFetcher>(
    vars: &[String],
    fetcher: &F,
) -> Result<Vec<(String, ZeroString)>, String> {
    let fetched = Fetched(fetcher);
    let src = resolve::Cached::new(&fetched);
    vars.iter().map(|v| entry(v, &src)).collect()
}

/// `kepr resolve kepr://…`: print the value (an attachment: its bytes).
pub fn cmd_resolve(args: &[String]) -> Response {
    let [text] = args else {
        return Response::fail(
            "usage: kepr resolve kepr://NAME[/field[i][sub] | /custom_field/LABEL | /file/FILE]",
        );
    };
    match resolve_to(text, &resolve::Daemon, &mut std::io::stdout()) {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(e),
    }
}

fn resolve_to(text: &str, src: &dyn Source, out: &mut dyn Write) -> Result<(), String> {
    let n = notation::parse(text)?;
    let written = match &n.sel {
        Sel::File(f) => out.write_all(&src.file(&n.name, f)?),
        _ => {
            let v = resolve::resolve(&n, src)?;
            out.write_all(v.as_bytes())
                .and_then(|()| out.write_all(b"\n"))
        }
    };
    written.map_err(|e| format!("write: {e}"))
}

#[cfg(test)]
mod tests {
    use super::super::resolve::tests::fixture;
    use super::*;

    #[test]
    fn env_entries_are_names_or_references() {
        let src = fixture();
        let (k, v) = entry("u=kepr://R/url[1]", &src).unwrap();
        assert_eq!((k.as_str(), v.as_str()), ("u", "https://b.example"));
        let (k, v) = entry("plain", &src).unwrap();
        assert_eq!((k.as_str(), v.as_str()), ("PLAIN", "https://x"));
        let (_, v) = entry(r"Q=kepr://R/custom_field/Q\/A \[1\]", &src).unwrap();
        assert_eq!(v.as_str(), "answer");
        for (bad, what) in [
            ("1X=kepr://R", "environment variable"),
            ("X=R/url", "starts with kepr://"),
            ("X=kepr://R/url[", "column 13"),
            (
                "X=kepr://R/nope",
                "cannot resolve X (kepr://R/nope): no field",
            ),
            ("NOPE", "cannot resolve NOPE"),
        ] {
            let e = entry(bad, &src).unwrap_err();
            assert!(e.contains(what), "{bad}: {e}");
        }
        assert!(check_entry("X=kepr://R/url[1]").is_ok() && check_entry("X=y").is_err());
    }

    #[test]
    fn escaped_commas_stay_in_the_entry() {
        assert_eq!(
            split_entries(r"A,B=kepr://R/custom_field/x\,y,C"),
            ["A", r"B=kepr://R/custom_field/x\,y", "C"]
        );
        assert_eq!(split_entries("A"), ["A"]);
        assert_eq!(split_entries("A,"), ["A", ""]);
        let n = notation::parse(r"kepr://R/custom_field/x\,y").unwrap();
        assert!(matches!(n.sel, Sel::Custom { ref label, .. } if label == "x,y"));
    }

    #[test]
    fn resolve_prints_values_and_raw_files_and_refuses_what_get_refuses() {
        let src = fixture();
        let mut out = Vec::new();
        resolve_to("kepr://R/phone[0][number]", &src, &mut out).unwrap();
        resolve_to("kepr://R/file/key.bin", &src, &mut out).unwrap();
        assert_eq!(out, b"111\n\xff\xfe\0");
        // A sealed credential: the daemon's Get refuses it, generically.
        let mut out = Vec::new();
        let e = resolve_to("kepr://SEALED/password", &src, &mut out).unwrap_err();
        assert_eq!(e, "credential unavailable");
        assert!(out.is_empty());
        assert!(resolve_to("R/url", &src, &mut out).is_err());
    }
}
