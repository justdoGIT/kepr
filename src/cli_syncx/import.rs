// cli_syncx/import.rs — T11.17: `kepr sync import --from SRC
// [--prefix P] [--name-prefix N] [--seal] [--overwrite] [--yes]`.
//
// Lists the secrets of a remote store and imports them through
// `cli_import::import_entries` (names-only plan; nothing stored without
// --yes; existing names skipped unless --overwrite; --seal stores
// provider API keys write-only). Values are pulled only with --yes.
//
//   --from aws-sm                 every secret (ListSecrets)
//   --from gcp-sm:projects/P      every secret of project P
//   --from vault:MOUNT[/PATH]     KV v2 secrets below PATH (folders walked)
//   --from azure-kv:VAULT         every secret of the vault
//   --from json:FILE              every string in the file (dotted keys)
//
// --prefix keeps the secrets whose id starts with P and drops P from the
// local name: `prod/db/password` with `--prefix prod/` → DB_PASSWORD.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;

use crate::cli_import::{import_entries, Opts};
use crate::cli_import_parse::{kepr_name, Entry};

/// `(id, sync URL)` of every secret in `from` whose id starts with `prefix`.
pub fn list_source(from: &str, prefix: &str) -> Result<Vec<(String, String)>, String> {
    let (scheme, rest) = from.split_once(':').unwrap_or((from, ""));
    match scheme {
        "aws-sm" if rest.is_empty() => crate::sync_aws_sm::list(prefix),
        "aws-sm" => Err("--from aws-sm takes no path; use --prefix".into()),
        "gcp-sm" => crate::sync_gcp_sm::list(rest, prefix),
        "vault" if !rest.is_empty() => crate::sync_vault::list(rest, prefix),
        "azure-kv" if !rest.is_empty() => super::azure_kv::list(rest, prefix),
        "json" if !rest.is_empty() => super::json_file::list(rest, prefix),
        _ => Err(format!(
            "unsupported --from {from:?} — aws-sm, gcp-sm:projects/P, vault:MOUNT[/PATH], \
             azure-kv:VAULT, json:FILE"
        )),
    }
}

/// The local name for a remote id: `prefix` dropped, then the usual
/// import mapping (`prod/db-pass` → `PROD_DB_PASS`).
pub fn local_name(id: &str, prefix: &str) -> String {
    kepr_name(id.strip_prefix(prefix).unwrap_or(id))
}

/// Pulls one secret by its sync URL.
type Pull<'a> = &'a dyn Fn(&str) -> Result<String, String>;

/// The entries to import: names from the listing, values pulled only
/// when `pull` is set (a plan needs names alone).
pub fn entries(listed: Vec<(String, String)>, prefix: &str, pull: Option<Pull>) -> Vec<Entry> {
    let mut out = Vec::new();
    for (id, url) in listed {
        let name = local_name(&id, prefix);
        let value = match pull {
            None => ZeroString::from_string(String::new()),
            Some(f) => match f(&url) {
                Ok(v) => ZeroString::from_string(v),
                Err(e) => {
                    crate::cli_ui::warn(&format!("skipping {id}: {e}"));
                    continue;
                }
            },
        };
        out.push(Entry { name, value });
    }
    out
}

pub fn cmd_import(args: &[String]) -> Response {
    use crate::cli_extra::flag;
    let Some(from) = flag(args, "--from") else {
        return Response::fail("usage: kepr sync import --from SRC [--prefix P] [--yes]");
    };
    let prefix = flag(args, "--prefix").unwrap_or("");
    let has = |f: &str| args.iter().any(|a| a == f);
    let listed = match list_source(from, prefix) {
        Ok(l) if l.is_empty() => return Response::fail(format!("no secrets in {from} {prefix}")),
        Ok(l) => l,
        Err(e) => return Response::fail(e),
    };
    let pull = |url: &str| crate::sync::pick_syncer(url)?.pull();
    let pull: Pull = &pull;
    let yes = has("--yes");
    let entries = entries(listed, prefix, yes.then_some(pull));
    let opts = Opts {
        format: "",
        prefix: flag(args, "--name-prefix"),
        seal: has("--seal"),
        overwrite: has("--overwrite"),
        yes,
    };
    import_entries(entries, &opts, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_drop_the_prefix() {
        assert_eq!(local_name("prod/db/password", "prod/"), "DB_PASSWORD");
        assert_eq!(local_name("prod-api-key", ""), "PROD_API_KEY");
        assert_eq!(local_name("a.b", "a."), "B");
    }

    #[test]
    fn a_plan_lists_names_without_pulling() {
        let listed = vec![
            ("prod/db".to_string(), "aws-sm:prod/db".to_string()),
            ("prod/api".to_string(), "aws-sm:prod/api".to_string()),
        ];
        let e = entries(listed.clone(), "prod/", None);
        let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["DB", "API"]);
        assert!(e.iter().all(|e| e.value.as_str().is_empty()));

        let pull = |url: &str| -> Result<String, String> {
            match url {
                "aws-sm:prod/db" => Ok("v1".into()),
                _ => Err("HTTP 403 AccessDenied".into()),
            }
        };
        let e = entries(listed, "prod/", Some(&pull));
        assert_eq!(e.len(), 1, "an unreadable secret is skipped");
        assert_eq!((e[0].name.as_str(), e[0].value.as_str()), ("DB", "v1"));
    }

    #[test]
    fn sources_are_checked() {
        for bad in [
            "s3:bucket",
            "aws-sm:prod/",
            "vault:",
            "azure-kv:",
            "json:",
            "nope",
        ] {
            assert!(list_source(bad, "").is_err(), "{bad}");
        }
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("s.json");
        std::fs::write(&f, r#"{"prod":{"db":"x","api":"y"},"dev":{"db":"z"}}"#).unwrap();
        let got = list_source(&format!("json:{}", f.display()), "prod.").unwrap();
        let names: Vec<String> = got.iter().map(|(id, _)| local_name(id, "prod.")).collect();
        assert_eq!(names, ["API", "DB"]);
    }
}
