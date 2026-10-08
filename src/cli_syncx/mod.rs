// cli_syncx/ — CLI side of the `sync` ticket batch (registered in
// cli_more.rs). `src/sync.rs` keeps the `Syncer` trait, `pick_syncer`
// and `kepr sync-push` / `sync-pull`; the targets this batch adds live
// here:
//
//   json_file   T8.06  json:PATH#KEY
//   azure_kv    T8.05  azure-kv:VAULT/SECRET (AZURE_ACCESS_TOKEN)
//   map         T11.17 kepr sync push --map FILE [--dry-run]
//   import      T11.17 kepr sync import --from SRC [--prefix P]
//   bundle      T6.09  kepr export --encrypted -o FILE; kepr import FILE
//                      (cli_import.rs hands a bundle file over here)
//   sync_now    T6.10  kepr sync remote add|ls|rm, kepr sync now
//   transport,  T6.10  where device bundles live: dir:, git:, s3:
//   s3
//
// Sync is client-side: the daemon never sees a cloud token and the
// cloud never sees kepr's master key. Sealed, SSH and share-key
// credentials are never pushed anywhere: the daemon refuses to return
// their values.

// The daemon's durable "replace this file" helper (temp file at the final
// mode, fsync, rename, fsync the directory), shared by file targets.
#[path = "../atomic_file.rs"]
mod atomic_file;
pub mod azure_kv;
mod bundle;
mod import;
pub mod json_file;
mod map;
mod s3;
mod sync_now;
#[cfg(test)]
mod testserver;
mod transport;

use kepr_core::protocol::Response;

/// Most pages any listing follows.
const MAX_PAGES: usize = 50;

pub use bundle::{cmd_import as import_bundle, is_bundle};

pub const VERBS: &[&str] = &["sync", "export"];

pub const HELP: &str = "\
  sync-push|sync-pull KEY --url azure-kv:VAULT/SECRET
                                       Azure Key Vault (token: AZURE_ACCESS_TOKEN, e.g. from
                                       az account get-access-token --resource https://vault.azure.net)
  sync-push|sync-pull KEY --url json:PATH#KEY
                                       one key (a.b = nested) of a JSON object file; written
                                       atomically at mode 0600, other keys kept
  sync push --map FILE [--dry-run]     push every KEY = \"SCHEME:PATH\" line of FILE; --dry-run
                                       prints create / update / unchanged (compared by hash)
  sync import --from SRC [--prefix P] [--name-prefix N] [--seal] [--overwrite] [--yes]
                                       import a remote store's secrets (SRC: aws-sm,
                                       gcp-sm:projects/P, vault:MOUNT[/PATH], azure-kv:VAULT,
                                       json:FILE); names only until --yes
  export --encrypted -o FILE           every credential `get` can read now (values, history,
                                       attachments) in a passphrase-encrypted bundle; sealed,
                                       SSH and gated ones are listed by name only
  import BUNDLE [--prefix P] [--overwrite] [--yes]
                                       open a bundle: create / update / unchanged per credential
  sync remote add|rm URL | sync remote ls
                                       where devices meet: dir:PATH, git:URL (git CLI) or
                                       s3:BUCKET[/PREFIX] (AWS_* env; KEPR_S3_ENDPOINT)
  sync now [--remote URL]              merge the other enrolled devices' bundles (newest change
                                       wins), then push this device's, encrypted to them
";

/// Refuse flags a subcommand doesn't know: a typo like `--dryrun` must
/// never turn a dry run into a real push.
fn check_flags(args: &[String], value_flags: &[&str], switches: &[&str]) -> Result<(), String> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if value_flags.contains(&a.as_str()) {
            skip = true;
        } else if a.starts_with('-') && !switches.contains(&a.as_str()) && a != "--json" {
            return Err(format!("unknown option {a}"));
        }
    }
    Ok(())
}

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "sync" => {}
        "export" => return bundle::cmd_export(args),
        _ => return Response::fail(format!("unknown command: {verb}")),
    }
    let rest = args.get(1..).unwrap_or_default();
    let r = match args.first().map(String::as_str) {
        Some("push") => check_flags(rest, &["--map"], &["--dry-run"]).map(|()| {
            match crate::cli_extra::flag(rest, "--map") {
                Some(map) => map::cmd_push_map(map, rest.iter().any(|a| a == "--dry-run")),
                None => Response::fail(
                    "usage: kepr sync push --map FILE [--dry-run] (one key: kepr sync-push KEY --url …)",
                ),
            }
        }),
        Some("import") => check_flags(
            rest,
            &["--from", "--prefix", "--name-prefix"],
            &["--seal", "--overwrite", "--yes"],
        )
        .map(|()| import::cmd_import(rest)),
        Some("remote") => Ok(sync_now::cmd_remote(rest)),
        Some("now") => check_flags(rest, &["--remote"], &[]).map(|()| sync_now::cmd_now(rest)),
        _ => Err("usage: kepr sync push --map FILE [--dry-run] | sync import --from SRC \
                  | sync remote add|ls|rm | sync now"
            .into()),
    };
    r.unwrap_or_else(Response::fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unknown_options_are_refused_before_anything_runs() {
        let r = dispatch("sync", &v(&["push", "--map", "m.toml", "--dryrun"]));
        assert_eq!(r.err_msg(), Some("unknown option --dryrun"));
        let r = dispatch("sync", &v(&["import", "--from", "aws-sm", "--force"]));
        assert_eq!(r.err_msg(), Some("unknown option --force"));
        assert!(check_flags(
            &v(&["--map", "--x", "--dry-run"]),
            &["--map"],
            &["--dry-run"]
        )
        .is_ok());
        assert!(dispatch("sync", &v(&["nope"]))
            .err_msg()
            .unwrap()
            .contains("usage"));
    }
}
