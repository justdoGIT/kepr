// cli_syncx/ — CLI side of the `sync` ticket batch (registered in
// cli_more.rs). `src/sync.rs` keeps the `Syncer` trait, `pick_syncer`
// and `kepr sync-push` / `sync-pull`; the targets this batch adds live
// here:
//
//   json_file   T8.06  json:PATH#KEY
//   azure_kv    T8.05  azure-kv:VAULT/SECRET (AZURE_ACCESS_TOKEN)
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
pub mod json_file;
#[cfg(test)]
mod testserver;

use kepr_core::protocol::Response;

pub const VERBS: &[&str] = &[];

pub const HELP: &str = "\
  sync-push|sync-pull KEY --url azure-kv:VAULT/SECRET
                                       Azure Key Vault (token: AZURE_ACCESS_TOKEN, e.g. from
                                       az account get-access-token --resource https://vault.azure.net)
  sync-push|sync-pull KEY --url json:PATH#KEY
                                       one key (a.b = nested) of a JSON object file; written
                                       atomically at mode 0600, other keys kept
";

pub fn dispatch(verb: &str, _args: &[String]) -> Response {
    Response::fail(format!("unknown command: {verb}"))
}
