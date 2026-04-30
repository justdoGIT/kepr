// sync.rs — `kepr sync` framework. Pluggable cloud-backed
// credential push/pull.
//
// Phase 2 ζ (the cloud-sync milestone). The CLI lets a user
// stash a credential in a remote secret store (HashiCorp Vault
// today; AWS Secrets Manager and GCP Secret Manager land in
// follow-up PRs) or pull one back. The remote store is identified
// by a URL with a scheme:
//
//     vault:secret/team/db_pass     → HashiCorp Vault KV v2
//     aws-sm:my-prod-key            → AWS Secrets Manager (future)
//     gcp-sm:projects/foo/secrets/x → GCP Secret Manager (future)
//
// Why client-side: the daemon never sees the cloud credentials
// (VAULT_TOKEN, AWS_*, GOOGLE_APPLICATION_CREDENTIALS). The CLI
// fetches the value from the daemon over the existing socket,
// then pushes it upstream itself. This keeps the daemon's threat
// model narrow: it manages the local cred store, period. A
// compromised cloud-token never reaches the daemon.
//
// Why URL scheme dispatch: each backend's "address" is naturally
// a path inside its store. Folding the scheme into the URL keeps
// the CLI surface flat (`kepr sync push NAME URL` — one verb, no
// `--backend` flag matrix). The dispatcher matches the scheme,
// picks the right `Syncer` impl, and the rest is interface.

/// Strategy for pushing a value to / pulling a value from a
/// remote secret store. Implementations live in sibling modules
/// (`sync_vault.rs`, etc.); the dispatcher in `pick_syncer` maps
/// a scheme prefix to the right impl.
pub trait Syncer {
    /// Push `value` to the remote location identified at
    /// construction time. Idempotent — the remote store
    /// overwrites existing values at the same path. Returns
    /// `Err` only on transport / authn / authz failures.
    fn push(&self, value: &str) -> Result<(), String>;

    /// Pull the value from the remote location. Returns the raw
    /// secret string the cred store should now hold. Round-tripping
    /// the value through `push` then `pull` MUST yield the
    /// original bytes — pin via integration tests per backend.
    fn pull(&self) -> Result<String, String>;

    /// Human-readable name of the backing store. Surfaces in
    /// audit messages and CLI output (e.g. "vault" / "aws-sm").
    fn backend(&self) -> &'static str;
}

/// Pick the right `Syncer` for `url`. Returns `Err` for an
/// unrecognised scheme. The CLI calls this once per `kepr sync`
/// invocation; the resulting boxed trait object handles the
/// actual transport.
pub fn pick_syncer(url: &str) -> Result<Box<dyn Syncer>, String> {
    if let Some(path) = url.strip_prefix("vault:") {
        Ok(Box::new(crate::sync_vault::VaultSyncer::from_path(path)))
    } else if let Some(path) = url.strip_prefix("aws-sm:") {
        Ok(Box::new(crate::sync_aws_sm::AwsSmSyncer::from_path(path)))
    } else if let Some(path) = url.strip_prefix("gcp-sm:") {
        Ok(Box::new(crate::sync_gcp_sm::GcpSmSyncer::from_path(path)))
    } else {
        Err(format!(
            "unsupported sync scheme in {url:?} — supported: vault:, aws-sm:, gcp-sm:"
        ))
    }
}

/// Top-level handler for `kepr sync-push NAME --url …`. Fetches
/// the cred from the local daemon, then hands the value to the
/// chosen Syncer. The daemon never sees the cloud token; the
/// upstream cloud never sees the kepr master key. Both
/// boundaries stay clean.
pub fn cmd_sync_push(name: &str, url: &str) -> kepr_core::protocol::Response {
    use kepr_core::protocol::{Request, Response};
    let syncer = match pick_syncer(url) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let upper = name.to_uppercase();
    let resp = match crate::client::send_request(&Request::Get {
        name: upper.clone(),
    }) {
        Ok(r) => r,
        Err(e) => return Response::fail(format!("daemon: {e}")),
    };
    let value = match resp {
        Response::GetOk { value, .. } => value,
        Response::Err { error } => return Response::fail(error),
        other => return Response::fail(format!("unexpected response: {other:?}")),
    };
    if let Err(e) = syncer.push(value.as_str()) {
        return Response::fail(e);
    }
    Response::SetOk {
        name: upper,
        cred_name: format!("{}:{url}", syncer.backend()),
    }
}

/// Top-level handler for `kepr sync-pull NAME --url …`. Pulls
/// the value from the chosen Syncer, then sets it on the local
/// daemon. Existing local cred (if any) is overwritten — same
/// semantics as `kepr set --value`.
pub fn cmd_sync_pull(name: &str, url: &str) -> kepr_core::protocol::Response {
    use kepr_core::protocol::{Request, Response};
    let syncer = match pick_syncer(url) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let value = match syncer.pull() {
        Ok(v) => v,
        Err(e) => return Response::fail(e),
    };
    let upper = name.to_uppercase();
    let req = Request::Set {
        name: upper.clone(),
        value: Some(kepr_core::generate::ZeroString::from_string(value)),
        generate: None,
        ttl_secs: None,
        requires_consent: None,
    };
    match crate::client::send_request(&req) {
        Ok(r @ Response::SetOk { .. }) => r,
        Ok(Response::Err { error }) => Response::fail(error),
        Ok(other) => Response::fail(format!("unexpected response: {other:?}")),
        Err(e) => Response::fail(format!("daemon: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_syncer_dispatches_vault_scheme() {
        let s = pick_syncer("vault:secret/team/db_pass").unwrap();
        assert_eq!(s.backend(), "vault");
    }

    #[test]
    fn pick_syncer_dispatches_aws_sm_scheme() {
        let s = pick_syncer("aws-sm:prod/db/password").unwrap();
        assert_eq!(s.backend(), "aws-sm");
    }

    #[test]
    fn pick_syncer_dispatches_gcp_sm_scheme() {
        let s = pick_syncer("gcp-sm:projects/myproj/secrets/db_pass").unwrap();
        assert_eq!(s.backend(), "gcp-sm");
    }

    #[test]
    fn pick_syncer_rejects_unknown_scheme() {
        match pick_syncer("s3:bucket/key") {
            Err(e) => {
                assert!(e.contains("unsupported"), "msg: {e}");
                assert!(e.contains("vault"), "names known schemes: {e}");
                assert!(e.contains("aws-sm"), "names aws-sm: {e}");
                assert!(e.contains("gcp-sm"), "names gcp-sm: {e}");
            }
            Ok(_) => panic!("s3 scheme should have been rejected"),
        }
    }

    #[test]
    fn pick_syncer_rejects_missing_scheme() {
        match pick_syncer("just-a-path-no-scheme") {
            Err(e) => assert!(e.contains("unsupported"), "msg: {e}"),
            Ok(_) => panic!("schemeless URL should have been rejected"),
        }
    }
}
