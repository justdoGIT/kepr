// cli_activity.rs — newtype wrapping the CLI subcommand the user invoked.
//
// The Rust "newtype" pattern (`struct Foo(T);`) turns a bare string into a
// distinct type that can only be produced by CliActivity::parse. The parse
// step enforces the verb-alias mapping (`ls`→list, `rm`→delete) and rejects
// unknown verbs, so downstream code sees exactly one of the five canonical
// activities and dispatch can rely on that invariant.

use crate::cli_args::Args;
use crate::cli_cmds;
use crate::cli_doctor;
use crate::cli_envdump;
use crate::cli_exec;
use crate::cli_manifest;
use crate::cli_rotate;
use kepr_core::protocol::Response;

/// Resolve `(env_vars, manifest_path)` into the effective list of
/// credentials for this invocation. Centralised here so `kepr exec`
/// and `kepr env` apply the same safe precedence (CLI > --manifest).
/// Ancestor discovery is available only with `KEPR_AUTO_MANIFEST=1`.
fn resolve_env_for(args: &Args) -> Result<Vec<String>, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("getcwd: {e}"))?;
    let resolver = if std::env::var("KEPR_AUTO_MANIFEST").as_deref() == Ok("1") {
        cli_manifest::resolve_with_auto_discovery
    } else {
        cli_manifest::resolve
    };
    let (resolved, _used) = resolver(&args.env_vars, args.manifest_path.as_deref(), &cwd)?;
    Ok(resolved)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliActivity(String);

impl CliActivity {
    /// Parse a user-supplied verb, resolving aliases to the canonical form.
    pub fn parse(s: &str) -> Result<Self, String> {
        let canonical = match s {
            "set" => "set",
            "get" => "get",
            "list" | "ls" => "list",
            "delete" | "rm" => "delete",
            "check" => "check",
            "lock" => "lock",
            "unlock" => "unlock",
            "status" => "status",
            "exec" => "exec",
            "doctor" => "doctor",
            "env" => "env",
            "rotate" => "rotate",
            "audit-verify" => "audit-verify",
            "sync-push" => "sync-push",
            "sync-pull" => "sync-pull",
            "fido2-register" => "fido2-register",
            "fido2-list" => "fido2-list",
            "protect-agent" => "protect-agent",
            "panic" => "panic",
            "mcp" => "mcp",
            other => return Err(format!("unknown command: {other}")),
        };
        Ok(Self(canonical.to_string()))
    }

    /// Canonical verb string — by construction one of the five built-in
    /// commands.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Route this activity to its CLI handler. Relies on the type invariant
    /// that `self.0` is always a known verb: the `_` arm is unreachable.
    pub fn dispatch(&self, args: &Args) -> Response {
        match self.as_str() {
            "set" => cli_cmds::cmd_set(args),
            "get" => cli_cmds::cmd_get(args),
            "list" => cli_cmds::cmd_list(args),
            "delete" => crate::cli_store::cmd_delete(args), // T11.2: trash / --force
            "check" => cli_cmds::cmd_check(args),
            "lock" => cli_cmds::cmd_lock(args),
            "unlock" => cli_cmds::cmd_unlock(args),
            "status" => cli_cmds::cmd_status(args),
            "exec" => match resolve_env_for(args) {
                Ok(vars) => cli_exec::cmd_exec(&vars, &args.memfd_vars, &args.exec_argv, args.mask),
                Err(e) => Response::fail(e),
            },
            "doctor" if args.store.verify => crate::cli_store::cmd_verify(args.json), // T11.10
            "doctor" => cli_doctor::cmd_doctor(args.json),
            "env" => match resolve_env_for(args) {
                Ok(vars) => cli_envdump::cmd_env(&vars),
                Err(e) => Response::fail(e),
            },
            "rotate" => match (&args.name, &args.hook_path) {
                (Some(n), Some(h)) => cli_rotate::cmd_rotate(n, args.gen_kind, h),
                (None, _) => Response::fail("rotate requires NAME"),
                (_, None) => Response::fail("rotate requires --hook PATH"),
            },
            "audit-verify" => cli_cmds::cmd_audit_verify(args),
            "sync-push" => match (&args.name, &args.url) {
                (Some(n), Some(u)) => crate::sync::cmd_sync_push(n, u),
                (None, _) => Response::fail("sync-push requires NAME"),
                (_, None) => Response::fail("sync-push requires --url"),
            },
            "sync-pull" => match (&args.name, &args.url) {
                (Some(n), Some(u)) => crate::sync::cmd_sync_pull(n, u),
                (None, _) => Response::fail("sync-pull requires NAME"),
                (_, None) => Response::fail("sync-pull requires --url"),
            },
            "fido2-register" => cli_cmds::cmd_fido2_register(args),
            "fido2-list" => cli_cmds::cmd_fido2_list(args),
            "protect-agent" => Response::fail(
                "`kepr protect-agent` was retired (it exposed the key to every tool the agent ran); \
                 use `kepr agent add NAME` and `kepr agent run <harness>`",
            ),
            "panic" => crate::cli_agent_cmd::cmd_panic(),
            "mcp" => crate::cli_mcp::cmd_mcp(),
            _ => unreachable!("CliActivity invariant broken: parse() only emits known verbs"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_canonical_verbs() {
        for v in [
            "set",
            "get",
            "list",
            "delete",
            "check",
            "exec",
            "doctor",
            "env",
            "rotate",
            "audit-verify",
            "sync-push",
            "sync-pull",
            "fido2-register",
            "fido2-list",
        ] {
            assert_eq!(CliActivity::parse(v).unwrap().as_str(), v);
        }
    }

    #[test]
    fn parse_resolves_aliases() {
        assert_eq!(CliActivity::parse("ls").unwrap().as_str(), "list");
        assert_eq!(CliActivity::parse("rm").unwrap().as_str(), "delete");
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(CliActivity::parse("zzz").is_err());
        assert!(CliActivity::parse("").is_err());
    }
}
