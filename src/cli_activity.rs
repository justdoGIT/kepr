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
/// and `kepr env` apply the same precedence (CLI > --manifest >
/// auto-discovery from $PWD) without each module re-implementing
/// the resolver call.
fn resolve_env_for(args: &Args) -> Result<Vec<String>, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("getcwd: {e}"))?;
    let (resolved, _used) =
        cli_manifest::resolve(&args.env_vars, args.manifest_path.as_deref(), &cwd)?;
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
            "exec" => "exec",
            "doctor" => "doctor",
            "env" => "env",
            "rotate" => "rotate",
            "audit-verify" => "audit-verify",
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
            "delete" => cli_cmds::cmd_delete(args),
            "check" => cli_cmds::cmd_check(args),
            "exec" => match resolve_env_for(args) {
                Ok(vars) => cli_exec::cmd_exec(&vars, &args.exec_argv),
                Err(e) => Response::fail(e),
            },
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
