// cli_rotate.rs — `kepr rotate NAME --hook ./script.sh`.
//
// Phase 2 γ. Atomic credential rotation: generate a new value,
// hand it to a user-supplied hook on stdin, commit only if the
// hook exits 0. The hook's job is to push the new value to whatever
// service owns the upstream truth — a database password change, a
// remote API key registration, a deploy-target secret update —
// and confirm by exit-code that the upstream now ACCEPTS the new
// value. Until then, the cred-store keeps the prior value, so a
// downstream `kepr get` never sees a rotation that hasn't actually
// taken effect upstream.
//
// Design contract:
//
//     1. Generate a fresh value via the existing GenKind path.
//     2. Run hook with value on stdin (NOT on argv — never on
//        argv: a process listing leaks the secret).
//     3. If hook exits 0 → call `set NAME --value <new>`. Atomic
//        commit, audited as a regular `set`.
//     4. If hook exits != 0 → return Err. Cred-store is untouched.
//
// This ordering is "validate-then-commit": the cred-store carries
// the new value only AFTER the hook proves the upstream accepts
// it. The reverse ordering (commit-then-rollback) would briefly
// expose the new value to any concurrent `kepr get` even when the
// hook ultimately fails. validate-first keeps the rotation
// invisible to readers until it's real.
//
// Stdin (not argv): a process listing (`ps`, `/proc/<pid>/cmdline`)
// is world-readable on most distros. Putting the new value on the
// hook's argv would leak it to every process that can `ps`. Stdin
// is the only channel that's confined to the parent-child pair.
// This matches the roadmap text and the established pattern in
// `kepr exec` for env-var provisioning.
//
// Testability: `rotate_with_hook` takes a `HookRunner` trait so
// unit tests can inject a mock that records the value it was
// fed and returns a configured exit-code outcome. Production code
// uses `ProcessHookRunner` which spawns the actual hook script.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kepr_core::generate::{generate_secret, GenKind, ZeroString};
use kepr_core::protocol::{Request, Response};

use crate::client;

/// Strategy for invoking the user's hook with a candidate new
/// secret on stdin. Production code spawns a real subprocess;
/// tests inject a mock so the orchestration can be exercised
/// without forking.
pub trait HookRunner {
    /// Run the hook with `value` written to stdin. Returns Ok on
    /// hook exit 0; Err with a human-readable message on any
    /// other exit code or spawn failure.
    fn run(&self, value: &str) -> Result<(), String>;
}

/// Production runner: spawns `hook_path` as a child process,
/// pipes the candidate value into its stdin, waits for the
/// status code. Stdout and stderr inherit from the parent so the
/// user sees the hook's diagnostics in real time.
pub struct ProcessHookRunner {
    pub hook_path: PathBuf,
}

impl HookRunner for ProcessHookRunner {
    fn run(&self, value: &str) -> Result<(), String> {
        let mut child = Command::new(&self.hook_path)
            .stdin(Stdio::piped())
            // stdout/stderr inherited so the user sees hook
            // logs immediately. The hook is the integration
            // surface to whatever upstream service; its messages
            // are the user's only feedback during a rotation.
            .spawn()
            .map_err(|e| format!("spawn hook {}: {e}", self.hook_path.display()))?;

        // Take stdin, write the value, drop stdin to send EOF.
        // The hook should treat its stdin as the entire secret
        // and not care about stream framing — the daemon's wire
        // contract enforces that secrets are opaque blobs.
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or("hook stdin handle missing (shouldn't happen)")?;
            stdin
                .write_all(value.as_bytes())
                .map_err(|e| format!("write hook stdin: {e}"))?;
            // Explicit drop closes stdin, signalling EOF to the
            // hook. Without this the hook may block on read.
        }
        // child.stdin is dropped at end of scope above ↑

        let status = child.wait().map_err(|e| format!("wait for hook: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "hook exited with status {} — credential not rotated",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "<signal>".to_string())
            ))
        }
    }
}

/// Outcome of a successful set: the daemon-supplied `cred_name`
/// (e.g. `kepr-1000-stripe-key`). Surfaced through the Setter
/// trait so `cmd_rotate` can return a real cred_name in its
/// `Response::SetOk` instead of a synthetic placeholder. Wire
/// shape consumers (`--json` mode) get the same field they'd see
/// from a regular `kepr set`.
pub type SetOutcome = Result<String, String>;

/// Function alias for the cred-set step. Production wires this
/// to `client::send_request(Request::Set { … })`; tests substitute
/// a closure that records what it was asked to commit. Returns
/// the cred_name on success so `cmd_rotate` can faithfully
/// propagate the daemon's view of the canonical on-disk name.
pub type Setter = Box<dyn FnOnce(&str, ZeroString) -> SetOutcome>;

/// Generate a fresh value of `kind`, run the hook with it, and
/// commit it via `set` only if the hook exits 0. Returns the
/// daemon-supplied cred_name on success. Public for tests;
/// production wraps it as `cmd_rotate`.
pub fn rotate_with_hook<H: HookRunner>(
    name: &str,
    kind: GenKind,
    hook: &H,
    set: Setter,
) -> Result<(String, String), String> {
    if name.is_empty() {
        return Err("rotate requires a credential name".to_string());
    }
    let new_value = generate_secret(kind);

    // Hook gets the candidate value. If it returns Err, we
    // return Err — the cred-store is NEVER touched.
    hook.run(new_value.as_str())?;

    // Hook accepted. Commit by calling the supplied setter
    // with a fresh ZeroString carrying the same bytes. The
    // setter wires through Request::Set, which audit-logs as a
    // regular `set` op (a future PR may add `Request::Rotate`
    // for distinct audit semantics; for now we lean on `set`).
    let upper = name.to_uppercase();
    let cred_name = set(&upper, new_value)?;
    Ok((upper, cred_name))
}

/// Top-level handler. Returns `Response::SetOk` on success
/// (matching the wire shape of a regular set), `Response::Err`
/// otherwise. Mirrors the existing CLI Response contract so
/// `--json` mode and exit-code mapping work without special-casing.
pub fn cmd_rotate(name: &str, kind: GenKind, hook_path: &Path) -> Response {
    if !hook_path.exists() {
        return Response::fail(format!(
            "hook not found: {} — pass an absolute path or one relative to $PWD",
            hook_path.display()
        ));
    }
    let runner = ProcessHookRunner {
        hook_path: hook_path.to_path_buf(),
    };
    let setter: Setter = Box::new(|name: &str, value: ZeroString| {
        match client::send_request(&Request::Set {
            name: name.to_string(),
            value: Some(value),
            generate: None,
            ttl_secs: None,
        }) {
            Ok(Response::SetOk { cred_name, .. }) => Ok(cred_name),
            Ok(Response::Err { error }) => Err(error),
            Ok(other) => Err(format!("unexpected daemon response: {other:?}")),
            Err(e) => Err(format!("daemon unreachable: {e}")),
        }
    });
    match rotate_with_hook(name, kind, &runner, setter) {
        Ok((committed, cred_name)) => Response::SetOk {
            name: committed,
            cred_name,
        },
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// In-memory hook runner. Captures the value it was given
    /// (for assertion) and returns a pre-configured outcome.
    struct MockHook {
        result: Result<(), String>,
        captured: Rc<RefCell<Option<String>>>,
    }
    impl HookRunner for MockHook {
        fn run(&self, value: &str) -> Result<(), String> {
            *self.captured.borrow_mut() = Some(value.to_string());
            self.result.clone()
        }
    }

    fn make_setter(committed: Rc<RefCell<Option<String>>>) -> Setter {
        // Return a synthetic cred_name so the SetOutcome shape is
        // exercised; tests that care only about the value compare
        // through the `committed` cell and ignore the cred_name.
        Box::new(move |name: &str, v: ZeroString| {
            *committed.borrow_mut() = Some(v.as_str().to_string());
            Ok(format!("kepr-1000-{}", name.to_lowercase()))
        })
    }

    #[test]
    fn happy_path_commits_when_hook_succeeds() {
        let captured = Rc::new(RefCell::new(None));
        let committed = Rc::new(RefCell::new(None));
        let hook = MockHook {
            result: Ok(()),
            captured: captured.clone(),
        };
        let setter = make_setter(committed.clone());
        let (name, cred_name) = rotate_with_hook("FOO", GenKind::Hex, &hook, setter).unwrap();
        assert_eq!(name, "FOO");
        assert!(
            cred_name.starts_with("kepr-"),
            "daemon-supplied cred_name propagates: {cred_name}"
        );
        // Hook saw the same value the setter committed — pin
        // that the value the upstream sees is exactly the value
        // the cred-store ends up holding.
        let h = captured.borrow().clone().expect("hook ran");
        let c = committed.borrow().clone().expect("setter ran");
        assert_eq!(h, c, "hook input must match committed value");
        assert_eq!(c.len(), 64, "hex GenKind produces 64-char output");
    }

    #[test]
    fn hook_failure_skips_setter() {
        // Critical contract: a non-zero hook exit MUST NOT touch
        // the cred-store. Validate by injecting a setter that
        // would record any call, and asserting nothing was
        // recorded.
        let captured = Rc::new(RefCell::new(None));
        let committed = Rc::new(RefCell::new(None));
        let hook = MockHook {
            result: Err("hook exited with status 1".into()),
            captured: captured.clone(),
        };
        let setter = make_setter(committed.clone());
        let err = rotate_with_hook("FOO", GenKind::Hex, &hook, setter)
            .expect_err("hook failure must propagate");
        assert!(
            err.contains("status 1"),
            "preserves hook's error message: {err}"
        );
        // Hook was called (it's the validation step).
        assert!(captured.borrow().is_some(), "hook ran");
        // Setter was NEVER called.
        assert!(
            committed.borrow().is_none(),
            "setter must not run on hook failure"
        );
    }

    #[test]
    fn empty_name_rejected_before_hook_runs() {
        // Don't waste a hook invocation on a request the daemon
        // would reject anyway. Cheaper to fail fast.
        let captured = Rc::new(RefCell::new(None));
        let committed = Rc::new(RefCell::new(None));
        let hook = MockHook {
            result: Ok(()),
            captured: captured.clone(),
        };
        let setter = make_setter(committed);
        let err = rotate_with_hook("", GenKind::Hex, &hook, setter).expect_err("empty name");
        assert!(err.contains("name"), "names the issue: {err}");
        assert!(captured.borrow().is_none(), "hook not invoked");
    }

    #[test]
    fn name_uppercased_before_setter() {
        // The daemon already re-uppercases, but the hook should
        // see the canonical form too — a hook that logs which
        // cred is rotating shouldn't render `Foo` differently
        // from `FOO`. Pin the contract.
        let captured = Rc::new(RefCell::new(None));
        let committed = Rc::new(RefCell::new(None));
        let hook = MockHook {
            result: Ok(()),
            captured: captured.clone(),
        };
        // Custom setter that records the NAME it was passed.
        let name_seen: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let name_seen_clone = name_seen.clone();
        let setter: Setter = Box::new(move |name: &str, _v: ZeroString| {
            *name_seen_clone.borrow_mut() = Some(name.to_string());
            *committed.borrow_mut() = Some(_v.as_str().to_string());
            Ok(format!("kepr-1000-{}", name.to_lowercase()))
        });
        rotate_with_hook("foo", GenKind::Hex, &hook, setter).unwrap();
        assert_eq!(name_seen.borrow().clone(), Some("FOO".to_string()));
    }

    #[test]
    fn setter_failure_propagates() {
        let captured = Rc::new(RefCell::new(None));
        let hook = MockHook {
            result: Ok(()),
            captured: captured.clone(),
        };
        let setter: Setter = Box::new(|_n, _v| Err("daemon unreachable".to_string()));
        let err = rotate_with_hook("FOO", GenKind::Hex, &hook, setter).expect_err("setter failure");
        assert!(err.contains("daemon unreachable"), "preserves: {err}");
    }

    #[test]
    fn process_hook_runner_returns_err_when_hook_missing() {
        // Smoke test the production runner without an actual
        // hook: spawn /nonexistent and assert we get a sensible
        // error rather than a panic. A real test against a real
        // hook lives in tests/e2e.sh.
        let runner = ProcessHookRunner {
            hook_path: PathBuf::from("/nonexistent/path/to/hook"),
        };
        let err = runner.run("anything").expect_err("missing hook fails");
        assert!(err.contains("spawn hook"), "names the failure: {err}");
    }

    #[test]
    fn cmd_rotate_rejects_missing_hook_before_generation() {
        // The top-level handler does an existence check before
        // generating a value, since generation pulls from
        // /dev/urandom and we'd rather not spend entropy on a
        // doomed call.
        let resp = cmd_rotate("FOO", GenKind::Hex, Path::new("/nonexistent/hook"));
        match resp {
            Response::Err { error } => {
                assert!(error.contains("hook not found"), "msg: {error}");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }
}
