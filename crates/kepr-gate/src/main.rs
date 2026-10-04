//! kepr-gate — credential-injecting local proxy for agent sessions.
//!
//! Spawned only by kepr-daemon (`Request::StartGate`) with a cleared
//! environment, the session config on stdin, the private daemon channel
//! on fd 3 and `--owner-pid` naming the agent process. It prints one
//! ready line, then forwards provider API calls, replacing the session
//! placeholder with the real key. See docs/content/docs/agent-vault-plan.mdx.

mod dlp;
mod journal;
mod limits;
mod placeholder;
mod proxy;
mod rewrite;
mod routes;
mod session;
mod vault;

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = session::harden() {
        eprintln!("kepr-gate: {e}");
        return ExitCode::from(70);
    }
    match session::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kepr-gate: {e}");
            ExitCode::from(70)
        }
    }
}
