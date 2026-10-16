//! kepr-gate — credential-injecting local proxy for agent sessions.
//!
//! Spawned only by kepr-daemon (`Request::StartGate`) with a cleared
//! environment, the session config on stdin, the private daemon channel
//! on fd 3 and `--owner-pid` naming the agent process. It prints one
//! ready line, then forwards provider API calls, replacing the session
//! placeholder with the real key. See docs/content/docs/agent-vault-plan.mdx.

mod aws_egress;
mod ca;
mod canary;
mod db;
mod dlp;
mod egress;
mod forward;
mod gcp_token;
mod git_http;
mod github_app;
mod journal;
mod limits;
mod mask;
mod mysql;
mod mysql_auth;
mod mysql_rotate;
mod pg;
mod pg_jit;
mod pg_rotate;
mod pg_tls;
mod placeholder;
mod proxy;
mod recording;
mod redis;
mod reply;
mod rewrite;
mod routes;
mod scram;
mod secret_cell;
mod service;
mod session;
mod sigv4_resign;
mod tls_provider;
mod tunnel;
mod vault;

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Err(e) = session::harden() {
        eprintln!("kepr-gate: {e}");
        return ExitCode::from(70);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((path, uid)) = service::parse_args(&args) {
        return match service::serve(&path, uid) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("kepr-gate: {e}");
                ExitCode::from(70)
            }
        };
    }
    match session::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kepr-gate: {e}");
            ExitCode::from(70)
        }
    }
}
