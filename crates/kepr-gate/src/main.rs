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
mod cloudflare;
mod db;
mod dlp;
mod egress;
mod forward;
mod gcp_guard;
mod gcp_token;
mod git_http;
mod github_app;
mod journal;
mod kube;
mod limits;
mod mask;
mod mysql;
mod mysql_auth;
mod mysql_rotate;
mod pg;
mod pg_ephemeral;
mod pg_jit;
mod pg_rotate;
mod pg_tls;
mod placeholder;
mod prompt;
mod proxy;
mod recording;
mod redis;
mod reply;
mod responses;
mod rewrite;
mod rotate_provider;
mod routes;
mod scram;
mod secret_cell;
mod service;
mod session;
mod sigv4_resign;
mod tls_provider;
mod tunnel;
mod vault;

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    // T13.01: what this build offers first to upstream hosts (no session).
    if std::env::args().nth(1).as_deref() == Some("--tls-info") {
        println!("Gate TLS: {}", tls_provider::first_group());
        return ExitCode::SUCCESS;
    }
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
        Err(error) => {
            let reason = if error.starts_with("cannot listen on 127.0.0.1:") {
                "gate port bind failed"
            } else if error.starts_with("database listener:") {
                "database port bind failed"
            } else {
                "gate startup failed"
            };
            let report = kepr_core::gate_protocol::ReadyLine {
                ready: false,
                port: 0,
                placeholders: std::collections::HashMap::new(),
                ca_pem: None,
                db_ports: std::collections::HashMap::new(),
                error: Some(reason.into()),
            };
            if let Ok(line) = serde_json::to_string(&report) {
                let _ = writeln!(std::io::stdout(), "{line}");
            }
            eprintln!("kepr-gate: {reason}");
            ExitCode::from(70)
        }
    }
}
