//! Credential-free exercise of the real gate's stdin/EOF, fd 3 and ready protocol.
//! No harness is launched, no daemon/vault is contacted and no request is proxied.

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kepr_core::gate_protocol::{GateRoute, SessionConfig};
use kepr_core::gate_startup::{read_ready, write_config};
use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

const READY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn check(harness: &str) -> Result<(), String> {
    let provider = match harness {
        "omp" => "anthropic",
        "grok" => "xai",
        _ => return Err("unsupported diagnostic harness".into()),
    };
    let binary = std::env::var_os("KEPR_GATE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_gate_bin(std::env::current_exe().ok().as_deref()));
    run(&mut Command::new(binary), provider, READY_TIMEOUT)
}

fn default_gate_bin(exe: Option<&Path>) -> PathBuf {
    exe.and_then(Path::parent)
        .map(|dir| dir.join("kepr-gate"))
        .filter(|path| {
            std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .unwrap_or_else(|| "/usr/local/bin/kepr-gate".into())
}

fn diagnostic_config(provider: &str) -> SessionConfig {
    SessionConfig {
        privacy: None,
        // Public diagnostic material, never a real session or credential.
        session_id: "0".repeat(16),
        session_key_hex: ZeroString::from_string("0".repeat(64)),
        routes: vec![GateRoute {
            provider: provider.into(),
            cred: "KEPR_DOCTOR_DIAGNOSTIC".into(),
            slot: 0,
            target: None,
        }],
        port: None,
        limits: Default::default(),
        tunnel: false,
        record: false,
        rotation: None,
    }
}

struct ProbeChild(Child);

impl Drop for ProbeChild {
    fn drop(&mut self) {
        // Readiness is the end of this diagnostic, including on success.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(command: &mut Command, provider: &str, timeout: Duration) -> Result<(), String> {
    let config = diagnostic_config(provider);
    let payload = Zeroizing::new(
        serde_json::to_vec(&config).map_err(|_| "cannot encode gate diagnostic config")?,
    );
    drop(config);
    let (_channel, gate_end) =
        UnixStream::pair().map_err(|_| "cannot create gate diagnostic channel")?;
    let fd = gate_end.as_raw_fd();
    command
        .arg("--owner-pid")
        .arg(std::process::id().to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Even a broken/replaced gate must not print session material.
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls before exec. gate_end remains
    // open until spawn returns; fd 3 is the private resolver channel, not
    // the config transport (which is stdin, closed after the JSON).
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ProbeChild(
        command
            .spawn()
            .map_err(|e| format!("cannot start kepr-gate ({})", e.kind()))?,
    );
    drop(gate_end);
    let deadline = Instant::now() + timeout;
    let stdin = child.0.stdin.take().ok_or("kepr-gate has no stdin")?;
    write_config(stdin, &payload, deadline)?;
    drop(payload);
    let stdout = child.0.stdout.take().ok_or("kepr-gate has no stdout")?;
    let ready = read_ready(stdout, deadline)?;
    if ready.privacy.is_some()
        || ready.placeholders.len() != 1
        || !ready
            .placeholders
            .get(provider)
            .is_some_and(|p| !p.is_empty())
        || ready.error.is_some()
    {
        return Err("kepr-gate did not confirm the diagnostic route".into());
    }
    match child.0.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err("kepr-gate exited during startup".into()),
        Err(_) => Err("cannot check kepr-gate startup status".into()),
    }
}

#[cfg(test)]
#[path = "cli_agent_doctor_startup_tests.rs"]
mod tests;
