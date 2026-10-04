//! Process setup for kepr-gate (T1.06): harden, read the session
//! config, watch the agent process, print the ready line, serve.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use kepr_core::gate_protocol::{ReadyLine, SessionConfig};
use zeroize::Zeroizing;

use crate::proxy::{self, Route, State};
use crate::vault::{Cache, FdResolver, DEFAULT_TTL};
use crate::{placeholder, routes};

const MAX_CONFIG: u64 = 64 * 1024;
const MAX_ROUTES: usize = 16;

/// Non-dumpable (blocks same-uid ptrace and makes /proc/PID/mem
/// root-owned) and no core files. Must run before any secret exists.
pub fn harden() -> Result<(), String> {
    // SAFETY: prctl/setrlimit with constant arguments; no pointers
    // other than a valid stack-local rlimit struct.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err("cannot make process non-dumpable".into());
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            return Err("cannot disable core dumps".into());
        }
    }
    Ok(())
}

pub fn parse_owner_pid(args: &[String]) -> Result<i32, String> {
    match args {
        [flag, pid] if flag == "--owner-pid" => pid
            .parse::<i32>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "invalid --owner-pid".to_string()),
        _ => Err("usage: kepr-gate --owner-pid PID (started by kepr-daemon)".into()),
    }
}

pub fn decode_key(hex_key: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(hex::decode(hex_key).map_err(|_| "session key is not hex")?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err("session key must be 32 bytes".into());
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn validate_config(cfg: &SessionConfig) -> Result<(), String> {
    if cfg.session_id.len() != 16 || !cfg.session_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("session id must be 16 hex chars".into());
    }
    if cfg.routes.is_empty() || cfg.routes.len() > MAX_ROUTES {
        return Err("1-16 routes required".into());
    }
    for r in &cfg.routes {
        if routes::lookup(&r.provider).is_none() {
            return Err(format!("unknown provider {}", r.provider));
        }
        if cfg
            .routes
            .iter()
            .filter(|o| o.provider == r.provider || o.slot == r.slot)
            .count()
            != 1
        {
            return Err("providers and slots must be unique".into());
        }
    }
    Ok(())
}

fn pidfd_open(pid: i32) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open takes a pid and flags; it returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err("owner process is not running".into());
    }
    // SAFETY: the syscall just returned this fd to us; we own it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn fd3_is_open() -> bool {
    // SAFETY: F_GETFD only reads the descriptor flags.
    unsafe { libc::fcntl(3, libc::F_GETFD) >= 0 }
}

pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let owner = pidfd_open(parse_owner_pid(&args)?)?;

    let mut raw = Zeroizing::new(String::new());
    std::io::stdin()
        .take(MAX_CONFIG)
        .read_to_string(&mut raw)
        .map_err(|e| format!("reading config: {e}"))?;
    let cfg: SessionConfig = serde_json::from_str(&raw).map_err(|_| "malformed session config")?;
    validate_config(&cfg)?;
    let key = decode_key(cfg.session_key_hex.as_str())?;
    if !fd3_is_open() {
        return Err("daemon channel (fd 3) missing".into());
    }
    let cache = Arc::new(Cache::new(Box::new(FdResolver::from_fd3()?), DEFAULT_TTL));

    let mut placeholders = HashMap::new();
    let mut table = HashMap::new();
    for r in &cfg.routes {
        placeholders.insert(
            r.cred.clone(),
            placeholder::make(&key, &cfg.session_id, r.slot),
        );
        table.insert(
            r.provider.clone(),
            Route {
                cred: r.cred.clone(),
                slot: r.slot,
            },
        );
    }
    let state = Arc::new(State::new(
        cfg.session_id.clone(),
        key,
        table,
        cache.clone(),
    ));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("bind: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("bind: {e}"))?
            .port();
        let ready = ReadyLine {
            ready: true,
            port,
            placeholders,
        };
        let mut out = std::io::stdout();
        writeln!(
            out,
            "{}",
            serde_json::to_string(&ready).map_err(|e| e.to_string())?
        )
        .and_then(|_| out.flush())
        .map_err(|e| format!("stdout: {e}"))?;

        tokio::spawn(async move {
            if let Ok(afd) = tokio::io::unix::AsyncFd::new(owner) {
                let _ = afd.readable().await;
            }
            cache.clear();
            std::process::exit(0);
        });
        proxy::serve(listener, state).await;
        Ok::<(), String>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::gate_protocol::GateRoute;
    use kepr_core::generate::ZeroString;

    fn cfg(routes: Vec<GateRoute>) -> SessionConfig {
        SessionConfig {
            session_id: "0123456789abcdef".into(),
            session_key_hex: ZeroString::from_string("00".repeat(32)),
            routes,
        }
    }

    fn route(p: &str, slot: u16) -> GateRoute {
        GateRoute {
            provider: p.into(),
            cred: "K".into(),
            slot,
        }
    }

    #[test]
    fn owner_pid_args() {
        assert_eq!(
            parse_owner_pid(&["--owner-pid".into(), "42".into()]),
            Ok(42)
        );
        assert!(parse_owner_pid(&["--owner-pid".into(), "0".into()]).is_err());
        assert!(parse_owner_pid(&[]).is_err());
    }

    #[test]
    fn key_decoding() {
        assert!(decode_key(&"ab".repeat(32)).is_ok());
        assert!(decode_key("abcd").is_err());
        assert!(decode_key(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn config_validation() {
        assert!(validate_config(&cfg(vec![route("anthropic", 0)])).is_ok());
        assert!(validate_config(&cfg(vec![])).is_err());
        assert!(validate_config(&cfg(vec![route("nope", 0)])).is_err());
        assert!(validate_config(&cfg(vec![route("anthropic", 0), route("xai", 0)])).is_err());
        assert!(validate_config(&cfg(vec![route("xai", 0), route("xai", 1)])).is_err());
        let mut bad = cfg(vec![route("xai", 0)]);
        bad.session_id = "xyz".into();
        assert!(validate_config(&bad).is_err());
    }
}
