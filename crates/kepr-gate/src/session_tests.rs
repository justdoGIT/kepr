// Session confinement, bind failure and configuration regressions.
use super::*;
use kepr_core::gate_protocol::GateRoute;
use kepr_core::generate::ZeroString;

fn cfg(routes: Vec<GateRoute>) -> SessionConfig {
    SessionConfig {
        session_id: "0123456789abcdef".into(),
        session_key_hex: ZeroString::from_string("00".repeat(32)),
        routes,
        port: None,
        limits: Default::default(),
        tunnel: false,
        record: false,
    }
}

fn route(p: &str, slot: u16) -> GateRoute {
    GateRoute {
        provider: p.into(),
        cred: "K".into(),
        slot,
        target: None,
    }
}

#[test]
fn configured_port_conflict_is_a_bind_failure() {
    let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = occupied.local_addr().unwrap().port();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime.block_on(bind_gate(port)).unwrap_err();
    assert!(error.starts_with(&format!("cannot listen on 127.0.0.1:{port}:")));
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

/// `check`'s verdict in a forked child that ran `confine()` first:
/// 0 passed, 1 failed, 2 could not confine. A hang fails the test.
fn confined_child(check: impl FnOnce() -> bool) -> i32 {
    use std::time::{Duration, Instant};
    // SAFETY: the child confines itself, runs `check` and leaves with
    // _exit; glibc keeps malloc and NSS usable in a forked child.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let code = match confine() {
            Ok(()) => i32::from(!check()),
            Err(_) => 2,
        };
        // SAFETY: leave the child without the parent's destructors.
        unsafe { libc::_exit(code) };
    }
    let start = Instant::now();
    let mut status = 0;
    // SAFETY: waiting for (and if need be killing) our own child.
    while unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } != pid {
        if start.elapsed() > Duration::from_secs(30) {
            // SAFETY: signalling a child this test spawned.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            // SAFETY: waiting for a child this code forked or spawned.
            unsafe { libc::waitpid(pid, &mut status, 0) };
            panic!("the confined child hung");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(libc::WIFEXITED(status), "killed: status {status}");
    libc::WEXITSTATUS(status)
}

#[test]
fn a_confined_session_runs_threads_but_not_programs() {
    let code = confined_child(|| {
        // Threads start (clone, after clone3's ENOSYS): a runtime works.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build();
        let ran = rt
            .is_ok_and(|rt| rt.block_on(async { tokio::spawn(async { 7 }).await }).ok() == Some(7));
        let exec = std::process::Command::new("/bin/true").status();
        ran && exec.is_err()
    });
    assert_eq!(code, 0);
}

#[test]
fn gate_read_paths_never_include_home() {
    let paths = gate_read_paths();
    assert!(paths.contains(&PathBuf::from("/etc")), "{paths:?}");
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let home = home.filter(|h| h.parent().is_some()); // not `/`
    for p in &paths {
        for never in home.iter().map(PathBuf::as_path).chain([
            Path::new("/root"),
            Path::new("/home"),
            Path::new("/run/user"),
            Path::new("/var/lib/kepr"),
        ]) {
            assert!(
                !p.starts_with(never) && !never.starts_with(p),
                "{p:?} reaches {never:?}"
            );
        }
    }
    assert!(paths.iter().all(|p| p.exists() && p.is_absolute()));
}

#[test]
fn a_too_wide_resolver_directory_falls_back_to_the_file() {
    let never = [PathBuf::from("/run/user"), PathBuf::from("/root")];
    let pick = |conf: &str| resolver_path(Path::new(conf), &never);
    assert_eq!(
        pick("/run/systemd/resolve/stub-resolv.conf"),
        PathBuf::from("/run/systemd/resolve")
    );
    assert_eq!(pick("/run/resolv.conf"), PathBuf::from("/run/resolv.conf"));
    assert_eq!(pick("/resolv.conf"), PathBuf::from("/resolv.conf"));
    assert_eq!(pick("/etc/resolv.conf"), PathBuf::from("/etc"));
}

#[test]
fn a_confined_session_reads_system_files_and_resolves_names_only() {
    use std::net::ToSocketAddrs;
    let landlock = kepr_core::landlock::abi() > 0;
    let tmp = std::env::temp_dir().join(format!("kepr-gate-ll-{}", std::process::id()));
    std::fs::write(&tmp, "x").unwrap();
    // Name resolution needs the network; without it, check the rest.
    let dns = ("api.anthropic.com", 443).to_socket_addrs().is_ok();
    let code = confined_child(|| {
        let hosts = std::fs::metadata("/etc/hosts").is_err() || std::fs::read("/etc/hosts").is_ok();
        let other = std::fs::read(&tmp).map_err(|e| e.raw_os_error());
        let fenced = !landlock || other == Err(Some(libc::EACCES));
        let written = std::fs::write(std::env::temp_dir().join("kepr-gate-w"), "x");
        let unwritable = !landlock || written.is_err();
        let resolves = !dns || ("api.anthropic.com", 443).to_socket_addrs().is_ok();
        let local = ("localhost", 80).to_socket_addrs().is_ok();
        hosts && fenced && unwritable && resolves && local
    });
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(std::env::temp_dir().join("kepr-gate-w"));
    if !landlock {
        eprintln!("skip: this kernel has no Landlock (checked the filter only)");
    }
    assert_eq!(code, 0);
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
