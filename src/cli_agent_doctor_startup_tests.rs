use super::*;

// Absolute /bin/sh plus shell builtins only: no installed gate, harness,
// vault, inherited environment, PATH lookup or network is used by these tests.
const PRELUDE: &str = r#"
printf '%s' "$$" > "$1"
[ "$2" = '--owner-pid' ] || exit 81
[ "$#" = 3 ] || exit 82
[ -z "${DOCTOR_TEST_INHERITED+x}" ] || exit 83
[ /proc/self/fd/2 -ef /dev/null ] || exit 84
[ -S /proc/self/fd/3 ] || exit 85
IFS= read -r config
case "$config" in
  *'"cred":"KEPR_DOCTOR_DIAGNOSTIC"'*) ;;
  *) exit 86 ;;
esac
"#;

fn exercise(script: &str, provider: &str, timeout: Duration) -> Result<(), String> {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &format!("{PRELUDE}\n{script}"), "doctor-test"])
        .arg(&pidfile)
        .env("DOCTOR_TEST_INHERITED", "synthetic-environment-marker");
    let result = run(&mut command, provider, timeout);
    let pid: i32 = std::fs::read_to_string(pidfile).unwrap().parse().unwrap();
    let mut status = 0;
    // A killed-but-unreaped child would return its PID here, and a live one
    // would return zero. ECHILD proves run() already reaped this exact child.
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let error = std::io::Error::last_os_error();
    if waited == 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }
    assert_eq!(waited, -1, "diagnostic left a live child or zombie");
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
    result
}

fn ready(provider: &str) -> String {
    format!(
        r#"printf '%s\n' '{{"ready":true,"port":12345,"placeholders":{{"{provider}":"diagnostic-placeholder"}}}}'
IFS= read -r hold <&3"#
    )
}

#[test]
fn diagnostic_configuration_is_valid_public_material() {
    for provider in ["anthropic", "xai"] {
        let config = diagnostic_config(provider);
        assert_eq!(config.session_id, "0".repeat(16));
        assert_eq!(config.session_key_hex.as_str(), "0".repeat(64));
        kepr_core::gate_protocol::validate_routes(&config.routes).unwrap();
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].provider, provider);
        assert_eq!(config.routes[0].cred, "KEPR_DOCTOR_DIAGNOSTIC");
        assert!(config.port.is_none());
        assert!(!config.tunnel && !config.record);
        assert!(config.rotation.is_none() && config.privacy.is_none());
    }
}

#[test]
fn consumes_stdin_to_eof_and_accepts_ready_then_reaps() {
    for provider in ["anthropic", "xai"] {
        exercise(&ready(provider), provider, Duration::from_secs(2)).unwrap();
    }
}

#[test]
fn timeout_is_bounded_and_reaps_the_child() {
    let started = Instant::now();
    let error = exercise(
        "IFS= read -r hold <&3",
        "anthropic",
        Duration::from_millis(500),
    )
    .unwrap_err();
    assert_eq!(error, "kepr-gate readiness timed out");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn malformed_ready_is_not_echoed_and_child_is_reaped() {
    let error = exercise(
        "printf '%s\\n' 'PRIVATE_CHILD_OUTPUT'; IFS= read -r hold <&3",
        "anthropic",
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error, "kepr-gate sent a malformed ready line");
    assert!(!error.contains("PRIVATE_CHILD_OUTPUT"));
}

#[test]
fn failed_child_is_reported_and_reaped() {
    assert_eq!(
        exercise("exit 70", "anthropic", Duration::from_secs(2)).unwrap_err(),
        "kepr-gate exited before reporting readiness"
    );
}

#[test]
fn gate_failure_reason_cannot_leak_child_output() {
    let error = exercise(
        r#"printf '%s\n' 'PRIVATE_STDERR_MARKER' >&2
printf '%s\n' '{"ready":false,"port":0,"placeholders":{},"error":"PRIVATE_SESSION_MARKER"}'
IFS= read -r hold <&3"#,
        "anthropic",
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error, "gate startup failed");
    assert!(!error.contains("PRIVATE_"));
}

#[test]
fn missing_route_confirmation_is_a_problem() {
    let error = exercise(&ready("xai"), "anthropic", Duration::from_secs(2)).unwrap_err();
    assert_eq!(error, "kepr-gate did not confirm the diagnostic route");
}

#[test]
fn missing_binary_does_not_disclose_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let error = run(
        &mut Command::new(dir.path().join("PRIVATE_PATH_MARKER")),
        "anthropic",
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(error.starts_with("cannot start kepr-gate ("));
    assert!(!error.contains("PRIVATE_PATH_MARKER"));
}
