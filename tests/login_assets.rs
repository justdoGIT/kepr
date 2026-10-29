// login_assets.rs — pin the files unlock-at-login ships (T13.25): the user
// units, the Debian pam-auth-update profile and what install.sh --login
// installs. None of this runs in the test suite (it needs a user manager and
// root), so a rename or an edit that breaks the wiring fails here instead.

use std::fs;
use std::path::PathBuf;

fn text(rel: &str) -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The non-comment lines of a unit or profile.
fn directives(rel: &str) -> Vec<String> {
    text(rel)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn has(lines: &[String], want: &str) -> bool {
    lines.iter().any(|l| l == want)
}

#[test]
fn the_user_daemon_unit_tells_the_daemon_a_login_unlock_may_come() {
    let u = directives("systemd/user/kepr-daemon.service");
    // `--login` is what opens the start-up wait (daemon_session/unlock_wait.rs).
    assert!(has(
        &u,
        "ExecStart=/usr/local/bin/kepr-daemon --user --login"
    ));
    assert!(has(&u, "WantedBy=default.target"));
    assert!(has(&u, "Restart=on-failure"));
    for d in ["NoNewPrivileges=yes", "LimitCORE=0", "UMask=0077"] {
        assert!(has(&u, d), "kepr-daemon.service lost {d}");
    }
    // Its children are the user's own tools: no filter that would break them.
    for bad in [
        "MemoryDenyWriteExecute",
        "SystemCallFilter",
        "ProtectSystem",
        "User=",
    ] {
        assert!(
            !u.iter().any(|l| l.starts_with(bad)),
            "kepr-daemon.service must not set {bad}"
        );
    }
}

#[test]
fn the_ssh_agent_unit_uses_the_socket_kepr_ssh_agent_defaults_to() {
    let u = directives("systemd/user/kepr-ssh-agent.service");
    assert!(has(
        &u,
        "ExecStart=/usr/local/bin/kepr ssh-agent --foreground --socket %t/kepr-ssh-agent.sock"
    ));
    assert!(has(&u, "After=kepr-daemon.service"));
    assert!(has(&u, "WantedBy=default.target"));
    // `%t` is $XDG_RUNTIME_DIR: the file name `kepr ssh-agent` picks itself
    // (cli_ssh_agent::default_socket) and `kepr login-unlock` exports.
    assert!(text("src/cli_ssh_agent.rs").contains("\"kepr-ssh-agent.sock\""));
    assert!(text("src/cli_session/login_unlock.rs")
        .contains("SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/kepr-ssh-agent.sock"));
    // The units `kepr login-unlock` enables are the ones shipped.
    let lu = text("src/cli_session/login_unlock.rs");
    assert!(lu.contains("\"kepr-daemon.service\"") && lu.contains("\"kepr-ssh-agent.service\""));
}

#[test]
fn the_debian_profile_never_lets_kepr_decide_a_login() {
    let p = directives("packaging/pam-configs/kepr");
    // Additional, optional: reached only after the password was checked,
    // and a missing or failing module is ignored.
    for d in [
        "Auth-Type: Additional",
        "Password-Type: Additional",
        "Session-Type: Additional",
    ] {
        assert!(has(&p, d), "profile lost {d}");
    }
    let module_lines: Vec<&String> = p.iter().filter(|l| l.contains("pam_kepr.so")).collect();
    assert_eq!(module_lines.len(), 3, "auth, password and session");
    for l in module_lines {
        assert!(l.starts_with("optional"), "{l} must be optional");
    }
    // Interactive sessions only: sudo, su and cron never reach it.
    assert!(has(&p, "Session-Interactive-Only: yes"));
    // Off until asked for, and the screen-lock option is on the auth line.
    assert!(has(&p, "Default: no"));
    assert!(p.iter().any(|l| l == "optional\tpam_kepr.so unlock"));
    assert!(p.iter().any(|l| l == "optional\tpam_kepr.so hint"));
}

#[test]
fn install_login_installs_every_piece_and_touches_pam_only_when_asked() {
    let s = text("install.sh");
    for want in [
        "--login) LOGIN=true",
        "crates/kepr-pam/Cargo.toml",
        "systemd/user/kepr-daemon.service",
        "systemd/user/kepr-ssh-agent.service",
        "packaging/pam-configs/kepr",
        "pam-auth-update --package --enable kepr",
        "/usr/share/pam-configs/kepr",
    ] {
        assert!(s.contains(want), "install.sh lost `{want}`");
    }
    // Every PAM change sits inside the `--login` branch.
    let first_pam_change = s.find("pam-auth-update --package").unwrap();
    let branch = s.find("echo -e \"\\n${CYN}━━━ Unlock at login").unwrap();
    assert!(branch < first_pam_change);
    assert!(s[..branch].contains("if $LOGIN; then"));
}

#[test]
fn the_module_and_the_helpers_agree_on_their_protocol() {
    // pam_kepr.so reads the first word of the helpers' stdout line.
    let pam = text("crates/kepr-pam/src/logic.rs");
    let helper = text("src/cli_session/pam_helper.rs");
    for (name, code) in [
        ("DONE", 0),
        ("OFF", 10),
        ("NOT_RUNNING", 11),
        ("REFUSED", 12),
    ] {
        assert!(
            helper.contains(&format!("pub const {name}: u8 = {code};")),
            "helper {name} != {code}"
        );
    }
    for (name, code) in [
        ("REPLY_DONE", 0),
        ("REPLY_OFF", 10),
        ("REPLY_NOT_RUNNING", 11),
    ] {
        assert!(
            pam.contains(&format!("pub const {name}: u32 = {code};")),
            "module {name} != {code}"
        );
    }
    // The helpers the module runs exist as verbs.
    let session = text("src/cli_session/mod.rs");
    assert!(session.contains("\"pam-unlock\"") && session.contains("\"pam-passwd\""));
    let ffi = text("crates/kepr-pam/src/ffi.rs");
    assert!(ffi.contains("&[\"pam-unlock\"]") && ffi.contains("&[\"pam-passwd\"]"));
    assert!(ffi.contains("\"--hint\""));
}
