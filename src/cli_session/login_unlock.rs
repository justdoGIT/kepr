// cli_session/login_unlock.rs — `kepr login-unlock on|off|status`
// (T13.25): the per-user switch pam_kepr.so obeys, plus what else a login
// unlock needs, checked or set up here:
//
//   * a passphrase store (`kepr lock`), whose passphrase is the login
//     password (`kepr passwd` changes it; `passwd` keeps them in step when
//     pam_kepr.so is in the password stack);
//   * the daemon started with the session: the `kepr-daemon.service` user
//     unit, enabled here when systemd knows it (it starts the daemon with
//     `--login`, so early requests wait for the unlock);
//   * pam_kepr.so in a PAM service (`pam-auth-update --enable kepr`), which
//     only root can do, so this only reports it;
//   * with `--ssh-agent`, `kepr-ssh-agent.service` and SSH_AUTH_SOCK for
//     the session (`~/.config/environment.d/50-kepr-ssh-agent.conf`).
//
// The switch is `~/.config/kepr/login-unlock` (kepr_core::login_unlock).
// Not in system mode: the shared store is root's to unlock.

use std::path::{Path, PathBuf};
use std::process::Command;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_session::SessionResponse;

use crate::{cli_mode, cli_ui};

pub const DAEMON_UNIT: &str = "kepr-daemon.service";
pub const AGENT_UNIT: &str = "kepr-ssh-agent.service";
const ENV_FILE: &str = ".config/environment.d/50-kepr-ssh-agent.conf";
const ENV_LINE: &str = "SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/kepr-ssh-agent.sock\n";
const USAGE: &str = "usage: kepr login-unlock on [--ssh-agent] | off | status";

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}

pub fn is_on() -> bool {
    kepr_core::login_unlock::enabled(&home())
}

/// Why login unlock can't be turned on for this store, if it can't.
pub fn check_on(system_mode: bool, default_profile: bool, status: &Response) -> Result<(), String> {
    if system_mode {
        return Err(
            "login unlock is for the user-mode store; in system mode the store \
                    opens at boot and only root locks or unlocks it"
                .into(),
        );
    }
    if !default_profile {
        return Err("login unlock works with the default profile only".into());
    }
    match status {
        Response::StatusOk {
            password_protected: false,
            ..
        } => Err(
            "this store has no passphrase: run `kepr lock` and give your login \
                  password as the passphrase, then `kepr login-unlock on`"
                .into(),
        ),
        Response::StatusOk { info, .. }
            if info.key_sealer.as_deref() == Some("passphrase+fido2") =>
        {
            Err("this store also needs its security key, which a login can't supply".into())
        }
        Response::StatusOk { .. } => Ok(()),
        Response::Err { error } => Err(error.clone()),
        _ => Err("unexpected reply".into()),
    }
}

/// PAM files under `dir` that use pam_kepr.so on a line that isn't a
/// comment.
pub fn pam_services_in(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            std::fs::read_to_string(e.path()).is_ok_and(|t| {
                t.lines()
                    .any(|l| !l.trim_start().starts_with('#') && l.contains("pam_kepr.so"))
            })
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// `systemctl --user is-enabled` output: whether the unit starts with the
/// session; `None` when systemd doesn't know it.
pub fn unit_state(stdout: &str) -> Option<bool> {
    match stdout.trim() {
        "enabled" | "enabled-runtime" | "static" | "linked" | "linked-runtime" | "alias" => {
            Some(true)
        }
        "disabled" | "masked" | "masked-runtime" | "indirect" => Some(false),
        _ => None,
    }
}

fn systemctl(args: &[&str]) -> Option<std::process::Output> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .ok()
}

fn unit_enabled(unit: &str) -> Option<bool> {
    systemctl(&["is-enabled", unit]).and_then(|o| unit_state(&String::from_utf8_lossy(&o.stdout)))
}

fn enable(unit: &str, now: bool) -> Result<(), String> {
    let mut args = vec!["enable"];
    if now {
        args.push("--now");
    }
    args.push(unit);
    match systemctl(&args) {
        Some(o) if o.status.success() => Ok(()),
        _ => Err(format!("systemctl --user enable {unit} failed")),
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn info() -> Response {
    Response::Session(SessionResponse::LoginUnlockInfo {
        on: is_on(),
        daemon_unit: unit_enabled(DAEMON_UNIT),
        ssh_agent_unit: unit_enabled(AGENT_UNIT),
        pam_services: pam_services_in(Path::new("/etc/pam.d")),
    })
}

fn say(m: &str) {
    if !cli_mode::json_mode() {
        cli_ui::info(m);
    }
}

fn cmd_on(ssh_agent: bool) -> Response {
    let status = crate::client::send_request(&Request::Status).unwrap_or_else(Response::fail);
    let default_profile = matches!(kepr_core::profile::current(), Ok(None));
    if let Err(e) = check_on(
        std::env::var_os("KEPR_SYSTEM_MODE").is_some(),
        default_profile,
        &status,
    ) {
        return Response::fail(e);
    }
    let marker = kepr_core::login_unlock::marker(&home());
    let note = "# kepr: unlock the store with the login password (pam_kepr.so). \
                Delete this file, or run `kepr login-unlock off`, to stop.\n";
    if let Err(e) = write_private(&marker, note) {
        return Response::fail(e);
    }
    match unit_enabled(DAEMON_UNIT) {
        Some(_) => match enable(DAEMON_UNIT, false) {
            Ok(()) => say("kepr-daemon.service enabled: the daemon starts with your session"),
            Err(e) => say(&e),
        },
        None => say(
            "no kepr-daemon.service user unit: the daemon starts on first use, so a login \
             unlocks it only once it runs (install.sh --login installs the unit)",
        ),
    }
    if ssh_agent {
        let env_file = home().join(ENV_FILE);
        let r = enable(AGENT_UNIT, true).and_then(|_| write_private(&env_file, ENV_LINE));
        match r {
            Ok(()) => say(&format!(
                "kepr ssh-agent runs with your session; SSH_AUTH_SOCK is set in {} (for \
                 shells: export SSH_AUTH_SOCK=\"$XDG_RUNTIME_DIR/kepr-ssh-agent.sock\")",
                env_file.display()
            )),
            Err(e) => say(&e),
        }
    }
    if pam_services_in(Path::new("/etc/pam.d")).is_empty() {
        say("pam_kepr.so is in no PAM service yet: ask root to run `pam-auth-update --enable kepr` \
             (Debian, Ubuntu) or add it as the login-unlock guide shows");
    }
    if !cli_mode::json_mode() {
        cli_ui::ok("Login unlock is on.");
        cli_ui::info(
            "Logging in with your password unlocks kepr, a screen lock locks it, unlocking the \
             screen opens it. Its passphrase must be your login password (kepr passwd).",
        );
    }
    info()
}

fn cmd_off() -> Response {
    match std::fs::remove_file(kepr_core::login_unlock::marker(&home())) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Response::fail(e.to_string()),
    }
    if !cli_mode::json_mode() {
        cli_ui::ok("Login unlock is off; logins no longer hand kepr your password.");
    }
    info()
}

fn yes_no(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "not installed",
    }
}

fn cmd_status() -> Response {
    let r = info();
    if let (
        false,
        Response::Session(SessionResponse::LoginUnlockInfo {
            on,
            daemon_unit,
            ssh_agent_unit,
            pam_services,
        }),
    ) = (cli_mode::json_mode(), &r)
    {
        cli_ui::info(&format!("Login unlock: {}", if *on { "on" } else { "off" }));
        cli_ui::info(&format!("{DAEMON_UNIT}: {}", yes_no(*daemon_unit)));
        cli_ui::info(&format!("{AGENT_UNIT}: {}", yes_no(*ssh_agent_unit)));
        let pam = if pam_services.is_empty() {
            "in no PAM service".to_string()
        } else {
            format!("in {}", pam_services.join(", "))
        };
        cli_ui::info(&format!("pam_kepr.so: {pam}"));
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(s) if s.ends_with("kepr-ssh-agent.sock") => {
                cli_ui::info("SSH_AUTH_SOCK: kepr ssh-agent")
            }
            Ok(s) => cli_ui::info(&format!("SSH_AUTH_SOCK: another agent ({s})")),
            Err(_) => cli_ui::info("SSH_AUTH_SOCK: not set"),
        }
    }
    r
}

pub fn cmd_login_unlock(args: &[&str]) -> Response {
    match args {
        ["on"] => cmd_on(false),
        ["on", "--ssh-agent"] | ["--ssh-agent", "on"] => cmd_on(true),
        ["off"] => cmd_off(),
        ["status"] | [] => cmd_status(),
        _ => Response::fail(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::protocol_session::StatusInfo;

    fn status(protected: bool, sealer: &str) -> Response {
        Response::StatusOk {
            locked: true,
            password_protected: protected,
            info: StatusInfo {
                key_sealer: Some(sealer.into()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn only_a_user_mode_passphrase_store_on_the_default_profile() {
        assert!(check_on(false, true, &status(true, "passphrase")).is_ok());
        assert!(check_on(true, true, &status(true, "passphrase"))
            .unwrap_err()
            .contains("system mode"));
        assert!(check_on(false, false, &status(true, "passphrase"))
            .unwrap_err()
            .contains("default profile"));
        assert!(check_on(false, true, &status(false, "file"))
            .unwrap_err()
            .contains("kepr lock"));
        assert!(check_on(false, true, &status(true, "passphrase+fido2"))
            .unwrap_err()
            .contains("security key"));
        assert_eq!(
            check_on(false, true, &Response::fail("no daemon")).unwrap_err(),
            "no daemon"
        );
    }

    #[test]
    fn pam_services_that_use_the_module() {
        let d = tempfile::tempdir().unwrap();
        let put = |n: &str, t: &str| std::fs::write(d.path().join(n), t).unwrap();
        put("common-auth", "auth\toptional\tpam_kepr.so\n");
        put("common-session", "session optional pam_unix.so\n");
        put(
            "sshd",
            "# session optional pam_kepr.so\n@include common-auth\n",
        );
        put(
            "gdm-password",
            "auth optional /lib/security/pam_kepr.so unlock\n",
        );
        assert_eq!(pam_services_in(d.path()), ["common-auth", "gdm-password"]);
        assert!(pam_services_in(&d.path().join("missing")).is_empty());
    }

    #[test]
    fn systemctl_is_enabled_answers() {
        assert_eq!(unit_state("enabled\n"), Some(true));
        assert_eq!(unit_state("static"), Some(true));
        assert_eq!(unit_state("disabled\n"), Some(false));
        assert_eq!(unit_state(""), None, "unknown unit: nothing on stdout");
        assert_eq!(unit_state("not-found"), None);
    }

    #[test]
    fn the_agent_variable_is_for_the_session_manager() {
        assert!(ENV_LINE.starts_with("SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/"));
        assert!(ENV_LINE.ends_with("kepr-ssh-agent.sock\n"));
        // The same socket the agent picks by default.
        let d = tempfile::tempdir().unwrap();
        let w = d.path().join("a/b/f.conf");
        write_private(&w, ENV_LINE).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&w).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
