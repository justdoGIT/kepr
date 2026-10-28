// cli_desktop/takeover_files.rs — what `kepr secret-service takeover` and
// `restore` change, and how they are undone (the commands: takeover.rs):
// make kepr the session's Secret Service instead of GNOME Keyring.
//
// What it changes is all in the user's own directories and is recorded in
// `~/.config/kepr/secret-service-takeover.json`, so `restore` undoes exactly
// that and nothing else:
//
//   * `~/.local/share/dbus-1/services/org.freedesktop.secrets.service` makes
//     the bus start `kepr secret-service run` when a program first asks;
//     the user directory outranks the system one;
//   * the user units that start GNOME Keyring (`gnome-keyring-daemon.socket`
//     and `.service`) are masked;
//   * its autostart entry for the secrets component is hidden (its ssh and
//     pkcs11 components are left alone).
//
// It never edits /etc: a PAM line that starts GNOME Keyring at login
// (pam_gnome_keyring.so) is reported for root to remove.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use super::ss::names as n;

pub const SERVICE_FILE: &str = "org.freedesktop.secrets.service";
const MARK: &str =
    "# Written by `kepr secret-service takeover`; `kepr secret-service restore` removes it.";
const HIDDEN_MARK: &str = "X-Kepr-Hidden=true";
/// The user unit packages ship; when systemd knows it, the bus starts it.
pub const UNIT: &str = "kepr-secret-service.service";
const UNITS: &[&str] = &[
    "gnome-keyring-daemon.socket",
    "gnome-keyring-daemon.service",
];
const AUTOSTART: &[&str] = &["gnome-keyring-secrets.desktop"];

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub service_file: bool,
    pub masked: Vec<String>,
    pub hidden: Vec<String>,
}

pub struct Dirs {
    pub data: PathBuf,
    pub config: PathBuf,
    pub system_autostart: Vec<PathBuf>,
}

impl Dirs {
    pub fn from_env() -> Dirs {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let env = |k: &str, d: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map_or_else(|| home.join(d), PathBuf::from)
        };
        let sys = std::env::var("XDG_CONFIG_DIRS").unwrap_or_else(|_| "/etc/xdg".into());
        Dirs {
            data: env("XDG_DATA_HOME", ".local/share"),
            config: env("XDG_CONFIG_HOME", ".config"),
            system_autostart: sys
                .split(':')
                .filter(|d| !d.is_empty())
                .map(|d| Path::new(d).join("autostart"))
                .collect(),
        }
    }
    fn service(&self) -> PathBuf {
        self.data.join("dbus-1/services").join(SERVICE_FILE)
    }
    fn autostart(&self, name: &str) -> PathBuf {
        self.config.join("autostart").join(name)
    }
    fn state(&self) -> PathBuf {
        self.config.join("kepr/secret-service-takeover.json")
    }
}

/// The part of systemd takeover uses.
pub trait Systemd {
    /// The unit exists (masked counts); `None` when systemd is not there.
    fn knows(&self, unit: &str) -> bool;
    fn masked(&self, unit: &str) -> bool;
    fn mask(&self, unit: &str) -> Result<(), String>;
    fn unmask(&self, unit: &str) -> Result<(), String>;
    fn stop(&self, unit: &str);
}

pub struct UserSystemd;

impl UserSystemd {
    fn out(args: &[&str]) -> Option<String> {
        let o = Command::new("systemctl")
            .arg("--user")
            .args(args)
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    fn run(args: &[&str]) -> Result<(), String> {
        match Command::new("systemctl").arg("--user").args(args).output() {
            Ok(o) if o.status.success() => Ok(()),
            _ => Err(format!("systemctl --user {} failed", args.join(" "))),
        }
    }
}

impl Systemd for UserSystemd {
    fn knows(&self, unit: &str) -> bool {
        Self::out(&["is-enabled", unit]).is_some_and(|s| {
            matches!(
                s.as_str(),
                "enabled"
                    | "enabled-runtime"
                    | "static"
                    | "linked"
                    | "linked-runtime"
                    | "alias"
                    | "disabled"
                    | "indirect"
            ) || s.starts_with("masked")
        })
    }
    fn masked(&self, unit: &str) -> bool {
        Self::out(&["is-enabled", unit]).is_some_and(|s| s.starts_with("masked"))
    }
    fn mask(&self, unit: &str) -> Result<(), String> {
        Self::run(&["mask", unit])
    }
    fn unmask(&self, unit: &str) -> Result<(), String> {
        Self::run(&["unmask", unit])
    }
    fn stop(&self, unit: &str) {
        let _ = Self::run(&["stop", unit]);
    }
}

/// The bus service file for `exe`; with `unit` it also names the systemd
/// unit, so the bus starts kepr through the user manager. The path is put on
/// an `Exec=` line, which the bus splits at spaces, so a path with any is
/// refused.
pub fn service_text(exe: &Path, unit: bool) -> Result<String, String> {
    let p = exe.to_string_lossy();
    if !p.starts_with('/')
        || p.chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '%'))
    {
        return Err(format!("kepr is at {p:?}, which a bus service file cannot hold; install it under a plain absolute path"));
    }
    let via = if unit {
        format!("SystemdService={UNIT}\n")
    } else {
        String::new()
    };
    Ok(format!(
        "{MARK}\n[D-BUS Service]\nName={}\nExec={p} secret-service run\n{via}",
        n::BUS_NAME
    ))
}

fn is_ours(path: &Path, mark: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| t.contains(mark))
}

/// Write `text` to `path`, never through a symbolic link: a link planted at
/// the path (even a dangling one, which `exists()` calls absent) would make
/// this create or overwrite a file somewhere else. `O_NOFOLLOW` makes the
/// open itself refuse, so there is no check-then-write gap.
fn write_file(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                format!(
                    "{} is a symbolic link; remove it or write the file yourself",
                    path.display()
                )
            } else {
                format!("{}: {e}", path.display())
            }
        })
}

fn load_state(d: &Dirs) -> State {
    std::fs::read_to_string(d.state())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Do the file and unit changes; returns what was done, one line each.
pub fn install(d: &Dirs, sd: &dyn Systemd, exe: &Path) -> Result<Vec<String>, String> {
    let text = service_text(exe, sd.knows(UNIT))?;
    let svc = d.service();
    if svc.exists() && !is_ours(&svc, MARK) {
        return Err(format!(
            "{} already exists and is not kepr's; remove it or merge it by hand",
            svc.display()
        ));
    }
    let mut st = load_state(d);
    let mut done = Vec::new();
    write_file(&svc, &text)?;
    st.service_file = true;
    done.push(format!(
        "the bus starts kepr for org.freedesktop.secrets ({})",
        svc.display()
    ));
    for u in UNITS {
        if sd.knows(u) && !sd.masked(u) {
            sd.mask(u)?;
            st.masked.push((*u).to_string());
            done.push(format!("masked {u}"));
        }
    }
    for a in AUTOSTART {
        let own = d.autostart(a);
        let system = d.system_autostart.iter().any(|dir| dir.join(a).exists());
        if system && !own.exists() {
            write_file(
                &own,
                &format!(
                    "[Desktop Entry]\nType=Application\nName={a}\nHidden=true\n{HIDDEN_MARK}\n"
                ),
            )?;
            st.hidden.push((*a).to_string());
            done.push(format!("hid the autostart entry {a}"));
        }
    }
    st.masked.sort();
    st.masked.dedup();
    st.hidden.sort();
    st.hidden.dedup();
    write_file(
        &d.state(),
        &serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
    )?;
    Ok(done)
}

/// Undo `install`.
pub fn uninstall(d: &Dirs, sd: &dyn Systemd) -> Result<Vec<String>, String> {
    let st = load_state(d);
    let mut done = Vec::new();
    let svc = d.service();
    if is_ours(&svc, MARK) {
        std::fs::remove_file(&svc).map_err(|e| format!("{}: {e}", svc.display()))?;
        done.push(format!("removed {}", svc.display()));
    }
    for u in &st.masked {
        sd.unmask(u)?;
        done.push(format!("unmasked {u}"));
    }
    for a in &st.hidden {
        let own = d.autostart(a);
        if is_ours(&own, HIDDEN_MARK) {
            let _ = std::fs::remove_file(&own);
            done.push(format!("restored the autostart entry {a}"));
        }
    }
    let _ = std::fs::remove_file(d.state());
    Ok(done)
}

/// Lines for `kepr secret-service status`.
pub fn report() -> Vec<String> {
    report_in(&Dirs::from_env(), &UserSystemd, Path::new("/etc/pam.d"))
}

pub fn report_in(d: &Dirs, sd: &dyn Systemd, pam: &Path) -> Vec<String> {
    let mut v = Vec::new();
    v.push(if is_ours(&d.service(), MARK) {
        "takeover: on (the bus starts kepr when a program asks; `kepr secret-service restore` undoes it)".into()
    } else {
        "takeover: off (`kepr secret-service takeover` makes kepr this session's Secret Service)".into()
    });
    for u in UNITS.iter().filter(|u| sd.knows(u) && !sd.masked(u)) {
        v.push(format!(
            "{u} is not masked: it can start GNOME Keyring and take the name first"
        ));
    }
    let pam_lines = pam_gnome_keyring(pam);
    if !pam_lines.is_empty() {
        v.push(format!("pam_gnome_keyring.so is in {}: it starts GNOME Keyring at login. Ask root to remove it (Debian, Ubuntu: `pam-auth-update --remove gnome-keyring`)", pam_lines.join(", ")));
    }
    v
}

/// PAM services that load pam_gnome_keyring.so.
pub fn pam_gnome_keyring(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            std::fs::read_to_string(e.path()).is_ok_and(|t| {
                t.lines()
                    .any(|l| !l.trim_start().starts_with('#') && l.contains("pam_gnome_keyring.so"))
            })
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    #[derive(Default)]
    struct Fake {
        units: BTreeSet<String>,
        masked: RefCell<BTreeSet<String>>,
    }
    impl Systemd for Fake {
        fn knows(&self, u: &str) -> bool {
            self.units.contains(u)
        }
        fn masked(&self, u: &str) -> bool {
            self.masked.borrow().contains(u)
        }
        fn mask(&self, u: &str) -> Result<(), String> {
            self.masked.borrow_mut().insert(u.into());
            Ok(())
        }
        fn unmask(&self, u: &str) -> Result<(), String> {
            self.masked.borrow_mut().remove(u);
            Ok(())
        }
        fn stop(&self, _: &str) {}
    }

    fn dirs(tag: &str) -> Dirs {
        let t = std::env::temp_dir().join(format!("kepr-takeover-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(t.join("sys/autostart")).unwrap();
        std::fs::write(
            t.join("sys/autostart/gnome-keyring-secrets.desktop"),
            "[Desktop Entry]\n",
        )
        .unwrap();
        Dirs {
            data: t.join("data"),
            config: t.join("config"),
            system_autostart: vec![t.join("sys/autostart")],
        }
    }

    fn gnome() -> Fake {
        Fake {
            units: UNITS.iter().map(|u| u.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_service_file_names_kepr_and_refuses_odd_paths() {
        let t = service_text(Path::new("/usr/bin/kepr"), false).unwrap();
        assert!(
            t.contains("Name=org.freedesktop.secrets\n")
                && t.contains("Exec=/usr/bin/kepr secret-service run\n")
                && t.contains("[D-BUS Service]")
        );
        assert!(!t.contains("SystemdService"));
        let via = service_text(Path::new("/usr/bin/kepr"), true).unwrap();
        assert!(via.contains("SystemdService=kepr-secret-service.service\n"));
        for bad in [
            "kepr",
            "/home/me/my tools/kepr",
            "/opt/\"x\"/kepr",
            "/a/%h/kepr",
        ] {
            assert!(service_text(Path::new(bad), false).is_err(), "{bad}");
        }
    }

    #[test]
    fn nothing_is_written_through_a_symbolic_link() {
        let d = dirs("symlink");
        let sd = gnome();
        let elsewhere = d.config.join("elsewhere/target.txt");
        std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        // A dangling link where the bus file goes.
        std::fs::create_dir_all(d.service().parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, d.service()).unwrap();
        let e = install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
        assert!(!elsewhere.exists(), "the link's target was created");
        // The same for the autostart entry it hides.
        std::fs::remove_file(d.service()).unwrap();
        std::fs::create_dir_all(d.autostart("x").parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, d.autostart("gnome-keyring-secrets.desktop"))
            .unwrap();
        // exists() is false for the dangling link, so it is treated as absent;
        // the write must still refuse.
        let e = install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
        assert!(!elsewhere.exists());
    }

    #[test]
    fn a_shipped_unit_is_named_in_the_bus_file() {
        let d = dirs("unit");
        let mut sd = gnome();
        sd.units.insert(UNIT.to_string());
        install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap();
        assert!(std::fs::read_to_string(d.service())
            .unwrap()
            .contains("SystemdService=kepr-secret-service.service"));
        assert!(!sd.masked(UNIT), "kepr's own unit is never masked");
    }

    #[test]
    fn takeover_then_restore_leaves_nothing_behind() {
        let d = dirs("round");
        let sd = gnome();
        let done = install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        assert!(d.service().exists() && d.autostart("gnome-keyring-secrets.desktop").exists());
        assert!(
            sd.masked("gnome-keyring-daemon.socket") && sd.masked("gnome-keyring-daemon.service")
        );
        let again = install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap();
        assert_eq!(
            again.len(),
            1,
            "idempotent: only the file is rewritten: {again:?}"
        );
        let undone = uninstall(&d, &sd).unwrap();
        assert!(undone.len() >= 4, "{undone:?}");
        assert!(
            !d.service().exists()
                && !d.autostart("gnome-keyring-secrets.desktop").exists()
                && !d.state().exists()
        );
        assert!(sd.masked.borrow().is_empty());
        assert!(
            uninstall(&d, &sd).unwrap().is_empty(),
            "nothing more to undo"
        );
    }

    #[test]
    fn what_was_not_kepr_s_is_never_touched() {
        let d = dirs("foreign");
        let sd = gnome();
        // The person already masked one unit and wrote their own service file.
        sd.mask("gnome-keyring-daemon.socket").unwrap();
        write_file(
            &d.service(),
            "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/opt/mine\n",
        )
        .unwrap();
        assert!(install(&d, &sd, Path::new("/usr/bin/kepr"))
            .unwrap_err()
            .contains("not kepr's"));
        std::fs::remove_file(d.service()).unwrap();
        install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap();
        uninstall(&d, &sd).unwrap();
        assert!(
            sd.masked("gnome-keyring-daemon.socket"),
            "their own mask stays"
        );
        // A file of theirs at a path restore would clean is left alone.
        write_file(
            &d.service(),
            "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/opt/mine\n",
        )
        .unwrap();
        uninstall(&d, &sd).unwrap();
        assert!(d.service().exists());
    }

    #[test]
    fn the_report_names_what_would_still_start_gnome_keyring() {
        let d = dirs("report");
        let sd = gnome();
        let pam = d.config.join("pam.d");
        std::fs::create_dir_all(&pam).unwrap();
        std::fs::write(
            pam.join("gdm-password"),
            "auth optional pam_gnome_keyring.so\n",
        )
        .unwrap();
        std::fs::write(pam.join("login"), "# auth optional pam_gnome_keyring.so\n").unwrap();
        let before = report_in(&d, &sd, &pam);
        assert!(before[0].starts_with("takeover: off"));
        assert!(before
            .iter()
            .any(|l| l.contains("gnome-keyring-daemon.socket is not masked")));
        assert!(before.iter().any(|l| l.contains("is in gdm-password:")));
        install(&d, &sd, Path::new("/usr/bin/kepr")).unwrap();
        let after = report_in(&d, &sd, &pam);
        assert!(after[0].starts_with("takeover: on"));
        assert!(!after.iter().any(|l| l.contains("is not masked")));
    }
}
