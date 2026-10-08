// cli_platform/fingerprint.rs — fingerprints through polkit (T10.03).
//
//   kepr unlock --fingerprint   reopen a store the idle timer or the sleep
//                               watcher locked (daemon: KEPR_FINGERPRINT_UNLOCK)
//   kepr doctor                 the "fingerprint" advisory: fprintd, enrolled
//                               fingers, pam_fprintd in polkit's PAM stack
//
// Consent prompts (`set --requires-consent`) need nothing here: they are
// polkit `auth_self` prompts already, so pam_fprintd in polkit-1 makes
// them accept a finger.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_platform::PlatformRequest;

use crate::cli_args::Args;
use crate::cli_doctor_hardening::{Finding, Level};

/// Flags of the `platform` batch on core verbs (parsed by cli_args.rs).
pub const FLAGS: &[&str] = &["--fingerprint"];

#[derive(Debug, Default)]
pub struct PlatformFlags {
    /// `unlock --fingerprint` (T10.03).
    pub fingerprint: bool,
}

impl PlatformFlags {
    /// Take the flag at `raw[i]`; returns the next index.
    pub fn take(&mut self, raw: &[String], i: usize) -> Result<usize, String> {
        match raw[i].as_str() {
            "--fingerprint" => self.fingerprint = true,
            other => return Err(format!("unknown flag: {other}")),
        }
        Ok(i + 1)
    }
}

/// `kepr unlock --fingerprint`; `None` for a plain `kepr unlock`.
pub fn cmd_unlock(a: &Args) -> Option<Response> {
    if !a.platform.fingerprint {
        return None;
    }
    let resp = crate::cli_cmds::dispatch(a, &Request::Platform(PlatformRequest::FingerprintUnlock));
    if !a.json {
        match &resp {
            Response::UnlockedOk => crate::cli_ui::ok("Credential store unlocked."),
            Response::Err { error } => crate::cli_ui::err(error),
            _ => crate::cli_ui::err("unexpected response"),
        }
    }
    Some(resp)
}

/// What `fprintd-list USER` reported.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrolled {
    NoDevice,
    Fingers(Vec<String>),
    /// fprintd couldn't be asked (no D-Bus, timeout, odd output).
    Unknown,
}

pub fn parse_fprintd_list(out: &str) -> Enrolled {
    if out.contains("No devices available") {
        return Enrolled::NoDevice;
    }
    let fingers: Vec<String> = out
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- #"))
        .filter_map(|l| l.split_once(": ").map(|(_, f)| f.trim().to_string()))
        .collect();
    if !fingers.is_empty() || out.contains("has no fingers enrolled") {
        Enrolled::Fingers(fingers)
    } else {
        Enrolled::Unknown
    }
}

/// True when the PAM service's auth stack reaches pam_fprintd, following
/// `@include X` (Debian) and `auth include|substack X` (Fedora, Arch).
pub fn pam_has_fprintd(service: &str, read: &dyn Fn(&str) -> Option<String>) -> bool {
    fn walk(svc: &str, read: &dyn Fn(&str) -> Option<String>, depth: u8) -> bool {
        let Some(text) = (depth < 6).then(|| read(svc)).flatten() else {
            return false;
        };
        text.lines().any(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["@include", inc, ..] => walk(inc, read, depth + 1),
                [kind, "include" | "substack", inc, ..]
                    if kind.trim_start_matches('-') == "auth" =>
                {
                    walk(inc, read, depth + 1)
                }
                [kind, ..] if kind.trim_start_matches('-') == "auth" => {
                    words.iter().any(|w| w.contains("pam_fprintd"))
                }
                _ => false,
            }
        })
    }
    walk(service, read, 0)
}

fn read_pam(service: &str) -> Option<String> {
    if service.contains('/') {
        return None;
    }
    ["/etc/pam.d", "/usr/lib/pam.d"]
        .iter()
        .find_map(|d| std::fs::read_to_string(format!("{d}/{service}")).ok())
}

/// The doctor finding from the three facts.
pub fn assess(installed: bool, enrolled: &Enrolled, pam: bool) -> Finding {
    let warn = |d: String| Finding {
        name: "fingerprint",
        level: Level::Warn,
        detail: d,
    };
    if !installed {
        return warn("fprintd not installed (optional: fingerprint for unlock and consent)".into());
    }
    let n = match enrolled {
        Enrolled::NoDevice => return warn("fprintd found no fingerprint reader".into()),
        Enrolled::Unknown => return warn("fprintd did not answer (is fprintd running?)".into()),
        Enrolled::Fingers(f) if f.is_empty() => {
            return warn("no fingers enrolled: run fprintd-enroll".into())
        }
        Enrolled::Fingers(f) => f.len(),
    };
    if !pam {
        return warn(format!(
            "{n} finger(s) enrolled, but polkit's PAM stack lacks pam_fprintd \
             (pam-auth-update, or authselect enable-feature with-fingerprint)"
        ));
    }
    Finding {
        name: "fingerprint",
        level: Level::Good,
        detail: format!(
            "{n} finger(s) enrolled; consent prompts and `kepr unlock --fingerprint` accept them"
        ),
    }
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

fn username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty() && !u.contains('/'))
}

/// `fprintd-list USER` with a 5 s deadline (it talks to the system bus).
fn run_fprintd_list(user: &str) -> Enrolled {
    let child = Command::new("fprintd-list")
        .arg(user)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return Enrolled::Unknown;
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Enrolled::Unknown;
            }
        }
    }
    match child.wait_with_output() {
        Ok(out) => parse_fprintd_list(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => Enrolled::Unknown,
    }
}

/// The `kepr doctor` advisory.
pub fn finding() -> Finding {
    let installed = on_path("fprintd-list");
    let enrolled = match (installed, username()) {
        (true, Some(u)) => run_fprintd_list(&u),
        _ => Enrolled::Unknown,
    };
    let pam = pam_has_fprintd("polkit-1", &read_pam);
    assess(installed, &enrolled, pam)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO: &str = "found 1 devices
Device at /net/reactivated/Fprint/Device/0
Using device /net/reactivated/Fprint/Device/0
Fingerprints for user alice on Goodix MOC Fingerprint Sensor (press):
 - #0: right-index-finger
 - #1: left-index-finger
";
    const NONE: &str = "found 1 devices
Device at /net/reactivated/Fprint/Device/0
Using device /net/reactivated/Fprint/Device/0
User alice has no fingers enrolled for Goodix MOC Fingerprint Sensor.
";

    #[test]
    fn parses_fprintd_list_output() {
        assert_eq!(
            parse_fprintd_list(TWO),
            Enrolled::Fingers(vec![
                "right-index-finger".into(),
                "left-index-finger".into()
            ])
        );
        assert_eq!(parse_fprintd_list(NONE), Enrolled::Fingers(vec![]));
        assert_eq!(
            parse_fprintd_list("No devices available\n"),
            Enrolled::NoDevice
        );
        assert_eq!(parse_fprintd_list(""), Enrolled::Unknown);
    }

    fn pam(files: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |svc| {
            files
                .iter()
                .find(|(n, _)| *n == svc)
                .map(|(_, t)| t.to_string())
        }
    }

    #[test]
    fn follows_pam_includes_to_pam_fprintd() {
        // Debian/Ubuntu after pam-auth-update.
        let debian = pam(&[
            ("polkit-1", "#%PAM-1.0\n@include common-auth\n@include common-account\n"),
            (
                "common-auth",
                "auth [success=2 default=ignore] pam_fprintd.so max-tries=1 timeout=10\nauth [success=1 default=ignore] pam_unix.so nullok\n",
            ),
            ("common-account", "account required pam_unix.so\n"),
        ]);
        assert!(pam_has_fprintd("polkit-1", &debian));
        // Fedora with authselect's with-fingerprint.
        let fedora = pam(&[
            (
                "polkit-1",
                "auth include system-auth\naccount include system-auth\n",
            ),
            (
                "system-auth",
                "auth sufficient pam_fprintd.so\nauth sufficient pam_unix.so\n",
            ),
        ]);
        assert!(pam_has_fprintd("polkit-1", &fedora));
        // Only mentioned in a comment, or in the account stack: no.
        let off = pam(&[
            (
                "polkit-1",
                "@include common-auth\naccount required pam_fprintd.so\n",
            ),
            (
                "common-auth",
                "# auth sufficient pam_fprintd.so\nauth required pam_unix.so\n",
            ),
        ]);
        assert!(!pam_has_fprintd("polkit-1", &off));
        // An include loop ends.
        let looped = pam(&[("polkit-1", "@include polkit-1\n")]);
        assert!(!pam_has_fprintd("polkit-1", &looped));
        assert!(!pam_has_fprintd("missing", &looped));
    }

    #[test]
    fn doctor_finding() {
        let two = Enrolled::Fingers(vec!["a".into(), "b".into()]);
        assert_eq!(assess(true, &two, true).level, Level::Good);
        assert!(assess(true, &two, true).detail.starts_with("2 finger(s)"));
        assert!(assess(true, &two, false).detail.contains("pam_fprintd"));
        assert!(assess(false, &two, true).detail.contains("not installed"));
        assert!(assess(true, &Enrolled::Fingers(vec![]), true)
            .detail
            .contains("fprintd-enroll"));
        assert_eq!(assess(true, &Enrolled::NoDevice, true).level, Level::Warn);
        assert_eq!(assess(true, &Enrolled::Unknown, true).level, Level::Warn);
    }

    #[test]
    fn flag_parsing() {
        let raw: Vec<String> = ["kepr", "unlock", "--fingerprint"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut f = PlatformFlags::default();
        assert_eq!(f.take(&raw, 2), Ok(3));
        assert!(f.fingerprint);
    }
}
