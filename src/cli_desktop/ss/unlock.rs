// cli_desktop/ss/unlock.rs — asking the person for the store passphrase
// when a program finds kepr locked.
//
// A `Prompter` shows a password dialog and returns what was typed (None if
// the person cancelled). Four are supported, tried in this order:
//
//   $KEPR_ASKPASS PROMPT      a program that prints the passphrase (like
//                             SSH_ASKPASS)
//   pinentry-gnome3 | -qt | -gtk-2 | -gnome | pinentry     (Assuan protocol)
//   zenity --entry --hide-text
//   kdialog --password
//
// GUI dialogs need a display. `Unlocker` sends the passphrase to the daemon
// (`Unlock`); a wrong one is shown in the next dialog, up to three times.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

const DIALOG_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_OUT: usize = 4096;
const ATTEMPTS: u32 = 3;

pub struct Ask<'a> {
    pub title: &'a str,
    pub description: &'a str,
    pub error: Option<&'a str>,
}

pub trait Prompter: Send + Sync {
    fn passphrase(&self, ask: &Ask, cancel: &AtomicBool) -> Result<Option<ZeroString>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Askpass,
    Pinentry,
    Zenity,
    Kdialog,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dialog {
    pub program: PathBuf,
    pub kind: Kind,
}

fn find(name: &str, path: &str) -> Option<PathBuf> {
    path.split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// The dialog to use, given `$KEPR_ASKPASS`, `$PATH` and whether there is a
/// display.
pub fn detect(askpass: Option<&str>, path: &str, display: bool) -> Option<Dialog> {
    if let Some(a) = askpass.filter(|a| !a.is_empty()) {
        return Some(Dialog {
            program: PathBuf::from(a),
            kind: Kind::Askpass,
        });
    }
    if !display {
        return None;
    }
    for name in [
        "pinentry-gnome3",
        "pinentry-qt",
        "pinentry-gtk-2",
        "pinentry-gnome",
        "pinentry",
    ] {
        if let Some(p) = find(name, path) {
            return Some(Dialog {
                program: p,
                kind: Kind::Pinentry,
            });
        }
    }
    if let Some(p) = find("zenity", path) {
        return Some(Dialog {
            program: p,
            kind: Kind::Zenity,
        });
    }
    find("kdialog", path).map(|p| Dialog {
        program: p,
        kind: Kind::Kdialog,
    })
}

pub fn detect_here() -> Option<Dialog> {
    let display =
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some();
    detect(
        std::env::var("KEPR_ASKPASS").ok().as_deref(),
        &std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        display,
    )
}

fn escape(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn unescape(s: &str) -> Zeroizing<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        match (
            b[i],
            b.get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok()),
        ) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// The passphrase out of a pinentry's output (`D <data>`), or why none.
pub fn parse_pinentry(out: &str) -> Result<Option<ZeroString>, String> {
    for line in out.lines() {
        if let Some(d) = line.strip_prefix("D ") {
            let pin = unescape(d);
            return String::from_utf8(pin.to_vec())
                .map(|s| Some(ZeroString::from_string(s)))
                .map_err(|_| "the passphrase is not UTF-8".to_string());
        }
        if let Some(e) = line.strip_prefix("ERR ") {
            // 83886179: "Operation cancelled".
            return if e.contains("cancel") || e.starts_with("83886179") {
                Ok(None)
            } else {
                Err(format!("pinentry: {e}"))
            };
        }
    }
    Err("pinentry gave no answer".into())
}

fn wait(mut child: Child, cancel: &AtomicBool) -> Result<(bool, Zeroizing<Vec<u8>>), String> {
    use std::sync::atomic::AtomicBool as Flag;
    use std::sync::Arc;
    let mut out = child.stdout.take().ok_or("no output pipe")?;
    // Drain on another thread so a chatty child cannot block on a full
    // pipe. A helper the dialog left running can hold the pipe open after
    // the dialog itself is gone, so the reader is waited for only briefly.
    let keep = Arc::new(Mutex::new(Zeroizing::new(Vec::new())));
    let eof = Arc::new(Flag::new(false));
    let (k, e) = (Arc::clone(&keep), Arc::clone(&eof));
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            let mut g = k.lock().unwrap_or_else(|p| p.into_inner());
            let room = MAX_OUT.saturating_sub(g.len());
            g.extend_from_slice(&buf[..n.min(room)]);
        }
        e.store(true, Ordering::SeqCst);
    });
    let start = Instant::now();
    let ok = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) if cancel.load(Ordering::SeqCst) || start.elapsed() > DIALOG_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok((false, Zeroizing::new(Vec::new())));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let grace = Instant::now();
    while !eof.load(Ordering::SeqCst) && grace.elapsed() < Duration::from_millis(500) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let got = std::mem::take(&mut *keep.lock().unwrap_or_else(|p| p.into_inner()));
    Ok((ok, got))
}

fn spawn(program: &Path, args: &[&str], stdin: Option<&str>) -> Result<Child, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // ETXTBSY: a program that was just written (a package upgrade replacing the dialog helper) is busy until
    // every write handle to it is closed, and another thread's fork can hold a copy of one for the instant before
    // its own exec. That window is a few milliseconds; waiting it out beats failing the unlock prompt.
    let mut busy = 0;
    let mut c = loop {
        match cmd.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && busy < 20 => {
                busy += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            other => break other.map_err(|e| format!("{}: {e}", program.display()))?,
        }
    };
    if let (Some(text), Some(mut si)) = (stdin, c.stdin.take()) {
        let _ = si.write_all(text.as_bytes());
    }
    Ok(c)
}

fn first_line(out: &[u8]) -> Option<ZeroString> {
    let text = std::str::from_utf8(out).ok()?;
    let line = text
        .split('\n')
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r');
    (!line.is_empty()).then(|| ZeroString::from(line))
}

impl Prompter for Dialog {
    fn passphrase(&self, ask: &Ask, cancel: &AtomicBool) -> Result<Option<ZeroString>, String> {
        let desc = match ask.error {
            Some(e) => format!("{e}\n\n{}", ask.description),
            None => ask.description.to_string(),
        };
        let child = match self.kind {
            Kind::Askpass => spawn(&self.program, &[&desc], None)?,
            Kind::Zenity => spawn(
                &self.program,
                &[
                    "--entry",
                    "--hide-text",
                    &format!("--title={}", ask.title),
                    &format!("--text={desc}"),
                ],
                None,
            )?,
            Kind::Kdialog => spawn(
                &self.program,
                &["--title", ask.title, "--password", &desc],
                None,
            )?,
            Kind::Pinentry => {
                let mut script = format!(
                    "SETTITLE {}\nSETDESC {}\nSETPROMPT Passphrase:\n",
                    escape(ask.title),
                    escape(ask.description)
                );
                if let Some(e) = ask.error {
                    script.push_str(&format!("SETERROR {}\n", escape(e)));
                }
                script.push_str("GETPIN\nBYE\n");
                spawn(&self.program, &[], Some(&script))?
            }
        };
        let (ok, out) = wait(child, cancel)?;
        if self.kind == Kind::Pinentry {
            return parse_pinentry(&String::from_utf8_lossy(&out));
        }
        Ok(if ok { first_line(&out) } else { None })
    }
}

/// What the unlock flow needs from kepr itself.
pub trait Kepr: Send + Sync {
    fn locked(&self) -> bool;
    fn unlock(&self, passphrase: ZeroString) -> Result<(), String>;
}

pub struct Daemon;

impl Kepr for Daemon {
    fn locked(&self) -> bool {
        use super::store::Store;
        super::daemon_store::DaemonStore.locked().unwrap_or(true)
    }

    fn unlock(&self, passphrase: ZeroString) -> Result<(), String> {
        use kepr_core::protocol::{Request, Response};
        match super::daemon_store::send(&Request::Unlock {
            password: passphrase,
        })
        .map_err(|e| e.to_string())?
        {
            Response::UnlockedOk => Ok(()),
            Response::Err { error } => Err(error),
            _ => Err("unexpected reply from the kepr daemon".into()),
        }
    }
}

pub trait Unlocker: Send + Sync {
    /// Ask until kepr is unlocked or the person gives up: Ok(unlocked).
    fn unlock(&self, cancel: &AtomicBool) -> Result<bool, String>;
}

pub struct Dialogs<K: Kepr, P: Prompter> {
    pub kepr: K,
    pub prompter: Option<P>,
}

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

impl<K: Kepr, P: Prompter> Unlocker for Dialogs<K, P> {
    fn unlock(&self, cancel: &AtomicBool) -> Result<bool, String> {
        // Programs that ask at the same moment share one dialog: the later
        // ones wait here and then find kepr already unlocked.
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        if !self.kepr.locked() {
            return Ok(true);
        }
        let Some(p) = &self.prompter else {
            return Err("there is no way to ask for the passphrase here: install pinentry or zenity, set KEPR_ASKPASS, or run `kepr unlock`".into());
        };
        let mut error: Option<String> = None;
        for _ in 0..ATTEMPTS {
            if cancel.load(Ordering::SeqCst) {
                return Ok(false);
            }
            let ask = Ask {
                title: "kepr",
                description: "A program asks for a key that kepr keeps. Enter your kepr passphrase to unlock it.",
                error: error.as_deref(),
            };
            let Some(pw) = p.passphrase(&ask, cancel)? else {
                return Ok(false);
            };
            match self.kepr.unlock(pw) {
                Ok(()) => return Ok(true),
                Err(e) if e.contains("security key") || e.contains("not password protected") => {
                    return Err(e)
                }
                Err(e) => error = Some(e),
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kepr-unlock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ask() -> Ask<'static> {
        Ask {
            title: "kepr",
            description: "desc\nline two",
            error: None,
        }
    }

    #[test]
    fn a_program_still_open_for_writing_is_waited_for_not_failed() {
        let d = tmp("busy");
        let p = script(&d, "d", "printf 'ok\\n'");
        // An open write handle makes exec fail with ETXTBSY until it is closed.
        let writer = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            drop(writer);
        });
        let dlg = Dialog {
            program: p,
            kind: Kind::Askpass,
        };
        let got = dlg
            .passphrase(&ask(), &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "ok");
        closer.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_dialog_is_chosen_in_order_and_only_with_a_display() {
        let d = tmp("detect");
        let path = d.display().to_string();
        assert_eq!(detect(None, &path, true), None);
        script(&d, "kdialog", "true");
        script(&d, "zenity", "true");
        assert_eq!(detect(None, &path, true).unwrap().kind, Kind::Zenity);
        script(&d, "pinentry", "true");
        assert_eq!(detect(None, &path, true).unwrap().kind, Kind::Pinentry);
        script(&d, "pinentry-gnome3", "true");
        assert!(detect(None, &path, true)
            .unwrap()
            .program
            .ends_with("pinentry-gnome3"));
        assert_eq!(
            detect(None, &path, false),
            None,
            "no display, no GUI dialog"
        );
        let a = detect(Some("/opt/ask"), &path, false).unwrap();
        assert_eq!(
            (a.kind, a.program),
            (Kind::Askpass, PathBuf::from("/opt/ask"))
        );
        assert_eq!(detect(Some(""), &path, false), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn assuan_escaping_and_answers() {
        assert_eq!(escape("a%b\nc"), "a%25b%0Ac");
        assert_eq!(&unescape("a%25b%0Ac%zz")[..], b"a%b\nc%zz");
        assert_eq!(
            parse_pinentry("OK hi\nOK\nD s3%25cret\nOK\n")
                .unwrap()
                .unwrap()
                .as_str(),
            "s3%cret"
        );
        assert!(
            parse_pinentry("OK\nERR 83886179 Operation cancelled <Pinentry>\n")
                .unwrap()
                .is_none()
        );
        assert!(parse_pinentry("OK\nERR 1 boom\n").is_err());
        assert!(parse_pinentry("OK\n").is_err());
    }

    #[test]
    fn a_pinentry_is_driven_over_assuan() {
        let d = tmp("pinentry");
        // Records what it was told and answers like a pinentry.
        let log = d.join("log");
        let pe = script(&d, "pinentry", &format!(
            "echo 'OK Pleased to meet you'\nwhile read cmd arg; do echo \"$cmd $arg\" >> {}\n case \"$cmd\" in GETPIN) echo 'D hunter%25two'; echo OK;; BYE) echo OK; exit 0;; *) echo OK;; esac\ndone",
            log.display()
        ));
        let dlg = Dialog {
            program: pe,
            kind: Kind::Pinentry,
        };
        let a = Ask {
            title: "kepr",
            description: "line one\nline two",
            error: Some("wrong passphrase"),
        };
        let got = dlg
            .passphrase(&a, &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        assert_eq!(got.as_str(), "hunter%two");
        let told = std::fs::read_to_string(&log).unwrap();
        assert!(told.contains("SETDESC line one%0Aline two"), "{told}");
        assert!(
            told.contains("SETERROR wrong passphrase")
                && told.contains("GETPIN")
                && told.contains("SETTITLE kepr")
        );
        // Cancelled.
        let cancelled = script(&d, "cancelled", "echo OK; while read c a; do case \"$c\" in GETPIN) echo 'ERR 83886179 Operation cancelled';; BYE) exit 0;; esac; done");
        let dlg = Dialog {
            program: cancelled,
            kind: Kind::Pinentry,
        };
        assert!(dlg
            .passphrase(&ask(), &AtomicBool::new(false))
            .unwrap()
            .is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn askpass_zenity_and_kdialog_print_the_passphrase() {
        let d = tmp("simple");
        for kind in [Kind::Askpass, Kind::Zenity, Kind::Kdialog] {
            let p = script(&d, "d", "printf 'secret-line\\nignored\\n'");
            let dlg = Dialog {
                program: p,
                kind: kind.clone(),
            };
            assert_eq!(
                dlg.passphrase(&ask(), &AtomicBool::new(false))
                    .unwrap()
                    .unwrap()
                    .as_str(),
                "secret-line",
                "{kind:?}"
            );
        }
        // The prompt reaches an askpass as its argument.
        let p = script(&d, "e", "printf '%s' \"$1\"");
        let echoed = Dialog {
            program: p,
            kind: Kind::Askpass,
        }
        .passphrase(&ask(), &AtomicBool::new(false))
        .unwrap()
        .unwrap();
        assert!(echoed.as_str().starts_with("desc"));
        // Cancel (non-zero exit) and empty answers are "no passphrase".
        let no = script(&d, "f", "exit 1");
        assert!(Dialog {
            program: no,
            kind: Kind::Askpass
        }
        .passphrase(&ask(), &AtomicBool::new(false))
        .unwrap()
        .is_none());
        let empty = script(&d, "g", "echo");
        assert!(Dialog {
            program: empty,
            kind: Kind::Zenity
        }
        .passphrase(&ask(), &AtomicBool::new(false))
        .unwrap()
        .is_none());
        assert!(Dialog {
            program: d.join("missing"),
            kind: Kind::Askpass
        }
        .passphrase(&ask(), &AtomicBool::new(false))
        .is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dismissing_kills_the_dialog() {
        let d = tmp("cancel");
        let p = script(&d, "slow", "sleep 30");
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = Arc::clone(&cancel);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            c2.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        let r = Dialog {
            program: p,
            kind: Kind::Askpass,
        }
        .passphrase(&ask(), &cancel)
        .unwrap();
        t.join().unwrap();
        assert!(r.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&d);
    }

    struct FakeKepr {
        locked: std::sync::atomic::AtomicBool,
        good: &'static str,
        tries: AtomicU32,
    }
    impl Kepr for FakeKepr {
        fn locked(&self) -> bool {
            self.locked.load(Ordering::SeqCst)
        }
        fn unlock(&self, pw: ZeroString) -> Result<(), String> {
            self.tries.fetch_add(1, Ordering::SeqCst);
            if pw.as_str() == self.good {
                self.locked.store(false, Ordering::SeqCst);
                Ok(())
            } else {
                Err("invalid password".into())
            }
        }
    }
    struct Typed(Mutex<Vec<&'static str>>, Mutex<Vec<Option<String>>>);
    impl Prompter for Typed {
        fn passphrase(&self, a: &Ask, _: &AtomicBool) -> Result<Option<ZeroString>, String> {
            self.1.lock().unwrap().push(a.error.map(String::from));
            Ok(self.0.lock().unwrap().pop().map(ZeroString::from))
        }
    }

    #[test]
    fn a_wrong_passphrase_is_shown_in_the_next_dialog_and_three_tries_end_it() {
        let k = FakeKepr {
            locked: true.into(),
            good: "right",
            tries: 0.into(),
        };
        let u = Dialogs {
            kepr: k,
            prompter: Some(Typed(
                Mutex::new(vec!["right", "wrong"]),
                Mutex::new(vec![]),
            )),
        };
        assert_eq!(u.unlock(&AtomicBool::new(false)), Ok(true));
        let seen = u.prompter.as_ref().unwrap().1.lock().unwrap().clone();
        assert_eq!(seen, [None, Some("invalid password".to_string())]);
        // Already unlocked: no dialog at all.
        assert_eq!(u.unlock(&AtomicBool::new(false)), Ok(true));
        assert_eq!(u.prompter.as_ref().unwrap().1.lock().unwrap().len(), 2);
        // Three wrong ones.
        let k = FakeKepr {
            locked: true.into(),
            good: "right",
            tries: 0.into(),
        };
        let u = Dialogs {
            kepr: k,
            prompter: Some(Typed(
                Mutex::new(vec!["x", "y", "z", "w"]),
                Mutex::new(vec![]),
            )),
        };
        assert_eq!(u.unlock(&AtomicBool::new(false)), Ok(false));
        assert_eq!(u.kepr.tries.load(Ordering::SeqCst), 3);
        // Cancelled.
        let k = FakeKepr {
            locked: true.into(),
            good: "right",
            tries: 0.into(),
        };
        let u = Dialogs {
            kepr: k,
            prompter: Some(Typed(Mutex::new(vec![]), Mutex::new(vec![]))),
        };
        assert_eq!(u.unlock(&AtomicBool::new(false)), Ok(false));
        assert_eq!(u.kepr.tries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn without_a_dialog_the_error_says_what_to_do() {
        let k = FakeKepr {
            locked: true.into(),
            good: "x",
            tries: 0.into(),
        };
        let u: Dialogs<FakeKepr, Dialog> = Dialogs {
            kepr: k,
            prompter: None,
        };
        let e = u.unlock(&AtomicBool::new(false)).unwrap_err();
        assert!(e.contains("kepr unlock") && e.contains("pinentry"));
    }
}
