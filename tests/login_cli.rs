// login_cli.rs — unlock at login and passphrase changes end to end
// (T13.25), without PAM: what pam_kepr.so does is run `kepr pam-unlock` /
// `kepr pam-passwd` as the user with passwords on stdin, so this drives
// those helpers, `kepr login-unlock`, `kepr passwd` and a user-mode daemon
// in a temporary HOME. tests/pam_e2e.sh covers the module itself (root).

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Option<Child>,
    home: tempfile::TempDir,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn env(cmd: &mut Command, home: &Path) {
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env("KEPR_LOCK_ON_SLEEP", "0")
        .env("KEPR_PAM_WAIT", "10");
}

impl Daemon {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("run")).unwrap();
        let mut d = Daemon { child: None, home };
        d.start(&[]);
        d
    }

    fn start(&mut self, extra: &[&str]) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr-daemon"));
        env(&mut cmd, self.home.path());
        let log = std::fs::File::create(self.home.path().join("daemon.log")).unwrap();
        let child = cmd
            .arg("--user")
            .args(extra)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start kepr-daemon");
        self.child = Some(child);
        let t = Instant::now();
        while !self.run(&["status"], "").status.success() {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "daemon did not come up"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// What the daemon has said so far, for failure messages.
    fn log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("daemon.log")).unwrap_or_default()
    }

    /// Wait until the daemon has logged `needle` (its audit lines).
    fn wait_log(&self, needle: &str) {
        let t = Instant::now();
        while !self.log().contains(needle) {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "no {needle}:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn restart(&mut self, extra: &[&str]) {
        self.stop();
        self.start(extra);
    }

    fn spawn(&self, args: &[&str], stdin: &str) -> Child {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kepr"));
        env(&mut cmd, self.home.path());
        let mut c = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run kepr");
        c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        c
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        self.spawn(args, stdin).wait_with_output().unwrap()
    }

    fn status(&self) -> serde_json::Value {
        let o = self.run(&["status", "--json"], "");
        serde_json::from_slice(&o.stdout).unwrap_or_default()
    }

    fn locked(&self) -> bool {
        self.status()["locked"] == serde_json::Value::Bool(true)
    }

    /// Wait for the detached helper's unlock (or give up).
    fn wait_unlocked(&self) -> bool {
        let t = Instant::now();
        while self.locked() {
            if t.elapsed() > Duration::from_secs(10) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }

    fn pam_unlock(&self, input: &str) {
        let o = self.run(&["pam-unlock"], input);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_login_unlocks_kepr_and_the_passphrase_follows_the_login_password() {
    let mut d = Daemon::new();
    let o = d.run(&["set", "K", "--value", "v1"], "");
    assert!(o.status.success(), "{}", text(&o));
    let o = d.run(&["lock"], "pw-one\npw-one\n");
    assert!(o.status.success(), "{}", text(&o));
    assert!(d.locked());

    // Off by default: the password is read and nothing else happens.
    d.pam_unlock("pw-one\0");
    std::thread::sleep(Duration::from_millis(800));
    assert!(d.locked(), "login unlock is off, yet the store opened");
    let o = d.run(&["pam-passwd"], "pw-one\0pw-x\0");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "10");

    let o = d.run(&["login-unlock", "on"], "");
    assert!(o.status.success(), "{}", text(&o));
    assert!(d.home.path().join(".config/kepr/login-unlock").is_file());

    // A login password that isn't the passphrase: counted on its own budget.
    d.pam_unlock("not-it\0");
    let t = Instant::now();
    while d.status()["login_failures"] != serde_json::json!(1) {
        assert!(t.elapsed() < Duration::from_secs(10), "{}", d.status());
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(d.locked());

    // (The failure above backs the next attempt off for a second.)
    std::thread::sleep(Duration::from_millis(1300));
    d.pam_unlock("pw-one\0");
    assert!(
        d.wait_unlocked(),
        "the login password did not unlock the store\n{}",
        d.log()
    );
    assert!(
        d.status().get("login_failures").is_none(),
        "a success clears it"
    );
    assert!(text(&d.run(&["get", "K"], "")).contains("v1"));

    // `kepr panic` is not undone by a login, only by `kepr unlock`.
    assert!(d.run(&["panic"], "").status.success());
    d.pam_unlock("pw-one\0");
    std::thread::sleep(Duration::from_secs(1));
    assert!(d.locked(), "a login undid kepr panic");
    let o = d.run(&["unlock"], "pw-one\n");
    assert!(o.status.success(), "{}", text(&o));

    // kepr passwd: the current passphrase, then the new one twice.
    let o = d.run(&["passwd"], "wrong\npw-two\npw-two\n");
    assert!(
        !o.status.success(),
        "changed without the current passphrase"
    );
    std::thread::sleep(Duration::from_millis(1300)); // the back-off after a wrong one
    let o = d.run(&["passwd"], "pw-one\npw-two\npw-two\n");
    assert!(o.status.success(), "{}", text(&o));

    // `passwd` (the PAM password hook): the store follows the new password.
    let o = d.run(&["pam-passwd"], "not-it\0pw-three\0");
    let line = String::from_utf8_lossy(&o.stdout);
    assert!(line.starts_with("12 "), "{line}");
    std::thread::sleep(Duration::from_millis(1300));
    let o = d.run(&["pam-passwd"], "pw-two\0pw-three\0");
    let line = String::from_utf8_lossy(&o.stdout);
    assert!(line.starts_with("0 "), "{line}");

    d.restart(&[]);
    assert!(d.locked(), "a passphrase store starts locked");
    d.pam_unlock("pw-two\0");
    std::thread::sleep(Duration::from_millis(800));
    assert!(d.locked(), "the old passphrase still works");
    // A password changed during the login (expired): unlock, then change.
    d.pam_unlock("pw-three\0pw-four\0");
    assert!(d.wait_unlocked());
    d.wait_log("op=login-passphrase-change name=- result=ok");
    d.restart(&[]);
    let o = d.run(&["unlock"], "pw-four\n");
    assert!(
        o.status.success(),
        "deferred change not applied: {}",
        text(&o)
    );

    // No daemon at all: the helpers neither hang nor start one.
    d.stop();
    let t = Instant::now();
    let o = d.run(&["pam-passwd"], "pw-four\0pw-five\0");
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "11");
    assert!(t.elapsed() < Duration::from_secs(8));
    let o = d.run(&["pam-unlock", "--hint"], "");
    assert!(String::from_utf8_lossy(&o.stdout).contains("kepr unlock"));
}

#[test]
fn requests_right_after_a_login_start_wait_for_its_unlock() {
    let mut d = Daemon::new();
    assert!(d.run(&["set", "K", "--value", "v1"], "").status.success());
    assert!(d.run(&["lock"], "pw\npw\n").status.success());
    assert!(d.run(&["login-unlock", "on"], "").status.success());
    // As the user unit starts it: an unlock is coming.
    d.restart(&["--login"]);
    let get = d.spawn(&["get", "K"], "");
    std::thread::sleep(Duration::from_millis(300));
    d.pam_unlock("pw\0");
    let o = get.wait_with_output().unwrap();
    assert!(
        o.status.success(),
        "the early get did not wait: {}\n{}",
        text(&o),
        d.log()
    );
    assert!(text(&o).contains("v1"));

    // Without a login coming, a locked store answers at once.
    d.restart(&[]);
    let t = Instant::now();
    assert!(!d.run(&["get", "K"], "").status.success());
    assert!(t.elapsed() < Duration::from_secs(3));
    // And with --login but no unlock: at most the start-up window.
    d.restart(&["--login"]);
    let t = Instant::now();
    assert!(!d.run(&["get", "K"], "").status.success());
    assert!(t.elapsed() < Duration::from_secs(8), "{:?}", t.elapsed());
}

#[test]
fn a_fetched_credential_arrives_as_a_sealed_descriptor() {
    use kepr_core::framing::{read_frame, write_frame};
    use kepr_core::protocol::{Request, Response, MAX_MSG_BYTES};
    use kepr_core::protocol_session::{SessionRequest, SessionResponse};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    let d = Daemon::new();
    assert!(d
        .run(&["set", "FD_LOGIN", "--value", "fixture-fd-value"], "")
        .status
        .success());
    let mut stream = UnixStream::connect(d.home.path().join("run/kepr/kepr.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = Request::Session(SessionRequest::FetchFd {
        name: "FD_LOGIN".into(),
    });
    write_frame(&mut stream, &serde_json::to_vec(&request).unwrap()).unwrap();
    let reply = read_frame(&mut stream, MAX_MSG_BYTES).unwrap();
    assert!(matches!(
        serde_json::from_slice::<Response>(&reply).unwrap(),
        Response::Session(SessionResponse::FdOk { len: 16 })
    ));
    let raw = kepr_core::fdpass::recv_fd(&stream)
        .unwrap()
        .expect("daemon must send the fd");
    // SAFETY: recv_fd transferred ownership of this descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(
        kepr_core::fdfetch::read_value(&fd).unwrap().as_slice(),
        b"fixture-fd-value"
    );
    // SAFETY: F_GET_SEALS reads flags without changing descriptor ownership.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    assert_ne!(seals & libc::F_SEAL_WRITE, 0);
}
