//! The decisions the PAM entry points make, without any PAM call, so they
//! test on their own.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_KEPR: &[&str] = &["/usr/bin/kepr", "/usr/local/bin/kepr"];

// Flags (Linux-PAM's values).
pub const PAM_SILENT: i32 = 0x8000;
const PAM_ESTABLISH_CRED: i32 = 0x2;
const PAM_DELETE_CRED: i32 = 0x4;
const PAM_REINITIALIZE_CRED: i32 = 0x8;
const PAM_REFRESH_CRED: i32 = 0x10;
const PAM_PRELIM_CHECK: i32 = 0x4000;
const PAM_UPDATE_AUTHTOK: i32 = 0x2000;

/// Answer codes of `kepr pam-passwd` / `pam-unlock --hint` (the first word
/// of their stdout line; src/cli_session/pam_helper.rs).
pub const REPLY_DONE: u32 = 0;
pub const REPLY_OFF: u32 = 10;
pub const REPLY_NOT_RUNNING: u32 = 11;

/// Where, besides the session, the password is handed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Early {
    /// Only when the session opens.
    No,
    /// Also when the application establishes or refreshes credentials,
    /// which it does only after a successful authentication (screen
    /// lockers that call `pam_setcred`).
    Setcred,
    /// Also straight from the authentication hook. For lockers that call
    /// nothing else; the stack must not reach this module after a failed
    /// password (Debian's `common-auth` layout, or `requisite`).
    Auth,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Opts {
    /// Candidate `kepr` paths, in order.
    pub kepr: Vec<PathBuf>,
    pub debug: bool,
    pub early: Early,
    /// Say why kepr stays locked when a login had no password.
    pub hint: bool,
}

/// Module arguments from the PAM config line. An unknown or relative
/// `kepr=` is dropped (the default stands), never guessed at.
pub fn parse_opts(args: &[String]) -> Opts {
    let mut o = Opts {
        kepr: Vec::new(),
        debug: false,
        early: Early::No,
        hint: false,
    };
    for a in args {
        match a.split_once('=') {
            Some(("kepr", p)) if Path::new(p).is_absolute() => o.kepr = vec![p.into()],
            Some(("unlock", "auth")) => o.early = Early::Auth,
            None if a == "unlock" && o.early == Early::No => o.early = Early::Setcred,
            None if a == "debug" => o.debug = true,
            None if a == "hint" => o.hint = true,
            _ => {}
        }
    }
    if o.kepr.is_empty() {
        o.kepr = DEFAULT_KEPR.iter().map(PathBuf::from).collect();
    }
    o
}

/// May this file be run with a user's password on its stdin? A regular
/// file owned by root that neither group nor others can write.
pub fn trusted_binary(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// The first candidate that is trusted.
pub fn pick_kepr(candidates: &[PathBuf]) -> Option<&PathBuf> {
    candidates.iter().find(|p| trusted_binary(p))
}

/// The environment the helper gets: nothing inherited from the login.
pub fn helper_env(uid: u32, home: &str) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), home.into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid}")),
        ("KEPR_PAM_WAIT".into(), "20".into()),
    ]
}

/// Does PAM data for this login mean anything to us? Root is left alone.
pub fn applies_to(uid: u32) -> bool {
    uid != 0
}

/// Is this `pam_setcred` call one that follows a successful login?
pub fn credentials_established(flags: i32) -> bool {
    flags & PAM_DELETE_CRED == 0
        && flags & (PAM_ESTABLISH_CRED | PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED) != 0
}

/// `pam_chauthtok`: the preliminary check changes nothing; the update does.
pub fn is_update(flags: i32) -> bool {
    flags & PAM_UPDATE_AUTHTOK != 0 && flags & PAM_PRELIM_CHECK == 0
}

/// A password that wipes itself when dropped.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: &[u8]) -> Self {
        let mut v = Vec::with_capacity(bytes.len() + 2);
        v.extend_from_slice(bytes);
        Secret(v)
    }

    /// `a NUL b NUL`: what the helpers read for two passwords.
    pub fn pair(a: &[u8], b: &[u8]) -> Self {
        let mut v = Vec::with_capacity(a.len() + b.len() + 2);
        v.extend_from_slice(a);
        v.push(0);
        v.extend_from_slice(b);
        v.push(0);
        Secret(v)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Zero `buf` in a way the optimiser may not remove.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: a volatile write to a byte we own, so the wipe is not optimised out.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
        self.0.clear();
    }
}

/// What one login remembers between the PAM calls: the user the
/// authentication was for and their password, optionally the new password
/// they set during the same login.
pub struct Stash {
    user: Vec<u8>,
    password: Secret,
    new: Option<Secret>,
    sent: bool,
}

impl Stash {
    pub fn new(user: &[u8], password: &[u8]) -> Self {
        Stash {
            user: user.to_vec(),
            password: Secret::new(password),
            new: None,
            sent: false,
        }
    }

    /// The helper's stdin for a session of `user`: the password (and the
    /// new one), NUL-terminated. `None` when the session is for another
    /// user than the one who authenticated (`sudo -u`, `su`): their
    /// password is not handed to someone else's kepr. Also `None` after it
    /// was already sent for this login.
    pub fn input_for(&self, user: &[u8]) -> Option<Secret> {
        if self.sent || self.user != user || self.password.as_bytes().is_empty() {
            return None;
        }
        let mut v = Secret::new(self.password.as_bytes());
        v.0.push(0);
        if let Some(n) = &self.new {
            v.0.extend_from_slice(n.as_bytes());
            v.0.push(0);
        }
        Some(v)
    }

    pub fn mark_sent(&mut self) {
        self.sent = true;
    }

    pub fn is_sent(&self) -> bool {
        self.sent
    }

    /// The password changed during this login (`old` → `new`), `code` is
    /// what `kepr pam-passwd` answered. The store passphrase now is `new`
    /// (done), is still `old` and will be moved to `new` at the session
    /// (kepr was not running yet), or is still `old` (refused, or kepr is
    /// not in use: the unlock then tries the old one and fails quietly).
    pub fn changed(&mut self, user: &[u8], code: Option<u32>, (old, new): (&[u8], &[u8])) {
        if self.user != user {
            self.user = user.to_vec();
        }
        match code {
            Some(REPLY_DONE) => {
                self.password = Secret::new(new);
                self.new = None;
            }
            Some(REPLY_NOT_RUNNING) => {
                self.password = Secret::new(old);
                self.new = Some(Secret::new(new));
            }
            _ => {
                self.password = Secret::new(old);
                self.new = None;
            }
        }
        self.sent = false;
    }
}

/// `CODE [MESSAGE]` from a helper's stdout. The message is for the user's
/// terminal: control characters are dropped, at most 300 characters.
pub fn parse_reply(out: &[u8]) -> Option<(u32, Option<String>)> {
    let text = std::str::from_utf8(out).ok()?;
    let line = text.lines().next()?.trim();
    let (code, rest) = line.split_once(' ').unwrap_or((line, ""));
    let code = code.parse().ok()?;
    let msg: String = rest.chars().filter(|c| !c.is_control()).take(300).collect();
    Some((code, (!msg.is_empty()).then_some(msg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn options() {
        assert_eq!(parse_opts(&[]).kepr.len(), 2);
        let o = parse_opts(&s(&["kepr=/opt/kepr/bin/kepr", "debug", "hint"]));
        assert_eq!(o.kepr, [PathBuf::from("/opt/kepr/bin/kepr")]);
        assert!(o.debug && o.hint);
        assert_eq!(o.early, Early::No);
        // A relative path is ignored; so is anything unknown.
        let o = parse_opts(&s(&["kepr=kepr", "wat=1", "nodebug"]));
        assert_eq!(o.kepr.len(), 2);
        assert!(!o.debug && !o.hint);
        assert_eq!(parse_opts(&s(&["unlock"])).early, Early::Setcred);
        assert_eq!(parse_opts(&s(&["unlock=auth"])).early, Early::Auth);
        // `auth` wins whatever the order.
        assert_eq!(
            parse_opts(&s(&["unlock=auth", "unlock"])).early,
            Early::Auth
        );
        assert_eq!(parse_opts(&s(&["unlock=never"])).early, Early::No);
    }

    #[test]
    fn only_a_root_owned_closed_binary_is_trusted() {
        let d = std::env::temp_dir().join(format!("kepr-pam-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("kepr");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let mine = std::fs::metadata(&f).unwrap().uid();
        for mode in [0o755, 0o775, 0o757, 0o777] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            let want = mine == 0 && mode & 0o022 == 0;
            assert_eq!(trusted_binary(&f), want, "{mode:o} owned by {mine}");
        }
        assert!(!trusted_binary(&d), "a directory");
        assert!(!trusted_binary(&d.join("missing")));
        assert_eq!(pick_kepr(&[d.join("missing")]), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_helper_gets_a_clean_environment() {
        let env = helper_env(1000, "/home/a");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1000"));
        assert_eq!(get("HOME"), Some("/home/a"));
        assert_eq!(get("PATH"), Some("/usr/bin:/bin"));
        assert!(env.iter().all(|(k, _)| !k.contains("PASS")));
    }

    #[test]
    fn root_is_left_alone() {
        assert!(!applies_to(0));
        assert!(applies_to(1000));
    }

    #[test]
    fn only_a_successful_login_establishes_credentials() {
        assert!(credentials_established(PAM_ESTABLISH_CRED));
        assert!(credentials_established(PAM_REINITIALIZE_CRED | PAM_SILENT));
        assert!(credentials_established(PAM_REFRESH_CRED));
        assert!(!credentials_established(PAM_DELETE_CRED));
        assert!(!credentials_established(0));
        assert!(is_update(PAM_UPDATE_AUTHTOK));
        assert!(!is_update(PAM_PRELIM_CHECK));
        assert!(!is_update(PAM_UPDATE_AUTHTOK | PAM_PRELIM_CHECK));
        assert!(!is_update(0));
    }

    #[test]
    fn a_session_for_another_user_gets_no_password() {
        // alice authenticated; `sudo -u bob` opens a session for bob.
        let st = Stash::new(b"alice", b"alice-pw");
        assert!(st.input_for(b"bob").is_none());
        assert!(st.input_for(b"root").is_none());
        assert!(st.input_for(b"alic").is_none(), "a prefix is not the user");
        let got = st.input_for(b"alice").unwrap();
        assert_eq!(got.as_bytes(), b"alice-pw\0");
    }

    #[test]
    fn the_password_is_sent_once_per_login() {
        let mut st = Stash::new(b"a", b"pw");
        assert!(st.input_for(b"a").is_some());
        st.mark_sent();
        assert!(st.is_sent());
        assert!(st.input_for(b"a").is_none(), "setcred, then session");
        // A new password during the login is a new thing to send.
        st.changed(b"a", Some(REPLY_NOT_RUNNING), (b"pw", b"pw2"));
        assert!(!st.is_sent());
        assert!(st.input_for(b"a").is_some());
        assert!(Stash::new(b"a", b"").input_for(b"a").is_none());
    }

    #[test]
    fn a_password_changed_during_the_login_follows_the_answer() {
        // Done: the store already has the new one.
        let mut st = Stash::new(b"a", b"old");
        st.changed(b"a", Some(REPLY_DONE), (b"old", b"new"));
        assert_eq!(st.input_for(b"a").unwrap().as_bytes(), b"new\0");
        // kepr not running yet: unlock with the old one, then move it.
        let mut st = Stash::new(b"a", b"old");
        st.changed(b"a", Some(REPLY_NOT_RUNNING), (b"old", b"new"));
        assert_eq!(st.input_for(b"a").unwrap().as_bytes(), b"old\0new\0");
        // Refused, off, or no answer: the store keeps the old one.
        for code in [Some(12), Some(REPLY_OFF), None] {
            let mut st = Stash::new(b"a", b"x");
            st.changed(b"a", code, (b"old", b"new"));
            assert_eq!(st.input_for(b"a").unwrap().as_bytes(), b"old\0", "{code:?}");
        }
    }

    #[test]
    fn helper_answers() {
        assert_eq!(parse_reply(b"0\n"), Some((0, None)));
        assert_eq!(
            parse_reply(b"12 kepr: not changed (bad)\n"),
            Some((12, Some("kepr: not changed (bad)".into())))
        );
        // Control characters can't reach the terminal.
        assert_eq!(
            parse_reply(b"0 hi\x1b[2J there\x07\n"),
            Some((0, Some("hi[2J there".into())))
        );
        let long = format!("0 {}\n", "x".repeat(1000));
        assert_eq!(parse_reply(long.as_bytes()).unwrap().1.unwrap().len(), 300);
        for bad in [&b""[..], b"\n", b"ok\n", b"x 1\n", &[0xff, 0xfe]] {
            assert_eq!(parse_reply(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn two_passwords_are_nul_terminated() {
        assert_eq!(Secret::pair(b"old", b"new").as_bytes(), b"old\0new\0");
    }

    #[test]
    fn wiping_zeroes_every_byte() {
        let mut b = *b"hunter2";
        wipe(&mut b);
        assert_eq!(b, [0u8; 7]);
        wipe(&mut []);
    }
}
