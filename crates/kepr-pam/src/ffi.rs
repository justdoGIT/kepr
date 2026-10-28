//! The PAM entry points. Every one returns PAM_IGNORE: this module adds a
//! convenience (unlocking kepr) and must never decide a login.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::logic;

const PAM_IGNORE: c_int = 25;
const PAM_SUCCESS: c_int = 0;
const PAM_AUTHTOK: c_int = 6;
const DATA: &CStr = c"pam_kepr_authtok";

extern "C" {
    fn pam_get_item(pamh: *const c_void, item: c_int, out: *mut *const c_void) -> c_int;
    fn pam_get_user(pamh: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_set_data(
        pamh: *mut c_void,
        name: *const c_char,
        data: *mut c_void,
        cleanup: Option<extern "C" fn(*mut c_void, *mut c_void, c_int)>,
    ) -> c_int;
    fn pam_get_data(pamh: *const c_void, name: *const c_char, out: *mut *const c_void) -> c_int;
}

fn args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..argc.max(0) as usize)
        // SAFETY: PAM passes argc valid NUL-terminated strings in argv.
        .map(|i| {
            unsafe { CStr::from_ptr(*argv.add(i)) }
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn log(msg: &str) {
    if let Ok(c) = CString::new(format!("pam_kepr: {msg}")) {
        // SAFETY: a constant "%s" format with one valid C string.
        unsafe { libc::syslog(libc::LOG_AUTH | libc::LOG_INFO, c"%s".as_ptr(), c.as_ptr()) };
    }
}

/// Wipes and frees the remembered password when the PAM handle ends.
extern "C" fn wipe(_pamh: *mut c_void, data: *mut c_void, _status: c_int) {
    if data.is_null() {
        return;
    }
    // SAFETY: `data` came from CString::into_raw in remember().
    let c = unsafe { CString::from_raw(data as *mut c_char) };
    let mut bytes = c.into_bytes_with_nul();
    for b in bytes.iter_mut() {
        // SAFETY: a volatile write to a byte we own, so the wipe is not optimised out.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

fn remember(pamh: *mut c_void) {
    let mut tok: *const c_void = std::ptr::null();
    // SAFETY: pamh is the live handle PAM passed in; `tok` receives a borrowed pointer.
    let rc = unsafe { pam_get_item(pamh, PAM_AUTHTOK, &mut tok) };
    if rc != PAM_SUCCESS || tok.is_null() {
        return;
    }
    // SAFETY: PAM_AUTHTOK is a NUL-terminated string owned by the handle.
    let copy = unsafe { CStr::from_ptr(tok as *const c_char) }.to_owned();
    if copy.as_bytes().is_empty() {
        return;
    }
    // SAFETY: ownership of the raw string passes to PAM, which calls `wipe` once.
    unsafe {
        pam_set_data(
            pamh,
            DATA.as_ptr(),
            copy.into_raw() as *mut c_void,
            Some(wipe),
        )
    };
}

fn password(pamh: *mut c_void) -> Option<CString> {
    let mut p: *const c_void = std::ptr::null();
    // SAFETY: as in remember(); data set by us earlier, or null.
    let have = unsafe { pam_get_data(pamh, DATA.as_ptr(), &mut p) } == PAM_SUCCESS && !p.is_null();
    if !have {
        // SAFETY: as in remember().
        let rc = unsafe { pam_get_item(pamh, PAM_AUTHTOK, &mut p) };
        if rc != PAM_SUCCESS || p.is_null() {
            return None;
        }
    }
    // SAFETY: a NUL-terminated string owned by PAM.
    let c = unsafe { CStr::from_ptr(p as *const c_char) }.to_owned();
    (!c.as_bytes().is_empty()).then_some(c)
}

struct User {
    uid: u32,
    gid: u32,
    home: String,
    name: CString,
}

fn lookup(pamh: *mut c_void) -> Option<User> {
    let mut u: *const c_char = std::ptr::null();
    // SAFETY: pamh is live; `u` receives a borrowed string.
    if unsafe { pam_get_user(pamh, &mut u, std::ptr::null()) } != PAM_SUCCESS || u.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated, owned by the handle.
    let name = unsafe { CStr::from_ptr(u) }.to_owned();
    let mut buf = vec![0 as c_char; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value of this plain C struct.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r fills `pw` and `buf` (valid for their sizes) and sets `out`.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`.
    let home = unsafe { CStr::from_ptr(pw.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Some(User {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
        home,
        name,
    })
}

fn groups(u: &User) -> Vec<libc::gid_t> {
    let mut n: c_int = 64;
    let mut g = vec![0 as libc::gid_t; n as usize];
    // SAFETY: `g` holds `n` entries; getgrouplist updates `n`.
    let rc = unsafe { libc::getgrouplist(u.name.as_ptr(), u.gid, g.as_mut_ptr(), &mut n) };
    if rc < 0 {
        return vec![u.gid];
    }
    g.truncate(n.max(0) as usize);
    g
}

fn unlock_as(u: &User, kepr: &std::path::Path, pw: &CString) -> std::io::Result<()> {
    let gids = groups(u);
    let (uid, gid) = (u.uid, u.gid);
    let mut cmd = Command::new(kepr);
    cmd.arg("pam-unlock")
        .env_clear()
        .envs(logic::helper_env(uid, &u.home))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe calls (setgroups, setgid, setuid, a
    // check that root cannot be regained) run between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(gids.len(), gids.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
                || libc::setuid(0) == 0
            {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let mut line = pw.as_bytes().to_vec();
        line.push(b'\n');
        let r = stdin.write_all(&line);
        for b in line.iter_mut() {
            // SAFETY: volatile wipe of our own buffer.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        r?;
    }
    // `kepr pam-unlock` detaches at once; this only reaps it.
    child.wait().map(drop)
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    remember(pamh);
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let opts = logic::parse_opts(&args(argc, argv));
    let Some(user) = lookup(pamh) else {
        return PAM_IGNORE;
    };
    if !logic::applies_to(user.uid) {
        return PAM_IGNORE;
    }
    let Some(kepr) = logic::pick_kepr(&opts.kepr) else {
        log("no trusted kepr binary (root-owned, not group/other writable); not unlocking");
        return PAM_IGNORE;
    };
    let Some(pw) = password(pamh) else {
        if opts.debug {
            log("no password in this PAM stack; not unlocking");
        }
        return PAM_IGNORE;
    };
    match unlock_as(&user, kepr, &pw) {
        Ok(()) if opts.debug => log("handed the login password to kepr pam-unlock"),
        Ok(()) => {}
        Err(e) => log(&format!("could not run kepr pam-unlock: {e}")),
    }
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
