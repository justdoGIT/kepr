//! The PAM entry points. Every one returns PAM_IGNORE: this module adds a
//! convenience (kepr follows the login password) and must never decide a
//! login, delay it for long or make it depend on kepr.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use crate::logic::{self, Early, Opts, Secret, Stash};
use crate::spawn::{lookup, run_helper, User};

const PAM_IGNORE: c_int = 25;
const PAM_SUCCESS: c_int = 0;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_TEXT_INFO: c_int = 4;
const DATA: &CStr = c"pam_kepr_stash";

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
    fn pam_prompt(
        pamh: *mut c_void,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
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

/// A line for the user's terminal, unless the application asked for quiet.
fn info(pamh: *mut c_void, flags: c_int, msg: &str) {
    if flags & logic::PAM_SILENT != 0 {
        return;
    }
    if let Ok(c) = CString::new(msg) {
        // SAFETY: a constant "%s" format with one valid C string; no reply wanted.
        unsafe {
            pam_prompt(
                pamh,
                PAM_TEXT_INFO,
                std::ptr::null_mut(),
                c"%s".as_ptr(),
                c.as_ptr(),
            )
        };
    }
}

/// Wipes and frees the stash when the PAM handle ends.
extern "C" fn drop_stash(_pamh: *mut c_void, data: *mut c_void, _status: c_int) {
    if !data.is_null() {
        // SAFETY: `data` came from Box::into_raw in store() and PAM calls this once.
        drop(unsafe { Box::from_raw(data as *mut Stash) });
    }
}

/// A PAM item that holds a password, copied into memory that wipes itself.
fn item(pamh: *mut c_void, which: c_int) -> Option<Secret> {
    let mut p: *const c_void = std::ptr::null();
    // SAFETY: pamh is the live handle PAM passed in; `p` receives a borrowed pointer.
    let rc = unsafe { pam_get_item(pamh, which, &mut p) };
    if rc != PAM_SUCCESS || p.is_null() {
        return None;
    }
    // SAFETY: PAM items of these kinds are NUL-terminated strings owned by the handle.
    let bytes = unsafe { CStr::from_ptr(p as *const c_char) }.to_bytes();
    (!bytes.is_empty()).then(|| Secret::new(bytes))
}

fn user_name(pamh: *mut c_void) -> Option<CString> {
    let mut u: *const c_char = std::ptr::null();
    // SAFETY: pamh is live; `u` receives a borrowed string.
    if unsafe { pam_get_user(pamh, &mut u, std::ptr::null()) } != PAM_SUCCESS || u.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated, owned by the handle.
    Some(unsafe { CStr::from_ptr(u) }.to_owned())
}

fn stash<'a>(pamh: *mut c_void) -> Option<&'a mut Stash> {
    let mut p: *const c_void = std::ptr::null();
    // SAFETY: as in item(); the data was set by store() as a Box<Stash>.
    let rc = unsafe { pam_get_data(pamh, DATA.as_ptr(), &mut p) };
    if rc != PAM_SUCCESS || p.is_null() {
        return None;
    }
    // SAFETY: only this module's PAM calls for one handle touch it, one at a time.
    Some(unsafe { &mut *(p as *mut Stash) })
}

fn store(pamh: *mut c_void, s: Stash) {
    let raw = Box::into_raw(Box::new(s));
    // SAFETY: ownership of the box passes to PAM, which calls `drop_stash` once.
    let rc = unsafe { pam_set_data(pamh, DATA.as_ptr(), raw as *mut c_void, Some(drop_stash)) };
    if rc != PAM_SUCCESS {
        // SAFETY: PAM did not take it, so we still own the box.
        drop(unsafe { Box::from_raw(raw) });
    }
}

struct Ctx {
    opts: Opts,
    user: User,
    kepr: std::path::PathBuf,
}

/// Options, the PAM user and a trusted `kepr`, or why not.
fn context(pamh: *mut c_void, argc: c_int, argv: *const *const c_char) -> Option<Ctx> {
    let opts = logic::parse_opts(&args(argc, argv));
    let user = lookup(user_name(pamh)?)?;
    if !logic::applies_to(user.uid) {
        return None;
    }
    let Some(kepr) = logic::pick_kepr(&opts.kepr).cloned() else {
        log("no trusted kepr binary (root-owned, not group/other writable); not running it");
        return None;
    };
    Some(Ctx { opts, user, kepr })
}

/// Hand the remembered password to `kepr pam-unlock`, once per login.
fn unlock(pamh: *mut c_void, flags: c_int, ctx: &Ctx) {
    let Some(st) = stash(pamh) else {
        if ctx.opts.debug {
            log("no password in this PAM stack; not unlocking");
        }
        if ctx.opts.hint {
            hint(pamh, flags, ctx);
        }
        return;
    };
    let Some(input) = st.input_for(ctx.user.name.as_bytes()) else {
        if ctx.opts.debug {
            log("nothing to hand over for this session (another user, or already sent)");
        }
        return;
    };
    st.mark_sent();
    match run_helper(&ctx.user, &ctx.kepr, &["pam-unlock"], &input, false) {
        Ok(_) if ctx.opts.debug => log("handed the login password to kepr pam-unlock"),
        Ok(_) => {}
        Err(e) => log(&format!("could not run kepr pam-unlock: {e}")),
    }
}

/// A login with no password (ssh key, fingerprint): say kepr stays locked.
fn hint(pamh: *mut c_void, flags: c_int, ctx: &Ctx) {
    let nothing = Secret::new(b"");
    let reply = run_helper(
        &ctx.user,
        &ctx.kepr,
        &["pam-unlock", "--hint"],
        &nothing,
        true,
    )
    .ok()
    .and_then(|o| logic::parse_reply(&o));
    if let Some((logic::REPLY_DONE, Some(msg))) = reply {
        info(pamh, flags, &msg);
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // The token and the user it was checked for, kept until the session.
    if let (Some(tok), Some(user)) = (item(pamh, PAM_AUTHTOK), user_name(pamh)) {
        store(pamh, Stash::new(user.as_bytes(), tok.as_bytes()));
        if logic::parse_opts(&args(argc, argv)).early == Early::Auth {
            if let Some(ctx) = context(pamh, argc, argv) {
                unlock(pamh, flags, &ctx);
            }
        }
    }
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Applications call this only after a successful authentication.
    if logic::credentials_established(flags)
        && logic::parse_opts(&args(argc, argv)).early != Early::No
    {
        if let Some(ctx) = context(pamh, argc, argv) {
            unlock(pamh, flags, &ctx);
        }
    }
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
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if let Some(ctx) = context(pamh, argc, argv) {
        unlock(pamh, flags, &ctx);
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

/// The login password was changed (`passwd`, or an expired password at
/// login): move the store passphrase along. Place after the module that
/// updates the password; it only runs when that one succeeded.
#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if !logic::is_update(flags) {
        return PAM_IGNORE;
    }
    let (Some(old), Some(new)) = (item(pamh, PAM_OLDAUTHTOK), item(pamh, PAM_AUTHTOK)) else {
        return PAM_IGNORE; // root changing someone else's password knows no old one
    };
    let Some(ctx) = context(pamh, argc, argv) else {
        return PAM_IGNORE;
    };
    let input = Secret::pair(old.as_bytes(), new.as_bytes());
    let reply = run_helper(&ctx.user, &ctx.kepr, &["pam-passwd"], &input, true)
        .ok()
        .and_then(|o| logic::parse_reply(&o));
    let code = reply.as_ref().map(|r| r.0);
    if ctx.opts.debug {
        log(&format!("kepr pam-passwd answered {code:?}"));
    }
    if let Some((_, Some(msg))) = &reply {
        info(pamh, flags, msg);
    } else if code == Some(logic::REPLY_NOT_RUNNING) {
        info(
            pamh,
            flags,
            "kepr: it is not running, so its passphrase is unchanged; the next login moves it",
        );
    }
    if let Some(st) = stash(pamh) {
        st.changed(
            ctx.user.name.as_bytes(),
            code,
            (old.as_bytes(), new.as_bytes()),
        );
    } else {
        // An expired password changed at login: nothing was stashed yet.
        let mut st = Stash::new(ctx.user.name.as_bytes(), old.as_bytes());
        st.changed(
            ctx.user.name.as_bytes(),
            code,
            (old.as_bytes(), new.as_bytes()),
        );
        store(pamh, st);
    }
    PAM_IGNORE
}
