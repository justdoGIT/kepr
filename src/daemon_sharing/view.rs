// daemon_sharing/view.rs — T11.15 view windows on received shares.
//
// The sender picks `--view-window 5m`; it travels in the share payload.
// The receiving daemon stores the value with `.meta` `view_window_secs`.
// The first `get` turns that into an ordinary expiry (`expires_at_unix`
// = then + window) and clears it, so from then on the existing TTL
// machinery refuses the value and the sweeper deletes it.
//
// Fail-closed: if the first get can't record the start of the window,
// the value is not returned.

use kepr_core::protocol::Response;

use crate::audit::username_for_uid;
use crate::expiry;
use crate::store::cred_path;

pub const MAX_WINDOW: u64 = 30 * 86_400;

pub fn check(window: Option<u64>) -> Result<(), String> {
    match window {
        Some(w) if w == 0 || w > MAX_WINDOW => {
            Err("--view-window must be 1 second to 30 days".into())
        }
        _ => Ok(()),
    }
}

fn meta_path(uid: u32, upper: &str) -> std::path::PathBuf {
    expiry::meta_path_for(&cred_path(uid, upper))
}

/// Give `upper` (just stored from a share) a view window.
pub(crate) fn mark(uid: u32, upper: &str, window: u64) -> Result<(), String> {
    check(Some(window))?;
    let _lock = crate::daemon_credlock::lock(uid, upper);
    let path = meta_path(uid, upper);
    let mut meta = match expiry::read_meta(&path) {
        None => expiry::CredMeta::default(),
        Some(Ok(m)) => m,
        Some(Err(e)) => return Err(e),
    };
    meta.view_window_secs = Some(window);
    expiry::write_meta(&path, &meta)
}

/// After a received share was stored as `name`: give it its view
/// window. If that fails the value is deleted again (never kept
/// without the window the sender asked for).
pub(crate) fn after_store(
    uid: u32,
    username: &str,
    name: &str,
    window: Option<u64>,
    stored: Response,
) -> Response {
    let (Some(w), Response::SetOk { .. }) = (window, &stored) else {
        return stored;
    };
    match mark(uid, name, w) {
        Ok(()) => stored,
        Err(e) => {
            let _ = crate::daemon_handlers::handle_delete(uid, username, name);
            Response::fail(format!("cannot set the view window: {e}"))
        }
    }
}

/// Called by `Get` (under the credential's lock) right before the
/// decrypt: start a pending view window at `now`.
pub(crate) fn start_at(uid: u32, upper: &str, now: u64) -> Result<(), String> {
    let path = meta_path(uid, upper);
    let Some(Ok(mut meta)) = expiry::read_meta(&path) else {
        return Ok(()); // no meta: no window (an unreadable one fails the gate)
    };
    let Some(window) = meta.view_window_secs.take() else {
        return Ok(());
    };
    let end = now.saturating_add(window);
    meta.expires_at_unix = Some(meta.expires_at_unix.map_or(end, |e| e.min(end)));
    expiry::write_meta(&path, &meta)
}

/// `Get`'s hook: `Err` means "don't return the value".
pub fn start(uid: u32, upper: &str) -> Result<(), ()> {
    start_at(uid, upper, expiry::now_unix()).map_err(|e| {
        let username = username_for_uid(uid);
        super::audit_r::<()>("view-window", uid, &username, Some(upper), &Err(e));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_handlers_get::handle_get;
    use crate::daemon_store::testkit;

    #[test]
    fn the_first_get_starts_the_window() {
        let u = testkit::uid();
        testkit::set(u, "VW_A", "v");
        mark(u, "VW_A", 300).unwrap();
        assert_eq!(testkit::meta(u, "VW_A").view_window_secs, Some(300));
        let before = expiry::now_unix();
        assert!(matches!(
            handle_get(u, 0, "t", "VW_A", None),
            Response::GetOk { .. }
        ));
        let m = testkit::meta(u, "VW_A");
        assert_eq!(m.view_window_secs, None);
        let exp = m.expires_at_unix.expect("window started");
        assert!((before + 300..=expiry::now_unix() + 300).contains(&exp));
        // A second get inside the window works and doesn't move it.
        assert!(handle_get(u, 0, "t", "VW_A", None).is_success());
        assert_eq!(testkit::meta(u, "VW_A").expires_at_unix, Some(exp));
    }

    #[test]
    fn after_the_window_get_is_refused_and_the_sweeper_deletes_it() {
        let u = testkit::uid();
        testkit::set(u, "VW_C", "v");
        mark(u, "VW_C", 300).unwrap();
        // The first read was 400 s ago: the window closed 100 s ago.
        start_at(u, "VW_C", expiry::now_unix() - 400).unwrap();
        let r = handle_get(u, 0, "t", "VW_C", None);
        assert!(matches!(&r, Response::Err { error } if error == "credential unavailable"));
        let dir = crate::store::store_dir();
        crate::daemon_expiry::sweep_once(&dir, expiry::now_unix(), None);
        assert!(!crate::store::cred_exists(u, "VW_C"));
    }

    #[test]
    fn an_earlier_ttl_is_kept() {
        let u = testkit::uid();
        testkit::set(u, "VW_B", "v");
        let path = meta_path(u, "VW_B");
        let mut m = testkit::meta(u, "VW_B");
        m.expires_at_unix = Some(1_000);
        m.view_window_secs = Some(600);
        expiry::write_meta(&path, &m).unwrap();
        start_at(u, "VW_B", 900).unwrap();
        assert_eq!(testkit::meta(u, "VW_B").expires_at_unix, Some(1_000));
        m.expires_at_unix = Some(10_000);
        m.view_window_secs = Some(600);
        expiry::write_meta(&path, &m).unwrap();
        start_at(u, "VW_B", 900).unwrap();
        assert_eq!(testkit::meta(u, "VW_B").expires_at_unix, Some(1_500));
    }

    #[test]
    fn window_bounds() {
        assert!(check(None).is_ok());
        assert!(check(Some(1)).is_ok());
        assert!(check(Some(MAX_WINDOW)).is_ok());
        assert!(check(Some(0)).is_err());
        assert!(check(Some(MAX_WINDOW + 1)).is_err());
    }
}
