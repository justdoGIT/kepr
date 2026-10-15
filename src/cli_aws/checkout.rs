// cli_aws/checkout.rs — `kepr checkout` / `kepr checkin` (T7.11).
//
//   kepr checkout NAME [--for 2h]            take it; prints the token
//   kepr checkin NAME [--token T] [--rotate] give it back
//
// The daemon mints a token when the credential is checked out and only
// that token checks it back in (daemon_aws/checkout.rs). The token is
// kept in the user's state directory, so the session that took the
// credential checks it in with no flags; another session, which never
// saw it, is refused. `--rotate` rotates the value first, through the
// credential's own rotation (`kepr rotate --scheduled`, T7.07), and
// checks in only if that worked. Nothing here prints a credential.

use std::io::Write;
use std::path::PathBuf;

use kepr_core::protocol::{CredInfo, Request, Response};
use kepr_core::protocol_aws::{AwsRequest, AwsResponse, HOLD_SECS};

const USAGE: &str = "usage: kepr checkout NAME [--for 2h] | kepr checkin NAME [--token T] \
                     [--rotate]";

/// Where the token of a hold this session took is kept:
/// `$XDG_STATE_HOME/kepr/holds` (or `~/.local/state/kepr/holds`).
fn token_path(name: &str) -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
        });
    base.join("kepr/holds").join(format!("{name}.token"))
}

fn save_token(name: &str, token: &str) -> Result<(), String> {
    let p = token_path(name);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    crate::cli_agent_egress::write_private(&p, token.as_bytes())
}

/// `--token`, else `$KEPR_HOLD_TOKEN`, else what `checkout` saved.
fn token_for(name: &str, flag: Option<&str>) -> Result<String, String> {
    if let Some(t) = flag {
        return Ok(t.to_string());
    }
    if let Some(t) = std::env::var_os("KEPR_HOLD_TOKEN") {
        return Ok(t.to_string_lossy().into_owned());
    }
    std::fs::read_to_string(token_path(name))
        .map(|t| t.trim().to_string())
        .map_err(|_| {
            format!(
                "no check-in token for {name} here: pass --token (checkout printed it) — the \
                 hold frees itself when it runs out"
            )
        })
}

fn secs(args: &[&str]) -> Result<u64, String> {
    match super::flag(args, "--for") {
        None => Ok(HOLD_SECS),
        Some(s) => super::grant::parse_for(s),
    }
}

fn checkout(args: &[&str]) -> Response {
    let name = match super::positional(args, &["--for"]) {
        Some(n) => n.to_uppercase(),
        None => return Response::fail(USAGE),
    };
    let for_secs = match secs(args) {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    let req = Request::Aws(AwsRequest::AwsCheckout {
        name: name.clone(),
        for_secs,
    });
    let r = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if let Response::Aws(AwsResponse::AwsCheckedOut { token, until, .. }) = &r {
        if let Err(e) = save_token(&name, token) {
            crate::cli_ui::warn(&format!("keep the token safe, it wasn't saved ({e})"));
        }
        if !crate::cli_ui::json_mode() {
            let left = super::rotate_sched::rough(until.saturating_sub(now()));
            crate::cli_ui::ok(&format!(
                "{name} checked out for {left}: nobody else can take it until then"
            ));
            crate::cli_ui::info(&format!(
                "check in with `kepr checkin {name}` here, or `--token {token}` elsewhere"
            ));
            std::io::stdout().flush().ok();
        }
    }
    r
}

fn checkin(args: &[&str]) -> Response {
    let name = match super::positional(args, &["--token"]) {
        Some(n) => n.to_uppercase(),
        None => return Response::fail(USAGE),
    };
    let token = match token_for(&name, super::flag(args, "--token")) {
        Ok(t) => t,
        Err(e) => return Response::fail(e),
    };
    let rotated = args.contains(&"--rotate");
    if rotated {
        let r = super::rotate_sched::run_scheduled(&name);
        if let Some(e) = r.err_msg() {
            return Response::fail(format!("{name} stays checked out: {e}"));
        }
    }
    let req = Request::Aws(AwsRequest::AwsCheckin {
        name: name.clone(),
        token,
        rotated,
    });
    let r = crate::client::send_request(&req).unwrap_or_else(Response::fail);
    if matches!(r, Response::Aws(AwsResponse::AwsCheckedIn { .. })) {
        let _ = std::fs::remove_file(token_path(&name));
        if !crate::cli_ui::json_mode() {
            let how = if rotated { ", rotated" } else { "" };
            crate::cli_ui::ok(&format!("{name} checked in{how}"));
        }
    }
    r
}

pub fn cmd(verb: &str, args: &[&str]) -> Response {
    match verb {
        "checkout" => checkout(args),
        _ => checkin(args),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `kepr list`: who holds it.
pub fn list_tail(c: &CredInfo) -> String {
    let now = now();
    let me = unsafe { libc::getuid() };
    match (c.held_until, c.held_by_uid) {
        (Some(until), _) if until <= now => String::new(),
        (Some(until), Some(uid)) => {
            let who = if uid == me {
                String::new()
            } else {
                format!(" by uid {uid}")
            };
            let left = super::rotate_sched::rough(until - now);
            format!("  (checked out{who}, {left} left)")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_and_a_window() {
        assert_eq!(secs(&["K"]), Ok(HOLD_SECS));
        assert_eq!(secs(&["K", "--for", "2h"]), Ok(7200));
        assert!(secs(&["K", "--for", "nope"]).is_err());
        assert!(super::super::positional(&["--for", "2h"], &["--for"]).is_none());
        assert!(matches!(cmd("checkout", &[]), Response::Err { .. }));
        assert!(matches!(
            cmd("checkin", &["--token", "ab"]),
            Response::Err { .. }
        ));
    }

    #[test]
    fn the_token_comes_from_the_flag_the_env_or_the_saved_file() {
        let name = format!("HOLD_TEST_{}", std::process::id());
        assert_eq!(token_for(&name, Some("flag")), Ok("flag".into()));
        let e = token_for(&name, None).unwrap_err();
        assert!(e.contains("no check-in token"), "{e}");
        std::env::set_var("KEPR_HOLD_TOKEN", "from-env");
        assert_eq!(token_for(&name, None), Ok("from-env".into()));
        std::env::remove_var("KEPR_HOLD_TOKEN");
        save_token(&name, "saved").unwrap();
        assert_eq!(token_for(&name, None), Ok("saved".into()));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(token_path(&name)).unwrap().permissions();
        assert_eq!(mode.mode() & 0o777, 0o600);
        std::fs::remove_file(token_path(&name)).unwrap();
    }

    #[test]
    fn list_shows_a_live_hold_only() {
        let mut c = CredInfo {
            name: "K".into(),
            ..Default::default()
        };
        assert_eq!(list_tail(&c), "");
        c.held_by_uid = Some(1000);
        c.held_until = Some(now() + 7200);
        let me = unsafe { libc::getuid() };
        let who = if me == 1000 { "" } else { " by uid 1000" };
        assert_eq!(list_tail(&c), format!("  (checked out{who}, 2h left)"));
        c.held_by_uid = Some(me);
        assert_eq!(list_tail(&c), "  (checked out, 2h left)");
        c.held_until = Some(now() - 1);
        assert_eq!(list_tail(&c), "");
    }
}
