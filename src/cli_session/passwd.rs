// cli_session/passwd.rs — `kepr passwd` (T13.25): change the store
// passphrase. The daemon checks the current one (with the same backoff and
// opt-in wipe as `kepr unlock`) and wraps the master key under the new one;
// nothing is re-encrypted. Keep it equal to the login password when login
// unlock is on; with pam_kepr.so in the password stack, `passwd` does that.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_session::{SessionRequest, SessionResponse};

use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui};

/// The request from the three answers, or why there is none.
pub fn request(old: ZeroString, new: ZeroString, again: &str) -> Result<SessionRequest, String> {
    if old.is_empty() || new.is_empty() {
        return Err("password cannot be empty".into());
    }
    if new.as_str() != again {
        return Err("passphrases do not match".into());
    }
    Ok(SessionRequest::ChangePassphrase {
        old,
        new,
        login: false,
    })
}

pub fn cmd_passwd(args: &[&str]) -> Response {
    if !args.is_empty() {
        return Response::fail("usage: kepr passwd");
    }
    let old = read_masked("  Current passphrase: ");
    let new = read_masked("  New passphrase: ");
    let again = read_masked("  Confirm new passphrase: ");
    let req = match request(old, new, again.as_str()) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let r = crate::client::send_request(&Request::Session(req)).unwrap_or_else(Response::fail);
    if !cli_mode::json_mode() && matches!(r, Response::Session(SessionResponse::PassphraseChanged))
    {
        cli_ui::ok("Store passphrase changed.");
        if super::login_unlock::is_on() {
            cli_ui::info(
                "Login unlock is on: keep this passphrase the same as your login password.",
            );
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_passphrase_is_asked_twice() {
        let r = request("a".into(), "b".into(), "b").unwrap();
        assert!(matches!(
            r,
            SessionRequest::ChangePassphrase { login: false, .. }
        ));
        assert!(request("a".into(), "b".into(), "c")
            .unwrap_err()
            .contains("do not match"));
        assert!(request("".into(), "b".into(), "b").is_err());
        assert!(request("a".into(), "".into(), "").is_err());
    }
}
