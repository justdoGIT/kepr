// protocol_session.rs — wire types of the `session` ticket batch:
// re-authentication before reveal (T11.14). Wrapped by
// `Request::Session` / `Response::Session`, which are
// `#[serde(untagged)]` and tried after every tagged variant, so the
// `cmd` / `kind` names here must not repeat one in protocol.rs.
//
// The only secret here is the store passphrase of `Reauth`, carried as a
// `ZeroString` like `Request::Unlock`'s.

use serde::{Deserialize, Serialize};

use crate::generate::ZeroString;

/// The `Response::Err` text of a `Get` (or `ReauthFlag { on: false }`)
/// that needs the store passphrase first. Clients prompt on exactly this.
pub const REAUTH_NEEDED: &str = "reauth needed";

/// How long a successful `Reauth` keeps a credential readable.
pub const REAUTH_WINDOW_SECS: u64 = 60;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SessionRequest {
    /// T11.14: check the store passphrase (rate-limited like `unlock`)
    /// and open a `REAUTH_WINDOW_SECS` reveal window for `name`.
    Reauth {
        name: String,
        passphrase: ZeroString,
    },
    /// T11.14: require re-authentication before `name` is revealed, or
    /// stop requiring it (`on: false` needs an open window).
    ReauthFlag { name: String, on: bool },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionResponse {
    /// The window for `name` is open for `valid_secs`.
    ReauthOk { name: String, valid_secs: u64 },
    /// `name` now does (`on`) or doesn't require re-authentication.
    ReauthFlagOk { name: String, on: bool },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn requests_round_trip_through_the_core_enum() {
        let reqs = [
            Request::Session(SessionRequest::Reauth {
                name: "K".into(),
                passphrase: ZeroString::from_string("pw".into()),
            }),
            Request::Session(SessionRequest::ReauthFlag {
                name: "K".into(),
                on: true,
            }),
        ];
        for r in reqs {
            let wire = serde_json::to_string(&r).unwrap();
            let back: Request = serde_json::from_str(&wire).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
            assert!(matches!(back, Request::Session(_)), "{wire}");
        }
        let wire = r#"{"cmd":"reauth_flag","name":"K","on":false}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(wire).unwrap(),
            Request::Session(SessionRequest::ReauthFlag { on: false, .. })
        ));
    }

    #[test]
    fn responses_round_trip_through_the_core_enum() {
        let resps = [
            Response::Session(SessionResponse::ReauthOk {
                name: "K".into(),
                valid_secs: REAUTH_WINDOW_SECS,
            }),
            Response::Session(SessionResponse::ReauthFlagOk {
                name: "K".into(),
                on: false,
            }),
        ];
        for r in resps {
            let wire = serde_json::to_string(&r).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
            assert!(matches!(back, Response::Session(_)), "{wire}");
        }
        // The tagged core variants still win.
        assert!(matches!(
            serde_json::from_str::<Response>(r#"{"kind":"err","error":"reauth needed"}"#),
            Ok(Response::Err { .. })
        ));
    }
}
