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
    /// T11.18 (CLI only, for `--json`): every line of `kepr batch` ran.
    BatchOk { ran: u32 },
}

/// T11.24: what `kepr status` shows beyond the lock state, flattened into
/// `Response::StatusOk`. Every field is optional: an older daemon sends
/// none of them and its status still parses.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// `user` or `system`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The daemon's profile (T11.16); `default` when none is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// `file` or `image` (T4.06 vault image).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_backend: Option<String>,
    /// What protects the master key at rest: `passphrase`, `host` (the
    /// credential backend, system mode) or `file` (owner-only key file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sealer: Option<String>,
    /// Agent gates running for the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gates: Option<u32>,
    /// Account-transfer escrow (T6.14) is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow: Option<bool>,
    /// The FIPS-validated crypto module is in use (T7.16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fips: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn status_info_rides_in_status_ok_and_old_daemons_still_parse() {
        let full = StatusInfo {
            mode: Some("user".into()),
            profile: Some("default".into()),
            store_backend: Some("file".into()),
            key_sealer: Some("passphrase".into()),
            gates: Some(2),
            escrow: Some(false),
            fips: Some(false),
        };
        let r = Response::StatusOk {
            locked: false,
            password_protected: true,
            info: full.clone(),
        };
        let v = serde_json::to_value(&r).unwrap();
        for k in [
            "kind",
            "locked",
            "password_protected",
            "mode",
            "profile",
            "store_backend",
            "key_sealer",
            "gates",
            "escrow",
            "fips",
        ] {
            assert!(v.get(k).is_some(), "{k} missing from {v}");
        }
        match serde_json::from_value::<Response>(v).unwrap() {
            Response::StatusOk { info, .. } => assert_eq!(info, full),
            other => panic!("{other:?}"),
        }
        let old = r#"{"kind":"status_ok","locked":true,"password_protected":false}"#;
        match serde_json::from_str::<Response>(old).unwrap() {
            Response::StatusOk { locked, info, .. } => {
                assert!(locked);
                assert_eq!(info, StatusInfo::default());
            }
            other => panic!("{other:?}"),
        }
    }

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
            Response::Session(SessionResponse::BatchOk { ran: 3 }),
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
