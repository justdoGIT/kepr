// protocol_session.rs — wire types of the `session` ticket batch:
// re-authentication before reveal (T11.14), `kepr status` details
// (T11.24), `kepr batch` (T11.18), `kepr ssh rotate` (T11.21), fetch as
// an fd (T3.06), unlock at login and passphrase change (T13.25). Wrapped
// by `Request::Session` / `Response::Session`, which are
// `#[serde(untagged)]` and tried after every tagged variant, so the
// `cmd` / `kind` names here must not repeat one in protocol.rs.
//
// The only secrets here are store passphrases (`Reauth`, `LoginUnlock`,
// `ChangePassphrase`), carried as `ZeroString` like `Request::Unlock`'s.

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
    /// T11.21 `kepr ssh rotate`: after the host accepted `next`, make
    /// `next`'s key `name`'s and delete `next`. Answers `SshKeyOk`.
    SshRotateCommit { name: String, next: String },
    /// T11.19 `kepr serve`: a `Get` that never prompts. A credential
    /// needing consent, FIDO2 or re-authentication reads as unavailable,
    /// even while a reveal window is open. Answers like `Get`.
    GetQuiet { name: String },
    /// T3.06: `name` under `Get`'s policy, answered with `FdOk` and then
    /// a sealed read-only memfd (SCM_RIGHTS) instead of the value.
    FetchFd { name: String },
    /// T13.25: `Unlock` with the password typed at login (`kepr
    /// pam-unlock`). User mode only; an unlocked store answers
    /// `UnlockedOk` without trying it; failures count against a budget of
    /// their own that never wipes and closes after
    /// `login_unlock::MAX_FAILURES`; a store locked by `kepr panic` stays
    /// locked.
    LoginUnlock { password: ZeroString },
    /// T13.25: wrap the master key under `new` after checking `old`
    /// (`kepr passwd`; `login`: from the PAM password hook, on the login
    /// budget). Answers `PassphraseChanged`.
    ChangePassphrase {
        old: ZeroString,
        new: ZeroString,
        #[serde(default)]
        login: bool,
    },
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
    /// T3.06: the memfd holding `len` bytes follows on the socket.
    FdOk { len: u64 },
    /// T13.25: the store passphrase is now the new one.
    PassphraseChanged,
    /// T13.25 (CLI only, for `--json`): `kepr login-unlock status`. A unit
    /// is `None` when systemd doesn't know it.
    LoginUnlockInfo {
        on: bool,
        daemon_unit: Option<bool>,
        ssh_agent_unit: Option<bool>,
        pam_services: Vec<String>,
    },
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
    /// What protects the master key at rest: `passphrase` or
    /// `passphrase+fido2`; `file` (owner-only key file); the credential
    /// backend's `host`, `tpm2` or `host+tpm2` (`host-unrecorded` for a
    /// key sealed before that was recorded); `tpm2+pin+pcrs+counter` (or
    /// a subset) for the TPM2 PIN / counter sealer; `aws-kms`, `gcp-kms`,
    /// `azure-kv`, `pkcs11`; `keychain`; `unseal-failed` (T12.32).
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
    /// A recovery key for the sealed master key is enrolled (T12.31);
    /// `None` on a passphrase store that has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<bool>,
    /// T13.25: failed login unlocks in a row (none = zero). A `u8`: the
    /// count stops at `login_unlock::MAX_FAILURES`, and a wider field would
    /// push `Response` past clippy's `result_large_err` limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_failures: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    /// `Response` rides in `Result<_, Response>` all over the CLI; at 128
    /// bytes clippy's `result_large_err` fires on every one of them.
    #[test]
    fn response_stays_small_enough_to_be_a_result_error() {
        assert!(
            std::mem::size_of::<Response>() < 128,
            "Response is {} bytes: box or narrow the field that grew it",
            std::mem::size_of::<Response>()
        );
    }

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
            recovery_key: Some(true),
            login_failures: Some(2),
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
            "recovery_key",
            "login_failures",
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
            Request::Session(SessionRequest::SshRotateCommit {
                name: "K".into(),
                next: "K_NEXT".into(),
            }),
            Request::Session(SessionRequest::GetQuiet { name: "K".into() }),
            Request::Session(SessionRequest::FetchFd { name: "K".into() }),
            Request::Session(SessionRequest::LoginUnlock {
                password: ZeroString::from_string("pw".into()),
            }),
            Request::Session(SessionRequest::ChangePassphrase {
                old: ZeroString::from_string("a".into()),
                new: ZeroString::from_string("b".into()),
                login: true,
            }),
        ];
        for r in reqs {
            let wire = serde_json::to_string(&r).unwrap();
            let back: Request = serde_json::from_str(&wire).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
            assert!(matches!(back, Request::Session(_)), "{wire}");
        }
        let wire = r#"{"cmd":"fetch_fd","name":"K"}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(wire).unwrap(),
            Request::Session(SessionRequest::FetchFd { .. })
        ));
        let wire = r#"{"cmd":"reauth_flag","name":"K","on":false}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(wire).unwrap(),
            Request::Session(SessionRequest::ReauthFlag { on: false, .. })
        ));
        // `login` defaults to the ordinary (manual) path.
        let wire = r#"{"cmd":"change_passphrase","old":"a","new":"b"}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(wire).unwrap(),
            Request::Session(SessionRequest::ChangePassphrase { login: false, .. })
        ));
        // The core `unlock` is still the core variant.
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"unlock","password":"x"}"#).unwrap(),
            Request::Unlock { .. }
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
            Response::Session(SessionResponse::FdOk { len: 12 }),
            Response::Session(SessionResponse::PassphraseChanged),
            Response::Session(SessionResponse::LoginUnlockInfo {
                on: true,
                daemon_unit: Some(true),
                ssh_agent_unit: None,
                pam_services: vec!["login".into()],
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
