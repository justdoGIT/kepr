// protocol_platform.rs — wire types for the P10 platform batch (`platform`).
// batch: platform
//
// Carried inside `Request::Platform` / `Response::Platform` (untagged), so
// the JSON is flat: `{"cmd":"fingerprint_unlock"}`,
// `{"kind":"systemd_cred_ok",...}`. CLI-only verbs use the response
// variants for their `--json` output.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum PlatformRequest {
    /// T10.03: `kepr unlock --fingerprint` — reopen a store that the idle
    /// timer or the sleep watcher locked, after polkit (`io.kepr.unlock`,
    /// fingerprint through pam_fprintd) authorises the calling process.
    /// Answered with `Response::UnlockedOk`.
    FingerprintUnlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlatformResponse {
    /// T10.06 (CLI only): `kepr systemd-cred` — the `SetCredentialEncrypted=`
    /// line for a unit file (ciphertext, safe to print).
    SystemdCredOk { name: String, line: String },
    /// T10.05 (CLI only): `kepr keyring add` — the new logon key's serial.
    KeyringAdded {
        name: String,
        desc: String,
        keyring: String,
        serial: i32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Response;

    fn round_trip(resp: Response) -> Response {
        let wire = serde_json::to_string(&resp).unwrap();
        serde_json::from_str::<Response>(&wire).unwrap()
    }

    #[test]
    fn systemd_cred_ok_round_trips_through_the_core_enum() {
        let ok = Response::Platform(PlatformResponse::SystemdCredOk {
            name: "DB_PASS".into(),
            line: "SetCredentialEncrypted=db: \\\n        QUJD".into(),
        });
        let wire = serde_json::to_string(&ok).unwrap();
        assert!(wire.starts_with(r#"{"kind":"systemd_cred_ok","name":"DB_PASS""#));
        match round_trip(ok) {
            Response::Platform(PlatformResponse::SystemdCredOk { name, line }) => {
                assert_eq!(name, "DB_PASS");
                assert!(line.starts_with("SetCredentialEncrypted=db:"));
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn keyring_added_round_trips() {
        let added = PlatformResponse::KeyringAdded {
            name: "VOL".into(),
            desc: "cryptsetup:vol".into(),
            keyring: "@u".into(),
            serial: 42,
        };
        let back = round_trip(Response::Platform(added.clone()));
        assert!(matches!(back, Response::Platform(p) if p == added));
    }

    #[test]
    fn fingerprint_unlock_round_trips_and_core_requests_keep_their_variants() {
        use crate::protocol::Request;
        let r = Request::Platform(PlatformRequest::FingerprintUnlock);
        let wire = serde_json::to_string(&r).unwrap();
        assert_eq!(wire, r#"{"cmd":"fingerprint_unlock"}"#);
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::FingerprintUnlock)
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"ping"}"#).unwrap(),
            Request::Ping
        ));
    }

    #[test]
    fn core_responses_still_decode_as_their_tagged_variants() {
        assert!(matches!(
            serde_json::from_str::<Response>(r#"{"kind":"pong"}"#).unwrap(),
            Response::Pong
        ));
    }
}
