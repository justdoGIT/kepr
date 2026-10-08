// protocol_platform.rs — wire types for the P10 platform batch (`platform`).
// batch: platform
//
// Carried inside `Response::Platform` (untagged), so the JSON is flat:
// `{"kind":"systemd_cred_ok",...}`. CLI-only verbs use these variants for
// their `--json` output.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlatformResponse {
    /// T10.06 (CLI only): `kepr systemd-cred` — the `SetCredentialEncrypted=`
    /// line for a unit file (ciphertext, safe to print).
    SystemdCredOk { name: String, line: String },
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
    fn core_responses_still_decode_as_their_tagged_variants() {
        assert!(matches!(
            serde_json::from_str::<Response>(r#"{"kind":"pong"}"#).unwrap(),
            Response::Pong
        ));
    }
}
