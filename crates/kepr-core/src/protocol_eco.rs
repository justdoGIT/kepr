// protocol_eco.rs — wire types for the P8 ecosystem batch (`eco`).
// batch: eco
//
// Carried inside `Request::Eco` / `Response::Eco` (untagged), so the JSON is
// flat: `{"cmd":"crypto_info"}` → `{"kind":"crypto_info_ok",...}`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum EcoRequest {
    /// T7.16: which crypto provider the daemon was built with (`kepr status`).
    CryptoInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EcoResponse {
    /// `fips` is true only when the daemon runs inside a validated FIPS
    /// module that passed its self tests, not merely when built with `fips`.
    CryptoInfoOk { provider: String, fips: bool },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn crypto_info_round_trips_through_the_core_enums() {
        let wire = serde_json::to_string(&Request::Eco(EcoRequest::CryptoInfo)).unwrap();
        assert_eq!(wire, r#"{"cmd":"crypto_info"}"#);
        match serde_json::from_str::<Request>(&wire).unwrap() {
            Request::Eco(EcoRequest::CryptoInfo) => {}
            other => panic!("decoded as {other:?}"),
        }

        let ok = Response::Eco(EcoResponse::CryptoInfoOk {
            provider: "aws-lc-rs (AWS-LC)".into(),
            fips: true,
        });
        let wire = serde_json::to_string(&ok).unwrap();
        assert_eq!(
            wire,
            r#"{"kind":"crypto_info_ok","provider":"aws-lc-rs (AWS-LC)","fips":true}"#
        );
        match serde_json::from_str::<Response>(&wire).unwrap() {
            Response::Eco(EcoResponse::CryptoInfoOk { provider, fips }) => {
                assert_eq!((provider.as_str(), fips), ("aws-lc-rs (AWS-LC)", true));
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn core_status_still_decodes_as_the_tagged_variant() {
        // Untagged variants come last: existing commands keep their meaning.
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"status"}"#).unwrap(),
            Request::Status
        ));
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"crypto_nope"}"#).is_err());
    }
}
