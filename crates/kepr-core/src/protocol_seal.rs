// protocol_seal.rs — requests and replies of the `seal` ticket batch:
// how the master key is protected and recovered (T4.08–T4.13, T10.04).
// Carried by `Request::Seal` / `Response::Seal`.
//
// The sealers themselves (TPM2, KMS, PKCS#11, Keychain) run only at
// daemon start-up and have no requests. T12.31 adds a recovery key for a
// sealed master key: the CLI makes it, and its words only ever travel
// from the CLI to the daemon, never back.

use serde::{Deserialize, Serialize};

use crate::generate::ZeroString;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SealRequest {
    /// T4.10: the master key as 24 recovery words. Same fences as
    /// `RecoveryKitCreate`: a passphrase-protected store, the passphrase
    /// checked again, the owner only, no agent gate running, audited.
    RecoveryWordsCreate { password: ZeroString },
    /// T4.10: rebuild the master key from its recovery words (same rules
    /// as `RecoveryRestore`); the store comes back under `new_password`.
    RecoveryWordsRestore {
        words: ZeroString,
        new_password: ZeroString,
    },
    /// T4.09: the security key `kepr unlock` must also use, if any.
    Fido2UnlockParams,
    /// T12.31: keep the master key of a sealed (not passphrase-protected)
    /// store wrapped under a recovery key the CLI made, sent as its 24
    /// words. Replacing an enrolled one needs its words (`current`). The
    /// owner only, no agent gate running, audited; the reply has no key.
    RecoveryKeyEnrol {
        words: ZeroString,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current: Option<ZeroString>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SealResponse {
    RecoveryWordsOk {
        /// Same fingerprint as the recovery kit's shares.
        fingerprint: String,
        words: ZeroString,
    },
    /// T12.31: the recovery key is enrolled. The master key's
    /// fingerprint, as the recovery kits show it; never key material.
    RecoveryKeyEnrolled { fingerprint: String },
    /// T12.31: what `kepr recovery-key enrol --json` prints, made by the
    /// CLI from its own words. The daemon never sends it.
    RecoveryKeyWords {
        fingerprint: String,
        words: ZeroString,
    },
    /// T4.09: public parameters of the store's FIDO2 factor (base64);
    /// `None` when the store needs only its passphrase.
    Fido2UnlockParamsOk {
        rp_id: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        credential_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        salt: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    fn round_trip_request(r: Request) {
        let json = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Request::Seal(_)), "{json}");
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn requests_survive_json() {
        round_trip_request(Request::Seal(SealRequest::RecoveryWordsCreate {
            password: "pw".into(),
        }));
        round_trip_request(Request::Seal(SealRequest::RecoveryWordsRestore {
            words: "abacus zoom".into(),
            new_password: "pw2".into(),
        }));
        round_trip_request(Request::Seal(SealRequest::Fido2UnlockParams));
        round_trip_request(Request::Seal(SealRequest::RecoveryKeyEnrol {
            words: "abacus zoom".into(),
            current: None,
        }));
        round_trip_request(Request::Seal(SealRequest::RecoveryKeyEnrol {
            words: "abacus zoom".into(),
            current: Some("acorn yodel".into()),
        }));
        // Core requests still parse as themselves.
        let r: Request = serde_json::from_str(
            r#"{"cmd":"recoverykitcreate","password":"p","threshold":2,"shares":3}"#,
        )
        .unwrap();
        assert!(matches!(r, Request::RecoveryKitCreate { .. }));
        let raw: Request =
            serde_json::from_str(r#"{"cmd":"recovery_words_create","password":"p"}"#).unwrap();
        assert!(matches!(
            raw,
            Request::Seal(SealRequest::RecoveryWordsCreate { .. })
        ));
    }

    #[test]
    fn recovery_key_words_stay_out_of_debug() {
        let r = Request::Seal(SealRequest::RecoveryKeyEnrol {
            words: "abacus zoom".into(),
            current: Some("acorn yodel".into()),
        });
        let d = format!("{r:?}");
        assert!(!d.contains("abacus") && !d.contains("acorn"), "{d}");
        // No `current` on a first enrolment: the field is left out.
        let first = Request::Seal(SealRequest::RecoveryKeyEnrol {
            words: "abacus zoom".into(),
            current: None,
        });
        let json = serde_json::to_string(&first).unwrap();
        assert_eq!(
            json,
            r#"{"cmd":"recovery_key_enrol","words":"abacus zoom"}"#
        );
        let done = Response::Seal(SealResponse::RecoveryKeyEnrolled {
            fingerprint: "00ff".into(),
        });
        let json = serde_json::to_string(&done).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"recovery_key_enrolled","fingerprint":"00ff"}"#
        );
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back,
            Response::Seal(SealResponse::RecoveryKeyEnrolled { .. })
        ));
        let shown = Response::Seal(SealResponse::RecoveryKeyWords {
            fingerprint: "00ff".into(),
            words: "abacus zoom".into(),
        });
        assert!(!format!("{shown:?}").contains("abacus"));
        let json = serde_json::to_string(&shown).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn responses_survive_json() {
        let r = Response::Seal(SealResponse::RecoveryWordsOk {
            fingerprint: "00ff".into(),
            words: "abacus zoom".into(),
        });
        let json = serde_json::to_string(&r).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert!(matches!(back, Response::Seal(_)), "{json}");
        assert!(back.is_success());
        // Secrets stay out of Debug output.
        assert!(!format!("{back:?}").contains("abacus"));
        for p in [
            SealResponse::Fido2UnlockParamsOk {
                rp_id: "kepr".into(),
                credential_id: Some("AAEC".into()),
                salt: Some("AwQF".into()),
            },
            SealResponse::Fido2UnlockParamsOk {
                rp_id: "kepr".into(),
                credential_id: None,
                salt: None,
            },
        ] {
            let json = serde_json::to_string(&Response::Seal(p)).unwrap();
            let back: Response = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
            assert!(matches!(back, Response::Seal(_)), "{json}");
        }
    }
}
