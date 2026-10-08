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
    /// T10.09: replace the executables allowed to `get` NAME
    /// (`kepr_core::exe_digest` identities; empty = clear). Only a caller
    /// the current binding allows may change it.
    ExeBind { name: String, digests: Vec<String> },
    /// T10.09: the identities NAME is bound to.
    ExeShow { name: String },
    /// T10.10: create the local CA (`--force` replaces an existing one).
    PkiInit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days: Option<u32>,
        #[serde(default)]
        force: bool,
    },
    /// T10.10: sign a leaf for `public_key` (hex SEC1 P-256 point; the
    /// CLI keeps the private key) with these DNS names / IP addresses.
    PkiIssue {
        sans: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days: Option<u32>,
        public_key: String,
    },
    /// T10.10: the CA certificate and the certificates it issued.
    PkiList,
    /// T10.11: a single-use nonce (2 min) for a TPM2 quote.
    PkiNonce,
    /// T10.11: an X.509 SVID for `spiffe_id` (URI SAN, empty subject).
    /// With a TPM enrolled, `quote` must cover PCR 7 over a fresh nonce.
    PkiSvid {
        spiffe_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u64>,
        public_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quote: Option<crate::pki::TpmQuote>,
    },
    /// T10.11: tie SVIDs to this attestation key and PCR 7 value (trust on
    /// first use; the quote proves the key signs over that PCR state).
    PkiTpmEnroll {
        ak_public: String,
        pcr7: String,
        quote: crate::pki::TpmQuote,
    },
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
    /// T10.09: NAME's executable identities after `ExeBind` / `ExeShow`.
    ExeBindings { name: String, digests: Vec<String> },
    /// T10.10: the new CA (certificate only; the key stays sealed).
    PkiCaOk { ca: crate::pki::PkiCa },
    /// T10.10: a signed leaf, with the CA certificate for the chain.
    PkiIssued {
        cert_pem: String,
        ca_pem: String,
        /// Boxed to keep `Response` small.
        cert: Box<crate::pki::PkiCert>,
    },
    /// T10.10: `kepr pki ls`.
    /// Boxed to keep `Response` small.
    PkiListOk { state: Box<crate::pki::PkiState> },
    /// T10.11: hex nonce for `tpm2_quote -q`.
    PkiNonceOk { nonce: String },
    /// T10.11: the enrolled policy.
    PkiTpmEnrolled { policy: crate::pki::TpmPolicy },
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
    fn exe_binding_messages_round_trip() {
        use crate::protocol::Request;
        let req = Request::Platform(PlatformRequest::ExeBind {
            name: "K".into(),
            digests: vec!["sha256:00".into()],
        });
        let wire = serde_json::to_string(&req).unwrap();
        assert!(wire.starts_with(r#"{"cmd":"exe_bind""#));
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::ExeBind { name, digests })
                if name == "K" && digests == ["sha256:00"]
        ));
        let show = Request::Platform(PlatformRequest::ExeShow { name: "K".into() });
        let wire = serde_json::to_string(&show).unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::ExeShow { name }) if name == "K"
        ));
        let resp = PlatformResponse::ExeBindings {
            name: "K".into(),
            digests: vec![],
        };
        let back = round_trip(Response::Platform(resp.clone()));
        assert!(matches!(back, Response::Platform(p) if p == resp));
    }

    #[test]
    fn pki_messages_round_trip() {
        use crate::pki::{PkiCa, PkiCert, PkiState};
        use crate::protocol::Request;
        let wire = serde_json::to_string(&Request::Platform(PlatformRequest::PkiIssue {
            sans: vec!["a.test".into()],
            days: Some(30),
            public_key: "04ab".into(),
        }))
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::PkiIssue { days: Some(30), .. })
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"pki_init"}"#).unwrap(),
            Request::Platform(PlatformRequest::PkiInit {
                days: None,
                force: false
            })
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"pki_list"}"#).unwrap(),
            Request::Platform(PlatformRequest::PkiList)
        ));
        let ca = PkiCa {
            cn: "c".into(),
            cert_pem: "p".into(),
            not_after: 9,
        };
        let cert = PkiCert {
            serial: "01".into(),
            sans: vec!["a.test".into()],
            not_after: 5,
            issued_at: 1,
            spiffe_id: None,
        };
        for r in [
            PlatformResponse::PkiCaOk { ca: ca.clone() },
            PlatformResponse::PkiIssued {
                cert_pem: "x".into(),
                ca_pem: "p".into(),
                cert: Box::new(cert.clone()),
            },
            PlatformResponse::PkiListOk {
                state: Box::new(PkiState {
                    ca,
                    issued: vec![cert],
                    tpm: None,
                }),
            },
        ] {
            let back = round_trip(Response::Platform(r.clone()));
            assert!(matches!(back, Response::Platform(p) if p == r));
        }
    }

    #[test]
    fn svid_messages_round_trip() {
        use crate::pki::{TpmPolicy, TpmQuote};
        use crate::protocol::Request;
        let quote = TpmQuote {
            nonce: "00".into(),
            attest: "ff".into(),
            signature: "18".into(),
        };
        let wire = serde_json::to_string(&Request::Platform(PlatformRequest::PkiSvid {
            spiffe_id: "spiffe://td/w".into(),
            ttl_secs: Some(600),
            public_key: "04".into(),
            quote: Some(quote.clone()),
        }))
        .unwrap();
        assert!(wire.starts_with(r#"{"cmd":"pki_svid""#));
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::PkiSvid { ttl_secs: Some(600), quote: Some(q), .. })
                if q == quote
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"pki_nonce"}"#).unwrap(),
            Request::Platform(PlatformRequest::PkiNonce)
        ));
        let wire = serde_json::to_string(&Request::Platform(PlatformRequest::PkiTpmEnroll {
            ak_public: "04".into(),
            pcr7: "aa".into(),
            quote,
        }))
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<Request>(&wire).unwrap(),
            Request::Platform(PlatformRequest::PkiTpmEnroll { pcr7, .. }) if pcr7 == "aa"
        ));
        for r in [
            PlatformResponse::PkiNonceOk { nonce: "ab".into() },
            PlatformResponse::PkiTpmEnrolled {
                policy: TpmPolicy {
                    ak_public: "04".into(),
                    pcr7: "aa".into(),
                },
            },
        ] {
            let back = round_trip(Response::Platform(r.clone()));
            assert!(matches!(back, Response::Platform(p) if p == r));
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
