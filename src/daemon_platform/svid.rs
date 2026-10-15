// daemon_platform/svid.rs — `kepr pki svid` and `kepr pki tpm-enroll`
// (T10.11).
//
// An X.509 SVID is a leaf from the local CA with exactly one URI SAN (the
// SPIFFE ID), an empty subject, digitalSignature, server + client auth, and
// a short life (default 1 h, at most 24 h). Once a TPM is enrolled
// (`PkiState.tpm`), every SVID needs a fresh quote over PCR 7 that matches
// the enrolled attestation key and value (tpm.rs). Enrolment is trust on
// first use; replacing it means a new CA (`kepr pki init --force`).

use kepr_core::pki::{self, TpmQuote};
use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformResponse;

use super::pki::{audit, issue_leaf, update_state, Subject};
use super::tpm;
use crate::expiry;

pub fn handle_nonce(uid: u32) -> Response {
    match tpm::new_nonce(uid) {
        Ok(nonce) => Response::Platform(PlatformResponse::PkiNonceOk { nonce }),
        Err(e) => Response::fail(e),
    }
}

/// The SVID validity window for `ttl` seconds (1 min back-dated for skew).
pub fn svid_window(now: u64, ttl: Option<u64>) -> Result<(u64, u64), String> {
    let ttl = ttl.unwrap_or(pki::DEFAULT_SVID_TTL);
    if !(60..=pki::MAX_SVID_TTL).contains(&ttl) {
        return Err(format!("--ttl: 60 s to {} h", pki::MAX_SVID_TTL / 3600));
    }
    Ok((now.saturating_sub(60), now + ttl))
}

/// Under the CA lock: a quote is needed exactly when a TPM is enrolled.
fn quote_gate(uid: u32, state: &pki::PkiState, quote: Option<&TpmQuote>) -> Result<(), String> {
    match (&state.tpm, quote) {
        (None, _) => Ok(()),
        (Some(_), None) => Err("this CA issues SVIDs only with a TPM2 quote over PCR 7: \
                                add --ak HANDLE|CTX (the attestation key enrolled \
                                with kepr pki tpm-enroll)"
            .into()),
        (Some(p), Some(q)) => tpm::verify(uid, p, q),
    }
}

pub fn handle_svid(
    uid: u32,
    username: &str,
    spiffe_id: &str,
    ttl: Option<u64>,
    public_key: &str,
    quote: Option<TpmQuote>,
) -> Response {
    let r = (|| {
        pki::validate_spiffe_id(spiffe_id)?;
        let window = svid_window(expiry::now_unix(), ttl)?;
        let who = Subject {
            sans: &[],
            uri: Some(spiffe_id),
        };
        let check = |s: &pki::PkiState| quote_gate(uid, s, quote.as_ref());
        issue_leaf(uid, public_key, who, window, &check)
    })();
    audit("pki-svid", uid, username, &r);
    match r {
        Ok((cert_pem, cert, ca_pem)) => Response::Platform(PlatformResponse::PkiIssued {
            cert_pem,
            ca_pem,
            cert: Box::new(cert),
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_tpm_enroll(
    uid: u32,
    username: &str,
    ak_public: &str,
    pcr7: &str,
    quote: &TpmQuote,
) -> Response {
    let r = (|| {
        let policy = tpm::policy(ak_public, pcr7)?;
        update_state(uid, |state| {
            if state.tpm.is_some() {
                return Err("a TPM is already enrolled for this CA; \
                            kepr pki init --force starts a new CA"
                    .to_string());
            }
            tpm::verify(uid, &policy, quote)?;
            state.tpm = Some(policy.clone());
            Ok(policy)
        })
    })();
    audit("pki-tpm-enroll", uid, username, &r);
    match r {
        Ok(policy) => Response::Platform(PlatformResponse::PkiTpmEnrolled { policy }),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::super::pki_sign::tests::{leaf_key, openssl};
    use super::super::tpm::tests::{ak_hex, quote};
    use super::*;

    #[test]
    fn ttl_window_is_capped() {
        let now = 1_000_000;
        assert_eq!(svid_window(now, None), Ok((now - 60, now + 3600)));
        assert_eq!(svid_window(now, Some(86_400)), Ok((now - 60, now + 86_400)));
        assert!(svid_window(now, Some(86_401)).is_err());
        assert!(svid_window(now, Some(59)).is_err());
    }

    fn svid(uid: u32, id: &str, q: Option<TpmQuote>) -> Response {
        let (_k, pk) = leaf_key();
        handle_svid(uid, "t", id, Some(600), &pk, q)
    }

    #[test]
    fn svids_have_one_uri_san_and_tpm_enrolment_gates_them() {
        let uid = crate::daemon_store::testkit::uid();
        assert!(svid(uid, "spiffe://td/w", None)
            .err_msg()
            .unwrap()
            .contains("pki init"));
        assert!(super::super::pki::handle_init(uid, "t", Some(30), false)
            .err_msg()
            .is_none());
        assert!(svid(uid, "https://td/w", None)
            .err_msg()
            .unwrap()
            .contains("SPIFFE"));
        let Response::Platform(PlatformResponse::PkiIssued {
            cert_pem,
            ca_pem,
            cert,
        }) = svid(uid, "spiffe://example.org/ns/prod/sa/api", None)
        else {
            panic!("svid failed");
        };
        assert_eq!(
            cert.spiffe_id.as_deref(),
            Some("spiffe://example.org/ns/prod/sa/api")
        );
        assert!(cert.sans.is_empty());
        let ttl = cert.not_after - cert.issued_at;
        assert!((590..=610).contains(&ttl), "{ttl}");
        check_with_openssl(&cert_pem, &ca_pem);
        // `kepr health` does not warn about short-lived SVIDs.
        let Response::HealthOk { items } =
            crate::daemon_health::handle_health(uid, "t", Some(0), None)
        else {
            panic!("health failed");
        };
        let ca_item = items.iter().find(|i| i.name == pki::CA_NAME).unwrap();
        assert!(ca_item.issues.is_empty(), "{:?}", ca_item.issues);

        // Enrol a TPM (synthetic quote; see tpm.rs), then SVIDs need quotes.
        let pcr7 = [0x5au8; 32];
        let r = handle_tpm_enroll(uid, "t", &ak_hex(), &hex::encode(pcr7), &quote(uid, &pcr7));
        assert!(
            matches!(
                r,
                Response::Platform(PlatformResponse::PkiTpmEnrolled { .. })
            ),
            "{r:?}"
        );
        let again = handle_tpm_enroll(uid, "t", &ak_hex(), &hex::encode(pcr7), &quote(uid, &pcr7));
        assert!(again.err_msg().unwrap().contains("already enrolled"));
        assert!(svid(uid, "spiffe://td/w", None)
            .err_msg()
            .unwrap()
            .contains("--ak HANDLE"));
        let changed = svid(uid, "spiffe://td/w", Some(quote(uid, &[0x5bu8; 32])));
        assert!(changed.err_msg().unwrap().contains("PCR 7 differs"));
        let ok = svid(uid, "spiffe://td/w", Some(quote(uid, &pcr7)));
        assert!(ok.err_msg().is_none(), "{ok:?}");
        let Response::Platform(PlatformResponse::PkiListOk { state }) =
            super::super::pki::handle_list(uid, "t")
        else {
            panic!("list failed");
        };
        assert_eq!(state.tpm.unwrap().pcr7, hex::encode(pcr7));
        assert_eq!(state.issued.len(), 2);
    }

    /// The SVID chains to the CA as a client and a server certificate, has
    /// an empty subject, and its only SAN is the URI (marked critical).
    fn check_with_openssl(cert_pem: &str, ca_pem: &str) {
        let dir = tempfile::tempdir().unwrap();
        let (c, l) = (dir.path().join("ca.pem"), dir.path().join("svid.pem"));
        std::fs::write(&c, ca_pem).unwrap();
        std::fs::write(&l, cert_pem).unwrap();
        let (c, l) = (c.to_str().unwrap(), l.to_str().unwrap());
        let Some((ok, out)) = openssl(&["verify", "-CAfile", c, "-purpose", "sslclient", l]) else {
            eprintln!("skipping SVID checks: openssl not installed");
            return;
        };
        assert!(ok, "{out}");
        let (ok, out) = openssl(&["verify", "-CAfile", c, "-purpose", "sslserver", l]).unwrap();
        assert!(ok, "{out}");
        let (_, text) = openssl(&["x509", "-in", l, "-noout", "-text"]).unwrap();
        assert!(
            text.contains("X509v3 Subject Alternative Name: critical"),
            "{text}"
        );
        assert!(
            text.contains("URI:spiffe://example.org/ns/prod/sa/api"),
            "{text}"
        );
        assert!(!text.contains("DNS:"), "{text}");
        assert!(
            text.contains("Subject: \n") || text.contains("Subject:\n"),
            "{text}"
        );
        assert!(text.contains("Digital Signature"), "{text}");
        assert!(text.contains("TLS Web Client Authentication"), "{text}");
    }
}
