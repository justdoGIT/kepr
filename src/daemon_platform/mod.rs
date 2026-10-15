// daemon_platform/ — the `platform` ticket batch (P10), daemon side.
// batch: platform
//
//   fingerprint   quick unlock after an idle / sleep lock (T10.03)
//   exe           binary-identity bindings: the Get gate, ExeBind (T10.09)
//   pki           local CA: init, issue, ls, health (T10.10)
//   pki_sign      X.509 building (kepr_core::x509_build) + P-256 signing (T10.10)
//   svid          SPIFFE X.509 SVIDs, TPM enrolment (T10.11)
//   tpm           TPM2 quote parsing and checks, nonces (T10.11)

pub mod exe;
pub mod fingerprint;
pub mod pki;
pub mod pki_sign;
pub mod svid;
pub mod tpm;

use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformRequest;

pub fn dispatch(uid: u32, peer_pid: i32, username: &str, r: PlatformRequest) -> Response {
    match r {
        PlatformRequest::FingerprintUnlock => fingerprint::handle_unlock(uid, peer_pid, username),
        PlatformRequest::ExeBind { name, digests } => {
            exe::handle_bind(uid, peer_pid, username, &name, &digests)
        }
        PlatformRequest::ExeShow { name } => exe::handle_show(uid, username, &name),
        PlatformRequest::PkiInit { days, force } => pki::handle_init(uid, username, days, force),
        PlatformRequest::PkiIssue {
            sans,
            days,
            public_key,
        } => pki::handle_issue(uid, username, &sans, days, &public_key),
        PlatformRequest::PkiList => pki::handle_list(uid, username),
        PlatformRequest::PkiNonce => svid::handle_nonce(uid),
        PlatformRequest::PkiSvid {
            spiffe_id,
            ttl_secs,
            public_key,
            quote,
        } => svid::handle_svid(uid, username, &spiffe_id, ttl_secs, &public_key, quote),
        PlatformRequest::PkiTpmEnroll {
            ak_public,
            pcr7,
            quote,
        } => svid::handle_tpm_enroll(uid, username, &ak_public, &pcr7, &quote),
    }
}
