// daemon_eco — daemon side of the P8 ecosystem batch (`eco`, 2026-10-05).
// batch: eco
//
//   cipher        the crypto seam (T7.16): RustCrypto by default,
//   crypto_fips   aws-lc-rs with the `fips` cargo feature
//   CryptoInfo    which provider the daemon runs (`kepr status`)

pub mod cipher;
#[cfg(feature = "fips")]
pub mod crypto_fips;

use kepr_core::protocol::Response;
use kepr_core::protocol_eco::{EcoRequest, EcoResponse};

use crate::audit::{self, AuditEvent, AuditResult};

pub fn dispatch(uid: u32, _peer_pid: i32, username: &str, request: EcoRequest) -> Response {
    match request {
        EcoRequest::CryptoInfo => {
            let (provider, fips) = cipher::describe();
            audit::log(&AuditEvent {
                op: "crypto-info",
                name: None,
                uid,
                username,
                result: AuditResult::Ok,
            });
            Response::Eco(EcoResponse::CryptoInfoOk {
                provider: provider.to_string(),
                fips,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_info_reports_the_active_suite() {
        match dispatch(1000, 0, "u", EcoRequest::CryptoInfo) {
            Response::Eco(EcoResponse::CryptoInfoOk { provider, fips }) => {
                assert_eq!((provider.as_str(), fips), cipher::describe());
                // Feature off: never claims FIPS.
                #[cfg(not(feature = "fips"))]
                assert!(!fips);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
