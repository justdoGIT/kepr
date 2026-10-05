// crypto.rs — the `Crypto:` line of `kepr status` (T7.16).
// batch: eco

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_eco::{EcoRequest, EcoResponse};

pub fn crypto_line(info: &EcoResponse) -> String {
    match info {
        EcoResponse::CryptoInfoOk { provider, fips } => format!(
            "Crypto: {provider}; FIPS mode {}",
            if *fips { "on" } else { "off" }
        ),
    }
}

/// Text mode of `kepr status`, after the store line. A daemon without the
/// request answers an error; then nothing is printed.
pub fn print_status_crypto(status: &Response) {
    if !matches!(status, Response::StatusOk { .. }) {
        return;
    }
    if let Ok(Response::Eco(info)) =
        crate::client::send_request(&Request::Eco(EcoRequest::CryptoInfo))
    {
        crate::cli_ui::info(&crypto_line(&info));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_line_says_whether_fips_mode_is_on() {
        let line = |provider: &str, fips| {
            crypto_line(&EcoResponse::CryptoInfoOk {
                provider: provider.into(),
                fips,
            })
        };
        assert_eq!(
            line("aws-lc-rs (AWS-LC)", true),
            "Crypto: aws-lc-rs (AWS-LC); FIPS mode on"
        );
        assert_eq!(
            line("RustCrypto", false),
            "Crypto: RustCrypto; FIPS mode off"
        );
    }
}
