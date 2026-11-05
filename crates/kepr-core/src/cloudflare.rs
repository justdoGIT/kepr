//! A Cloudflare AI Gateway login, resolved only inside the trusted gate.
//! Routing identifiers travel with the token so applications need neither
//! real credentials nor account/gateway environment variables.

use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};

pub const HOST: &str = "gateway.ai.cloudflare.com";
pub const PROVIDER: &str = "cloudflare";
pub const CREDENTIAL: &str = "CLOUDFLARE_AI_GATEWAY_API_KEY";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCredential {
    pub token: ZeroString,
    pub account_id: String,
    pub gateway_id: String,
}

impl GatewayCredential {
    pub fn new(token: ZeroString, account_id: String, gateway_id: String) -> Result<Self, String> {
        let login = Self {
            token,
            account_id,
            gateway_id,
        };
        login.validate()?;
        Ok(login)
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        let login: Self = serde_json::from_str(value)
            .map_err(|_| "invalid sealed Cloudflare login; run `kepr agent add-cloudflare`")?;
        login.validate()?;
        Ok(login)
    }

    fn validate(&self) -> Result<(), String> {
        if self.account_id.len() != 32 || !self.account_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Cloudflare account ID must contain 32 hexadecimal characters".into());
        }
        if !(1..=64).contains(&self.gateway_id.len())
            || !self
                .gateway_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(
                "Cloudflare gateway ID must contain 1-64 letters, digits, '-' or '_'".into(),
            );
        }
        if self.token.as_str().is_empty()
            || !self.token.as_str().bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(
                "Cloudflare token must be nonempty and contain no whitespace or control characters"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn encode(&self) -> ZeroString {
        // Serializing these string-only fields cannot fail.
        ZeroString::from_string(
            serde_json::to_string(self).expect("Cloudflare login serialization"),
        )
    }

    /// No caller-supplied account or gateway may override the stored login.
    pub fn upstream_path(&self, suffix: &str) -> Result<String, String> {
        if !matches!(
            suffix,
            "/compat/chat/completions"
                | "/openai/chat/completions"
                | "/openai/responses"
                | "/anthropic/v1/messages"
        ) {
            return Err("unsupported Cloudflare AI Gateway endpoint".into());
        }
        Ok(format!(
            "/v1/{}/{}{}",
            self.account_id, self.gateway_id, suffix
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> GatewayCredential {
        GatewayCredential::new(
            "synthetic-cloudflare-token".into(),
            "a".repeat(32),
            "coding-gateway".into(),
        )
        .unwrap()
    }

    #[test]
    fn routing_stays_under_the_stored_account_and_gateway() {
        let login = login();
        assert_eq!(
            login.upstream_path("/compat/chat/completions").unwrap(),
            format!(
                "/v1/{}/coding-gateway/compat/chat/completions",
                "a".repeat(32)
            )
        );
        for bad in [
            "//other.example/x",
            "/compat/../accounts",
            "/v1/other/gateway/compat/chat/completions",
            "/compat/chat/completions?token=x",
        ] {
            assert!(login.upstream_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn malformed_fields_never_enter_a_sealed_login() {
        for account in ["", "../account", "gggggggggggggggggggggggggggggggg"] {
            assert!(
                GatewayCredential::new("token".into(), account.into(), "gateway".into()).is_err()
            );
        }
        for gateway in [
            "",
            "../other",
            "gateway/other",
            "gateway?query",
            "gateway%2fother",
        ] {
            assert!(
                GatewayCredential::new("token".into(), "a".repeat(32), gateway.into()).is_err()
            );
        }
        for token in ["", "token\r\nheader:value", "token with spaces"] {
            assert!(
                GatewayCredential::new(token.into(), "a".repeat(32), "gateway".into()).is_err()
            );
        }
    }

    #[test]
    fn parse_errors_and_debug_do_not_disclose_the_token() {
        let login = login();
        assert!(!format!("{login:?}").contains("synthetic-cloudflare-token"));
        assert_eq!(
            GatewayCredential::parse(login.encode().as_str())
                .unwrap()
                .gateway_id,
            "coding-gateway"
        );
        let error =
            GatewayCredential::parse("{\"token\":\"synthetic-cloudflare-token\"}").unwrap_err();
        assert!(!error.contains("synthetic-cloudflare-token"));
    }

    #[test]
    fn gateway_credentials_cannot_be_bound_to_other_hosts_or_ports() {
        let provider = crate::providers::lookup(PROVIDER).unwrap();
        let binding = provider.binding();
        assert_eq!(binding.inject, crate::binding::Inject::CloudflareGateway);
        assert_eq!(binding.host, HOST);
        assert!(crate::binding::validate_binding(&binding).is_ok());
        let mut wrong = binding.clone();
        wrong.host = "api.openai.com".into();
        assert!(crate::binding::validate_binding(&wrong).is_err());
        wrong = binding;
        wrong.port = 8443;
        assert!(crate::binding::validate_binding(&wrong).is_err());
    }
}
