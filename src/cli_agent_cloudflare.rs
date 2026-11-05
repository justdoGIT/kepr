// cli_agent_cloudflare.rs — fixed-shape Cloudflare AI Gateway onboarding.

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_gatex::GatexRequest;

/// Replace the standard token credential with its structured sealed login.
pub fn cmd_add_cloudflare(args: &[String]) -> Response {
    if !args.is_empty() {
        return Response::fail("usage: kepr agent add-cloudflare");
    }
    match crate::client::send_request(&Request::Gatex(GatexRequest::CloudflareImport)) {
        Ok(response) => response,
        Err(error) => Response::fail(error),
    }
}
