//! Restrict privacy sessions to providers handled by the text adapters.

use super::{Policy, Preset};
use crate::gate_protocol::GateRoute;

pub fn supports_provider(name: &str) -> bool {
    const INSPECTED: &[&str] = &[
        "anthropic",
        "openai",
        "agentrouter",
        "selora",
        "cloudflare",
        "xai",
        "mistral",
        "deepseek",
        "groq",
        "openrouter",
        "fireworks",
        "moonshot",
        "venice",
    ];
    if INSPECTED.contains(&name) {
        return true;
    }
    let Some((host, _)) = crate::http_route::parse(name) else {
        return false;
    };
    INSPECTED
        .iter()
        .any(|name| crate::providers::lookup(name).is_some_and(|p| p.host == host))
}

impl Policy {
    pub fn validate_routes(&self, routes: &[GateRoute], tunnel: bool) -> Result<(), String> {
        self.validate().map_err(str::to_owned)?;
        if self.preset == Preset::LocalOnly {
            return Err(
                "local-only inference routing is unavailable; no cloud gate was started".into(),
            );
        }
        if tunnel
            || routes
                .iter()
                .any(|r| r.target.is_some() || !supports_provider(&r.provider))
        {
            return Err(
                "privacy sessions require supported inspected model-provider routes".into(),
            );
        }
        Ok(())
    }
}
