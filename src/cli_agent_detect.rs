// cli_agent_detect.rs — turn `kepr agent add --for SPEC` into a binding.
// SPEC is a provider name from kepr_core::providers (shared with
// kepr-gate, so a stored binding is always a host the gate routes) or a
// raw `host[:port]:inject` binding. Key detection lives in
// kepr_core::providers::detect.

use kepr_core::binding::{parse_binding, Binding};
use kepr_core::providers;

pub fn binding_for(spec: &str) -> Result<Binding, String> {
    if let Some(p) = providers::lookup(spec) {
        return Ok(p.binding());
    }
    parse_binding(spec).map_err(|e| {
        let names: Vec<&str> = providers::PROVIDERS.iter().map(|p| p.name).collect();
        format!(
            "--for {spec}: not a provider ({}) or binding: {e}",
            names.join("|")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::binding::Inject;

    #[test]
    fn for_provider_and_raw_binding() {
        let b = binding_for("anthropic").unwrap();
        assert_eq!(b.host, "api.anthropic.com");
        assert_eq!(
            b.inject,
            Inject::Header {
                name: "x-api-key".into()
            }
        );
        assert_eq!(binding_for("xai").unwrap().inject, Inject::Bearer);
        assert_eq!(
            binding_for("api.example.com:bearer").unwrap().host,
            "api.example.com"
        );
        assert!(binding_for("nope").is_err());
    }
}
