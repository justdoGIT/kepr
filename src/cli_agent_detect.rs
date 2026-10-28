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

/// `binding_for`, plus the extra hosts a preset binds (T2.04: `--for
/// gcloud` also binds the common `*.googleapis.com` services; T12.06:
/// `--for github` also binds github.com for git over HTTPS).
pub fn bindings_for(spec: &str) -> Result<Vec<Binding>, String> {
    let first = binding_for(spec)?;
    let extra: &[&str] = match spec {
        "gcloud" => providers::GCLOUD_HOSTS,
        _ => &[],
    };
    let more = extra.iter().map(|h| Binding {
        host: h.to_string(),
        ..first.clone()
    });
    let git = (spec == "github")
        .then(|| providers::lookup("git").map(|p| p.binding()))
        .flatten();
    Ok(std::iter::once(first.clone())
        .chain(more)
        .chain(git)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::binding::Inject;

    #[test]
    fn gcloud_binds_its_common_hosts() {
        let b = bindings_for("gcloud").unwrap();
        assert_eq!(b.len(), 1 + providers::GCLOUD_HOSTS.len());
        assert_eq!(b[0].host, "www.googleapis.com");
        assert!(b
            .iter()
            .all(|x| x.inject == Inject::Bearer && x.port == 443));
        assert!(b.iter().any(|x| x.host == "storage.googleapis.com"));
        assert_eq!(bindings_for("npm").unwrap().len(), 1);
    }

    #[test]
    fn github_also_binds_github_com_for_git() {
        let b = bindings_for("github").unwrap();
        let got: Vec<(&str, &Inject)> = b.iter().map(|x| (x.host.as_str(), &x.inject)).collect();
        assert_eq!(
            got,
            [
                ("api.github.com", &Inject::Bearer),
                ("github.com", &Inject::BasicPassword)
            ]
        );
        assert!(b.iter().all(|x| x.port == 443));
    }

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
