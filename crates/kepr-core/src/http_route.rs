//! HTTPS routes for configured API providers without a built-in preset.
//! These name a destination, never grant it: the daemon still requires a
//! sealed credential with an exact host:443 binding at every resolution.

pub const MAX_ROUTES: usize = 256;

pub fn key(host: &str, credential: &str) -> Option<String> {
    let route = format!("https+{host}+{credential}");
    parse(&route).map(|_| route.clone())
}

pub fn parse(route: &str) -> Option<(&str, &str)> {
    let (host, credential) = route.strip_prefix("https+")?.split_once('+')?;
    if host == "github.com" // The dedicated git route restricts this host to smart HTTP.
        || host.contains([':', '/', '@', '?', '#'])
        || host != host.to_ascii_lowercase()
        || crate::binding::validate_host(host).is_err()
        || credential.is_empty()
        || credential.len() > 128
        || !credential.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
    {
        return None;
    }
    Some((host, credential))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_https_hosts_and_credential_names_form_routes() {
        let route = key("api.example.com", "WORK_API_KEY").unwrap();
        assert_eq!(parse(&route), Some(("api.example.com", "WORK_API_KEY")));
        for host in [
            "api.example.com:80",
            "api.example.com/path",
            "user@api.example.com",
            "api.example.com?x",
            "API.EXAMPLE.COM",
        ] {
            assert!(key(host, "WORK_API_KEY").is_none());
        }
        for name in ["", "../secret", "KEY+OTHER", "lowercase"] {
            assert!(key("api.example.com", name).is_none());
        }
    }

    #[test]
    fn generic_routes_cannot_bypass_git_smart_http_policy() {
        assert!(key("github.com", "GH_TOKEN").is_none());
    }
}
