//! Destination bindings for sealed credentials (agent vault plan §4.3).
//!
//! A sealed credential carries one or more `Binding`s. The daemon only
//! releases the value to kepr-gate for a `(host, port)` that appears in
//! this list, and the gate only injects it the way `inject` says. This
//! is what stops a prompt-injected agent from asking the gate to send
//! a key to an attacker's host.

/// How the gate places the secret into the outgoing request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Inject {
    /// `Authorization: Bearer <value>`
    Bearer,
    /// `<name>: <value>`, e.g. `x-api-key`.
    Header { name: String },
    /// `?<param>=<value>`
    Query { param: String },
    /// `Authorization: Basic base64(<value>)`; store the value as
    /// `user:password`.
    Basic,
    /// P7.1: a PostgreSQL login. The value is a `database` record (JSON:
    /// user, password, database, sslmode, optional ca_pem); the gate logs
    /// in to host:port with it on the agent's behalf.
    Postgres,
    /// T7.01: a Redis login (`database` record with `kind: redis`); the
    /// gate sends `AUTH` upstream for the agent.
    Redis,
    /// T7.02: a MySQL login (`kind: mysql`); the gate completes the
    /// server handshake for the agent.
    Mysql,
    /// T2.02: an AWS access key (JSON `{"access_key_id","secret_access_key",
    /// "session_token"?}`). The gate checks the agent's SigV4 signature
    /// (made with the session placeholder) and signs again with the key;
    /// `*.amazonaws.com` hosts only.
    Sigv4,
    /// T7.08: a GitHub App private key (PEM). The gate never sends it: it
    /// signs an app JWT and injects the 1-hour installation token it
    /// exchanges that for (`Authorization: Bearer`). api.github.com only.
    GithubApp { app_id: u64, installation_id: u64 },
}

impl Inject {
    /// The database protocol of a database login, `None` for HTTP.
    pub fn db_kind(&self) -> Option<&'static str> {
        match self {
            Self::Postgres => Some("postgres"),
            Self::Redis => Some("redis"),
            Self::Mysql => Some("mysql"),
            _ => None,
        }
    }

    /// Inject and default port for a `database` record's `kind` field
    /// (empty = postgres, the P7.1 records written before `kind`).
    pub fn for_db_kind(kind: &str) -> Option<(Self, u16)> {
        match kind {
            "" | "postgres" => Some((Self::Postgres, 5432)),
            "redis" => Some((Self::Redis, 6379)),
            "mysql" => Some((Self::Mysql, 3306)),
            _ => None,
        }
    }
}

/// One allowed destination for a sealed credential.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    /// Lowercase DNS name: no scheme, no path, no port.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub inject: Inject,
}

fn default_port() -> u16 {
    443
}

fn valid_token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validate a host name: 1..=253 chars of `[a-z0-9.-]`, at least one
/// dot, not starting or ending with `.` or `-`.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err("host must be 1-253 characters".to_string());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err("host may only contain a-z, 0-9, '.' and '-'".to_string());
    }
    if !host.contains('.') {
        return Err("host must be a fully-qualified name".to_string());
    }
    let edge = |c: char| c == '.' || c == '-';
    if host.starts_with(edge) || host.ends_with(edge) {
        return Err("host must not start or end with '.' or '-'".to_string());
    }
    Ok(())
}

/// `Ok(())` or a short reason.
pub fn validate_binding(b: &Binding) -> Result<(), String> {
    validate_host(&b.host)?;
    if b.port == 0 {
        return Err("port must not be 0".to_string());
    }
    match &b.inject {
        Inject::Header { name } if !valid_token(name) => {
            Err("header name must be 1-64 chars of A-Z a-z 0-9 - _".to_string())
        }
        Inject::Query { param } if !valid_token(param) => {
            Err("query parameter must be 1-64 chars of A-Z a-z 0-9 - _".to_string())
        }
        Inject::Sigv4 if !b.host.ends_with(".amazonaws.com") || b.port != 443 => {
            Err("sigv4 binds only *.amazonaws.com hosts on port 443".to_string())
        }
        Inject::GithubApp {
            app_id,
            installation_id,
        } if b.host != crate::github_app::API_HOST
            || b.port != 443
            || *app_id == 0
            || *installation_id == 0 =>
        {
            Err(
                "a GitHub App key binds only api.github.com:443, with app and installation ids"
                    .into(),
            )
        }
        _ => Ok(()),
    }
}

fn parse_inject(s: &str) -> Result<Inject, String> {
    match s {
        "bearer" => Ok(Inject::Bearer),
        "basic" => Ok(Inject::Basic),
        "sigv4" => Ok(Inject::Sigv4),
        _ => {
            if let Some(n) = s.strip_prefix("header=") {
                Ok(Inject::Header {
                    name: n.to_string(),
                })
            } else if let Some(p) = s.strip_prefix("query=") {
                Ok(Inject::Query {
                    param: p.to_string(),
                })
            } else {
                Err(format!(
                    "unknown inject '{s}' (use bearer, basic, sigv4, header=NAME or query=NAME)"
                ))
            }
        }
    }
}

/// Parse the CLI form `host[:port]:inject`, e.g.
/// `api.anthropic.com:header=x-api-key` or `h.example.com:8443:bearer`.
pub fn parse_binding(s: &str) -> Result<Binding, String> {
    let parts: Vec<&str> = s.split(':').collect();
    let (host, port, inject) = match parts.as_slice() {
        [h, i] => (*h, 443u16, *i),
        [h, p, i] => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("invalid port '{p}'"))?;
            (*h, port, *i)
        }
        _ => {
            return Err(format!(
                "binding '{s}' must look like host[:port]:inject, e.g. api.openai.com:bearer"
            ))
        }
    };
    let b = Binding {
        host: host.to_string(),
        port,
        inject: parse_inject(inject)?,
    };
    validate_binding(&b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(host: &str, port: u16, inject: Inject) -> Binding {
        Binding {
            host: host.to_string(),
            port,
            inject,
        }
    }

    #[test]
    fn inject_variants_round_trip() {
        for i in [
            Inject::Bearer,
            Inject::Basic,
            Inject::Header {
                name: "x-api-key".into(),
            },
            Inject::Query {
                param: "key".into(),
            },
            Inject::Redis,
            Inject::Mysql,
        ] {
            let bb = b("api.example.com", 443, i);
            let json = serde_json::to_string(&bb).unwrap();
            let back: Binding = serde_json::from_str(&json).unwrap();
            assert_eq!(bb, back);
        }
    }

    #[test]
    fn db_kinds_map_to_injects() {
        for kind in ["postgres", "redis", "mysql"] {
            let (inject, _) = Inject::for_db_kind(kind).unwrap();
            assert_eq!(inject.db_kind(), Some(kind));
        }
        assert_eq!(Inject::for_db_kind(""), Some((Inject::Postgres, 5432)));
        assert_eq!(Inject::for_db_kind("redis").unwrap().1, 6379);
        assert!(Inject::for_db_kind("oracle").is_none());
        assert_eq!(Inject::Bearer.db_kind(), None);
    }

    #[test]
    fn port_defaults_to_443() {
        let bb: Binding =
            serde_json::from_str(r#"{"host":"api.x.ai","inject":{"kind":"bearer"}}"#).unwrap();
        assert_eq!(bb.port, 443);
    }

    #[test]
    fn validate_rejects_bad_bindings() {
        for host in [
            "https://x.com",
            "x.com/path",
            "EXAMPLE.COM",
            "localhost",
            ".x.com",
            "x.com-",
        ] {
            assert!(
                validate_binding(&b(host, 443, Inject::Bearer)).is_err(),
                "{host}"
            );
        }
        assert!(validate_binding(&b("x.com", 0, Inject::Bearer)).is_err());
        let bad_header = Inject::Header {
            name: "x api".into(),
        };
        assert!(validate_binding(&b("x.com", 443, bad_header)).is_err());
        assert!(validate_binding(&b("api.openai.com", 443, Inject::Bearer)).is_ok());
    }

    #[test]
    fn sigv4_binds_only_amazonaws_hosts() {
        assert_eq!(
            parse_binding("sts.amazonaws.com:sigv4").unwrap(),
            b("sts.amazonaws.com", 443, Inject::Sigv4)
        );
        assert!(parse_binding("s3.eu-west-1.amazonaws.com:sigv4").is_ok());
        for bad in [
            "api.example.com:sigv4",
            "amazonaws.com:sigv4",
            "evilamazonaws.com:sigv4",
            "sts.amazonaws.com.evil.com:sigv4",
            "sts.amazonaws.com:8443:sigv4",
        ] {
            assert!(parse_binding(bad).is_err(), "{bad}");
        }
        let j = serde_json::to_string(&b("sts.amazonaws.com", 443, Inject::Sigv4)).unwrap();
        assert!(j.contains(r#"{"kind":"sigv4"}"#), "{j}");
    }

    #[test]
    fn github_app_binds_only_api_github_com() {
        let app = |a, i| Inject::GithubApp {
            app_id: a,
            installation_id: i,
        };
        assert!(validate_binding(&b("api.github.com", 443, app(1, 2))).is_ok());
        assert!(validate_binding(&b("github.com", 443, app(1, 2))).is_err());
        assert!(validate_binding(&b("api.github.com", 8443, app(1, 2))).is_err());
        assert!(validate_binding(&b("api.github.com", 443, app(0, 2))).is_err());
        assert!(validate_binding(&b("api.github.com", 443, app(1, 0))).is_err());
        let j = serde_json::to_string(&b("api.github.com", 443, app(7, 9))).unwrap();
        assert!(
            j.contains(r#"{"kind":"github_app","app_id":7,"installation_id":9}"#),
            "{j}"
        );
        assert_eq!(
            serde_json::from_str::<Binding>(&j).unwrap().inject,
            app(7, 9)
        );
    }

    #[test]
    fn parse_binding_forms() {
        assert_eq!(
            parse_binding("api.openai.com:bearer").unwrap(),
            b("api.openai.com", 443, Inject::Bearer)
        );
        assert_eq!(
            parse_binding("h.example.com:8443:query=key").unwrap(),
            b(
                "h.example.com",
                8443,
                Inject::Query {
                    param: "key".into()
                }
            )
        );
        assert!(parse_binding("api.openai.com").is_err());
        assert!(parse_binding("a.b:99999:bearer").is_err());
        assert!(parse_binding("a.b:443:token").is_err());
    }
}
