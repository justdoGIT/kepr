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
        _ => Ok(()),
    }
}

fn parse_inject(s: &str) -> Result<Inject, String> {
    match s {
        "bearer" => Ok(Inject::Bearer),
        "basic" => Ok(Inject::Basic),
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
                    "unknown inject '{s}' (use bearer, basic, header=NAME or query=NAME)"
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
        ] {
            let bb = b("api.example.com", 443, i);
            let json = serde_json::to_string(&bb).unwrap();
            let back: Binding = serde_json::from_str(&json).unwrap();
            assert_eq!(bb, back);
        }
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
