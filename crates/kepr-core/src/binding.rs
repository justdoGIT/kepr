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
    /// T12.05: the value is a password or token alone. The gate keeps the
    /// user name of the client's own `Authorization: Basic` header (or
    /// `x-access-token` when it has none) and sends
    /// `Basic base64(<user>:<value>)`. git over HTTPS logs in this way.
    BasicPassword,
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
    /// T12.08: a Google service-account key or `authorized_user` file
    /// (JSON). The gate mints a 1-hour access token with it (then, with
    /// `impersonate`, one for that service account) and injects that as
    /// `Authorization: Bearer`. `*.googleapis.com:443` only.
    GcpToken {
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        impersonate: Option<String>,
    },
    /// T13.04: a Kubernetes API server login (a `kube` record: server, bearer
    /// token, the cluster's CA). The gate puts the token in
    /// `Authorization: Bearer` toward the bound host:port and trusts the
    /// cluster CA for that connection only.
    KubeToken,
    /// A Cloudflare AI Gateway login: token and routing IDs stay in the gate.
    CloudflareGateway,
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

/// `https://HOST[:PORT][/…]` → (host, port); https only, 443 by default.
pub fn kube_server(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("the server must be an https:// URL")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("the server URL must not carry credentials".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| "invalid port in the server URL")?,
        ),
        None => (authority, 443),
    };
    if host.is_empty() {
        return Err("the server URL has no host".into());
    }
    Ok((host.to_ascii_lowercase(), port))
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
        Inject::GcpToken {
            scopes,
            impersonate,
        } => crate::gcp_token::validate(&b.host, b.port, scopes, impersonate.as_deref()),
        // The session CA signs for names; an address has none to sign.
        Inject::KubeToken if b.host.bytes().all(|c| c.is_ascii_digit() || c == b'.') => {
            Err("a Kubernetes API server must be given by DNS name, not IP address".into())
        }
        Inject::CloudflareGateway if b.host != crate::cloudflare::HOST || b.port != 443 => {
            Err("Cloudflare logins bind only gateway.ai.cloudflare.com:443".into())
        }
        _ => Ok(()),
    }
}

fn parse_inject(s: &str) -> Result<Inject, String> {
    match s {
        "bearer" => Ok(Inject::Bearer),
        "basic" => Ok(Inject::Basic),
        "basic-password" => Ok(Inject::BasicPassword),
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
                    "unknown inject '{s}' (use bearer, basic, basic-password, sigv4, header=NAME or query=NAME)"
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
#[path = "binding_tests.rs"]
mod tests;
