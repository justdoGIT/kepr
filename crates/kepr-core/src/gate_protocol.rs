//! Private daemon ↔ kepr-gate protocol (agent vault plan §4.3).
//!
//! These messages travel only over the socket pair the daemon creates
//! when it spawns a gate (`Request::StartGate`). The daemon never
//! accepts them on its public socket, so no other process can ask for a
//! sealed value.

use crate::binding::Inject;
pub use crate::gate_limits::GateLimits;
use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};

/// Gate → daemon. Every request carries an `id` that the reply echoes,
/// so a reply that arrives after the gate gave up waiting (a slow
/// consent prompt) is recognised as stale instead of being taken as the
/// answer to the next request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum GateRequest {
    Resolve {
        id: u64,
        name: String,
        host: String,
        port: u16,
    },
    /// Current store generation: changes whenever any credential is set,
    /// deleted or expires, so gates can drop cached values.
    Generation { id: u64 },
    /// T7.09: recorded chunks for the daemon to store, encrypted.
    Record {
        id: u64,
        record: crate::gate_record::GateRecord,
    },
    /// T11.22: request journal entries for `kepr agent logs` (at most
    /// `gate_journal::MAX_BATCH`); answered with `Recorded`.
    Journal {
        id: u64,
        entries: Vec<crate::gate_journal::JournalEntry>,
    },
    /// T9.06: add to today's usage of credential `name` (shared by every
    /// session of the user); answered with `UsageToday`.
    DayUsage {
        id: u64,
        name: String,
        requests: u64,
        tokens: u64,
    },
    /// T9.08: canary fingerprints of key-shaped strings in a request;
    /// answered with `CanaryChecked` (the daemon raises the alarm).
    Canary { id: u64, fingerprints: Vec<String> },
    /// T13.03: a rotator inside a `rotate:` session stores the new value of
    /// the credential it rotated (the daemon keeps the seal and bindings),
    /// answered with `Rotated`. Refused for any other session.
    RotateCommit {
        id: u64,
        name: String,
        value: ZeroString,
    },
}

/// Daemon → gate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateResponse {
    ResolveOk {
        id: u64,
        value: ZeroString,
        inject: Inject,
    },
    Generation {
        id: u64,
        generation: u64,
    },
    Recorded {
        id: u64,
    },
    /// T13.03: the new value is stored; gates re-fetch.
    Rotated {
        id: u64,
    },
    /// T9.06: the credential's totals today, this report included.
    UsageToday {
        id: u64,
        requests: u64,
        tokens: u64,
    },
    /// T9.08: whether one of them is a planted canary.
    CanaryChecked {
        id: u64,
        tripped: bool,
    },
    Err {
        id: u64,
        error: String,
    },
}

impl GateResponse {
    pub fn id(&self) -> u64 {
        match self {
            Self::ResolveOk { id, .. }
            | Self::Generation { id, .. }
            | Self::Recorded { id }
            | Self::Rotated { id }
            | Self::UsageToday { id, .. }
            | Self::CanaryChecked { id, .. }
            | Self::Err { id, .. } => *id,
        }
    }
}

/// One provider route of an agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRoute {
    /// Key into kepr-gate's provider table, e.g. `anthropic`.
    pub provider: String,
    /// Credential NAME in the vault.
    pub cred: String,
    pub slot: u16,
    /// P7.1 database routes (`provider` = `db:<CRED>`): where the gate
    /// logs in. `None` for HTTP provider routes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<DbTarget>,
}

/// The database a `db:` route logs in to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbTarget {
    pub host: String,
    pub port: u16,
    /// Set only by `kepr agent rotate-db`: this route may run the
    /// `kepr_rotate` login. An agent's own session never has it, so the
    /// agent can't change the database password.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rotate: bool,
    /// Which protocol the gate speaks on this route's port (T7.01).
    #[serde(default, skip_serializing_if = "TargetKind::is_postgres")]
    pub kind: TargetKind,
    /// T7.18 (PostgreSQL): a role granted to this route's login for the
    /// session, by the gate, with another sealed record's admin login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<RoleGrant>,
}

/// `kepr agent run --grant NAME=ROLE:ADMIN` (T7.18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleGrant {
    /// The PostgreSQL role, as named in the database (case kept).
    pub role: String,
    /// The sealed database record (NAME) whose login may grant `role`.
    pub admin: String,
}

impl RoleGrant {
    /// Role: 1-63 bytes (PostgreSQL truncates longer names), no NUL or
    /// backslash. Admin: a credential NAME other than the route's own.
    fn validate(&self, cred: &str, kind: TargetKind) -> Result<(), String> {
        let role_ok = (1..=63).contains(&self.role.len()) && !self.role.contains(['\0', '\\']);
        let admin_ok = (1..=128).contains(&self.admin.len())
            && self
                .admin
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !self.admin.eq_ignore_ascii_case(cred);
        match (kind, role_ok, admin_ok) {
            (TargetKind::Postgres, true, true) => Ok(()),
            (TargetKind::Postgres, false, _) => Err("--grant: invalid role name".into()),
            (TargetKind::Postgres, _, false) => {
                Err("--grant: the admin must be another sealed database login".into())
            }
            _ => Err("--grant: role elevation is for PostgreSQL logins only".into()),
        }
    }
}

/// The protocol of a database route (Postgres for routes written before
/// the field existed), or `Tcp` for a raw tunnel (T7.03).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    #[default]
    Postgres,
    Redis,
    Mysql,
    /// A raw TCP tunnel: bytes are piped, no credential is involved.
    Tcp,
}

impl TargetKind {
    pub fn is_postgres(&self) -> bool {
        *self == Self::Postgres
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Mysql => "mysql",
            Self::Tcp => "tcp",
        }
    }

    /// From a record's binding kind (`Inject::db_kind`).
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Postgres, Self::Redis, Self::Mysql]
            .into_iter()
            .find(|k| k.name() == s)
    }

    /// The binding inject a sealed login of this kind carries (`None` for
    /// a tunnel, which has no login).
    pub fn inject(self) -> Option<Inject> {
        match self {
            Self::Postgres => Some(Inject::Postgres),
            Self::Redis => Some(Inject::Redis),
            Self::Mysql => Some(Inject::Mysql),
            Self::Tcp => None,
        }
    }
}

/// Route key for a database credential.
pub fn db_route_key(cred: &str) -> String {
    format!("db:{cred}")
}

/// Route key for a raw TCP tunnel named `name` (T7.03).
pub fn tunnel_route_key(name: &str) -> String {
    format!("tcp:{name}")
}

/// T2.02 (batch: aws): route key for a sealed AWS key (SigV4 re-signing).
pub fn aws_route_key(cred: &str) -> String {
    format!("aws:{cred}")
}

/// Route key for a provider-side rotation of `cred` (T13.03): the session
/// exists to rotate that sealed key, and only such a session may send
/// `RotateCommit`. An agent's own session never has one.
pub fn rotate_route_key(cred: &str) -> String {
    format!("rotate:{cred}")
}

impl GateRoute {
    pub fn is_tunnel(&self) -> bool {
        self.target
            .as_ref()
            .is_some_and(|t| t.kind == TargetKind::Tcp)
    }
}

/// The credentials a session may rotate (T13.03): its `rotate:` routes.
pub fn rotatable_creds(routes: &[GateRoute]) -> std::collections::HashSet<String> {
    routes
        .iter()
        .filter(|r| r.provider == rotate_route_key(&r.cred))
        .map(|r| r.cred.to_uppercase())
        .collect()
}

/// The credential NAMEs a session's gate may ask the daemon for: every
/// route's credential except a tunnel's (its "cred" is only its name),
/// plus the admin logins of role grants (T7.18).
pub fn resolvable_creds(routes: &[GateRoute]) -> std::collections::HashSet<String> {
    let admins = routes
        .iter()
        .filter_map(|r| r.target.as_ref()?.grant.as_ref())
        .map(|g| g.admin.to_uppercase());
    routes
        .iter()
        .filter(|r| !r.is_tunnel())
        .map(|r| r.cred.to_uppercase())
        .chain(admins)
        .collect()
}

/// What the daemon writes to a freshly spawned gate's stdin.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    /// 16 hex chars.
    pub session_id: String,
    /// 64 hex chars (32 bytes).
    pub session_key_hex: ZeroString,
    pub routes: Vec<GateRoute>,
    /// Fixed loopback port; `None` = any free port.
    #[serde(default)]
    pub port: Option<u16>,
    /// P9.5 spend and rate guard for this session.
    #[serde(default)]
    pub limits: GateLimits,
    /// P2.1 egress proxy: tunnel CONNECTs to hosts no route is bound to
    /// (off under `--isolate-net`, where only bound hosts are reachable).
    #[serde(default)]
    pub tunnel: bool,
    /// T7.09: send what the agent sends and receives to the daemon.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub record: bool,
}

/// System-mode daemon → kepr-gate service (T1.19), sent after the
/// session channel fd (SCM_RIGHTS) on the service's root-only socket.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceStart {
    /// The agent process; the session gate exits when it does.
    pub owner_pid: i32,
    pub config: SessionConfig,
}

/// The single line a gate prints to stdout once it is listening.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyLine {
    pub ready: bool,
    pub port: u16,
    /// Provider name → placeholder (one per route; providers are unique).
    pub placeholders: std::collections::HashMap<String, String>,
    /// P2.1: the session CA (PEM) the egress proxy signs bound hosts with.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ca_pem: Option<String>,
    /// P7.1: route key (`db:<CRED>`) → local port of its database proxy.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub db_ports: std::collections::HashMap<String, u16>,
}

/// Rules every StartGate request must meet, checked by the daemon before
/// it spawns a gate and again by the gate: 1-16 routes, known providers,
/// unique providers and unique slots. Credential names are checked by
/// the daemon (`store::validate_name`).
pub fn validate_routes(routes: &[GateRoute]) -> Result<(), String> {
    if routes.is_empty() || routes.len() > 16 {
        return Err("an agent session needs 1-16 routes".into());
    }
    for (i, r) in routes.iter().enumerate() {
        let db_ok = r.target.as_ref().is_some_and(|t| {
            let key = match t.kind {
                TargetKind::Tcp => tunnel_route_key(&r.cred),
                _ => db_route_key(&r.cred),
            };
            r.provider == key && t.port != 0 && crate::binding::validate_host(&t.host).is_ok()
        });
        let aws_ok = r.target.is_none() && r.provider == aws_route_key(&r.cred);
        let rotate_ok = r.target.is_none() && r.provider == rotate_route_key(&r.cred);
        if !db_ok
            && !aws_ok
            && !rotate_ok
            && (r.target.is_some() || crate::providers::lookup(&r.provider).is_none())
        {
            return Err(format!("unknown provider {}", r.provider));
        }
        if let Some((t, g)) = r.target.as_ref().and_then(|t| Some((t, t.grant.as_ref()?))) {
            g.validate(&r.cred, t.kind)?;
            // The agent would hold the admin login itself.
            if routes.iter().any(|o| o.cred.eq_ignore_ascii_case(&g.admin)) {
                return Err(format!(
                    "--grant: {} grants roles, so it can't also be a route of the session",
                    g.admin
                ));
            }
        }
        if routes[..i]
            .iter()
            .any(|o| o.provider == r.provider || o.slot == r.slot)
        {
            return Err("route providers and slots must be unique".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_messages_and_routes() {
        let r = GateRequest::RotateCommit {
            id: 4,
            name: "GH".into(),
            value: ZeroString::from("new"),
        };
        let wire = serde_json::to_string(&r).unwrap();
        assert!(wire.contains("rotatecommit"));
        assert!(matches!(
            serde_json::from_str::<GateRequest>(&wire).unwrap(),
            GateRequest::RotateCommit { id: 4, .. }
        ));
        let ok = serde_json::to_string(&GateResponse::Rotated { id: 4 }).unwrap();
        assert_eq!(serde_json::from_str::<GateResponse>(&ok).unwrap().id(), 4);
        let route = |provider: &str| GateRoute {
            provider: provider.into(),
            cred: "GH".into(),
            slot: 0,
            target: None,
        };
        assert!(validate_routes(&[route("rotate:GH")]).is_ok());
        assert!(validate_routes(&[route("rotate:OTHER")]).is_err());
        assert_eq!(rotatable_creds(&[route("rotate:GH")]).len(), 1);
        assert!(rotatable_creds(&[route("anthropic")]).is_empty());
    }

    #[test]
    fn gate_messages_round_trip() {
        let r = GateRequest::Resolve {
            id: 7,
            name: "A".into(),
            host: "api.x.ai".into(),
            port: 443,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""cmd":"resolve""#));
        let _: GateRequest = serde_json::from_str(&j).unwrap();
        let ok = GateResponse::ResolveOk {
            id: 7,
            value: ZeroString::from_string("v".into()),
            inject: Inject::Bearer,
        };
        let j = serde_json::to_string(&ok).unwrap();
        let back: GateResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id(), 7);
    }

    #[test]
    fn route_rules() {
        let r = |p: &str, slot: u16| GateRoute {
            provider: p.into(),
            cred: "K".into(),
            slot,
            target: None,
        };
        assert!(validate_routes(&[r("anthropic", 0), r("xai", 1)]).is_ok());
        assert!(validate_routes(&[]).is_err());
        assert!(validate_routes(&[r("nope", 0)]).is_err());
        assert!(validate_routes(&[r("xai", 0), r("xai", 1)]).is_err());
        assert!(validate_routes(&[r("xai", 0), r("openai", 0)]).is_err());
        assert!(validate_routes(&(0..17).map(|i| r("xai", i)).collect::<Vec<_>>()).is_err());
        // T2.02: an AWS route is keyed by its own credential only.
        assert!(validate_routes(&[r("xai", 0), r("aws:K", 1)]).is_ok());
        assert!(validate_routes(&[r("aws:OTHER", 0)]).is_err());
        assert!(validate_routes(&[r("aws:", 0)]).is_err());
    }

    #[test]
    fn target_kind_defaults_to_postgres_and_round_trips() {
        let t: DbTarget = serde_json::from_str(r#"{"host":"db.x.io","port":5432}"#).unwrap();
        assert_eq!(t.kind, TargetKind::Postgres);
        assert!(!serde_json::to_string(&t).unwrap().contains("kind"));
        let r = DbTarget {
            kind: TargetKind::Redis,
            ..t
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""kind":"redis""#), "{j}");
        assert_eq!(serde_json::from_str::<DbTarget>(&j).unwrap(), r);
        for k in [TargetKind::Postgres, TargetKind::Redis, TargetKind::Mysql] {
            assert_eq!(
                TargetKind::parse(k.inject().unwrap().db_kind().unwrap()),
                Some(k)
            );
        }
    }

    #[test]
    fn tunnel_routes_need_their_own_key_and_are_never_resolved() {
        let tunnel = |provider: &str, slot| GateRoute {
            provider: provider.into(),
            cred: "WIKI".into(),
            slot,
            target: Some(DbTarget {
                host: "wiki.internal.example".into(),
                port: 8080,
                kind: TargetKind::Tcp,
                ..Default::default()
            }),
        };
        let api = GateRoute {
            provider: "anthropic".into(),
            cred: "ANTHROPIC_API_KEY".into(),
            slot: 0,
            target: None,
        };
        assert!(validate_routes(&[api.clone(), tunnel("tcp:WIKI", 1)]).is_ok());
        assert!(validate_routes(&[tunnel("db:WIKI", 1)]).is_err());
        let as_db = GateRoute {
            target: Some(DbTarget {
                kind: TargetKind::Postgres,
                ..tunnel("", 0).target.unwrap()
            }),
            ..tunnel("tcp:WIKI", 1)
        };
        assert!(validate_routes(&[as_db]).is_err());
        let creds = resolvable_creds(&[api, tunnel("tcp:WIKI", 1)]);
        assert_eq!(
            creds.into_iter().collect::<Vec<_>>(),
            vec!["ANTHROPIC_API_KEY"]
        );
        assert_eq!(TargetKind::parse("tcp"), None);
    }

    #[test]
    fn role_grants_are_postgres_only_and_make_the_admin_resolvable() {
        let db = |kind, role: &str, admin: &str| GateRoute {
            provider: "db:APP_DB".into(),
            cred: "APP_DB".into(),
            slot: 0,
            target: Some(DbTarget {
                host: "db.example.com".into(),
                port: 5432,
                kind,
                grant: Some(RoleGrant {
                    role: role.into(),
                    admin: admin.into(),
                }),
                ..Default::default()
            }),
        };
        let ok = db(TargetKind::Postgres, "Analyst \"rw\"", "APP_ADMIN");
        assert!(validate_routes(std::slice::from_ref(&ok)).is_ok());
        let j = serde_json::to_string(&ok).unwrap();
        assert!(j.contains(r#""grant":{"role":"#), "{j}");
        assert_eq!(serde_json::from_str::<GateRoute>(&j).unwrap(), ok);
        let plain: DbTarget = serde_json::from_str(r#"{"host":"db.x.io","port":5432}"#).unwrap();
        assert!(plain.grant.is_none());
        assert!(!serde_json::to_string(&plain).unwrap().contains("grant"));
        for bad in [
            db(TargetKind::Mysql, "analyst", "APP_ADMIN"),
            db(TargetKind::Postgres, "", "APP_ADMIN"),
            db(TargetKind::Postgres, &"r".repeat(64), "APP_ADMIN"),
            db(TargetKind::Postgres, "a\0b", "APP_ADMIN"),
            db(TargetKind::Postgres, "a\\b", "APP_ADMIN"),
            db(TargetKind::Postgres, "analyst", "../x"),
            db(TargetKind::Postgres, "analyst", ""),
            db(TargetKind::Postgres, "analyst", "app_db"),
        ] {
            assert!(
                validate_routes(std::slice::from_ref(&bad)).is_err(),
                "{bad:?}"
            );
        }
        // The admin login must not be reachable by the agent itself.
        let admin_route = GateRoute {
            provider: "db:APP_ADMIN".into(),
            cred: "APP_ADMIN".into(),
            slot: 1,
            target: Some(DbTarget {
                host: "db.example.com".into(),
                port: 5432,
                ..Default::default()
            }),
        };
        let both = [ok.clone(), admin_route];
        assert!(validate_routes(&both).unwrap_err().contains("APP_ADMIN"));
        let mut creds: Vec<_> = resolvable_creds(&[ok]).into_iter().collect();
        creds.sort();
        assert_eq!(creds, vec!["APP_ADMIN", "APP_DB"]);
    }

    #[test]
    fn limits_validate_and_default_to_none() {
        assert!(GateLimits::default().is_none());
        assert!(GateLimits::default().validate().is_ok());
        let l = |r, t, m| GateLimits {
            max_requests: r,
            max_tokens: t,
            per_minute: m,
            ..Default::default()
        };
        assert!(l(Some(10), Some(1000), Some(60)).validate().is_ok());
        assert!(l(Some(0), None, None).validate().is_err());
        assert!(l(None, Some(0), None).validate().is_err());
        assert!(l(None, None, Some(0)).validate().is_err());
        assert!(l(None, None, Some(20_000)).validate().is_err());
        let cfg: SessionConfig =
            serde_json::from_str(r#"{"session_id":"a","session_key_hex":"b","routes":[]}"#)
                .unwrap();
        assert!(cfg.limits.is_none());
    }

    #[test]
    fn daily_caps_and_usage_reports() {
        let day = GateLimits {
            max_requests_day: Some(100),
            max_tokens_day: Some(50_000),
            ..Default::default()
        };
        assert!(day.validate().is_ok() && !day.is_none());
        let zero = GateLimits {
            max_tokens_day: Some(0),
            ..Default::default()
        };
        assert!(zero.validate().is_err());
        let wire = serde_json::to_string(&GateRequest::DayUsage {
            id: 7,
            name: "K".into(),
            requests: 1,
            tokens: 0,
        })
        .unwrap();
        assert_eq!(
            wire,
            r#"{"cmd":"dayusage","id":7,"name":"K","requests":1,"tokens":0}"#
        );
        assert!(serde_json::from_str::<crate::protocol::Request>(&wire).is_err());
        let back: GateResponse = serde_json::from_str(
            &serde_json::to_string(&GateResponse::UsageToday {
                id: 7,
                requests: 3,
                tokens: 9,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(back.id(), 7);
    }

    #[test]
    fn canary_checks_are_private() {
        let wire = serde_json::to_string(&GateRequest::Canary {
            id: 3,
            fingerprints: vec!["ab".into()],
        })
        .unwrap();
        assert_eq!(wire, r#"{"cmd":"canary","id":3,"fingerprints":["ab"]}"#);
        assert!(serde_json::from_str::<crate::protocol::Request>(&wire).is_err());
        let r = GateResponse::CanaryChecked {
            id: 3,
            tripped: true,
        };
        assert_eq!(r.id(), 3);
    }

    #[test]
    fn resolve_is_not_a_public_request() {
        let j = r#"{"cmd":"resolve","name":"A","host":"api.x.ai","port":443}"#;
        assert!(serde_json::from_str::<crate::protocol::Request>(j).is_err());
    }
}
