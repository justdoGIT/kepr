//! Where a gate route goes (split out of `gate_protocol`): the database,
//! tunnel or Kubernetes API server a route logs in to, its optional role
//! grant (T7.18) and ephemeral login (T13.02), and the checks on them.

use serde::{Deserialize, Serialize};

use crate::binding::Inject;

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
    /// T13.02 (PostgreSQL): the route's sealed record is an admin login the
    /// agent never uses; the gate makes a short-lived login role for the
    /// session instead and drops it at the end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<Ephemeral>,
}

/// `kepr agent run --db-user NAME=ROLE[:TTL]` (T13.02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ephemeral {
    /// The existing role whose privileges the new login inherits
    /// (membership); case kept.
    pub role: String,
    /// The login's `VALID UNTIL`, from creation: a gate killed before it
    /// can drop the role leaves one that no longer logs in.
    pub ttl_secs: u64,
}

/// Longest and shortest life of an ephemeral login.
pub const EPHEMERAL_TTL: std::ops::RangeInclusive<u64> = 60..=86_400;
/// Default when `--db-user` gives no TTL.
pub const EPHEMERAL_DEFAULT_TTL: u64 = 3_600;

impl Ephemeral {
    pub(crate) fn validate(&self, kind: TargetKind, t: &DbTarget) -> Result<(), String> {
        let role_ok = (1..=63).contains(&self.role.len()) && !self.role.contains(['\0', '\\']);
        match kind {
            TargetKind::Postgres if !role_ok => Err("--db-user: invalid role name".into()),
            TargetKind::Postgres if !EPHEMERAL_TTL.contains(&self.ttl_secs) => Err(format!(
                "--db-user: the TTL is {} to {} seconds",
                EPHEMERAL_TTL.start(),
                EPHEMERAL_TTL.end()
            )),
            TargetKind::Postgres if t.rotate || t.grant.is_some() => {
                Err("--db-user can't be combined with --grant or password rotation".into())
            }
            TargetKind::Postgres => Ok(()),
            _ => Err("--db-user is for PostgreSQL logins only".into()),
        }
    }
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
    pub(crate) fn validate(&self, cred: &str, kind: TargetKind) -> Result<(), String> {
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
    /// T13.04: a Kubernetes API server (HTTPS). Not a database: it gets no
    /// loopback listener; the egress proxy serves its CONNECT.
    Kube,
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
            Self::Kube => "kube",
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
            Self::Kube => Some(Inject::KubeToken),
            Self::Tcp => None,
        }
    }
}
