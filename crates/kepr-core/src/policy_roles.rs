//! Roles for `policy.toml` (T13.13): named sets of callers, matched by
//! uid, user name, group id or group name. Split out of `policy`.

use serde::Deserialize;

/// A named set of callers (T13.13).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    /// `uid:N`, `user:NAME`, `gid:N` or `group:NAME`.
    pub members: Vec<String>,
}

/// Who the daemon found at the other end of the socket.
#[derive(Debug, Default, Clone)]
pub struct Identity<'a> {
    pub uid: u32,
    pub user: &'a str,
    /// The caller's primary and supplementary group ids.
    pub gids: &'a [u32],
    /// Names of those groups, where known.
    pub groups: &'a [String],
}

impl Role {
    pub(crate) fn has(&self, id: &Identity) -> bool {
        self.members.iter().any(|m| match m.split_once(':') {
            Some(("uid", v)) => v.parse() == Ok(id.uid),
            Some(("user", v)) => v == id.user,
            Some(("gid", v)) => v.parse().is_ok_and(|g| id.gids.contains(&g)),
            Some(("group", v)) => id.groups.iter().any(|g| g == v),
            _ => false,
        })
    }

    pub(crate) fn validate(&self, name: &str) -> Result<(), String> {
        if self.members.is_empty() {
            return Err(format!("role `{name}`: `members` is empty"));
        }
        for m in &self.members {
            let ok = match m.split_once(':') {
                Some(("uid" | "gid", v)) => v.parse::<u32>().is_ok(),
                Some(("user" | "group", v)) => !v.is_empty(),
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "role `{name}`: member `{m}` is not uid:N, user:NAME, gid:N or group:NAME"
                ));
            }
        }
        Ok(())
    }
}
