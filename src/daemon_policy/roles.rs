// daemon_policy/roles.rs — which policy roles the caller holds (T13.13).
//
// Groups come from the SO_PEERCRED pid's /proc/PID/status (`Gid:` and
// `Groups:`, the groups it has now) plus /etc/group membership by user
// name, since the system unit's ProtectProc= hides other users'
// processes. Names for group ids come from /etc/group. Only read when the
// policy defines roles.

use kepr_core::policy::{Identity, PolicyFile};

/// Group ids named in /proc/PID/status: the real and effective `Gid:`
/// and every `Groups:` entry.
pub fn parse_status_gids(status: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for line in status.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let take = match key {
            "Gid" => 2, // real, effective
            "Groups" => usize::MAX,
            _ => continue,
        };
        out.extend(
            rest.split_whitespace()
                .take(take)
                .filter_map(|g| g.parse::<u32>().ok()),
        );
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// From /etc/group text: the names of the groups with an id in `gids` or
/// listing `user` as a member, and those groups' ids.
pub fn groups_from_etc(text: &str, user: &str, gids: &[u32]) -> (Vec<String>, Vec<u32>) {
    let (mut names, mut ids) = (Vec::new(), Vec::new());
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(name), _, Some(gid), members) = (f.next(), f.next(), f.next(), f.next()) else {
            continue;
        };
        let Ok(gid) = gid.parse::<u32>() else {
            continue;
        };
        let listed = members.is_some_and(|m| m.split(',').any(|u| u == user));
        if listed || gids.contains(&gid) {
            names.push(name.to_string());
            ids.push(gid);
        }
    }
    (names, ids)
}

/// The roles `policy` gives the caller; empty when it defines none.
pub fn held(policy: &PolicyFile, uid: u32, user: &str, peer_pid: i32) -> Vec<String> {
    if policy.roles.is_empty() {
        return Vec::new();
    }
    let mut gids = std::fs::read_to_string(format!("/proc/{peer_pid}/status"))
        .map(|s| parse_status_gids(&s))
        .unwrap_or_default();
    let etc = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let (names, more) = groups_from_etc(&etc, user, &gids);
    gids.extend(more);
    gids.sort_unstable();
    gids.dedup();
    policy.roles_of(&Identity {
        uid,
        user,
        gids: &gids,
        groups: &names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_groups_and_primary_gid() {
        let s = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1001\t1000\t1000\nGroups:\t4 24 1000\n";
        assert_eq!(parse_status_gids(s), [4, 24, 1000, 1001]);
        assert!(parse_status_gids("Name:\tx\n").is_empty());
    }

    #[test]
    fn etc_group_by_id_and_by_member() {
        let g = "root:x:0:\nops:x:2000:alice,bob\nstaff:x:50:\nbroken\nbad:x:zz:alice\n";
        let (names, ids) = groups_from_etc(g, "alice", &[50]);
        assert_eq!(names, ["ops", "staff"]);
        assert_eq!(ids, [2000, 50]);
        assert!(groups_from_etc(g, "carol", &[]).0.is_empty());
    }

    #[test]
    fn no_roles_means_no_lookups() {
        assert!(held(&PolicyFile::default(), 1, "x", 1).is_empty());
    }
}
