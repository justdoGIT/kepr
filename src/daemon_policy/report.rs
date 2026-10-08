// daemon_policy/report.rs — `kepr report access NAME` (T6.12): every path
// a credential can take: gate bindings, aliases, folder, sync devices,
// policy rules that allow it, and from the audit chain the shares sent,
// agent-gate releases, reads and signatures. Names, hosts and counts
// only; the value is never read.

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{AccessRow, PolicyResponse};
use kepr_core::protocol_sharing::SharingResponse;

use crate::audit::{self, AuditEvent, AuditResult};
use crate::audit_chain::ChainEntry;
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

/// What the store and policy say about the credential.
#[derive(Default)]
pub struct Facts {
    pub meta: CredMeta,
    pub aliases: Vec<String>,
    pub devices: Vec<String>,
    pub policy: Vec<String>,
}

/// Audit ops that are a use of the value, as (op, kind, wording).
const USES: &[(&str, &str, &str)] = &[
    ("share-send", "share", "sent in a share envelope"),
    ("share-link", "share", "put in a one-time share link"),
    ("resolve", "agent", "released to an agent gate"),
    ("get", "read", "read (get / exec / env / inject / copy)"),
    ("ssh-sign", "ssh", "signed with (ssh-agent)"),
];

fn row(kind: &str, detail: String) -> AccessRow {
    AccessRow {
        kind: kind.to_string(),
        detail,
    }
}

pub fn rows(name: &str, uid: u32, entries: &[ChainEntry], facts: &Facts) -> Vec<AccessRow> {
    let mut out = Vec::new();
    for b in facts.meta.bindings.iter().flatten() {
        out.push(row(
            "binding",
            format!("agent gates may send it to {}:{}", b.host, b.port),
        ));
    }
    for (op, kind, wording) in USES {
        let ok = entries.iter().filter(|e| {
            e.uid == uid && e.op == *op && e.result == "ok" && e.name.as_deref() == Some(name)
        });
        let (n, last) = ok.fold((0u64, 0u64), |(n, l), e| (n + 1, l.max(e.timestamp_unix)));
        if n > 0 {
            let last = expiry::format_expires_at(last);
            out.push(row(kind, format!("{wording} {n} time(s), last {last} UTC")));
        }
    }
    if !facts.aliases.is_empty() {
        out.push(row(
            "alias",
            format!("also read as {}", facts.aliases.join(", ")),
        ));
    }
    if let Some(f) = &facts.meta.folder {
        out.push(row("folder", f.clone()));
    }
    let local_only = facts.meta.sealed == Some(true)
        || facts.meta.ssh.is_some()
        || facts.meta.share_key == Some(true);
    if !facts.devices.is_empty() && !local_only {
        out.push(row(
            "sync",
            format!(
                "encrypted to enrolled devices: {}",
                facts.devices.join(", ")
            ),
        ));
    }
    out.extend(facts.policy.iter().map(|p| row("policy", p.clone())));
    out
}

fn facts(uid: u32, upper: &str) -> Facts {
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .and_then(Result::ok)
        .unwrap_or_default();
    let aliases = crate::daemon_store::alias_infos(uid)
        .into_iter()
        .filter(|a| a.alias_of.as_deref() == Some(upper))
        .map(|a| a.name)
        .collect();
    let devices = match crate::daemon_sharing::devices::handle_list(uid) {
        Response::Sharing(SharingResponse::DeviceListing { devices, .. }) => {
            devices.into_iter().map(|d| d.label).collect()
        }
        _ => Vec::new(),
    };
    let policy = match &*super::enforce::current() {
        super::enforce::Loaded::Active(p) => kepr_core::policy::OPS
            .iter()
            .flat_map(|op| p.paths(op, upper))
            .collect(),
        super::enforce::Loaded::Broken(_) => vec!["the policy file has errors: all denied".into()],
        super::enforce::Loaded::Absent => Vec::new(),
    };
    Facts {
        meta,
        aliases,
        devices,
        policy,
    }
}

pub fn handle_access(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    let upper = crate::daemon_store::resolve_alias(uid, &name.to_uppercase());
    let exists = crate::store::cred_exists(uid, &upper);
    audit::log(&AuditEvent {
        op: "report-access",
        name: Some(&upper),
        uid,
        username,
        result: if exists {
            AuditResult::Ok
        } else {
            AuditResult::Fail("not found".into())
        },
    });
    if !exists {
        return Response::fail("credential unavailable");
    }
    let entries = super::events::read_chain();
    let rows = rows(&upper, uid, &entries, &facts(uid, &upper));
    Response::Policy(PolicyResponse::AccessReportOk { name: upper, rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(uid: u32, ts: u64, op: &str, name: &str, result: &str) -> ChainEntry {
        ChainEntry {
            seq: 0,
            timestamp_unix: ts,
            op: op.into(),
            name: Some(name.into()),
            uid,
            username: "u".into(),
            result: result.into(),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn share_resolve_and_get_give_three_rows() {
        let log = [
            e(1, 100, "share-send", "K", "ok"),
            e(1, 200, "resolve", "K", "ok"),
            e(1, 300, "get", "K", "ok"),
            e(1, 400, "get", "K", "ok"),
            e(1, 500, "get", "K", "fail: expired"),
            e(2, 600, "get", "K", "ok"),
            e(1, 700, "get", "OTHER", "ok"),
            e(1, 800, "set", "K", "ok"),
        ];
        let r = rows("K", 1, &log, &Facts::default());
        let kinds: Vec<&str> = r.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["share", "agent", "read"]);
        assert_eq!(
            r[2].detail,
            "read (get / exec / env / inject / copy) 2 time(s), last 1970-01-01 00:06 UTC"
        );
    }

    #[test]
    fn one_time_links_count_as_shares() {
        let r = rows(
            "K",
            1,
            &[e(1, 60, "share-link", "K", "ok")],
            &Facts::default(),
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, "share");
        assert!(r[0]
            .detail
            .starts_with("put in a one-time share link 1 time(s)"));
    }

    #[test]
    fn store_facts_become_rows() {
        let facts = Facts {
            meta: CredMeta {
                sealed: Some(true),
                bindings: Some(vec![kepr_core::binding::Binding {
                    host: "api.x.ai".into(),
                    port: 443,
                    inject: kepr_core::binding::Inject::Bearer,
                }]),
                folder: Some("work/ai".into()),
                ..Default::default()
            },
            aliases: vec!["XAI".into()],
            devices: vec!["laptop".into()],
            policy: vec!["get allowed by rule 1 (anyone)".into()],
        };
        let r = rows("K", 1, &[], &facts);
        let kinds: Vec<&str> = r.iter().map(|r| r.kind.as_str()).collect();
        // A sealed key never syncs, so no "sync" row.
        assert_eq!(kinds, ["binding", "alias", "folder", "policy"]);
        assert_eq!(r[0].detail, "agent gates may send it to api.x.ai:443");
    }
}
