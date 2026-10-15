// daemon_policy/canary.rs — honeytokens (T9.08). `kepr canary plant`
// stores a decoy key in a provider's format as an ordinary credential
// whose `.meta` `canary` keeps the provider, the decoy's fingerprint and
// a webhook trip id. It trips (audit `canary-tripped`, journald error
// priority, so `kepr alerts` and SIEM forwarding see it) when:
//   - it is read: `Get` returns it exactly like any other value (the
//     reader can't tell), then the alarm goes off;
//   - a gate sees it in a request (`GateRequest::Canary` fingerprints);
//   - a gate asks to release it (never granted);
//   - a provider-side webhook fires (`kepr canary listen`).
// The audit result says how ("read by …", "sent through an agent gate"):
// op / name / uid / result only, never the value.

use serde::{Deserialize, Serialize};

use kepr_core::gate_protocol::GateResponse;
use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{CanaryEntry, PolicyResponse};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::daemon_handlers::{handle_delete, handle_set, SetFlags};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryMeta {
    pub provider: String,
    /// `kepr_core::canary::fingerprint` of the decoy.
    pub fingerprint: String,
    /// 32 hex chars: the webhook path `/kepr-canary/<trip_id>`.
    pub trip_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planted_in: Option<String>,
    pub created: u64,
}

const MAX_PLANTED_IN: usize = 1024;

fn meta_of(uid: u32, upper: &str) -> Option<CredMeta> {
    expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))).and_then(Result::ok)
}

/// The caller's canaries: (NAME, meta).
fn canaries(uid: u32) -> Vec<(String, CanaryMeta)> {
    crate::daemon_cache::list_for_uid(uid)
        .into_iter()
        .filter_map(|(name, path)| {
            let m = expiry::read_meta(&expiry::meta_path_for(&path))?.ok()?;
            Some((name, m.canary?))
        })
        .collect()
}

fn log(op: &str, name: Option<&str>, uid: u32, username: &str, result: AuditResult) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result,
    });
}

/// Sound the alarm for canary `name`; `how` goes in the audit result.
fn trip(uid: u32, username: &str, name: &str, how: &str) {
    log(
        "canary-tripped",
        Some(name),
        uid,
        username,
        AuditResult::Fail(how.into()),
    );
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(hex::encode(b))
}

pub fn handle_plant(
    uid: u32,
    username: &str,
    name: &str,
    provider: &str,
    planted_in: Option<String>,
) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    if planted_in
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PLANTED_IN || p.contains('\n'))
    {
        return Response::fail("the planted-in path is too long or has a line break");
    }
    let upper = name.to_uppercase();
    let r = (|| {
        let value = kepr_core::canary::make(provider)?;
        let _lock = crate::daemon_credlock::lock(uid, &upper);
        if crate::store::cred_exists(uid, &upper) {
            return Err(format!("{upper} exists; choose another name (--name)"));
        }
        let set = handle_set(
            uid,
            username,
            &upper,
            Some(&value),
            None,
            SetFlags::default(),
        );
        if let Response::Err { error } = set {
            return Err(error);
        }
        let mut meta = meta_of(uid, &upper).unwrap_or_default();
        let trip_id = random_hex(16)?;
        meta.canary = Some(CanaryMeta {
            provider: provider.to_string(),
            fingerprint: kepr_core::canary::fingerprint(value.as_bytes()),
            trip_id: trip_id.clone(),
            planted_in,
            created: expiry::now_unix(),
        });
        let mp = expiry::meta_path_for(&cred_path(uid, &upper));
        if let Err(e) = expiry::write_meta(&mp, &meta) {
            let _ = crate::crypto::default_backend().delete(uid, &upper);
            return Err(format!("meta write failed: {e}"));
        }
        crate::daemon_gate::bump_generation();
        Ok((value, trip_id))
    })();
    let result = match &r {
        Ok(_) => AuditResult::Ok,
        Err(e) => AuditResult::Fail(e.clone()),
    };
    log("canary-plant", Some(&upper), uid, username, result);
    match r {
        Ok((value, trip_id)) => Response::Policy(PolicyResponse::CanaryPlanted {
            name: upper,
            value,
            trip_id,
        }),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32) -> Response {
    let chain = super::events::read_chain();
    let canaries = canaries(uid)
        .into_iter()
        .map(|(name, c)| {
            let trips: Vec<u64> = chain
                .iter()
                .filter(|e| e.uid == uid && e.op == "canary-tripped")
                .filter(|e| e.name.as_deref() == Some(name.as_str()))
                .map(|e| e.timestamp_unix)
                .collect();
            CanaryEntry {
                provider: c.provider,
                planted_in: c.planted_in,
                created: expiry::format_expires_at(c.created),
                trip_id: c.trip_id,
                fingerprint: c.fingerprint,
                tripped: trips.len() as u64,
                last_tripped: trips.iter().max().copied().map(expiry::format_expires_at),
                name,
            }
        })
        .collect();
    Response::Policy(PolicyResponse::CanaryListing { canaries })
}

pub fn handle_remove(uid: u32, username: &str, name: &str) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    let upper = name.to_uppercase();
    let _lock = crate::daemon_credlock::lock(uid, &upper);
    let Some(c) = meta_of(uid, &upper).and_then(|m| m.canary) else {
        return Response::fail(format!("{upper} is not a canary (kepr canary ls)"));
    };
    let r = handle_delete(uid, username, &upper);
    if !r.is_success() {
        return r;
    }
    log("canary-rm", Some(&upper), uid, username, AuditResult::Ok);
    Response::Policy(PolicyResponse::CanaryRemoved {
        name: upper,
        planted_in: c.planted_in,
    })
}

/// `PolicyRequest::CanaryTrip` from `kepr canary listen`.
pub fn handle_webhook(uid: u32, username: &str, trip_id: &str) -> Response {
    let hit = canaries(uid)
        .into_iter()
        .find(|(_, c)| super::approvals::ct_eq(&c.trip_id, trip_id));
    match hit {
        Some((name, _)) => {
            trip(uid, username, &name, "provider webhook");
            Response::Policy(PolicyResponse::PolicyDone {
                message: format!("{name}: canary tripped"),
            })
        }
        None => Response::fail("unknown canary"),
    }
}

/// `Get` hook, after the value went out unchanged: trips if `upper` is
/// a canary. Returns whether it was.
pub fn read(uid: u32, peer_pid: i32, username: &str, upper: &str) -> bool {
    if meta_of(uid, upper).and_then(|m| m.canary).is_none() {
        return false;
    }
    let who = super::caller::inspect(peer_pid);
    let mut how = format!(
        "read by {}",
        who.exe.as_deref().unwrap_or("an unknown program")
    );
    if let Some(h) = who.harness {
        how.push_str(&format!(" in agent session ({h})"));
    }
    trip(uid, username, upper, &how);
    true
}

/// Gate resolve hook: a canary is never released; asking trips it.
pub fn refuse_release(uid: u32, username: &str, upper: &str, meta: Option<&CredMeta>) -> bool {
    if meta.and_then(|m| m.canary.as_ref()).is_none() {
        return false;
    }
    trip(uid, username, upper, "an agent gate asked to release it");
    true
}

/// `GateRequest::Canary`: does any fingerprint match one of `uid`'s
/// canaries? Each match trips.
pub fn gate_check(uid: u32, username: &str, id: u64, fingerprints: &[String]) -> GateResponse {
    let probes = &fingerprints[..fingerprints.len().min(kepr_core::leak::MAX_CANARY_PROBES)];
    let mut tripped = false;
    for (name, c) in canaries(uid) {
        if probes
            .iter()
            .any(|f| super::approvals::ct_eq(f, &c.fingerprint))
        {
            trip(uid, username, &name, "sent through an agent gate");
            tripped = true;
        }
    }
    GateResponse::CanaryChecked { id, tripped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn planted(uid: u32, name: &str, provider: &str) -> (String, String) {
        match handle_plant(uid, "t", name, provider, Some("/tmp/x/.env".into())) {
            Response::Policy(PolicyResponse::CanaryPlanted { value, trip_id, .. }) => {
                (value, trip_id)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn plant_ls_rm_round_trip() {
        let uid = testkit::uid();
        let (value, trip_id) = planted(uid, "openai_api_key", "openai");
        assert!(value.starts_with("sk-proj-"));
        assert_eq!(
            testkit::value(uid, "OPENAI_API_KEY").as_deref(),
            Some(value.as_str())
        );
        // An existing name is never overwritten.
        testkit::set(uid, "REAL", "v");
        assert!(matches!(
            handle_plant(uid, "t", "REAL", "xai", None),
            Response::Err { .. }
        ));
        assert_eq!(testkit::value(uid, "REAL").as_deref(), Some("v"));
        let Response::Policy(PolicyResponse::CanaryListing { canaries }) = handle_list(uid) else {
            panic!("listing");
        };
        assert_eq!(canaries.len(), 1);
        let c = &canaries[0];
        assert_eq!(
            (c.name.as_str(), c.provider.as_str()),
            ("OPENAI_API_KEY", "openai")
        );
        assert_eq!(
            (c.trip_id.as_str(), c.planted_in.as_deref()),
            (trip_id.as_str(), Some("/tmp/x/.env"))
        );
        assert!(
            matches!(handle_remove(uid, "t", "REAL"), Response::Err { .. }),
            "not a canary"
        );
        let Response::Policy(PolicyResponse::CanaryRemoved { planted_in, .. }) =
            handle_remove(uid, "t", "OPENAI_API_KEY")
        else {
            panic!("remove");
        };
        assert_eq!(planted_in.as_deref(), Some("/tmp/x/.env"));
        assert_eq!(testkit::value(uid, "OPENAI_API_KEY"), None);
        assert!(
            matches!(handle_list(uid), Response::Policy(PolicyResponse::CanaryListing { canaries }) if canaries.is_empty())
        );
    }

    #[test]
    fn a_read_looks_normal_and_trips() {
        let uid = testkit::uid();
        let (value, _) = planted(uid, "GROQ_API_KEY", "groq");
        let got = crate::daemon_handlers_get::handle_get(uid, 0, "t", "GROQ_API_KEY", None);
        match got {
            Response::GetOk { name, value: v } => {
                assert_eq!(
                    (name.as_str(), v.as_str()),
                    ("GROQ_API_KEY", value.as_str())
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(read(uid, 0, "t", "GROQ_API_KEY"));
        testkit::set(uid, "PLAIN", "v");
        assert!(!read(uid, 0, "t", "PLAIN"));
    }

    #[test]
    fn gates_never_get_one_and_report_its_use() {
        let uid = testkit::uid();
        let (value, trip_id) = planted(uid, "XAI_API_KEY", "xai");
        let meta = testkit::meta(uid, "XAI_API_KEY");
        assert!(refuse_release(uid, "t", "XAI_API_KEY", Some(&meta)));
        assert!(!refuse_release(
            uid,
            "t",
            "OTHER",
            Some(&CredMeta::default())
        ));
        let probe = kepr_core::canary::fingerprint(value.as_bytes());
        let other = kepr_core::canary::fingerprint(b"sk-ant-something");
        assert!(matches!(
            gate_check(uid, "t", 9, &[other.clone(), probe]),
            GateResponse::CanaryChecked {
                id: 9,
                tripped: true
            }
        ));
        assert!(matches!(
            gate_check(uid, "t", 10, &[other]),
            GateResponse::CanaryChecked { tripped: false, .. }
        ));
        // Another user's gate doesn't match this user's canary.
        let probe = kepr_core::canary::fingerprint(value.as_bytes());
        assert!(matches!(
            gate_check(testkit::uid(), "t", 11, &[probe]),
            GateResponse::CanaryChecked { tripped: false, .. }
        ));
        assert!(handle_webhook(uid, "t", &trip_id).is_success());
        assert!(!handle_webhook(uid, "t", "0000").is_success());
    }
}
