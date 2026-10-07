// daemon_sharing/emergency.rs — T6.06 emergency access with a time delay.
//
//   (owner)   kepr emergency add CONTACT --delay 7d --names A,B | --all
//   (contact) kepr emergency request OWNER_KEY [-o FILE]
//             → a request authenticated with the contact's share key
//               (emergency_proof.rs), handed to the owner's daemon
//   (owner)   kepr emergency ls | deny CONTACT | rm CONTACT
//   (sweeper) `delay` after an undenied request, the chosen credentials
//             are released: one share envelope each, encrypted to the
//             contact's key, kept here until fetched or 30 days pass
//   (contact) kepr emergency fetch
//
// What can be released follows `share send`: sealed, SSH, share-key,
// consent- and FIDO2-gated values are never included. Every request,
// denial and released credential is audited (under the owner's uid) and
// written to the journal. At most 5 contacts, delays 1 hour to 90 days.
//
// State: one JSON file per owner uid (`emergency-<uid>.json`).

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{EmergencyInfo, SharingResponse};

use super::contacts::{fingerprint, resolve};
use super::emergency_proof::x_of;
use super::{audit_r, load, save, state_path, LOCK};
use crate::expiry::{format_expires_at, now_unix};
use crate::store::validate_name;

pub(crate) const KIND: &str = "emergency";
const MAX_CONTACTS: usize = 5;
const MAX_NAMES: usize = 256;
pub const MIN_DELAY: u64 = 3600;
pub const MAX_DELAY: u64 = 90 * 86_400;

#[derive(serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct Grants {
    /// The owner's share public key when the grants were last changed.
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct Grant {
    pub label: String,
    pub public: String,
    pub delay: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    pub added: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<u64>,
    /// `at` of the newest request accepted (or denied): older or equal
    /// requests are replays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_proof: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released: Option<u64>,
    /// Share envelopes made at release, until fetched or expired.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub envelopes: Vec<String>,
}

impl Grant {
    fn info(&self) -> EmergencyInfo {
        let state = match (self.released, self.requested) {
            (Some(_), _) => "released",
            (None, Some(_)) => "requested",
            (None, None) => "waiting",
        };
        EmergencyInfo {
            contact: self.label.clone(),
            fingerprint: fingerprint(&self.public),
            delay_secs: self.delay,
            names: self.names.clone(),
            state: state.into(),
            requested_at: self.requested.map(format_expires_at),
            release_at: self
                .requested
                .filter(|_| self.released.is_none())
                .map(|t| format_expires_at(t.saturating_add(self.delay))),
            released_at: self.released.map(format_expires_at),
        }
    }
}

/// The grant `who` names: its label (case-insensitive) or its key.
pub(crate) fn find(grants: &[Grant], who: &str) -> Option<usize> {
    let x = x_of(who);
    grants.iter().position(|g| {
        g.label.eq_ignore_ascii_case(who.trim()) || (x.is_some() && x_of(&g.public) == x)
    })
}

fn check_names(names: Option<Vec<String>>) -> Result<Option<Vec<String>>, String> {
    let Some(names) = names else { return Ok(None) };
    if names.is_empty() || names.len() > MAX_NAMES {
        return Err(format!("name 1 to {MAX_NAMES} credentials (or all)"));
    }
    let mut out = Vec::new();
    for n in names {
        validate_name(&n)?;
        let upper = n.to_uppercase();
        if !out.contains(&upper) {
            out.push(upper);
        }
    }
    Ok(Some(out))
}

pub fn handle_add(
    uid: u32,
    username: &str,
    contact: &str,
    delay: u64,
    names: Option<Vec<String>>,
) -> Response {
    let r = (|| {
        if !(MIN_DELAY..=MAX_DELAY).contains(&delay) {
            return Err("--delay must be 1 hour to 90 days".to_string());
        }
        let names = check_names(names)?;
        let (to, label) = resolve(uid, contact)?;
        // The owner's share key verifies requests: make it if needed.
        let owner = match crate::daemon_share::handle_key(uid, username, true) {
            Response::ShareKeyOk { public } => public,
            Response::Err { error } => return Err(error),
            _ => return Err("unexpected store reply".into()),
        };
        let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
        let path = state_path(KIND, uid);
        let mut st: Grants = load(&path);
        st.owner = owner;
        let grant = Grant {
            label: label.clone(),
            public: to.text(),
            delay,
            names,
            added: now_unix(),
            requested: None,
            last_proof: None,
            released: None,
            envelopes: Vec::new(),
        };
        match find(&st.grants, &grant.public) {
            // Re-adding keeps the replay mark, so old requests stay used.
            Some(i) => {
                let last_proof = st.grants[i].last_proof;
                st.grants[i] = Grant {
                    last_proof,
                    ..grant
                };
            }
            None if st.grants.len() >= MAX_CONTACTS => {
                return Err(format!("at most {MAX_CONTACTS} emergency contacts"));
            }
            None => st.grants.push(grant),
        }
        save(&path, &st)?;
        Ok(label)
    })();
    audit_r("emergency-add", uid, username, None, &r);
    match r {
        Ok(label) => super::done(format!(
            "{label} can now request emergency access; it is granted {} after a request \
             unless you deny it (they need your share key: kepr share key)",
            human(delay)
        )),
        Err(e) => Response::fail(e),
    }
}

pub(crate) fn human(secs: u64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{} day(s)", s / 86_400),
        s if s % 3600 == 0 => format!("{} hour(s)", s / 3600),
        s => format!("{s} s"),
    }
}

pub fn handle_list(uid: u32) -> Response {
    let st: Grants = {
        let _g = LOCK.lock();
        load(&state_path(KIND, uid))
    };
    SharingResponse::EmergencyListing {
        grants: st.grants.iter().map(Grant::info).collect(),
    }
    .into()
}

/// Change the grant `who` names under the lock; `f` returns the reply.
fn with_grant(
    uid: u32,
    who: &str,
    f: impl FnOnce(&mut Vec<Grant>, usize) -> Result<String, String>,
) -> Result<String, String> {
    let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
    let path = state_path(KIND, uid);
    let mut st: Grants = load(&path);
    let i = find(&st.grants, who).ok_or_else(|| format!("no emergency contact {}", who.trim()))?;
    let msg = f(&mut st.grants, i)?;
    save(&path, &st)?;
    Ok(msg)
}

pub fn handle_remove(uid: u32, username: &str, who: &str) -> Response {
    let r = with_grant(uid, who, |g, i| {
        let gone = g.remove(i);
        Ok(format!("{} can no longer request access", gone.label))
    });
    audit_r("emergency-rm", uid, username, None, &r);
    super::reply(r)
}

/// Deny a pending request; releases not fetched yet are dropped too.
pub fn handle_deny(uid: u32, username: &str, who: &str) -> Response {
    let r = with_grant(uid, who, |g, i| {
        let g = &mut g[i];
        if g.requested.is_none() {
            return Err(format!("{} has no pending request", g.label));
        }
        let dropped = g.envelopes.len();
        g.requested = None;
        g.released = None;
        g.envelopes.clear();
        Ok(match dropped {
            0 => format!("denied {}'s request", g.label),
            n => format!(
                "denied {}'s request; {n} unfetched envelope(s) dropped",
                g.label
            ),
        })
    });
    audit_r("emergency-deny", uid, username, None, &r);
    if r.is_ok() {
        eprintln!("[kepr-daemon] emergency access request denied by uid {uid}");
    }
    super::reply(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn key(uid: u32) -> String {
        match crate::daemon_share::handle_key(uid, "t", true) {
            Response::ShareKeyOk { public } => public,
            other => panic!("{other:?}"),
        }
    }

    fn grants(uid: u32) -> Vec<EmergencyInfo> {
        match handle_list(uid) {
            Response::Sharing(SharingResponse::EmergencyListing { grants }) => grants,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn add_list_remove_and_limits() {
        let (a, b) = (testkit::uid(), testkit::uid());
        let kb = key(b);
        let day = 86_400;
        assert!(!handle_add(a, "t", &kb, 60, None).is_success(), "too short");
        assert!(
            !handle_add(a, "t", &kb, 91 * day, None).is_success(),
            "too long"
        );
        assert!(
            !handle_add(a, "t", "nobody", day, None).is_success(),
            "not pinned"
        );
        let bad = Some(vec!["../x".to_string()]);
        assert!(!handle_add(a, "t", &kb, day, bad).is_success());
        let names = Some(vec!["api_key".to_string(), "API_KEY".to_string()]);
        assert!(handle_add(a, "t", &kb, 7 * day, names).is_success());
        let g = grants(a);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].state, "waiting");
        assert_eq!(g[0].names.as_deref(), Some(&["API_KEY".to_string()][..]));
        // Re-adding the same key updates it instead of adding another.
        assert!(handle_add(a, "t", &kb, day, None).is_success());
        assert_eq!(grants(a).len(), 1);
        assert_eq!(grants(a)[0].delay_secs, day);
        for _ in 0..4 {
            let k = key(testkit::uid());
            assert!(handle_add(a, "t", &k, day, None).is_success());
        }
        let sixth = key(testkit::uid());
        assert!(!handle_add(a, "t", &sixth, day, None).is_success(), "max 5");
        let label = grants(a)[0].contact.clone();
        assert!(handle_remove(a, "t", &label).is_success());
        assert!(!handle_remove(a, "t", &kb).is_success(), "already gone");
        assert_eq!(grants(a).len(), 4);
    }
}
