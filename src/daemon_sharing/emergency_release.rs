// daemon_sharing/emergency_release.rs — T6.06, the request side and the
// timed release (grants and owner commands are in emergency.rs).
//
//   EmergencyProve    (contact) make a request to an owner's key
//   EmergencyRequest  (anyone holding one) the owner's daemon checks it:
//                     fresh (7 days), not replayed or denied, made by a
//                     granted contact's key for the owner's key. The
//                     clock starts; the owner is told (audit + journal).
//   sweep             `delay` after an undenied request: one envelope
//                     per releasable credential, to the contact's key
//   EmergencyRelease  (contact, or the owner to pass them on) fetch them
//
// A refused request says only "not a valid emergency request": it never
// tells the sender whether the owner or the grant exists.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::SharingResponse;
use zeroize::Zeroizing;

use super::emergency::{Grant, Grants, KIND};
use super::emergency_proof::{self as proof, x_of};
use super::kem::Recipient;
use super::{audit_r, load, save, state_path, state_root, LOCK};
use crate::audit::username_for_uid;
use crate::daemon_share::{load_secret, new_payload, KEY_NAME};
use crate::expiry::{format_expires_at, now_unix};

const MAX_AGE: u64 = 7 * 86_400;
const SKEW: u64 = 300;
/// Released envelopes (and their payloads) live this long.
const ENVELOPE_TTL: u64 = 30 * 86_400;
const INVALID: &str = "not a valid emergency request";

pub fn handle_prove(uid: u32, username: &str, owner: &str) -> Response {
    let r = (|| {
        let (to, _) = super::contacts::resolve(uid, owner)?;
        proof::make(&load_secret(uid)?, &to, now_unix())
    })();
    audit_r("emergency-prove", uid, username, None, &r);
    match r {
        Ok(proof) => SharingResponse::EmergencyProof { proof }.into(),
        Err(e) => Response::fail(e),
    }
}

/// Every uid with an emergency state file.
fn owner_uids() -> Vec<u32> {
    let Ok(rd) = std::fs::read_dir(state_root()) else {
        return Vec::new();
    };
    let prefix = format!("{KIND}-");
    rd.flatten()
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            n.strip_prefix(&prefix)?.strip_suffix(".json")?.parse().ok()
        })
        .collect()
}

/// Accept request `text` at `now`. Returns (owner uid, reply line).
pub(crate) fn request_at(text: &str, now: u64) -> Result<(u32, String), String> {
    let p = proof::parse(text)?;
    if p.at > now.saturating_add(SKEW) || now.saturating_sub(p.at) > MAX_AGE {
        return Err("this request is too old (or dated in the future); make a new one".into());
    }
    let (to, from) = (x_of(&p.to).ok_or(INVALID)?, x_of(&p.from).ok_or(INVALID)?);
    let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
    for uid in owner_uids() {
        let path = state_path(KIND, uid);
        let mut st: Grants = load(&path);
        if x_of(&st.owner) != Some(to) {
            continue;
        }
        let Some(g) = st.grants.iter_mut().find(|g| x_of(&g.public) == Some(from)) else {
            continue;
        };
        let contact = Recipient::parse(&g.public)?;
        let secret = load_secret(uid).map_err(|_| INVALID)?;
        if !proof::verify(&p, &secret, &contact) {
            continue;
        }
        if g.released.is_some() {
            return Ok((uid, "access was already released".into()));
        }
        if let Some(t) = g.requested {
            let at = format_expires_at(t.saturating_add(g.delay));
            return Ok((uid, format!("already requested; released at {at} UTC")));
        }
        if g.last_proof.is_some_and(|l| p.at <= l) {
            return Err("this request was already used or denied; make a new one".into());
        }
        g.requested = Some(now);
        g.last_proof = Some(p.at);
        let at = format_expires_at(now.saturating_add(g.delay));
        let label = g.label.clone();
        save(&path, &st)?;
        eprintln!(
            "[kepr-daemon] EMERGENCY ACCESS requested from uid {uid} by {label}: \
             released at {at} UTC unless denied (kepr emergency deny)"
        );
        return Ok((
            uid,
            format!("request recorded; access is released at {at} UTC unless the owner denies it"),
        ));
    }
    Err(INVALID.into())
}

pub fn handle_request(uid: u32, username: &str, text: &str) -> Response {
    match request_at(text, now_unix()) {
        Ok((owner, msg)) => {
            // The owner's own log says who asked and when.
            let owner_name = username_for_uid(owner);
            audit_r::<()>("emergency-request", owner, &owner_name, None, &Ok(()));
            super::done(msg)
        }
        Err(e) => {
            audit_r::<()>("emergency-request", uid, username, None, &Err(e.clone()));
            Response::fail(e)
        }
    }
}

/// The credentials a grant releases: its list, or every name the owner
/// has. Each one goes through `share send`'s policy, so sealed, SSH,
/// share-key, consent- and FIDO2-gated values are skipped.
fn release(owner: u32, g: &mut Grant, now: u64) {
    let names: Vec<String> = match &g.names {
        Some(n) => n.clone(),
        None => crate::store::list_for_uid(owner)
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| n != KEY_NAME && crate::store::validate_name(n).is_ok())
            .collect(),
    };
    let Ok(to) = Recipient::parse(&g.public) else {
        return;
    };
    let username = username_for_uid(owner);
    let mut envelopes = Vec::new();
    for name in names {
        // peer pid 0: no caller to ask for consent, so gated values fail closed.
        let r = new_payload((owner, 0), &name, Some(ENVELOPE_TTL)).and_then(|p| {
            let json = Zeroizing::new(serde_json::to_vec(&p).map_err(|e| e.to_string())?);
            super::kem::seal(&to, &json)
        });
        if let Ok(env) = &r {
            envelopes.push(env.clone());
        }
        audit_r("emergency-release", owner, &username, Some(&name), &r);
    }
    eprintln!(
        "[kepr-daemon] EMERGENCY ACCESS released: {} credential(s) of uid {owner} to {}",
        envelopes.len(),
        g.label
    );
    g.released = Some(now);
    g.envelopes = envelopes;
}

/// Release what is due for `owner` at `now`; drop old envelopes.
pub(crate) fn sweep_uid(owner: u32, now: u64) {
    let Ok(_g) = LOCK.lock() else { return };
    let path = state_path(KIND, owner);
    let mut st: Grants = load(&path);
    let mut changed = false;
    for g in &mut st.grants {
        let due = g
            .requested
            .is_some_and(|t| now >= t.saturating_add(g.delay));
        if due && g.released.is_none() {
            release(owner, g, now);
            changed = true;
        }
        if g.released
            .is_some_and(|t| now >= t.saturating_add(ENVELOPE_TTL))
            && !g.envelopes.is_empty()
        {
            g.envelopes.clear();
            changed = true;
        }
    }
    if changed {
        if let Err(e) = save(&path, &st) {
            eprintln!("[kepr-daemon] emergency state: {e}");
        }
    }
}

pub fn sweep(now: u64) {
    for uid in owner_uids() {
        sweep_uid(uid, now);
    }
}

/// Released envelopes for `uid`: those to its share key, from any
/// owner, and those released from its own grants.
pub(crate) fn fetch(uid: u32) -> Vec<String> {
    let me = load_secret(uid).ok().map(|s| *s.recipient().x25519());
    let _g = LOCK.lock();
    let mut out = Vec::new();
    for owner in owner_uids() {
        let st: Grants = load(&state_path(KIND, owner));
        for g in st.grants.iter().filter(|g| g.released.is_some()) {
            if owner == uid || (me.is_some() && x_of(&g.public) == me) {
                out.extend(g.envelopes.iter().cloned());
            }
        }
    }
    out
}

pub fn handle_release(uid: u32, username: &str) -> Response {
    let envelopes = fetch(uid);
    audit_r::<()>("emergency-fetch", uid, username, None, &Ok(()));
    SharingResponse::EmergencyEnvelopes { envelopes }.into()
}

#[cfg(test)]
mod tests {
    use super::super::emergency::{handle_add, handle_deny, handle_list};
    use super::*;
    use crate::daemon_share::handle_receive;
    use crate::daemon_store::testkit;
    use kepr_core::protocol_sharing::SharingResponse as S;

    const HOUR: u64 = 3600;

    fn key(uid: u32) -> String {
        match crate::daemon_share::handle_key(uid, "t", true) {
            Response::ShareKeyOk { public } => public,
            other => panic!("{other:?}"),
        }
    }

    /// Owner `a` with a plain and a sealed credential, contact `b`
    /// granted everything after an hour; `b`'s request text.
    fn setup() -> (u32, u32, String) {
        let (a, b) = (testkit::uid(), testkit::uid());
        let (ka, kb) = (key(a), key(b));
        testkit::set(a, "EM_PLAIN", "open-me");
        testkit::set_sealed(a, "EM_SEALED", "never");
        assert!(handle_add(a, "t", &kb, HOUR, None).is_success());
        let Response::Sharing(S::EmergencyProof { proof }) = handle_prove(b, "t", &ka) else {
            panic!("no proof");
        };
        (a, b, proof)
    }

    fn state(a: u32) -> String {
        match handle_list(a) {
            Response::Sharing(S::EmergencyListing { grants }) => grants[0].state.clone(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_request_releases_after_the_delay_and_never_sealed_values() {
        super::super::test_chain();
        let (a, b, proof) = setup();
        let t0 = now_unix();
        assert_eq!(request_at(&proof, t0).unwrap().0, a);
        assert_eq!(state(a), "requested");
        sweep_uid(a, t0 + HOUR - 1);
        assert_eq!(state(a), "requested", "not before the delay");
        assert!(fetch(b).is_empty());
        sweep_uid(a, t0 + HOUR);
        assert_eq!(state(a), "released");
        let envs = fetch(b);
        assert_eq!(envs.len(), 1, "only the plain credential");
        assert_eq!(fetch(a), envs, "the owner can pass them on");
        assert!(fetch(testkit::uid()).is_empty());
        assert!(handle_receive(b, "t", &envs[0], None).is_success());
        assert_eq!(testkit::value(b, "EM_PLAIN").as_deref(), Some("open-me"));
        assert!(testkit::value(b, "EM_SEALED").is_none());
        assert!(super::super::audited(a, "emergency-release", "EM_PLAIN"));
    }

    #[test]
    fn deny_cancels_and_the_same_request_cant_be_replayed() {
        let (a, b, proof) = setup();
        let t0 = now_unix();
        request_at(&proof, t0).unwrap();
        // A repeat while pending is harmless.
        assert!(request_at(&proof, t0 + 5)
            .unwrap()
            .1
            .contains("already requested"));
        assert!(handle_deny(a, "t", &key(b)).is_success());
        assert_eq!(state(a), "waiting");
        sweep_uid(a, t0 + 2 * HOUR);
        assert!(fetch(b).is_empty());
        let again = request_at(&proof, t0 + 10).unwrap_err();
        assert!(again.contains("already used or denied"), "{again}");
        // A fresh (later) request starts the clock again.
        let owner = Recipient::parse(&key(a)).unwrap();
        let fresh = proof::make(&load_secret(b).unwrap(), &owner, t0 + 20).unwrap();
        assert!(request_at(&fresh, t0 + 20).is_ok());
        assert_eq!(state(a), "requested");
    }

    #[test]
    fn forged_stale_and_unknown_requests_are_refused() {
        let (a, _b, proof) = setup();
        let t0 = now_unix();
        // Someone else's key, claiming nothing: no grant for them.
        let c = testkit::uid();
        key(c);
        let Response::Sharing(S::EmergencyProof { proof: other }) = handle_prove(c, "t", &key(a))
        else {
            panic!("no proof");
        };
        assert_eq!(request_at(&other, t0).unwrap_err(), INVALID);
        // The contact's request with its time changed: MAC fails.
        let mut p = proof::parse(&proof).unwrap();
        p.at += 1;
        let json = serde_json::to_vec(&p).unwrap();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let tampered = format!("{}{b64}", proof::PREFIX);
        assert_eq!(request_at(&tampered, t0).unwrap_err(), INVALID);
        // Too old, or from the future.
        assert!(request_at(&proof, t0 + MAX_AGE + 1).is_err());
        assert!(request_at(&proof, t0 - SKEW - 5).is_err());
        assert_eq!(state(a), "waiting");
    }
}
