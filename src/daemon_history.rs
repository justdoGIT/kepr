// daemon_history.rs — bounded encrypted credential history and
// `kepr restore` (agent vault P5.3).
//
// Before a `set` (or `rotate`, or `restore`) replaces a value, the old
// value is saved to one of DEPTH history slots. A slot is an ordinary
// credential file named `<NAME>~<slot>`: same AES-GCM encryption, AAD
// bound to that exact name, same rollback counter. `~` fails
// `validate_name`, so no request can name a slot directly and
// `list_for_uid` never shows one. The slot plaintext starts with a
// small header — `kh2:<flags>:<saved_unix_nanos>:<bindings>:` — so the
// save time, whether the value was sealed, and a fingerprint of the
// bindings it was sealed to are authenticated with it. A sealed version
// restores only while the credential has those same bindings: otherwise
// a same-uid caller could re-seal NAME to its own host, restore the old
// value under that binding, and have a gate send it there.
//
// History never returns a value. `History` lists version numbers,
// times and sizes; `Restore` puts an old value back as the current one,
// under the credential's current policy (a value saved while sealed is
// only restored into a sealed credential). SSH keys keep no history:
// their `.meta` carries the public key, which an old seed would not
// match. Delete and TTL expiry purge the history with the credential.

use std::path::Path;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{HistoryEntry, Response};

use crate::audit::{self, AuditEvent, AuditResult};
use crate::store::{cred_path, to_cred_name, validate_name};
use crate::version_state::VersionState;
use crate::{crypto, daemon_cache, expiry};

/// Previous values kept per credential.
pub const DEPTH: u32 = 5;
const HEADER: &str = "kh2:";
const HEADER_V1: &str = "kh1:";
const FLAG_SEALED: u8 = 1;

fn slot_name(name: &str, slot: u32) -> String {
    format!("{name}~{slot}")
}

/// A short fingerprint of a credential's bindings ("-" when none).
fn bindings_fp(meta: &expiry::CredMeta) -> String {
    use sha2::{Digest, Sha256};
    match &meta.bindings {
        None => "-".into(),
        Some(b) => {
            let json = serde_json::to_vec(b).unwrap_or_default();
            hex::encode(&Sha256::digest(&json)[..12])
        }
    }
}

fn encode(flags: u8, saved_ns: u128, bindings: &str, secret: &str) -> ZeroString {
    ZeroString::from_string(format!("{HEADER}{flags}:{saved_ns}:{bindings}:{secret}"))
}

/// `(flags, saved_ns, bindings fingerprint, secret)` from a slot
/// plaintext; `kh1` slots (before fingerprints) have none.
fn decode(plain: &str) -> Option<(u8, u128, Option<&str>, &str)> {
    let (v2, rest) = match plain.strip_prefix(HEADER) {
        Some(r) => (true, r),
        None => (false, plain.strip_prefix(HEADER_V1)?),
    };
    let (flags, rest) = rest.split_once(':')?;
    let (ns, rest) = rest.split_once(':')?;
    let (fp, secret) = if v2 {
        let (fp, s) = rest.split_once(':')?;
        (Some(fp), s)
    } else {
        (None, rest)
    };
    Some((flags.parse().ok()?, ns.parse().ok()?, fp, secret))
}

fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// A readable slot: `(slot, flags, saved_ns, secret_len)`.
type SlotInfo = (u32, u8, u128, usize);

/// Every occupied slot, newest first. A slot that no longer decrypts
/// (corrupt, rolled back) is reported with `saved_ns = 0` so it sorts
/// last and is the first to be overwritten; `History` hides it.
fn slots(uid: u32, name: &str) -> Vec<SlotInfo> {
    let mut out: Vec<SlotInfo> = (0..DEPTH)
        .filter(|s| crate::store::cred_exists(uid, &slot_name(name, *s)))
        .map(|s| {
            match crypto::default_backend().decrypt(uid, &slot_name(name, s)) {
                Ok(z) => decode(z.as_str()).map(|(f, ns, _, v)| (s, f, ns, v.len())),
                Err(_) => None,
            }
            .unwrap_or((s, 0, 0, 0))
        })
        .collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.2));
    out
}

/// The slot the next save goes to: a free one, else the oldest.
fn next_slot(uid: u32, name: &str) -> u32 {
    let used = slots(uid, name);
    (0..DEPTH)
        .find(|s| !used.iter().any(|u| u.0 == *s))
        .or_else(|| used.last().map(|u| u.0))
        .unwrap_or(0)
}

/// Save the current value of `name` (uppercased) before it is replaced.
/// Best effort: a failure is logged and never blocks the write.
pub fn save_current(uid: u32, name: &str) {
    let meta =
        expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, name))).and_then(Result::ok);
    // SSH and share private keys never go to history: a restored slot
    // carries no meta, so `Get` would then return them.
    if meta
        .as_ref()
        .is_some_and(|m| m.ssh.is_some() || m.share_key == Some(true))
        || !crate::store::cred_exists(uid, name)
    {
        return;
    }
    let current = match crypto::default_backend().decrypt(uid, name) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[kepr-daemon] history: current value unreadable, not saved: {e}");
            return;
        }
    };
    let meta = meta.unwrap_or_default();
    let flags = if meta.sealed == Some(true) {
        FLAG_SEALED
    } else {
        0
    };
    let slot = slot_name(name, next_slot(uid, name));
    let plain = encode(flags, now_ns(), &bindings_fp(&meta), current.as_str());
    if let Err(e) = crypto::default_backend().encrypt(uid, &slot, plain.as_bytes()) {
        eprintln!("[kepr-daemon] history: save failed: {e}");
    }
}

/// Drop every history slot of `name` (on delete).
pub fn purge(uid: u32, name: &str) {
    for s in 0..DEPTH {
        let slot = slot_name(name, s);
        if crate::store::cred_exists(uid, &slot) {
            if let Err(e) = crypto::default_backend().delete(uid, &slot) {
                eprintln!("[kepr-daemon] history: purge failed: {e}");
            }
        }
    }
}

/// Drop every history slot of `name` under `dir` (the TTL sweeper,
/// which works on a directory + version state, not the backend).
pub fn purge_in(dir: &Path, versions: Option<&VersionState>, uid: u32, name: &str) {
    for s in 0..DEPTH {
        let file = to_cred_name(uid, &slot_name(name, s));
        let path = dir.join(&file);
        if !path.exists() {
            continue;
        }
        if let Some(Err(e)) = versions.map(|v| v.tombstone(&file)) {
            eprintln!("[kepr-daemon] history: tombstone failed: {e}");
            continue;
        }
        let _ = std::fs::remove_file(path);
    }
}

fn audit_result(op: &'static str, uid: u32, username: &str, name: &str, r: &Result<(), String>) {
    audit::log(&AuditEvent {
        op,
        name: Some(name),
        uid,
        username,
        result: match r {
            Ok(()) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.clone()),
        },
    });
}

pub fn handle_history(uid: u32, username: &str, name: &str) -> Response {
    let upper = name.to_uppercase();
    let checked = validate_name(name).and_then(|_| {
        if crate::store::cred_exists(uid, &upper) {
            Ok(())
        } else {
            Err(format!("credential not found: {upper}"))
        }
    });
    audit_result("history", uid, username, &upper, &checked);
    if let Err(e) = checked {
        return Response::fail(e);
    }
    let versions = slots(uid, &upper)
        .into_iter()
        .filter(|s| s.2 > 0)
        .enumerate()
        .map(|(i, (_, flags, ns, len))| HistoryEntry {
            version: i as u32 + 1,
            saved_at: expiry::format_expires_at((ns / 1_000_000_000) as u64),
            size: len as u64,
            sealed: (flags & FLAG_SEALED != 0).then_some(true),
        })
        .collect();
    Response::HistoryOk {
        name: upper,
        versions,
    }
}

/// The decrypted slot plaintext (header + value) of history `version`
/// (1 = most recent).
fn slot_plain(uid: u32, upper: &str, version: u32) -> Result<ZeroString, String> {
    let readable: Vec<SlotInfo> = slots(uid, upper).into_iter().filter(|s| s.2 > 0).collect();
    let slot = version
        .checked_sub(1)
        .and_then(|i| readable.get(i as usize))
        .ok_or_else(|| format!("no version {version} of {upper} (see: kepr history {upper})"))?;
    crypto::default_backend()
        .decrypt(uid, &slot_name(upper, slot.0))
        .map_err(|e| crypto::sanitize_lookup_error(&e))
}

/// T11.3: version `version` (0 = current, 1 = newest saved) and whether
/// it was saved while sealed, for `kepr history --diff`. The value stays
/// in the daemon; the caller checks the credential's policy first.
pub fn version_value(uid: u32, upper: &str, version: u32) -> Result<(ZeroString, bool), String> {
    if version == 0 {
        return crypto::default_backend()
            .decrypt(uid, upper)
            .map(|v| (v, false))
            .map_err(|e| crypto::sanitize_lookup_error(&e));
    }
    let plain = slot_plain(uid, upper, version)?;
    let (flags, _, _, secret) = decode(plain.as_str()).ok_or("history entry is malformed")?;
    Ok((
        ZeroString::from_string(secret.to_string()),
        flags & FLAG_SEALED != 0,
    ))
}

/// Decrypt history version `version` (1 = most recent) and check it may
/// go back under the current policy. The value stays in the daemon.
fn pick(uid: u32, upper: &str, version: u32) -> Result<ZeroString, String> {
    validate_name(upper)?;
    if !crate::store::cred_exists(uid, upper) {
        return Err(format!("credential not found: {upper}"));
    }
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .transpose()?
        .unwrap_or_default();
    if meta.ssh.is_some() {
        return Err("SSH keys keep no history".into());
    }
    let plain = slot_plain(uid, upper, version)?;
    let (flags, _, fp, secret) = decode(plain.as_str()).ok_or("history entry is malformed")?;
    if flags & FLAG_SEALED != 0 {
        if meta.sealed != Some(true) {
            return Err(
                "that version was sealed; it can only be restored into a sealed credential".into(),
            );
        }
        if fp != Some(bindings_fp(&meta).as_str()) {
            return Err("that version was sealed to different hosts; restore refused".into());
        }
    }
    Ok(ZeroString::from_string(secret.to_string()))
}

pub fn handle_restore(uid: u32, username: &str, name: &str, version: u32) -> Response {
    let _lock = crate::daemon_credlock::lock(uid, name);
    let upper = name.to_uppercase();
    let r = pick(uid, &upper, version).and_then(|old| {
        // Read the old value first: saving the current one may reuse
        // the very slot being restored.
        save_current(uid, &upper);
        crypto::default_backend().encrypt(uid, &upper, old.as_bytes())
    });
    audit_result("restore", uid, username, &upper, &r);
    match r {
        Ok(()) => {
            daemon_cache::invalidate(uid);
            crate::daemon_gate::bump_generation();
            Response::RestoreOk {
                name: upper,
                version,
            }
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let z = encode(1, 1_700_000_000_123_456_789, "ab12", "a:b:c");
        assert_eq!(
            decode(z.as_str()),
            Some((1, 1_700_000_000_123_456_789, Some("ab12"), "a:b:c"))
        );
        // Slots written before fingerprints still decode, without one.
        assert_eq!(decode("kh1:0:5:a:b"), Some((0, 5, None, "a:b")));
        assert_eq!(decode("plain value"), None);
        assert_eq!(decode("kh1:x:1:v"), None);
    }

    #[test]
    fn bindings_fingerprint_changes_with_the_hosts() {
        let b = |h: &str| expiry::CredMeta {
            sealed: Some(true),
            bindings: Some(vec![kepr_core::binding::Binding {
                host: h.into(),
                port: 443,
                inject: kepr_core::binding::Inject::Bearer,
            }]),
            ..Default::default()
        };
        assert_eq!(bindings_fp(&b("api.x.ai")), bindings_fp(&b("api.x.ai")));
        assert_ne!(bindings_fp(&b("api.x.ai")), bindings_fp(&b("evil.example")));
        assert_eq!(bindings_fp(&expiry::CredMeta::default()), "-");
    }

    #[test]
    fn slot_names_are_never_valid_credential_names() {
        let s = slot_name("API_KEY", 3);
        assert!(validate_name(&s).is_err());
        assert!(crate::store::from_cred_name(&to_cred_name(1000, &s)).is_none());
    }

    #[test]
    fn purge_in_removes_only_this_credentials_slots() {
        let dir = std::env::temp_dir().join(format!("kepr-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mine = to_cred_name(7, &slot_name("A", 2));
        let other = to_cred_name(7, &slot_name("AB", 2));
        std::fs::write(dir.join(&mine), b"x").unwrap();
        std::fs::write(dir.join(&other), b"x").unwrap();
        purge_in(&dir, None, 7, "A");
        assert!(!dir.join(&mine).exists());
        assert!(dir.join(&other).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
