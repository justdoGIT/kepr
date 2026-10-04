// daemon_history.rs — bounded encrypted credential history and
// `kepr restore` (agent vault P5.3).
//
// Before a `set` (or `rotate`, or `restore`) replaces a value, the old
// value is saved to one of DEPTH history slots. A slot is an ordinary
// credential file named `<NAME>~<slot>`: same AES-GCM encryption, AAD
// bound to that exact name, same rollback counter. `~` fails
// `validate_name`, so no request can name a slot directly and
// `list_for_uid` never shows one. The slot plaintext starts with a
// small header — `kh1:<flags>:<saved_unix_nanos>:` — so the save time
// and whether the value was sealed are authenticated with it.
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
const HEADER: &str = "kh1:";
const FLAG_SEALED: u8 = 1;

fn slot_name(name: &str, slot: u32) -> String {
    format!("{name}~{slot}")
}

fn encode(flags: u8, saved_ns: u128, secret: &str) -> ZeroString {
    ZeroString::from_string(format!("{HEADER}{flags}:{saved_ns}:{secret}"))
}

/// `(flags, saved_ns, secret)` from a slot plaintext.
fn decode(plain: &str) -> Option<(u8, u128, &str)> {
    let rest = plain.strip_prefix(HEADER)?;
    let (flags, rest) = rest.split_once(':')?;
    let (ns, secret) = rest.split_once(':')?;
    Some((flags.parse().ok()?, ns.parse().ok()?, secret))
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
        .filter(|s| cred_path(uid, &slot_name(name, *s)).exists())
        .map(|s| {
            match crypto::default_backend().decrypt(uid, &slot_name(name, s)) {
                Ok(z) => decode(z.as_str()).map(|(f, ns, v)| (s, f, ns, v.len())),
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
    if meta.as_ref().is_some_and(|m| m.ssh.is_some()) || !cred_path(uid, name).exists() {
        return;
    }
    let current = match crypto::default_backend().decrypt(uid, name) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[kepr-daemon] history: current value unreadable, not saved: {e}");
            return;
        }
    };
    let flags = if meta.is_some_and(|m| m.sealed == Some(true)) {
        FLAG_SEALED
    } else {
        0
    };
    let slot = slot_name(name, next_slot(uid, name));
    let plain = encode(flags, now_ns(), current.as_str());
    if let Err(e) = crypto::default_backend().encrypt(uid, &slot, plain.as_bytes()) {
        eprintln!("[kepr-daemon] history: save failed: {e}");
    }
}

/// Drop every history slot of `name` (on delete).
pub fn purge(uid: u32, name: &str) {
    for s in 0..DEPTH {
        let slot = slot_name(name, s);
        if cred_path(uid, &slot).exists() {
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
        if cred_path(uid, &upper).exists() {
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

/// Decrypt history version `version` (1 = most recent) and check it may
/// go back under the current policy. The value stays in the daemon.
fn pick(uid: u32, upper: &str, version: u32) -> Result<ZeroString, String> {
    validate_name(upper)?;
    if !cred_path(uid, upper).exists() {
        return Err(format!("credential not found: {upper}"));
    }
    let meta = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper)))
        .transpose()?
        .unwrap_or_default();
    if meta.ssh.is_some() {
        return Err("SSH keys keep no history".into());
    }
    let readable: Vec<SlotInfo> = slots(uid, upper).into_iter().filter(|s| s.2 > 0).collect();
    let slot = version
        .checked_sub(1)
        .and_then(|i| readable.get(i as usize))
        .ok_or_else(|| format!("no version {version} of {upper} (see: kepr history {upper})"))?;
    let plain = crypto::default_backend()
        .decrypt(uid, &slot_name(upper, slot.0))
        .map_err(|e| crypto::sanitize_lookup_error(&e))?;
    let (flags, _, secret) = decode(plain.as_str()).ok_or("history entry is malformed")?;
    if flags & FLAG_SEALED != 0 && meta.sealed != Some(true) {
        return Err(
            "that version was sealed; it can only be restored into a sealed credential".into(),
        );
    }
    Ok(ZeroString::from_string(secret.to_string()))
}

pub fn handle_restore(uid: u32, username: &str, name: &str, version: u32) -> Response {
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
        let z = encode(1, 1_700_000_000_123_456_789, "a:b:c");
        assert_eq!(
            decode(z.as_str()),
            Some((1, 1_700_000_000_123_456_789, "a:b:c"))
        );
        assert_eq!(decode("plain value"), None);
        assert_eq!(decode("kh1:x:1:v"), None);
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
