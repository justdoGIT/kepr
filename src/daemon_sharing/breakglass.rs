// daemon_sharing/breakglass.rs — T6.07 break-glass reveal of a sealed
// credential: the only path that returns a sealed value.
//
//   kepr break-glass NAME   paste k recovery-kit shares (P6.3); the value
//                           is printed once and NAME is marked
//                           `must_rotate` (cleared by the next set)
//
// Rationale: k shares rebuild the master key, and whoever has them and
// the credential files can already decrypt everything offline. This adds
// no capability; it makes that access loud. Fenced like the recovery
// kit (AGENTS.md):
//   - refused while any agent gate runs (of any user);
//   - the shares must rebuild exactly the running store's key (constant-
//     time compare); any mistake gets one message that never says which
//     share was wrong;
//   - sealed credentials only (`get` serves the rest; SSH and share keys
//     are never revealed);
//   - `must_rotate` is written before the value is decrypted (no mark,
//     no value), and every attempt is audited as `break-glass`.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::shamir;

use super::audit_r;
use crate::store::{cred_exists, cred_path, validate_name};
use crate::{crypto, expiry};

const WRONG: &str =
    "these recovery shares don't rebuild this store's key (give at least the kit's threshold, \
     all from one kit)";

/// Any gate of any user running? (A poisoned registry counts as yes.)
fn gates_running() -> bool {
    crate::daemon_gate_registry::GATES
        .lock()
        .map_or(true, |g| !g.is_empty())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Do `shares` rebuild `live`? Every failure is the same `WRONG`.
pub(crate) fn check_shares(shares: &[ZeroString], live: &[u8; 32]) -> Result<(), String> {
    let fp = crate::daemon_recovery::fingerprint(live);
    let mut parsed = Vec::new();
    let mut same_kit = true;
    for s in shares {
        let (share, f) = shamir::decode(s.as_str()).map_err(|_| WRONG)?;
        same_kit &= f == fp;
        parsed.push(share);
    }
    let key = shamir::combine(&parsed).map_err(|_| WRONG)?;
    (same_kit && ct_eq(&key, live))
        .then_some(())
        .ok_or_else(|| WRONG.to_string())
}

fn reveal(
    uid: u32,
    upper: &str,
    shares: &[ZeroString],
    gate_running: bool,
) -> Result<ZeroString, String> {
    if gate_running {
        return Err("stop running agent sessions first (kepr panic)".into());
    }
    let _lock = crate::daemon_credlock::lock(uid, upper);
    if !cred_exists(uid, upper) {
        return Err("credential unavailable".into());
    }
    let path = expiry::meta_path_for(&cred_path(uid, upper));
    let mut meta = match expiry::read_meta(&path) {
        // Never SSH or share keys, even if one were ever marked sealed.
        Some(Ok(m)) if m.ssh.is_some() || m.share_key == Some(true) => {
            return Err("credential unavailable".into())
        }
        Some(Ok(m)) if m.sealed == Some(true) => m,
        Some(Err(_)) => return Err("credential unavailable".into()),
        _ => return Err(format!("{upper} is not sealed: use `kepr get`")),
    };
    check_shares(shares, &*crypto::snapshot_key()?)?;
    meta.must_rotate = Some(true);
    expiry::write_meta(&path, &meta)?;
    crypto::default_backend()
        .decrypt(uid, upper)
        .map_err(|e| crypto::sanitize_lookup_error(&e))
}

pub fn handle(uid: u32, username: &str, name: &str, shares: &[ZeroString]) -> Response {
    handle_with(uid, username, name, shares, gates_running)
}

fn handle_with(
    uid: u32,
    username: &str,
    name: &str,
    shares: &[ZeroString],
    gate_running: fn() -> bool,
) -> Response {
    if let Err(e) = validate_name(name) {
        return Response::fail(e);
    }
    let upper = name.to_uppercase();
    let r = reveal(uid, &upper, shares, gate_running());
    audit_r("break-glass", uid, username, Some(&upper), &r);
    match r {
        Ok(value) => {
            eprintln!("[kepr-daemon] BREAK-GLASS: sealed {upper} of uid {uid} revealed");
            Response::GetOk { name: upper, value }
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    /// The test backend's key is [0x5a; 32] (testkit).
    fn kit(key: &[u8; 32], k: u8, n: u8) -> Vec<ZeroString> {
        let fp = crate::daemon_recovery::fingerprint(key);
        shamir::split(key, k, n)
            .unwrap()
            .iter()
            .map(|s| ZeroString::from_string(shamir::encode(s, &fp).to_string()))
            .collect()
    }

    fn live() -> [u8; 32] {
        *crypto::snapshot_key().unwrap()
    }

    /// `handle` with no gate running (other tests may track fake gates).
    fn handle(uid: u32, username: &str, name: &str, shares: &[ZeroString]) -> Response {
        handle_with(uid, username, name, shares, || false)
    }

    #[test]
    fn correct_shares_reveal_once_and_mark_must_rotate_until_the_next_set() {
        super::super::test_chain();
        let u = testkit::uid();
        testkit::set_sealed(u, "BG_KEY", "sk-live-123");
        let shares = kit(&live(), 2, 3);
        let r = handle(u, "t", "bg_key", &shares[1..]);
        let Response::GetOk { name, value } = r else {
            panic!("{r:?}");
        };
        assert_eq!((name.as_str(), value.as_str()), ("BG_KEY", "sk-live-123"));
        let m = testkit::meta(u, "BG_KEY");
        assert_eq!((m.must_rotate, m.sealed), (Some(true), Some(true)));
        assert!(super::super::audited(u, "break-glass", "BG_KEY"));
        // `kepr list` flags it.
        let Response::ListOk { credentials, .. } = crate::daemon_handlers_list::handle_list(u, "t")
        else {
            panic!("no list");
        };
        let c = credentials.iter().find(|c| c.name == "BG_KEY").unwrap();
        assert_eq!(c.must_rotate, Some(true));
        // The next set (the rotation) clears it.
        testkit::set_sealed(u, "BG_KEY", "sk-live-456");
        assert_eq!(testkit::meta(u, "BG_KEY").must_rotate, None);
    }

    #[test]
    fn wrong_shares_are_refused_without_saying_which() {
        let u = testkit::uid();
        testkit::set_sealed(u, "BG_WRONG", "v");
        let good = kit(&live(), 2, 3);
        let other = kit(&[7u8; 32], 2, 3);
        let z = |v: &[ZeroString], i: usize| ZeroString::from_string(v[i].as_str().to_string());
        // A share from another kit, too few shares, a mangled share,
        // the same share twice: all the same message, nothing revealed.
        let mangled = ZeroString::from_string(format!("{}0", good[1].as_str()));
        for bad in [
            vec![z(&good, 0), z(&other, 1)],
            vec![z(&good, 0)],
            vec![z(&good, 0), mangled],
            vec![z(&good, 0), z(&good, 0)],
            vec![],
        ] {
            let r = handle(u, "t", "BG_WRONG", &bad);
            assert!(
                matches!(&r, Response::Err { error } if error == WRONG),
                "{r:?}"
            );
        }
        assert_eq!(testkit::meta(u, "BG_WRONG").must_rotate, None);
    }

    #[test]
    fn only_sealed_credentials_and_never_while_a_gate_runs() {
        let u = testkit::uid();
        testkit::set(u, "BG_PLAIN", "v");
        let shares = kit(&live(), 2, 2);
        let r = handle(u, "t", "BG_PLAIN", &shares);
        assert!(matches!(&r, Response::Err { error } if error.contains("not sealed")));
        let r = handle(u, "t", "BG_MISSING", &shares);
        assert!(matches!(&r, Response::Err { error } if error == "credential unavailable"));
        assert!(!handle(u, "t", "../x", &shares).is_success());
        // A sealed credential that is also an SSH or share key: refused.
        for (name, ssh) in [("BG_SSH", true), ("BG_SHAREKEY", false)] {
            testkit::set_sealed(u, name, "v");
            let mp = expiry::meta_path_for(&cred_path(u, name));
            let mut m = testkit::meta(u, name);
            if ssh {
                m.ssh = Some(crate::cred_meta::SshMeta {
                    public_b64: "AAAA".into(),
                    comment: "c".into(),
                });
            } else {
                m.share_key = Some(true);
            }
            expiry::write_meta(&mp, &m).unwrap();
            let r = handle(u, "t", name, &shares);
            assert!(
                matches!(&r, Response::Err { error } if error == "credential unavailable"),
                "{name}: {r:?}"
            );
            assert_eq!(testkit::meta(u, name).must_rotate, None);
        }
        testkit::set_sealed(u, "BG_GATED", "v");
        let r = handle_with(u, "t", "BG_GATED", &shares, || true);
        assert!(matches!(&r, Response::Err { error } if error.contains("agent sessions")));
        assert_eq!(testkit::meta(u, "BG_GATED").must_rotate, None);
    }

    #[test]
    fn share_check_is_exact() {
        let key = [9u8; 32];
        assert!(check_shares(&kit(&key, 3, 5)[2..], &key).is_ok());
        assert!(check_shares(&kit(&key, 3, 5)[3..], &key).is_err());
        assert!(check_shares(&kit(&key, 2, 2), &[8u8; 32]).is_err());
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac") && !ct_eq(b"a", b"ab"));
    }
}
