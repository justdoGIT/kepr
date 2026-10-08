// daemon_session/ssh_rotate.rs — the vault half of `kepr ssh rotate`
// (T11.21). The CLI generates the new key as NEXT, puts it on the host
// and checks a login with it; `SshRotateCommit { name, next }` then makes
// NEXT's key NAME's (keeping NAME's consent flag) and deletes NEXT. The
// private key never leaves the daemon: the seed is re-stored in place,
// and SSH keys keep no history, so the old key is gone for good.
//
// Re-running after a crash between the two steps is safe: when NAME
// already holds NEXT's key only NEXT is removed.

use kepr_core::protocol::Response;
use kepr_core::ssh_wire;

use crate::daemon_handlers::{handle_delete, handle_set, SetFlags};
use crate::expiry::{self, CredMeta};
use crate::store::{cred_path, validate_name};

fn ssh_meta(uid: u32, upper: &str) -> Result<CredMeta, String> {
    match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        Some(Ok(m)) if m.ssh.is_some() && crate::store::cred_exists(uid, upper) => Ok(m),
        _ => Err(format!("{upper} is not an SSH key")),
    }
}

fn commit(uid: u32, username: &str, name: &str, next: &str) -> Result<String, String> {
    validate_name(name)?;
    validate_name(next)?;
    let (name, next) = (name.to_uppercase(), next.to_uppercase());
    if name == next {
        return Err("the new key needs its own name".into());
    }
    let (a, b) = if name < next {
        (&name, &next)
    } else {
        (&next, &name)
    };
    let _locks = (
        crate::daemon_credlock::lock(uid, a),
        crate::daemon_credlock::lock(uid, b),
    );
    let old = ssh_meta(uid, &name)?;
    let new = ssh_meta(uid, &next)?;
    let ssh = new.ssh.clone().ok_or("not an SSH key")?;
    let line = format!("{} {} {}", ssh_wire::ED25519, ssh.public_b64, ssh.comment);
    if old.ssh.as_ref().map(|s| &s.public_b64) != Some(&ssh.public_b64) {
        let seed = crate::crypto::default_backend()
            .decrypt(uid, &next)
            .map_err(|e| crate::crypto::sanitize_lookup_error(&e))?;
        let flags = SetFlags {
            requires_consent: old.requires_consent,
            ssh: Some(ssh),
            ..Default::default()
        };
        let r = handle_set(uid, username, &name, Some(seed.as_str()), None, flags);
        if !r.is_success() {
            return Err(r.err_msg().unwrap_or("store failed").to_string());
        }
    }
    let r = handle_delete(uid, username, &next);
    if !r.is_success() {
        return Err(r.err_msg().unwrap_or("delete failed").to_string());
    }
    Ok(line.trim_end().to_string())
}

pub fn handle_commit(uid: u32, username: &str, name: &str, next: &str) -> Response {
    let r = commit(uid, username, name, next);
    let upper = name.to_uppercase();
    super::audit_op(
        "ssh-rotate",
        Some(&upper),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
    match r {
        Ok(public_line) => Response::SshKeyOk {
            name: upper,
            public_line,
        },
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;
    use kepr_core::protocol::Request;

    fn generate(uid: u32, name: &str, consent: Option<bool>) -> String {
        let req = Request::SshGenerate {
            name: name.into(),
            comment: "c".into(),
            requires_consent: consent,
        };
        match crate::daemon_ssh::dispatch(uid, 0, "t", req) {
            Response::SshKeyOk { public_line, .. } => public_line,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn next_becomes_name_and_is_removed() {
        let uid = testkit::uid();
        generate(uid, "SR_KEY", Some(true));
        let new_line = generate(uid, "SR_KEY_NEXT", None);
        match handle_commit(uid, "t", "sr_key", "SR_KEY_NEXT") {
            Response::SshKeyOk { name, public_line } => {
                assert_eq!((name.as_str(), public_line), ("SR_KEY", new_line.clone()));
            }
            other => panic!("{other:?}"),
        }
        let m = testkit::meta(uid, "SR_KEY");
        assert!(new_line.contains(&m.ssh.unwrap().public_b64));
        assert_eq!(m.requires_consent, Some(true), "NAME keeps its policy");
        assert!(!crate::store::cred_exists(uid, "SR_KEY_NEXT"));
    }

    #[test]
    fn rerun_after_a_crash_only_cleans_up() {
        let uid = testkit::uid();
        let line = generate(uid, "SR_A_NEXT", None);
        generate(uid, "SR_A", None);
        assert!(handle_commit(uid, "t", "SR_A", "SR_A_NEXT").is_success());
        generate(uid, "SR_A_NEXT", None);
        // Simulate the crash: NEXT holds the same key as NAME again.
        let m = testkit::meta(uid, "SR_A");
        let mp = expiry::meta_path_for(&cred_path(uid, "SR_A_NEXT"));
        expiry::write_meta(&mp, &m).unwrap();
        assert!(handle_commit(uid, "t", "SR_A", "SR_A_NEXT").is_success());
        assert!(!crate::store::cred_exists(uid, "SR_A_NEXT"));
        assert!(line.contains(&testkit::meta(uid, "SR_A").ssh.unwrap().public_b64));
    }

    #[test]
    fn only_ssh_keys_and_two_names() {
        let uid = testkit::uid();
        generate(uid, "SR_K", None);
        testkit::set(uid, "SR_PLAIN", "v");
        let e = |n: &str, x: &str| handle_commit(uid, "t", n, x).err_msg().map(str::to_string);
        assert_eq!(e("SR_K", "SR_PLAIN").unwrap(), "SR_PLAIN is not an SSH key");
        assert_eq!(e("SR_PLAIN", "SR_K").unwrap(), "SR_PLAIN is not an SSH key");
        assert!(e("SR_K", "sr_k").unwrap().contains("own name"));
        assert!(e("SR_K", "../x").is_some());
        assert_eq!(testkit::value(uid, "SR_PLAIN").as_deref(), Some("v"));
    }
}
