// daemon_platform/exe.rs — binary-identity bindings (T10.09).
//
// `.meta` `exe_digests` lists the executables (kepr_core::exe_digest
// identities) allowed to read a credential through `Get`. `gate` runs in
// `precheck_meta`, before any decrypt: it opens /proc/<pid>/exe of the
// SO_PEERCRED pid and refuses unless that file matches. Refusals are the
// generic "credential unavailable" on the wire; the audit line says why.
//
// Fail closed: an unreadable /proc entry, a deleted executable (`(deleted)`
// link or no links left), a read error, or only fs-verity identities for a
// file without verity are all refusals.
//
// What it stops: other programs of the same user reading the value through
// the socket (scripts, SDK clients, `kepr get` when kepr isn't listed).
// What it doesn't: a same-uid attacker who can ptrace or LD_PRELOAD an
// allowed program, run an allowed interpreter with their own script, or
// hand a socket opened by an allowed program to another process. The peer
// is the process that connected (`kepr exec` fetches as kepr, not as the
// child it starts).
//
// Exec after connect: SO_PEERCRED names the pid that connected, and the
// check reads that pid's executable when each request arrives, not when
// it connected. A program that connects, keeps the socket (in a forked
// child, or across exec) and then execs an allowed binary passes with
// what it sends over that socket; so does a socket whose connecting pid
// exits and is reused by an allowed program. Only same-uid code can do
// this, which is why a binding narrows which programs read a value, not a
// boundary against code already running as the user.
//
// The binding is sticky: `set` keeps it (`carry_over`), and only a caller
// the binding allows can change or clear it (delete + re-create otherwise).
// In system mode the root daemon needs CAP_SYS_PTRACE to open other users'
// /proc/<pid>/exe; without it a binding is refused when it is created.

use std::fs::File;
use std::os::unix::fs::MetadataExt;

use kepr_core::exe_digest;
use kepr_core::protocol::Response;
use kepr_core::protocol_platform::PlatformResponse;

use crate::expiry::{self, CredMeta};
use crate::store::cred_path;

/// The Get gate: `Ok` when the credential has no binding or the peer's
/// executable matches one of its identities.
pub fn gate(meta: &CredMeta, peer_pid: i32) -> Result<(), String> {
    match meta.exe_digests.as_deref() {
        None | Some([]) => Ok(()),
        Some(allowed) => check_pid(allowed, peer_pid),
    }
}

/// Open the peer's executable, refusing deleted ones.
fn open_exe(pid: i32) -> Result<File, String> {
    if pid <= 0 {
        return Err("exe: no peer pid".into());
    }
    let link = format!("/proc/{pid}/exe");
    let f = File::open(&link).map_err(|_| "exe: unreadable".to_string())?;
    let target = std::fs::read_link(&link).map_err(|_| "exe: unreadable".to_string())?;
    let deleted = target.to_string_lossy().ends_with(" (deleted)")
        || f.metadata().map(|m| m.nlink() == 0).unwrap_or(true);
    if deleted {
        return Err("exe: deleted".into());
    }
    Ok(f)
}

pub fn check_pid(allowed: &[String], pid: i32) -> Result<(), String> {
    let f = open_exe(pid)?;
    if exe_digest::matches(allowed, exe_digest::verity_of(&f), || {
        exe_digest::sha256_of(&f)
    }) {
        Ok(())
    } else {
        Err("exe: not an allowed executable".into())
    }
}

/// `set` keeps an existing binding (sticky, like `requires_reauth`).
pub fn carry_over(uid: u32, upper: &str, meta: &mut CredMeta) {
    if meta.exe_digests.is_some() {
        return;
    }
    if let Some(Ok(old)) = expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        meta.exe_digests = old.exe_digests;
    }
}

/// Validate, dedupe and cap the requested identities.
pub fn normalize(digests: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for d in digests {
        if !exe_digest::is_valid(d) {
            return Err("invalid executable identity".into());
        }
        if !out.contains(d) {
            out.push(d.clone());
        }
    }
    if out.len() > exe_digest::MAX_ENTRIES {
        return Err(format!(
            "at most {} executable identities",
            exe_digest::MAX_ENTRIES
        ));
    }
    Ok(out)
}

/// Pure policy for a change: `may_change` checks the caller against the
/// current binding, `can_verify` that this daemon can read callers'
/// executables at all.
pub fn rebind(
    meta: &CredMeta,
    new: Vec<String>,
    may_change: impl FnOnce(&[String]) -> bool,
    can_verify: impl FnOnce() -> bool,
) -> Result<CredMeta, String> {
    if meta.sealed == Some(true) || meta.ssh.is_some() || meta.share_key == Some(true) {
        return Err("sealed, SSH and share keys are never returned by get; nothing to bind".into());
    }
    if let Some(cur) = meta.exe_digests.as_deref().filter(|c| !c.is_empty()) {
        if !may_change(cur) {
            return Err(
                "only a program the binding allows can change it; delete and re-create the credential to drop it"
                    .into(),
            );
        }
    }
    if !new.is_empty() && !can_verify() {
        return Err("this daemon cannot read callers' executables (system mode needs CAP_SYS_PTRACE: see systemd/kepr.service.d/ptrace.conf.example); binding refused".into());
    }
    let mut out = meta.clone();
    out.exe_digests = (!new.is_empty()).then_some(new);
    Ok(out)
}

fn target(uid: u32, name: &str) -> Result<String, String> {
    crate::store::validate_name(name)?;
    Ok(crate::daemon_store::resolve_alias(
        uid,
        &name.to_uppercase(),
    ))
}

fn read_meta(uid: u32, upper: &str) -> Result<CredMeta, String> {
    if !crate::store::cred_exists(uid, upper) {
        return Err(crate::crypto::SANITIZED_LOOKUP_ERROR.to_string());
    }
    match expiry::read_meta(&expiry::meta_path_for(&cred_path(uid, upper))) {
        None => Ok(CredMeta::default()),
        Some(Ok(m)) => Ok(m),
        Some(Err(_)) => Err("credential metadata unreadable".into()),
    }
}

/// `ExeBind`: replace the binding (empty = clear).
pub fn handle_bind(
    uid: u32,
    peer_pid: i32,
    username: &str,
    name: &str,
    digests: &[String],
) -> Response {
    let mut upper = name.to_uppercase();
    let r = (|| {
        upper = target(uid, name)?;
        let new = normalize(digests)?;
        let _lock = crate::daemon_credlock::lock(uid, &upper);
        let meta = read_meta(uid, &upper)?;
        let next = rebind(
            &meta,
            new,
            |cur| check_pid(cur, peer_pid).is_ok(),
            || open_exe(peer_pid).is_ok(),
        )?;
        let mp = expiry::meta_path_for(&cred_path(uid, &upper));
        if next.is_empty() {
            expiry::delete_meta(&mp);
            Ok(Vec::new())
        } else {
            expiry::write_meta(&mp, &next)?;
            Ok(next.exe_digests.unwrap_or_default())
        }
    })();
    let op = if digests.is_empty() {
        "exe-unbind"
    } else {
        "exe-bind"
    };
    reply(op, uid, username, upper, r)
}

/// `ExeShow`: the recorded identities (hashes only, no paths).
pub fn handle_show(uid: u32, username: &str, name: &str) -> Response {
    let mut upper = name.to_uppercase();
    let r = (|| {
        upper = target(uid, name)?;
        Ok(read_meta(uid, &upper)?.exe_digests.unwrap_or_default())
    })();
    reply("exe-show", uid, username, upper, r)
}

fn reply(
    op: &'static str,
    uid: u32,
    username: &str,
    name: String,
    r: Result<Vec<String>, String>,
) -> Response {
    crate::daemon_session::audit_op(
        op,
        Some(&name),
        uid,
        username,
        r.as_ref().map(drop).map_err(String::as_str),
    );
    match r {
        Ok(digests) => Response::Platform(PlatformResponse::ExeBindings { name, digests }),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("kepr-exe-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }

    fn which(bin: &str) -> std::path::PathBuf {
        ["/usr/bin", "/bin"]
            .iter()
            .map(|d| std::path::Path::new(d).join(bin))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("{bin} not found"))
    }

    /// A private copy of `bin`, its identities, and a running instance.
    fn run_copy(s: &Scratch, bin: &str) -> (std::path::PathBuf, Vec<String>, Child) {
        let p = s.0.join(bin);
        std::fs::copy(which(bin), &p).unwrap();
        let ids = exe_digest::entries_of(&File::open(&p).unwrap()).unwrap();
        let child = Command::new(&p).arg("30").spawn().unwrap();
        // Let execve finish so /proc/<pid>/exe names the copy.
        for _ in 0..100 {
            let exe = std::fs::read_link(format!("/proc/{}/exe", child.id()));
            if exe.is_ok_and(|e| e.starts_with(&s.0)) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        (p, ids, child)
    }

    fn meta_with(ids: Vec<String>) -> CredMeta {
        CredMeta {
            exe_digests: Some(ids),
            ..Default::default()
        }
    }

    #[test]
    fn matching_digest_allowed_and_other_binary_refused() {
        let s = scratch("match");
        let (_, ids, mut child) = run_copy(&s, "sleep");
        let pid = child.id() as i32;
        assert_eq!(gate(&meta_with(ids), pid), Ok(()));
        let other = exe_digest::entries_of(&File::open(which("true")).unwrap()).unwrap();
        assert_eq!(
            gate(&meta_with(other), pid),
            Err("exe: not an allowed executable".into())
        );
        assert_eq!(gate(&CredMeta::default(), pid), Ok(()), "no binding");
        assert_eq!(gate(&meta_with(vec![]), pid), Ok(()), "empty binding");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn deleted_executable_refused() {
        let s = scratch("deleted");
        let (p, ids, mut child) = run_copy(&s, "sleep");
        std::fs::remove_file(&p).unwrap();
        let pid = child.id() as i32;
        assert!(std::fs::read_link(format!("/proc/{pid}/exe"))
            .unwrap()
            .to_string_lossy()
            .ends_with(" (deleted)"));
        assert_eq!(gate(&meta_with(ids), pid), Err("exe: deleted".into()));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn verity_only_binding_falls_back_and_refuses_without_verity() {
        let s = scratch("verity");
        let (_, ids, mut child) = run_copy(&s, "sleep");
        let pid = child.id() as i32;
        // A verity identity that doesn't match plus the real SHA-256: the
        // read falls back to hashing the file.
        let mut both = vec![format!("verity-sha256:{}", "0".repeat(64))];
        both.push(ids[0].clone());
        assert_eq!(gate(&meta_with(both), pid), Ok(()));
        // Only verity identities, and this file has no verity: refused.
        if ids.len() == 1 {
            let only = vec![format!("verity-sha256:{}", "0".repeat(64))];
            assert!(gate(&meta_with(only), pid).is_err());
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn gone_or_bogus_peer_refused() {
        let ids = vec![format!("sha256:{}", "0".repeat(64))];
        assert!(gate(&meta_with(ids.clone()), 0).is_err());
        assert!(gate(&meta_with(ids), i32::MAX).is_err());
    }

    #[test]
    fn rebind_policy() {
        let a = vec![format!("sha256:{}", "a".repeat(64))];
        let b = vec![format!("sha256:{}", "b".repeat(64))];
        // First binding: no current one to satisfy.
        let m = rebind(&CredMeta::default(), a.clone(), |_| false, || true).unwrap();
        assert_eq!(m.exe_digests, Some(a.clone()));
        // Changing or clearing needs a caller the current binding allows.
        assert!(rebind(&m, b.clone(), |_| false, || true).is_err());
        assert!(rebind(&m, vec![], |_| false, || true).is_err());
        let cleared = rebind(&m, vec![], |cur| cur == a.as_slice(), || false).unwrap();
        assert_eq!(cleared.exe_digests, None);
        // A daemon that can't read executables refuses new bindings.
        assert!(rebind(&CredMeta::default(), b, |_| true, || false).is_err());
        // Never-revealed kinds have nothing to bind.
        let sealed = CredMeta {
            sealed: Some(true),
            ..Default::default()
        };
        assert!(rebind(&sealed, a, |_| true, || true).is_err());
    }

    #[test]
    fn normalize_validates_dedupes_and_caps() {
        let a = format!("sha256:{}", "a".repeat(64));
        assert_eq!(normalize(&[a.clone(), a.clone()]).unwrap(), vec![a]);
        assert!(normalize(&["sha256:xyz".into()]).is_err());
        let many: Vec<String> = (0..17).map(|i| format!("sha256:{:064x}", i)).collect();
        assert!(normalize(&many).is_err());
    }

    #[test]
    fn set_keeps_the_binding() {
        // carry_over leaves an explicit binding alone.
        let mut m = meta_with(vec![format!("sha256:{}", "c".repeat(64))]);
        carry_over(4_000_000, "NOPE", &mut m);
        assert!(m.exe_digests.is_some());
    }
}
