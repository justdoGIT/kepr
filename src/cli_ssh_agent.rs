// cli_ssh_agent.rs — `kepr ssh-agent` (agent vault P2.4): an ssh-agent
// whose keys never leave the kepr daemon. It answers the two requests
// ssh and git need (list identities, sign); everything else (adding or
// exporting keys, locking) gets SSH_AGENT_FAILURE.
//
//   eval "$(kepr ssh-agent)"        # starts in the background, prints exports
//   kepr ssh-agent --foreground [--socket PATH]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kepr_core::protocol::{Request, Response, SshKeyInfo};
use kepr_core::ssh_wire::{self, put_string, take_string, take_u32};

use crate::client;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const MAX_MSG: usize = 256 * 1024;

/// `$XDG_RUNTIME_DIR/kepr-ssh-agent.sock` (a private, per-user tmpfs), or
/// a socket in a fresh 0700 directory with an unpredictable name: a fixed
/// path in a shared /tmp could be taken first by another user.
pub fn default_socket() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        // T11.16: one agent per profile.
        let file = match kepr_core::profile::current() {
            Ok(Some(p)) => format!("kepr-ssh-agent-{p}.sock"),
            _ => "kepr-ssh-agent.sock".to_string(),
        };
        return Ok(PathBuf::from(dir).join(file));
    }
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let dir = std::env::temp_dir().join(format!("kepr-ssh-{}", hex::encode(rnd)));
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir.join("agent.sock"))
}

/// The connecting process runs as us (SO_PEERCRED).
pub(crate) fn same_user(s: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero ucred is a valid value of this plain C struct.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let ok = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } == 0;
    // SAFETY: geteuid has no preconditions.
    ok && cred.uid == unsafe { libc::geteuid() }
}

/// Backend the agent asks; production goes to the daemon.
pub trait Keys {
    fn list(&self) -> Result<Vec<SshKeyInfo>, String>;
    fn sign(&self, name: &str, data: &[u8]) -> Result<Vec<u8>, String>;
}

pub(crate) struct Daemon;
impl Keys for Daemon {
    fn list(&self) -> Result<Vec<SshKeyInfo>, String> {
        match client::send_request(&Request::SshList)? {
            Response::SshListOk { keys } => Ok(keys),
            other => Err(other.err_msg().unwrap_or("unexpected reply").to_string()),
        }
    }
    fn sign(&self, name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        let req = Request::SshSign {
            name: name.to_string(),
            data_b64: ssh_wire::b64(data),
        };
        match client::send_request(&req)? {
            Response::SshSignOk { signature_b64 } => {
                ssh_wire::unb64(&signature_b64).ok_or_else(|| "bad signature".into())
            }
            other => Err(other.err_msg().unwrap_or("unexpected reply").to_string()),
        }
    }
}

/// Answer one agent request (type byte + payload) with a reply message.
pub fn answer(keys: &dyn Keys, msg: &[u8]) -> Vec<u8> {
    let fail = vec![FAILURE];
    let Some((&kind, mut body)) = msg.split_first() else {
        return fail;
    };
    match kind {
        REQUEST_IDENTITIES => {
            let Ok(list) = keys.list() else { return fail };
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for k in &list {
                put_string(
                    &mut out,
                    &ssh_wire::unb64(&k.public_b64).unwrap_or_default(),
                );
                put_string(&mut out, k.comment.as_bytes());
            }
            out
        }
        SIGN_REQUEST => {
            let (Some(blob), Some(data), Some(_flags)) = (
                take_string(&mut body),
                take_string(&mut body),
                take_u32(&mut body),
            ) else {
                return fail;
            };
            let Ok(list) = keys.list() else { return fail };
            let Some(k) = list
                .iter()
                .find(|k| ssh_wire::unb64(&k.public_b64).as_deref() == Some(blob))
            else {
                return fail;
            };
            match keys.sign(&k.name, data) {
                Ok(sig) => {
                    let mut out = vec![SIGN_RESPONSE];
                    put_string(&mut out, &sig);
                    out
                }
                Err(_) => fail,
            }
        }
        _ => fail,
    }
}

pub(crate) fn serve_conn(mut s: UnixStream, keys: &dyn Keys) {
    loop {
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_MSG {
            return;
        }
        let mut msg = vec![0u8; n];
        if s.read_exact(&mut msg).is_err() {
            return;
        }
        let reply = answer(keys, &msg);
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        if s.write_all(&framed).is_err() {
            return;
        }
    }
}

fn serve(path: &PathBuf) -> Response {
    let _ = std::fs::remove_file(path);
    // Create the socket 0600 from the start (no chmod window).
    // SAFETY: umask only changes this process's file-creation mask.
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(path);
    // SAFETY: as above, restoring the previous mask.
    unsafe { libc::umask(old) };
    let listener = match bound {
        Ok(l) => l,
        Err(e) => return Response::fail(format!("{}: {e}", path.display())),
    };
    for conn in listener.incoming().flatten() {
        if same_user(&conn) {
            std::thread::spawn(move || serve_conn(conn, &Daemon));
        }
    }
    Response::Pong
}

pub fn cmd_ssh_agent(args: &[String]) -> Response {
    let path = args
        .iter()
        .position(|a| a == "--socket")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let path = match path {
        Some(p) => p,
        None => match default_socket() {
            Ok(p) => p,
            Err(e) => return Response::fail(e),
        },
    };
    if args.iter().any(|a| a == "--foreground") {
        return serve(&path);
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => return Response::fail(e.to_string()),
    };
    let mut c = Command::new(exe);
    c.args(["ssh-agent", "--foreground", "--socket"]).arg(&path);
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe; detaches the agent from the terminal.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match c.spawn() {
        Ok(mut child) => {
            // Ready means: our agent is still running and the socket is
            // ours. A socket someone else left at that path is not.
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            // SAFETY: geteuid has no preconditions.
            let me = unsafe { libc::geteuid() };
            let ours = |p: &PathBuf| {
                std::fs::symlink_metadata(p)
                    .is_ok_and(|m| m.file_type().is_socket() && m.uid() == me)
            };
            for _ in 0..50 {
                if ours(&path) || matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            if !ours(&path) || matches!(child.try_wait(), Ok(Some(_))) {
                return Response::fail(format!("the agent could not listen on {}", path.display()));
            }
            println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", path.display());
            println!("echo kepr ssh-agent pid {};", child.id());
            Response::Pong
        }
        Err(e) => Response::fail(format!("cannot start the agent: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl Keys for Fake {
        fn list(&self) -> Result<Vec<SshKeyInfo>, String> {
            Ok(vec![SshKeyInfo {
                name: "K".into(),
                public_b64: ssh_wire::b64(&ssh_wire::ed25519_public_blob(&[3; 32])),
                comment: "c".into(),
            }])
        }
        fn sign(&self, name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
            assert_eq!((name, data), ("K", &b"tbs"[..]));
            Ok(ssh_wire::ed25519_signature_blob(&[9; 64]))
        }
    }

    #[test]
    fn identities_and_sign() {
        let r = answer(&Fake, &[REQUEST_IDENTITIES]);
        assert_eq!(r[0], IDENTITIES_ANSWER);
        assert_eq!(&r[1..5], &1u32.to_be_bytes());
        let mut req = vec![SIGN_REQUEST];
        put_string(&mut req, &ssh_wire::ed25519_public_blob(&[3; 32]));
        put_string(&mut req, b"tbs");
        req.extend_from_slice(&0u32.to_be_bytes());
        let r = answer(&Fake, &req);
        assert_eq!(r[0], SIGN_RESPONSE);
    }

    #[test]
    fn an_ecdsa_identity_is_listed_and_signs() {
        // T12.11: the agent passes blobs through, whatever their type.
        struct Ecdsa;
        let blob = kepr_core::ssh_wire_ecdsa::public_blob(&[4; 65]);
        impl Keys for Ecdsa {
            fn list(&self) -> Result<Vec<SshKeyInfo>, String> {
                Ok(vec![SshKeyInfo {
                    name: "E".into(),
                    public_b64: ssh_wire::b64(&kepr_core::ssh_wire_ecdsa::public_blob(&[4; 65])),
                    comment: "c".into(),
                }])
            }
            fn sign(&self, name: &str, _: &[u8]) -> Result<Vec<u8>, String> {
                assert_eq!(name, "E");
                Ok(kepr_core::ssh_wire_ecdsa::signature_blob(
                    &[1; 32], &[2; 32],
                ))
            }
        }
        let r = answer(&Ecdsa, &[REQUEST_IDENTITIES]);
        let mut body: &[u8] = &r[5..];
        assert_eq!(take_string(&mut body), Some(blob.as_slice()));
        let mut req = vec![SIGN_REQUEST];
        put_string(&mut req, &blob);
        put_string(&mut req, b"tbs");
        req.extend_from_slice(&0u32.to_be_bytes());
        let r = answer(&Ecdsa, &req);
        assert_eq!(r[0], SIGN_RESPONSE);
        let mut body: &[u8] = &r[1..];
        let sig = take_string(&mut body).unwrap();
        assert_eq!(
            kepr_core::ssh_wire_ecdsa::parse_signature_blob(sig),
            Some(([1; 32], [2; 32]))
        );
    }

    #[test]
    fn unknown_key_and_other_requests_fail() {
        let mut req = vec![SIGN_REQUEST];
        put_string(&mut req, &ssh_wire::ed25519_public_blob(&[4; 32]));
        put_string(&mut req, b"tbs");
        req.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(answer(&Fake, &req), vec![FAILURE]);
        assert_eq!(
            answer(&Fake, &[17]),
            vec![FAILURE],
            "add-identity is refused"
        );
        assert_eq!(answer(&Fake, &[]), vec![FAILURE]);
    }
}
