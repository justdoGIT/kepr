// cli_ssh_agent.rs — `kepr ssh-agent` (agent vault P2.4): an ssh-agent
// whose keys never leave the kepr daemon. It answers the two requests
// ssh and git need (list identities, sign); everything else (adding or
// exporting keys, locking) gets SSH_AGENT_FAILURE.
//
//   eval "$(kepr ssh-agent)"        # starts in the background, prints exports
//   kepr ssh-agent --foreground [--socket PATH]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
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

pub fn default_socket() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    dir.join("kepr-ssh-agent.sock")
}

/// Backend the agent asks; production goes to the daemon.
pub trait Keys {
    fn list(&self) -> Result<Vec<SshKeyInfo>, String>;
    fn sign(&self, name: &str, data: &[u8]) -> Result<Vec<u8>, String>;
}

struct Daemon;
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

fn serve_conn(mut s: UnixStream) {
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
        let reply = answer(&Daemon, &msg);
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        if s.write_all(&framed).is_err() {
            return;
        }
    }
}

fn serve(path: &PathBuf) -> Response {
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => return Response::fail(format!("{}: {e}", path.display())),
    };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    for conn in listener.incoming().flatten() {
        std::thread::spawn(move || serve_conn(conn));
    }
    Response::Pong
}

pub fn cmd_ssh_agent(args: &[String]) -> Response {
    let path = args
        .iter()
        .position(|a| a == "--socket")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(default_socket);
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
        Ok(child) => {
            for _ in 0..50 {
                if path.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
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
