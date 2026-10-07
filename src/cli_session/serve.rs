// cli_session/serve.rs — `kepr serve` (T11.19): a local REST API for
// tools that can't run `kepr exec`.
//
//   KEPR_SERVE_TOKEN_FILE=~/.config/kepr/serve.token \
//     kepr serve (--listen 127.0.0.1:PORT | --socket PATH) --allow list,get [--rate N]
//
// Loopback addresses and Unix sockets only (a socket is 0600 and only
// our uid may connect). Every request needs `Authorization: Bearer
// TOKEN`; the token file must be private (no group/other access) and at
// least 16 characters. `--rate` is requests per minute for the token
// (default 60). Routing and policy: serve_route.rs. Values come from the
// daemon's own `Get`, which audits each read and never returns sealed,
// SSH or share-key credentials; nothing here prompts.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kepr_core::generate::ZeroString;
use kepr_core::http_lite::{parse_request, write_response_with, TimedStream};
use kepr_core::protocol::{Request, Response};
use zeroize::Zeroizing;

use super::serve_route::{Bucket, Policy, Vault};

const USAGE: &str = "usage: KEPR_SERVE_TOKEN_FILE=FILE kepr serve \
                     (--listen 127.0.0.1:PORT | --socket PATH) --allow list,get [--rate N]";
const MAX_CONNS: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Bind {
    Tcp(std::net::SocketAddr),
    Unix(std::path::PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Opts {
    pub bind: Bind,
    pub allow_list: bool,
    pub allow_get: bool,
    pub rate: u32,
}

pub fn parse(args: &[&str]) -> Result<Opts, String> {
    let (mut bind, mut allow, mut rate) = (None, None, 60);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .copied()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match *a {
            "--listen" => {
                let addr: std::net::SocketAddr = val()?
                    .parse()
                    .map_err(|_| "--listen takes IP:PORT".to_string())?;
                if !addr.ip().is_loopback() {
                    return Err(format!(
                        "{addr} is not a loopback address: kepr serve listens on 127.0.0.1, \
                         ::1 or a Unix socket only"
                    ));
                }
                bind = Some(Bind::Tcp(addr));
            }
            "--socket" => bind = Some(Bind::Unix(val()?.into())),
            "--allow" => allow = Some(val()?.to_string()),
            "--rate" => {
                rate = val()?
                    .parse()
                    .ok()
                    .filter(|r| (1..=6000).contains(r))
                    .ok_or("--rate takes 1-6000 requests per minute")?
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let (Some(bind), Some(allow)) = (bind, allow) else {
        return Err(USAGE.into());
    };
    let (mut allow_list, mut allow_get) = (false, false);
    for op in allow.split(',').map(str::trim) {
        match op {
            "list" => allow_list = true,
            "get" => allow_get = true,
            other => return Err(format!("--allow: unknown operation {other:?} (list, get)")),
        }
    }
    Ok(Opts {
        bind,
        allow_list,
        allow_get,
        rate,
    })
}

/// The token from `KEPR_SERVE_TOKEN_FILE`: private file, ≥ 16 characters.
pub fn read_token(path: &std::path::Path) -> Result<Zeroizing<String>, String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{shown}: other users can read it; chmod 600 {shown}"
        ));
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| format!("{shown}: {e}"))?);
    let token = Zeroizing::new(text.trim().to_string());
    if token.chars().count() < 16 || token.chars().any(char::is_whitespace) {
        return Err(format!(
            "{shown}: the token must be one word of at least 16 characters"
        ));
    }
    Ok(token)
}

struct Daemon;
impl Vault for Daemon {
    /// Names, without sealed credentials, SSH keys and the share key.
    fn list(&self) -> Result<Vec<String>, String> {
        let ssh: Vec<String> = match crate::client::send_request(&Request::SshList)? {
            Response::SshListOk { keys } => keys.into_iter().map(|k| k.name).collect(),
            _ => return Err("unexpected reply".into()),
        };
        match crate::client::send_request(&Request::List)? {
            Response::ListOk { credentials, .. } => Ok(credentials
                .into_iter()
                .filter(|c| c.sealed != Some(true) && c.name != "KEPR_SHARE_KEY")
                .map(|c| c.name)
                .filter(|n| !ssh.contains(n))
                .collect()),
            _ => Err("unexpected reply".into()),
        }
    }
    /// The plain `Get`: no FIDO2 ceremony, no passphrase prompt.
    fn get(&self, name: &str) -> Result<ZeroString, String> {
        let req = Request::Get {
            name: name.to_string(),
            fido2_assertion: None,
        };
        match crate::client::send_request(&req)? {
            Response::GetOk { value, .. } => Ok(value),
            _ => Err("credential unavailable".into()),
        }
    }
}

fn serve_one<S: TimedStream + std::io::Write>(mut s: S, policy: &Policy) {
    let reply = match parse_request(&s, 0) {
        Ok(req) => {
            let r = policy.route(&req, Instant::now(), &Daemon);
            let path = req.path.split('?').next().unwrap_or("");
            eprintln!("kepr serve: {} {path} {}", req.method, r.status);
            r
        }
        Err(_) => super::serve_route::bad_request(),
    };
    let retry = reply.retry_after.map(|s| s.to_string());
    let headers: Vec<(&str, &str)> = match (&retry, reply.status) {
        (Some(s), _) => vec![("Retry-After", s.as_str())],
        (None, 401) => vec![("WWW-Authenticate", "Bearer")],
        _ => vec![],
    };
    let _ = write_response_with(&mut s, reply.status, &headers, &reply.body);
}

fn spawn<S>(s: S, policy: &Arc<Policy>, live: &Arc<AtomicUsize>)
where
    S: TimedStream + std::io::Write + Send + 'static,
{
    if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
        live.fetch_sub(1, Ordering::SeqCst);
        return; // dropped: too many at once
    }
    let (p, l) = (Arc::clone(policy), Arc::clone(live));
    std::thread::spawn(move || {
        serve_one(s, &p);
        l.fetch_sub(1, Ordering::SeqCst);
    });
}

fn bind_unix(path: &std::path::Path) -> Result<UnixListener, String> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if !m.file_type().is_socket() {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
        let _ = std::fs::remove_file(path);
    }
    // SAFETY: umask only changes this process's file-creation mask.
    let old = unsafe { libc::umask(0o177) };
    let r = UnixListener::bind(path);
    // SAFETY: as above, restoring the previous mask.
    unsafe { libc::umask(old) };
    r.map_err(|e| format!("{}: {e}", path.display()))
}

pub fn cmd_serve(args: &[&str]) -> Response {
    let r = (|| {
        let o = parse(args)?;
        let file = std::env::var_os("KEPR_SERVE_TOKEN_FILE")
            .ok_or("set KEPR_SERVE_TOKEN_FILE to a file holding the bearer token")?;
        let policy = Arc::new(Policy {
            token: read_token(std::path::Path::new(&file))?,
            allow_list: o.allow_list,
            allow_get: o.allow_get,
            ok: Mutex::new(Bucket::per_minute(o.rate)),
            failed: Mutex::new(Bucket::per_minute(30)),
        });
        let live = Arc::new(AtomicUsize::new(0));
        match o.bind {
            Bind::Tcp(addr) => {
                let l = std::net::TcpListener::bind(addr).map_err(|e| format!("{addr}: {e}"))?;
                crate::cli_ui::info(&format!(
                    "kepr serve on http://{}",
                    l.local_addr().map_err(|e| e.to_string())?
                ));
                for c in l.incoming().flatten() {
                    spawn(c, &policy, &live);
                }
            }
            Bind::Unix(path) => {
                let l = bind_unix(&path)?;
                crate::cli_ui::info(&format!("kepr serve on unix:{}", path.display()));
                for c in l.incoming().flatten() {
                    if crate::cli_ssh_agent::same_user(&c) {
                        spawn::<UnixStream>(c, &policy, &live);
                    }
                }
            }
        }
        Ok::<(), String>(())
    })();
    match r {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_on_a_non_loopback_address_is_refused() {
        for addr in ["0.0.0.0:8080", "192.168.1.5:80", "[::]:80"] {
            let e = parse(&["--listen", addr, "--allow", "get"]).unwrap_err();
            assert!(e.contains("loopback"), "{addr}: {e}");
        }
        let o = parse(&[
            "--listen",
            "127.0.0.1:8080",
            "--allow",
            "list,get",
            "--rate",
            "5",
        ])
        .unwrap();
        assert_eq!(o.bind, Bind::Tcp("127.0.0.1:8080".parse().unwrap()));
        assert!(o.allow_list && o.allow_get && o.rate == 5);
        assert!(parse(&["--listen", "[::1]:80", "--allow", "get"]).is_ok());
        assert!(parse(&[
            "--insecure-network",
            "--listen",
            "0.0.0.0:1",
            "--allow",
            "get"
        ])
        .is_err());
    }

    #[test]
    fn allow_is_required_and_checked() {
        assert_eq!(parse(&["--socket", "/tmp/s"]).unwrap_err(), USAGE);
        assert!(parse(&["--socket", "/tmp/s", "--allow", "get,delete"]).is_err());
        let o = parse(&["--socket", "/tmp/s", "--allow", "list"]).unwrap();
        assert!(o.allow_list && !o.allow_get);
        assert!(parse(&["--socket", "/tmp/s", "--allow", "get", "--rate", "0"]).is_err());
    }

    #[test]
    fn the_token_file_must_be_private_and_long_enough() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tok");
        std::fs::write(&p, "abcdefghijklmnopqrstuvwxyz\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&p).unwrap_err().contains("chmod 600"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_token(&p).unwrap().as_str(),
            "abcdefghijklmnopqrstuvwxyz"
        );
        std::fs::write(&p, "short").unwrap();
        assert!(read_token(&p).is_err());
    }

    #[test]
    fn a_regular_file_is_never_replaced_by_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, "keep").unwrap();
        assert!(bind_unix(&p).unwrap_err().contains("not a socket"));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "keep");
    }
}
