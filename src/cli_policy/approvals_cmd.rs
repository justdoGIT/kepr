// cli_policy/approvals_cmd.rs — T9.04 commands:
//
//   kepr approvals set NAME --via desktop|ntfy|any | --off
//   kepr approvals serve [--desktop] [--ntfy URL|kepr:NAME
//                        --listen ADDR:PORT [--callback-url URL]]
//
// `serve` registers this process as the approver (one polkit prompt),
// then polls the daemon every second and asks the human for each pending
// consent request on the desktop and / or through ntfy, whose buttons
// call back to `--listen` (reachable from the phone: LAN, VPN, Tailscale).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PendingApproval, PolicyRequest, PolicyResponse};

use super::approve_notify::{self as an, Callbacks};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr approvals set NAME --via desktop|ntfy|any | approvals set NAME --off | approvals serve [--desktop] [--ntfy URL --listen ADDR:PORT [--callback-url URL]]";

pub fn cmd_approvals(args: &[String]) -> Response {
    let a = super::plain_args(args);
    match a.as_slice() {
        ["set", name, ..] => {
            let via = if args.iter().any(|a| a == "--off") {
                None
            } else {
                match crate::cli_extra::flag(args, "--via") {
                    Some(v) => Some(v.to_string()),
                    None => return Response::fail(USAGE),
                }
            };
            super::send(PolicyRequest::ApproveVia {
                name: name.to_uppercase(),
                via,
            })
        }
        ["serve", ..] => match serve(args) {
            Ok(()) => super::done("approver stopped".into()),
            Err(e) => Response::fail(format!("approvals: {e}")),
        },
        _ => Response::fail(USAGE),
    }
}

/// Read one request head and answer it from `cb`; a verdict goes to
/// `answer` (the daemon) before the phone hears "allowed".
pub fn handle_conn(
    mut s: TcpStream,
    cb: &mut Callbacks,
    answer: &dyn Fn(&str, &str, bool) -> Result<(), String>,
) {
    let (method, path) = request_line(&mut s);
    let mut r = cb.handle(&method, &path, Instant::now());
    if let Some((id, token, allow)) = &r.verdict {
        if answer(id, token, *allow).is_err() {
            r.status = 410;
            r.text = "expired: the request was denied";
        }
    }
    reply(&mut s, r.status, r.text);
}

/// Method and path of one request (head read with a 2 s timeout, 8 KiB
/// at most; the body is never read).
pub fn request_line(s: &mut TcpStream) -> (String, String) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < 8192 && !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or("").to_string();
    (method, first.next().unwrap_or("").to_string())
}

/// A plain-text answer, then close.
pub fn reply(s: &mut TcpStream, status: u16, text: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 {status} kepr\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
}

fn request(req: PolicyRequest) -> Result<PolicyResponse, String> {
    match super::send(req) {
        Response::Policy(p) => Ok(p),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

fn serve(args: &[String]) -> Result<(), String> {
    let ntfy = crate::cli_extra::flag(args, "--ntfy")
        .map(super::notify::resolve_url)
        .transpose()?;
    let desktop = args.iter().any(|a| a == "--desktop") || ntfy.is_none();
    let listener = match &ntfy {
        Some(_) => {
            let addr = crate::cli_extra::flag(args, "--listen")
                .ok_or("--ntfy needs --listen ADDR:PORT (reachable from the phone)")?;
            let l = TcpListener::bind(addr).map_err(|e| format!("listen {addr}: {e}"))?;
            l.set_nonblocking(true).map_err(|e| e.to_string())?;
            let base = crate::cli_extra::flag(args, "--callback-url")
                .map(String::from)
                .unwrap_or_else(|| format!("http://{addr}"));
            Some((l, base))
        }
        None => None,
    };
    let PolicyResponse::ApproverKey { key, timeout_secs } =
        request(PolicyRequest::ApproverRegister)?
    else {
        return Err("unexpected daemon response".into());
    };
    let key = Zeroizing::new(key);
    let answer = |id: &str, token: &str, allow: bool| {
        request(PolicyRequest::ApprovalAnswer {
            key: key.to_string(),
            id: id.to_string(),
            token: token.to_string(),
            allow,
        })
        .map(|_| ())
    };
    if !cli_mode::json_mode() {
        let mut ways = Vec::new();
        if desktop {
            ways.push("desktop notifications");
        }
        if ntfy.is_some() {
            ways.push("ntfy");
        }
        cli_ui::info(&format!(
            "answering consent prompts through {}; unanswered after {timeout_secs}s = denied (Ctrl-C stops)",
            ways.join(" and ")
        ));
    }
    let (mut cb, mut seen) = (Callbacks::default(), HashSet::new());
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some((l, _)) = &listener {
            while let Ok((s, _)) = l.accept() {
                let _ = s.set_nonblocking(false);
                handle_conn(s, &mut cb, &answer);
            }
        }
        if last_poll.elapsed() >= Duration::from_secs(1) {
            last_poll = Instant::now();
            let PolicyResponse::ApprovalsPending { pending } =
                request(PolicyRequest::ApprovalPoll {
                    key: key.to_string(),
                })?
            else {
                return Err("unexpected daemon response".into());
            };
            for p in pending.into_iter().filter(|p| seen.insert(p.id.clone())) {
                let ntfy_target = ntfy.as_ref().zip(listener.as_ref());
                ask(
                    &p,
                    desktop,
                    ntfy_target.map(|(u, (_, b))| (u.as_str(), b.as_str())),
                    &mut cb,
                    &key,
                );
            }
        }
        cb.sweep(Instant::now());
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Put one pending request in front of the human on its channel(s).
fn ask(
    p: &PendingApproval,
    desktop: bool,
    ntfy: Option<(&str, &str)>,
    cb: &mut Callbacks,
    key: &str,
) {
    let left = p.expires_at.saturating_sub(super::tail::now_unix());
    let use_ntfy = ntfy.filter(|_| p.via != "desktop");
    let use_desktop = desktop && (p.via != "ntfy" || use_ntfy.is_none());
    if let Some((url, base)) = use_ntfy {
        match an::ntfy_send(url, p, base) {
            Ok(()) => cb.add(&p.id, &p.token, Instant::now() + Duration::from_secs(left)),
            Err(e) => cli_ui::warn(&format!("{}: {e}", p.name)),
        }
    }
    if use_desktop {
        let (p, key) = (p.clone(), Zeroizing::new(key.to_string()));
        std::thread::spawn(move || {
            if let Some(allow) = an::desktop_ask(&p, left) {
                let _ = request(PolicyRequest::ApprovalAnswer {
                    key: key.to_string(),
                    id: p.id.clone(),
                    token: p.token.clone(),
                    allow,
                });
            }
        });
    }
    if !cli_mode::json_mode() {
        cli_ui::dim(&format!("asked about {} for {}", p.name, p.requester));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn call(
        cb: &mut Callbacks,
        path: &str,
        answer: &dyn Fn(&str, &str, bool) -> Result<(), String>,
    ) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let path = path.to_string();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(
                s,
                "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        });
        let (s, _) = l.accept().unwrap();
        handle_conn(s, cb, answer);
        client.join().unwrap()
    }

    #[test]
    fn callback_relays_only_the_right_token() {
        let mut cb = Callbacks::default();
        cb.add("id1", "tok1", Instant::now() + Duration::from_secs(60));
        let got = RefCell::new(Vec::new());
        let answer = |id: &str, token: &str, allow: bool| {
            got.borrow_mut()
                .push((id.to_string(), token.to_string(), allow));
            Ok(())
        };
        assert!(call(&mut cb, "/approve/id1/nope/allow", &answer).starts_with("HTTP/1.1 403"));
        assert!(got.borrow().is_empty());
        let ok = call(&mut cb, "/approve/id1/tok1/deny", &answer);
        assert!(
            ok.starts_with("HTTP/1.1 200") && ok.ends_with("denied"),
            "{ok}"
        );
        assert_eq!(*got.borrow(), [("id1".into(), "tok1".into(), false)]);
        assert!(call(&mut cb, "/approve/id1/tok1/allow", &answer).starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn a_daemon_refusal_is_reported_as_expired() {
        let mut cb = Callbacks::default();
        cb.add("id2", "tok2", Instant::now() + Duration::from_secs(60));
        let refuse = |_: &str, _: &str, _: bool| Err("no such pending approval".to_string());
        assert!(call(&mut cb, "/approve/id2/tok2/allow", &refuse).starts_with("HTTP/1.1 410"));
    }
}
