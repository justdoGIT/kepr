// cli_policy/approvals_cmd.rs — T9.04 commands:
//
//   kepr approvals set NAME --via desktop|ntfy|any | --off
//   kepr approvals serve [--desktop] [--ntfy URL|kepr:NAME]
//                        [--slack-webhook URL --slack-signing-secret FILE]
//                        [--teams-webhook URL]
//                        --listen ADDR:PORT [--callback-url URL]  (T13.08)
//
// `serve` registers this process as the approver (one polkit prompt),
// then polls the daemon every second and asks the human for each pending
// consent request on the desktop and / or through ntfy, whose buttons
// call back to `--listen` (reachable from the phone: LAN, VPN, Tailscale).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use kepr_core::protocol::Response;
use kepr_core::protocol_policy::{PendingApproval, PolicyRequest, PolicyResponse};

use super::approve_chat as chat;
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

/// Where Slack's interactivity Request URL points.
pub const SLACK_PATH: &str = "/slack/interact";

/// Read one request and answer it from `cb`; a verdict goes to `answer`
/// (the daemon) before the phone hears "allowed". `slack` is the app's
/// signing secret, when Slack clicks are accepted.
pub fn handle_conn(
    mut s: TcpStream,
    cb: &mut Callbacks,
    slack: Option<&[u8]>,
    answer: &dyn Fn(&str, &str, bool) -> Result<(), String>,
) {
    let req = match kepr_core::http_lite::parse_request_within(
        &s,
        chat::MAX_BODY,
        Duration::from_secs(5),
    ) {
        Ok(r) => r,
        Err(_) => return reply(&mut s, 400, "bad request"),
    };
    let now = Instant::now();
    let mut r = if req.path == SLACK_PATH {
        match slack_click(&req, slack, cb, now) {
            Ok(r) => r,
            Err((status, text)) => return reply(&mut s, status, text),
        }
    } else {
        cb.handle(&req.method, &req.path, now)
    };
    let slack_reply = req.path == SLACK_PATH;
    let mut verdict = r.verdict.as_ref().map(|(_, _, a)| *a);
    if let Some((id, token, allow)) = &r.verdict {
        if answer(id, token, *allow).is_err() {
            r.status = 410;
            r.text = "expired: the request was denied";
            verdict = None;
        }
    }
    if slack_reply {
        let body = chat::slack_reply(verdict);
        return reply(&mut s, 200, &body);
    }
    reply(&mut s, r.status, r.text);
}

/// A Slack click: signature, fresh timestamp, then the one-time token.
fn slack_click(
    req: &kepr_core::http_lite::HttpRequest,
    secret: Option<&[u8]>,
    cb: &mut Callbacks,
    now: Instant,
) -> Result<an::Reply, (u16, &'static str)> {
    let secret = secret.ok_or((404, "not found"))?;
    if req.method != "POST" {
        return Err((405, "use POST"));
    }
    let (Some(ts), Some(sig)) = (
        req.header("x-slack-request-timestamp"),
        req.header("x-slack-signature"),
    ) else {
        return Err((401, "unsigned"));
    };
    chat::verify_slack(secret, ts, &req.body, sig, super::tail::now_unix())
        .map_err(|_| (401, "unauthorised"))?;
    let (id, token, allow) = chat::slack_verdict(&req.body).map_err(|_| (400, "bad request"))?;
    Ok(cb.answer(&id, &token, allow, now))
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
    let ct = match text.as_bytes().first() {
        Some(b'{') => "application/json",
        Some(b'<') => "text/html; charset=utf-8",
        _ => "text/plain",
    };
    let _ = write!(
        s,
        "HTTP/1.1 {status} kepr\r\nContent-Type: {ct}\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; form-action 'self'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
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

/// The remote channels `serve` was asked to use.
struct Chat {
    ntfy: Option<ZeroString>,
    slack: Option<ZeroString>,
    teams: Option<ZeroString>,
    /// Slack app signing secret (for clicks).
    secret: Option<Zeroizing<Vec<u8>>>,
    /// Public base URL of the listener.
    base: String,
}

impl Chat {
    fn any(&self) -> bool {
        self.ntfy.is_some() || self.slack.is_some() || self.teams.is_some()
    }

    fn from_args(args: &[String]) -> Result<Self, String> {
        let url = |flag| {
            crate::cli_extra::flag(args, flag)
                .map(super::notify::resolve_url)
                .transpose()
        };
        let secret = crate::cli_extra::flag(args, "--slack-signing-secret")
            .map(|f| {
                std::fs::read_to_string(f)
                    .map(|t| Zeroizing::new(t.trim().as_bytes().to_vec()))
                    .map_err(|e| format!("{f}: {e}"))
            })
            .transpose()?;
        let c = Self {
            ntfy: url("--ntfy")?,
            slack: url("--slack-webhook")?,
            teams: url("--teams-webhook")?,
            secret,
            base: String::new(),
        };
        if c.slack.is_some() != c.secret.is_some() {
            return Err("Slack needs both --slack-webhook and --slack-signing-secret FILE".into());
        }
        Ok(c)
    }
}

fn serve(args: &[String]) -> Result<(), String> {
    let mut chat = Chat::from_args(args)?;
    let desktop = args.iter().any(|a| a == "--desktop") || !chat.any();
    let listener = if chat.any() {
        let addr = crate::cli_extra::flag(args, "--listen")
            .ok_or("--ntfy, --slack-webhook and --teams-webhook need --listen ADDR:PORT (reachable from the phone)")?;
        let l = TcpListener::bind(addr).map_err(|e| format!("listen {addr}: {e}"))?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        chat.base = crate::cli_extra::flag(args, "--callback-url")
            .map(String::from)
            .unwrap_or_else(|| format!("http://{addr}"));
        Some(l)
    } else {
        None
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
        for (on, name) in [
            (chat.ntfy.is_some(), "ntfy"),
            (chat.slack.is_some(), "Slack"),
            (chat.teams.is_some(), "Teams"),
        ] {
            if on {
                ways.push(name);
            }
        }
        cli_ui::info(&format!(
            "answering consent prompts through {}; unanswered after {timeout_secs}s = denied (Ctrl-C stops)",
            ways.join(" and ")
        ));
    }
    let (mut cb, mut seen) = (Callbacks::default(), HashSet::new());
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    loop {
        if let Some(l) = &listener {
            while let Ok((s, _)) = l.accept() {
                let _ = s.set_nonblocking(false);
                handle_conn(
                    s,
                    &mut cb,
                    chat.secret.as_ref().map(|s| s.as_slice()),
                    &answer,
                );
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
                ask(&p, desktop, &chat, &mut cb, &key);
            }
        }
        cb.sweep(Instant::now());
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Put one pending request in front of the human on its channel(s).
fn ask(p: &PendingApproval, desktop: bool, chat: &Chat, cb: &mut Callbacks, key: &str) {
    let left = p.expires_at.saturating_sub(super::tail::now_unix());
    let remote = p.via != "desktop";
    let mut sent = false;
    if remote {
        let base = chat.base.as_str();
        let results = [
            chat.ntfy
                .as_ref()
                .map(|u| an::ntfy_send(u.as_str(), p, base)),
            chat.slack
                .as_deref()
                .map(|u| chat::post(u, &chat::slack_message(p))),
            chat.teams
                .as_deref()
                .map(|u| chat::post(u, &chat::teams_card(p, base))),
        ];
        for r in results.into_iter().flatten() {
            match r {
                Ok(()) => sent = true,
                Err(e) => cli_ui::warn(&format!("{}: {e}", p.name)),
            }
        }
        if sent {
            cb.add(&p.id, &p.token, Instant::now() + Duration::from_secs(left));
        }
    }
    let use_desktop = desktop && (p.via != "ntfy" || !sent);
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
        handle_conn(s, cb, None, answer);
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

    const SECRET: &[u8] = b"slack-signing-secret";

    fn slack_post(cb: &mut Callbacks, ts: u64, sig_for: &[u8], value: &str) -> (String, usize) {
        use kepr_core::mac::hmac_sha256;
        let payload = serde_json::json!({
            "type": "block_actions",
            "actions": [{ "action_id": "kepr_allow", "value": value }],
        })
        .to_string();
        let enc: String = payload.bytes().map(|b| format!("%{b:02X}")).collect();
        let body = format!("payload={enc}");
        let base = format!("v0:{ts}:{body}");
        let sig = format!(
            "v0={}",
            hex::encode(hmac_sha256(sig_for, &[base.as_bytes()]).as_slice())
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            write!(
                s,
                "POST {SLACK_PATH} HTTP/1.1\r\nHost: x\r\nX-Slack-Request-Timestamp: {ts}\r\nX-Slack-Signature: {sig}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        });
        let (s, _) = l.accept().unwrap();
        let calls = RefCell::new(0usize);
        let answer = |_: &str, _: &str, _: bool| {
            *calls.borrow_mut() += 1;
            Ok(())
        };
        handle_conn(s, cb, Some(SECRET), &answer);
        let n = *calls.borrow();
        (client.join().unwrap(), n)
    }

    #[test]
    fn a_signed_slack_click_answers_once() {
        let mut cb = Callbacks::default();
        cb.add("id9", "tok9", Instant::now() + Duration::from_secs(60));
        let now = super::super::tail::now_unix();
        let (out, n) = slack_post(&mut cb, now, SECRET, "id9:tok9");
        assert!(
            out.starts_with("HTTP/1.1 200") && out.contains("kepr: allowed"),
            "{out}"
        );
        assert_eq!(n, 1);
        // The same click again: the request is spent.
        let (out, n) = slack_post(&mut cb, now, SECRET, "id9:tok9");
        assert!(out.contains("no longer open"), "{out}");
        assert_eq!(n, 0);
    }

    #[test]
    fn unsigned_stale_and_misdirected_slack_clicks_do_nothing() {
        let mut cb = Callbacks::default();
        cb.add("id8", "tok8", Instant::now() + Duration::from_secs(60));
        let now = super::super::tail::now_unix();
        let (out, n) = slack_post(&mut cb, now, b"another secret", "id8:tok8");
        assert!(out.starts_with("HTTP/1.1 401"), "{out}");
        let (out, _) = slack_post(&mut cb, now - 600, SECRET, "id8:tok8");
        assert!(out.starts_with("HTTP/1.1 401"), "{out}");
        let (out, n2) = slack_post(&mut cb, now, SECRET, "id8:wrong");
        assert!(out.contains("no longer open"), "{out}");
        assert_eq!((n, n2), (0, 0));
        assert!(cb.contains("id8"), "the request is still open");
    }

    #[test]
    fn a_daemon_refusal_is_reported_as_expired() {
        let mut cb = Callbacks::default();
        cb.add("id2", "tok2", Instant::now() + Duration::from_secs(60));
        let refuse = |_: &str, _: &str, _: bool| Err("no such pending approval".to_string());
        assert!(call(&mut cb, "/approve/id2/tok2/allow", &refuse).starts_with("HTTP/1.1 410"));
    }
}
