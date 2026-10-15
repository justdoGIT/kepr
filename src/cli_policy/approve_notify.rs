// cli_policy/approve_notify.rs — T9.04: how `kepr approvals serve` asks
// a human. Two channels:
//
//   desktop  `notify-send --wait` with Allow / Deny actions (libnotify
//            0.7.10+ prints the chosen action);
//   ntfy     a message on an ntfy topic whose Allow / Deny buttons POST
//            to this machine's one-shot callback URL, carrying the pending
//            request's one-time token.
//
// The callback accepts each token once, before its deadline, and nothing
// else. The daemon checks the token again and that the answer comes from
// the registered approver process; no answer by the deadline is a deny.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Instant;

use zeroize::Zeroizing;

use kepr_core::protocol_policy::PendingApproval;

fn title(p: &PendingApproval) -> String {
    format!("kepr: allow access to {}?", p.name)
}

fn message(p: &PendingApproval) -> String {
    format!(
        "requested by {}; unanswered = denied at {}",
        p.requester,
        super::siem::rfc3339(p.expires_at)
    )
}

/// `https://ntfy.sh/TOPIC` → (`https://ntfy.sh`, `TOPIC`).
pub fn split_ntfy(url: &str) -> Result<(String, String), String> {
    let (server, topic) = url
        .trim_end_matches('/')
        .rsplit_once('/')
        .filter(|(s, t)| s.contains("://") && !s.ends_with('/') && !t.is_empty())
        .ok_or("an ntfy URL looks like https://ntfy.sh/TOPIC")?;
    Ok((server.to_string(), topic.to_string()))
}

/// The JSON message (published by POSTing it to the server root).
pub fn ntfy_body(topic: &str, p: &PendingApproval, callback_base: &str) -> serde_json::Value {
    let base = callback_base.trim_end_matches('/');
    let url = |verdict: &str| format!("{base}/approve/{}/{}/{verdict}", p.id, p.token);
    serde_json::json!({
        "topic": topic,
        "title": title(p),
        "message": message(p),
        "priority": 4,
        "tags": ["key"],
        "actions": [
            { "action": "http", "label": "Allow", "url": url("allow"), "method": "POST", "clear": true },
            { "action": "http", "label": "Deny", "url": url("deny"), "method": "POST", "clear": true },
        ],
    })
}

pub fn ntfy_send(topic_url: &str, p: &PendingApproval, callback_base: &str) -> Result<(), String> {
    let (server, topic) = split_ntfy(topic_url)?;
    let body = ntfy_body(&topic, p, callback_base).to_string();
    let req = crate::sync_http::agent()
        .post(&server)
        .set("Content-Type", "application/json")
        .set("User-Agent", "kepr");
    match crate::sync_http::send(req, Some(body.as_bytes())) {
        Ok((code, _)) if (200..300).contains(&code) => Ok(()),
        Ok((code, _)) => Err(format!("ntfy answered HTTP {code}")),
        Err(_) => Err("ntfy unreachable".into()),
    }
}

/// Ask on the desktop; blocks until clicked, dismissed or expired.
/// `Some(true|false)` for a button, `None` otherwise.
pub fn desktop_ask(p: &PendingApproval, timeout_secs: u64) -> Option<bool> {
    let out = Command::new("notify-send")
        .args([
            "--app-name=kepr",
            "--urgency=critical",
            &format!("--expire-time={}", timeout_secs * 1000),
            "--wait",
            "--action=allow=Allow",
            "--action=deny=Deny",
            &title(p),
            &message(p),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "allow" => Some(true),
        "deny" => Some(false),
        _ => None,
    }
}

/// The one-shot callback URLs handed out in ntfy messages.
#[derive(Default)]
pub struct Callbacks {
    open: HashMap<String, (Zeroizing<String>, Instant)>,
}

/// What the callback answers, and the verdict to pass on.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub text: &'static str,
    /// (id, token, allow) for the daemon.
    pub verdict: Option<(String, String, bool)>,
}

fn reply(status: u16, text: &'static str) -> Reply {
    Reply {
        status,
        text,
        verdict: None,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

impl Callbacks {
    pub fn add(&mut self, id: &str, token: &str, deadline: Instant) {
        self.open.insert(
            id.to_string(),
            (Zeroizing::new(token.to_string()), deadline),
        );
    }

    #[cfg(test)]
    pub fn contains(&self, id: &str) -> bool {
        self.open.contains_key(id)
    }

    /// `POST /approve/ID/TOKEN/allow|deny`.
    pub fn handle(&mut self, method: &str, path: &str, now: Instant) -> Reply {
        if method != "POST" {
            return reply(405, "use POST");
        }
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let ["approve", id, token, verdict] = parts.as_slice() else {
            return reply(404, "not found");
        };
        let allow = match *verdict {
            "allow" => true,
            "deny" => false,
            _ => return reply(404, "not found"),
        };
        let Some((want, deadline)) = self.open.get(*id) else {
            return reply(404, "unknown or already answered");
        };
        if !ct_eq(want, token) {
            return reply(403, "wrong token");
        }
        if now >= *deadline {
            self.open.remove(*id);
            return reply(410, "expired: the request was denied");
        }
        self.open.remove(*id);
        Reply {
            status: 200,
            text: if allow { "allowed" } else { "denied" },
            verdict: Some((id.to_string(), token.to_string(), allow)),
        }
    }

    /// Drop entries past their deadline.
    pub fn sweep(&mut self, now: Instant) {
        self.open.retain(|_, (_, d)| *d > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pending() -> PendingApproval {
        PendingApproval {
            id: "a1b2".into(),
            token: "f00dfeed".into(),
            name: "DB_PASS".into(),
            via: "ntfy".into(),
            requester: "/usr/bin/python3 (pid 42)".into(),
            expires_at: 1_791_331_260,
        }
    }

    #[test]
    fn ntfy_message_has_action_urls() {
        let b = ntfy_body("kepr-x7", &pending(), "http://laptop.tail:8787/");
        assert_eq!(b["topic"], "kepr-x7");
        assert_eq!(b["title"], "kepr: allow access to DB_PASS?");
        assert_eq!(
            b["message"],
            "requested by /usr/bin/python3 (pid 42); unanswered = denied at 2026-10-07T00:01:00Z"
        );
        let a = &b["actions"];
        assert_eq!(a[0]["action"], "http");
        assert_eq!(a[0]["method"], "POST");
        assert_eq!(
            a[0]["url"],
            "http://laptop.tail:8787/approve/a1b2/f00dfeed/allow"
        );
        assert_eq!(a[1]["label"], "Deny");
        assert_eq!(
            a[1]["url"],
            "http://laptop.tail:8787/approve/a1b2/f00dfeed/deny"
        );
        assert_eq!(
            split_ntfy("https://ntfy.sh/kepr-x7").unwrap(),
            ("https://ntfy.sh".into(), "kepr-x7".into())
        );
        assert!(split_ntfy("https://ntfy.sh/").is_err());
        assert!(split_ntfy("kepr-x7").is_err());
    }

    #[test]
    fn the_callback_accepts_only_its_one_time_token() {
        let now = Instant::now();
        let mut cb = Callbacks::default();
        cb.add("a1b2", "f00dfeed", now + Duration::from_secs(60));
        assert_eq!(
            cb.handle("GET", "/approve/a1b2/f00dfeed/allow", now).status,
            405
        );
        assert_eq!(
            cb.handle("POST", "/approve/a1b2/deadbeef/allow", now)
                .status,
            403
        );
        assert_eq!(
            cb.handle("POST", "/approve/zzzz/f00dfeed/allow", now)
                .status,
            404
        );
        assert_eq!(
            cb.handle("POST", "/approve/a1b2/f00dfeed/maybe", now)
                .status,
            404
        );
        assert_eq!(cb.handle("POST", "/etc/passwd", now).status, 404);
        let r = cb.handle("POST", "/approve/a1b2/f00dfeed/allow", now);
        assert_eq!(r.status, 200);
        assert_eq!(r.verdict, Some(("a1b2".into(), "f00dfeed".into(), true)));
        // Spent.
        assert_eq!(
            cb.handle("POST", "/approve/a1b2/f00dfeed/allow", now)
                .status,
            404
        );
    }

    #[test]
    fn late_answers_are_refused() {
        let now = Instant::now();
        let mut cb = Callbacks::default();
        cb.add("i", "t", now + Duration::from_secs(1));
        let late = now + Duration::from_secs(2);
        let r = cb.handle("POST", "/approve/i/t/allow", late);
        assert_eq!((r.status, r.verdict), (410, None));
        cb.add("j", "t", now + Duration::from_secs(1));
        cb.sweep(late);
        assert!(!cb.contains("j"));
    }
}
