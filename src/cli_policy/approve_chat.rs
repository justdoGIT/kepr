// cli_policy/approve_chat.rs — answer an approval request from Slack or
// Teams (T13.08).
//
// Slack: `kepr approvals serve --slack-webhook URL --slack-signing-secret
// FILE --listen ADDR:PORT` posts the request with Allow / Deny buttons to
// an incoming webhook; the Slack app's interactivity Request URL points at
// `https://HOST/slack/interact` (behind a TLS proxy). Slack signs each
// click: `v0=` HMAC-SHA256 of `v0:TIMESTAMP:BODY` under the app's signing
// secret. A click is accepted only with a valid signature, a timestamp
// within five minutes, and the request's own one-time token.
//
// Teams: an incoming-webhook card whose Allow / Deny links open a
// confirmation page on this machine (`GET` never answers; its button
// `POST`s to the same one-time URL). The link carries the one-time token.
//
// The daemon still checks the token again and that the answer comes from
// the registered approver process.

use serde_json::{json, Value};

use kepr_core::protocol_policy::PendingApproval;

/// How far a request timestamp may be from now (Slack's own advice).
pub const MAX_SKEW_SECS: u64 = 300;
/// Largest interaction body read.
pub const MAX_BODY: usize = 16 * 1024;

/// `Ok` for a request signed with `secret`: fresh timestamp, matching
/// `X-Slack-Signature`.
pub fn verify_slack(
    secret: &[u8],
    timestamp: &str,
    body: &[u8],
    signature: &str,
    now: u64,
) -> Result<(), &'static str> {
    let ts: u64 = timestamp.parse().map_err(|_| "bad timestamp")?;
    if now.abs_diff(ts) > MAX_SKEW_SECS {
        return Err("stale timestamp");
    }
    let tag = signature.strip_prefix("v0=").ok_or("bad signature")?;
    let tag = hex::decode(tag).map_err(|_| "bad signature")?;
    let base = [b"v0:".as_slice(), timestamp.as_bytes(), b":", body].concat();
    if kepr_core::mac::hmac_sha256_verify(secret, &[&base], &tag) {
        Ok(())
    } else {
        Err("bad signature")
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit() =>
            {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'?'));
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// `(id, token, allow)` from a Slack interaction body
/// (`payload=<url-encoded JSON>`; the button's `value` is `ID:TOKEN`).
pub fn slack_verdict(body: &[u8]) -> Result<(String, String, bool), &'static str> {
    let text = std::str::from_utf8(body).map_err(|_| "bad body")?;
    let raw = text
        .split('&')
        .find_map(|kv| kv.strip_prefix("payload="))
        .ok_or("no payload")?;
    let v: Value = serde_json::from_slice(&percent_decode(raw)).map_err(|_| "bad payload")?;
    if v["type"] != "block_actions" {
        return Err("not a button click");
    }
    let action = v["actions"].get(0).ok_or("no action")?;
    let allow = match action["action_id"].as_str() {
        Some("kepr_allow") => true,
        Some("kepr_deny") => false,
        _ => return Err("unknown action"),
    };
    let (id, token) = action["value"]
        .as_str()
        .and_then(|s| s.split_once(':'))
        .ok_or("bad value")?;
    Ok((id.to_string(), token.to_string(), allow))
}

fn headline(p: &PendingApproval) -> String {
    format!(
        "kepr: allow access to {}? Requested by {}; unanswered = denied at {}.",
        p.name,
        p.requester,
        super::siem::rfc3339(p.expires_at)
    )
}

/// The Slack message with Allow / Deny buttons.
pub fn slack_message(p: &PendingApproval) -> Value {
    let value = format!("{}:{}", p.id, p.token);
    json!({
        "text": format!("kepr: allow access to {}?", p.name),
        "blocks": [
            { "type": "section", "text": { "type": "mrkdwn", "text": headline(p) } },
            { "type": "actions", "elements": [
                { "type": "button", "style": "primary", "action_id": "kepr_allow",
                  "text": { "type": "plain_text", "text": "Allow" }, "value": value },
                { "type": "button", "style": "danger", "action_id": "kepr_deny",
                  "text": { "type": "plain_text", "text": "Deny" }, "value": value },
            ] },
        ],
    })
}

/// The Teams MessageCard whose links open the confirmation page.
pub fn teams_card(p: &PendingApproval, callback_base: &str) -> Value {
    let base = callback_base.trim_end_matches('/');
    let link = |verdict: &str| format!("{base}/approve/{}/{}/{verdict}", p.id, p.token);
    json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": format!("kepr: allow access to {}?", p.name),
        "title": format!("kepr: allow access to {}?", p.name),
        "text": headline(p),
        "potentialAction": [
            { "@type": "OpenUri", "name": "Allow", "targets": [{ "os": "default", "uri": link("allow") }] },
            { "@type": "OpenUri", "name": "Deny", "targets": [{ "os": "default", "uri": link("deny") }] },
        ],
    })
}

/// POST a JSON message to a chat webhook.
pub fn post(url: &str, body: &Value) -> Result<(), String> {
    let req = crate::sync_http::agent()
        .post(url)
        .set("Content-Type", "application/json")
        .set("User-Agent", "kepr");
    match crate::sync_http::send(req, Some(body.to_string().as_bytes())) {
        Ok((code, _)) if (200..300).contains(&code) => Ok(()),
        Ok((code, _)) => Err(format!("the chat webhook answered HTTP {code}")),
        Err(_) => Err("the chat webhook is unreachable".into()),
    }
}

/// Slack's reply to a click: replace the message so the buttons go away.
pub fn slack_reply(name_allowed: Option<bool>) -> String {
    let text = match name_allowed {
        Some(true) => "kepr: allowed",
        Some(false) => "kepr: denied",
        None => "kepr: this request is no longer open",
    };
    json!({ "replace_original": true, "text": text }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"8f742231b10e8888abcd99yyyzzz85a5";

    fn sign(ts: &str, body: &[u8]) -> String {
        let base = [b"v0:".as_slice(), ts.as_bytes(), b":", body].concat();
        format!(
            "v0={}",
            hex::encode(kepr_core::mac::hmac_sha256(SECRET, &[&base]).as_slice())
        )
    }

    fn pending() -> PendingApproval {
        PendingApproval {
            id: "a1b2".into(),
            token: "f00dfeed".into(),
            name: "DB_PASS".into(),
            via: "slack".into(),
            requester: "/usr/bin/python3 (pid 42)".into(),
            expires_at: 1_791_331_260,
        }
    }

    fn click(action: &str, value: &str) -> Vec<u8> {
        let payload = json!({
            "type": "block_actions",
            "actions": [{ "action_id": action, "value": value }],
        })
        .to_string();
        let enc: String = payload
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect();
        format!("payload={enc}").into_bytes()
    }

    #[test]
    fn a_valid_signature_passes() {
        let body = click("kepr_allow", "a1b2:f00dfeed");
        let sig = sign("1700000000", &body);
        assert_eq!(
            verify_slack(SECRET, "1700000000", &body, &sig, 1_700_000_100),
            Ok(())
        );
    }

    #[test]
    fn a_wrong_signature_is_refused() {
        let body = click("kepr_allow", "a1b2:f00dfeed");
        let sig = sign("1700000000", &body);
        let other = sign("1700000000", b"payload=x");
        assert!(verify_slack(b"another secret", "1700000000", &body, &sig, 1_700_000_000).is_err());
        assert!(verify_slack(SECRET, "1700000000", &body, &other, 1_700_000_000).is_err());
        assert!(verify_slack(SECRET, "1700000000", &body, "v1=00", 1_700_000_000).is_err());
        assert!(verify_slack(SECRET, "1700000000", &body, "v0=zz", 1_700_000_000).is_err());
        // A body altered after signing.
        let mut tampered = body.clone();
        tampered.push(b'x');
        assert!(verify_slack(SECRET, "1700000000", &tampered, &sig, 1_700_000_000).is_err());
    }

    #[test]
    fn a_replayed_timestamp_is_refused() {
        let body = click("kepr_allow", "a1b2:f00dfeed");
        let sig = sign("1700000000", &body);
        assert_eq!(
            verify_slack(SECRET, "1700000000", &body, &sig, 1_700_000_000 + 301),
            Err("stale timestamp")
        );
        assert_eq!(
            verify_slack(SECRET, "1700000000", &body, &sig, 1_700_000_000 - 301),
            Err("stale timestamp")
        );
        assert!(verify_slack(SECRET, "soon", &body, &sig, 1).is_err());
    }

    #[test]
    fn clicks_become_verdicts() {
        assert_eq!(
            slack_verdict(&click("kepr_allow", "a1b2:f00dfeed")).unwrap(),
            ("a1b2".into(), "f00dfeed".into(), true)
        );
        assert!(!slack_verdict(&click("kepr_deny", "i:t")).unwrap().2);
        assert!(slack_verdict(&click("other", "i:t")).is_err());
        assert!(slack_verdict(&click("kepr_allow", "no-colon")).is_err());
        assert!(slack_verdict(b"nothing=here").is_err());
        assert!(slack_verdict(b"payload=%7Bnot-json").is_err());
    }

    #[test]
    fn messages_carry_the_one_time_values() {
        let m = slack_message(&pending());
        let b = &m["blocks"][1]["elements"];
        assert_eq!(b[0]["value"], "a1b2:f00dfeed");
        assert_eq!(b[1]["action_id"], "kepr_deny");
        let t = teams_card(&pending(), "https://kepr.example/");
        assert_eq!(
            t["potentialAction"][0]["targets"][0]["uri"],
            "https://kepr.example/approve/a1b2/f00dfeed/allow"
        );
    }

    #[test]
    fn the_reply_replaces_the_buttons() {
        let v: Value = serde_json::from_str(&slack_reply(Some(true))).unwrap();
        assert_eq!(v["replace_original"], true);
        assert!(slack_reply(None).contains("no longer open"));
    }
}
