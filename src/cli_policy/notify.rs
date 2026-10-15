// cli_policy/notify.rs — webhook notifications (T6.08; also used by the
// alert rules, T7.15): one short message rendered for Slack, Microsoft
// Teams, Discord, ntfy or plain JSON, posted with the shared HTTP agent
// (no redirects, 30 s timeout).
//
// A `Note` is built only from names, flags, ops and results: callers
// never put a value, a hash or a hash prefix in it. A webhook URL can
// itself be a secret, so `kepr:NAME` reads it from the vault instead of
// argv.

use kepr_core::generate::ZeroString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Slack,
    Teams,
    Discord,
    Ntfy,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self, String> {
        Ok(match s {
            "slack" => Self::Slack,
            "teams" => Self::Teams,
            "discord" => Self::Discord,
            "ntfy" => Self::Ntfy,
            "json" => Self::Json,
            other => {
                return Err(format!(
                    "unknown webhook format `{other}` (slack, teams, discord, ntfy or json)"
                ))
            }
        })
    }

    /// The format a webhook URL's host expects; plain JSON otherwise.
    pub fn guess(url: &str) -> Self {
        let host = url
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let host = host.rsplit('@').next().unwrap_or_default();
        let host = host.split(':').next().unwrap_or_default();
        let is = |d: &str| host == d || host.ends_with(&format!(".{d}"));
        if is("slack.com") {
            Self::Slack
        } else if is("discord.com") || is("discordapp.com") {
            Self::Discord
        } else if is("office.com") || is("logic.azure.com") {
            Self::Teams
        } else if is("ntfy.sh") {
            Self::Ntfy
        } else {
            Self::Json
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub title: String,
    pub lines: Vec<String>,
}

pub struct Body {
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

const MAX_LINES: usize = 40;
const DISCORD_MAX: usize = 2000;

/// The lines, capped, with a "… and N more" tail.
fn capped(note: &Note) -> Vec<String> {
    let mut lines: Vec<String> = note.lines.iter().take(MAX_LINES).cloned().collect();
    if note.lines.len() > MAX_LINES {
        lines.push(format!("… and {} more", note.lines.len() - MAX_LINES));
    }
    lines
}

pub fn render(format: Format, note: &Note) -> Body {
    let lines = capped(note);
    let json = |v: serde_json::Value| Body {
        content_type: "application/json",
        headers: Vec::new(),
        body: v.to_string(),
    };
    match format {
        Format::Slack => json(serde_json::json!({
            "text": format!("*{}*\n{}", note.title, lines.iter().map(|l| format!("• {l}")).collect::<Vec<_>>().join("\n")),
        })),
        Format::Teams => json(serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": note.title,
            "title": note.title,
            "text": lines.join("<br>"),
        })),
        Format::Discord => {
            let text = format!(
                "**{}**\n{}",
                note.title,
                lines
                    .iter()
                    .map(|l| format!("- {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            json(
                serde_json::json!({ "content": text.chars().take(DISCORD_MAX).collect::<String>() }),
            )
        }
        Format::Ntfy => Body {
            content_type: "text/plain; charset=utf-8",
            // Header values must be ASCII: keep the title's ASCII only.
            headers: vec![
                ("Title", note.title.chars().filter(char::is_ascii).collect()),
                ("Tags", "warning,key".to_string()),
            ],
            body: lines.join("\n"),
        },
        Format::Json => json(serde_json::json!({ "title": note.title, "lines": lines })),
    }
}

/// `kepr:NAME` → the URL stored under NAME; anything else as given.
pub fn resolve_url(spec: &str) -> Result<ZeroString, String> {
    let url = match spec.strip_prefix("kepr:") {
        Some(name) => {
            use crate::cli_exec::CredFetcher;
            let v = crate::cli_exec::DaemonFetcher
                .fetch(&name.to_uppercase())
                .map_err(|e| format!("webhook {name}: {e}"))?;
            ZeroString::from_string(v.as_str().trim().to_string())
        }
        None => ZeroString::from_string(spec.to_string()),
    };
    let u = url.as_str();
    if u.starts_with("https://") || u.starts_with("http://") {
        Ok(url)
    } else {
        Err("a webhook URL must start with https:// (or http://)".into())
    }
}

/// POST `note`; any non-2xx answer is an error (the reply body is not
/// echoed: it could reflect the URL's token).
pub fn send(url: &str, format: Format, note: &Note) -> Result<(), String> {
    let b = render(format, note);
    let mut req = crate::sync_http::agent()
        .post(url)
        .set("Content-Type", b.content_type)
        .set("User-Agent", "kepr");
    for (k, v) in &b.headers {
        req = req.set(k, v);
    }
    match crate::sync_http::send(req, Some(b.body.as_bytes())) {
        Ok((code, _)) if (200..300).contains(&code) => Ok(()),
        Ok((code, _)) => Err(format!("webhook answered HTTP {code}")),
        Err(_) => Err("webhook unreachable".into()),
    }
}

#[cfg(test)]
pub mod testserver {
    //! A one-request loopback HTTP server for the webhook tests.
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serve one request with `status`; the thread returns the raw request
    /// (and panics when none arrives within 10 s, so a test can't hang).
    pub fn once(status: u16) -> (String, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(e) => panic!("no request arrived: {e}"),
                }
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len || n == 0 {
                        break;
                    }
                }
            }
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            );
            String::from_utf8_lossy(&buf).to_string()
        });
        (url, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> Note {
        Note {
            title: "kepr health: 1 of 2 credential(s) need attention".into(),
            lines: vec!["DB_PASS: weak (easy to guess); found in a data breach".into()],
        }
    }

    #[test]
    fn body_per_format() {
        let n = note();
        let slack: serde_json::Value =
            serde_json::from_str(&render(Format::Slack, &n).body).unwrap();
        assert!(slack["text"].as_str().unwrap().contains("• DB_PASS: weak"));
        let teams: serde_json::Value =
            serde_json::from_str(&render(Format::Teams, &n).body).unwrap();
        assert_eq!(teams["@type"], "MessageCard");
        assert_eq!(teams["title"], n.title);
        let discord: serde_json::Value =
            serde_json::from_str(&render(Format::Discord, &n).body).unwrap();
        assert!(discord["content"]
            .as_str()
            .unwrap()
            .starts_with("**kepr health"));
        let ntfy = render(Format::Ntfy, &n);
        assert_eq!(ntfy.content_type, "text/plain; charset=utf-8");
        assert_eq!(ntfy.body, n.lines[0]);
        assert!(ntfy.headers.contains(&("Title", n.title.clone())));
        let plain: serde_json::Value =
            serde_json::from_str(&render(Format::Json, &n).body).unwrap();
        assert_eq!(plain["lines"][0], n.lines[0]);
        assert!(Format::parse("pager").is_err());
    }

    #[test]
    fn long_notes_are_capped() {
        let n = Note {
            title: "t".into(),
            lines: (0..100).map(|i| format!("K{i}: weak")).collect(),
        };
        let b = render(Format::Json, &n).body;
        assert!(b.contains("and 60 more") && !b.contains("K99"));
        let d: serde_json::Value = serde_json::from_str(&render(Format::Discord, &n).body).unwrap();
        assert!(d["content"].as_str().unwrap().chars().count() <= DISCORD_MAX);
    }

    #[test]
    fn posts_and_reports_non_2xx() {
        let (url, h) = testserver::once(200);
        send(&url, Format::Slack, &note()).unwrap();
        let req = h.join().unwrap();
        assert!(req.starts_with("POST /hook HTTP/1.1"));
        assert!(req.contains("DB_PASS: weak"));
        let (url, h) = testserver::once(500);
        assert_eq!(
            send(&url, Format::Ntfy, &note()).unwrap_err(),
            "webhook answered HTTP 500"
        );
        assert!(h
            .join()
            .unwrap()
            .to_ascii_lowercase()
            .contains("title: kepr health"));
        assert!(resolve_url("ftp://x").is_err());
    }

    #[test]
    fn guesses_format_from_host() {
        assert_eq!(
            Format::guess("https://hooks.slack.com/services/T/B/X"),
            Format::Slack
        );
        assert_eq!(
            Format::guess("https://discord.com/api/webhooks/1/x"),
            Format::Discord
        );
        assert_eq!(
            Format::guess("https://acme.webhook.office.com/webhookb2/x"),
            Format::Teams
        );
        assert_eq!(Format::guess("https://ntfy.sh/kepr-alerts"), Format::Ntfy);
        assert_eq!(
            Format::guess("https://slack.com.evil.example/x"),
            Format::Json
        );
        assert_eq!(Format::guess("http://127.0.0.1:9/hook"), Format::Json);
    }
}
