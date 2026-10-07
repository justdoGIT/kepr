// cli_sharing/contacts.rs — T11.15 share contacts and the share report.
//
//   kepr share contact add NAME KEY | contact ls | contact rm NAME
//   kepr share report        sent shares: to, when, expires, opened?
//
// `share send --to NAME`, `--view-window` and `--qr` are in cli_share.rs
// and once.rs; this file has the helpers they share.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{ContactInfo, SentShare, SharingRequest, SharingResponse};

use super::{parse_duration, send};
use crate::cli_extra::flag;
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr share contact add NAME KEY | contact ls | contact rm NAME";

/// `--view-window 5m` → seconds.
pub fn view_window_arg(args: &[String]) -> Result<Option<u64>, Response> {
    flag(args, "--view-window")
        .map(parse_duration)
        .transpose()
        .map_err(Response::fail)
}

fn print_contacts(contacts: &[ContactInfo]) {
    if contacts.is_empty() {
        cli_ui::info("No contacts pinned (kepr share contact add NAME KEY).");
        return;
    }
    for c in contacts {
        println!("  {:<24} {}  pinned {}", c.name, c.fingerprint, c.added);
    }
}

pub fn cmd_contact(args: &[String]) -> Response {
    let r = match (args.first().map(String::as_str), args.get(1), args.get(2)) {
        (Some("add"), Some(name), Some(key)) => send(SharingRequest::ShareContactAdd {
            name: name.clone(),
            key: key.clone(),
        }),
        (Some("ls" | "list"), None, _) => send(SharingRequest::ShareContactList),
        (Some("rm" | "remove"), Some(name), None) => {
            send(SharingRequest::ShareContactRemove { name: name.clone() })
        }
        _ => return Response::fail(USAGE),
    };
    if cli_mode::json_mode() {
        return r;
    }
    match &r {
        Response::Sharing(SharingResponse::ShareContacts { contacts }) => print_contacts(contacts),
        Response::Sharing(SharingResponse::SharingDone { message }) => cli_ui::ok(message),
        _ => {}
    }
    r
}

fn when(unix: u64) -> String {
    match unix {
        0 => "-".into(),
        t => crate::cli_sharing::fmt_time(t),
    }
}

/// One report line: name, kind, to, sent, expires, opened.
pub(crate) fn report_line(s: &SentShare, now: u64) -> String {
    let opened = match (s.opened_unix, s.expires_unix) {
        (Some(t), _) => format!("opened {}", when(t)),
        (None, 0) => "-".into(),
        (None, e) if e <= now => "expired unopened".into(),
        (None, _) => "not yet".into(),
    };
    format!(
        "  {:<24} {:<8} {:<20} {:<16} {:<16} {}",
        s.name,
        s.kind,
        s.to.as_deref().or(s.relay.as_deref()).unwrap_or("-"),
        when(s.sent_unix),
        when(s.expires_unix),
        opened
    )
}

pub fn cmd_report() -> Response {
    let r = send(SharingRequest::ShareReport);
    let (Response::Sharing(SharingResponse::ShareSent { shares }), false) =
        (&r, cli_mode::json_mode())
    else {
        return r;
    };
    if shares.is_empty() {
        cli_ui::info("No shares sent.");
        return r;
    }
    println!(
        "  {:<24} {:<8} {:<20} {:<16} {:<16} OPENED",
        "NAME", "KIND", "TO", "SENT (UTC)", "EXPIRES (UTC)"
    );
    let now = super::now();
    for s in shares {
        println!("{}", report_line(s, now));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(to: Option<&str>, expires: u64, opened: Option<u64>) -> SentShare {
        SentShare {
            id: "i".into(),
            name: "API_KEY".into(),
            kind: "envelope".into(),
            to: to.map(Into::into),
            relay: None,
            sent_unix: 86_400,
            expires_unix: expires,
            opened_unix: opened,
            self_destruct: false,
            settled: false,
        }
    }

    #[test]
    fn report_lines_say_who_when_and_whether_opened() {
        let now = 200_000;
        let l = report_line(&row(Some("bob"), 172_800, Some(90_000)), now);
        assert!(l.contains("API_KEY") && l.contains("bob"), "{l}");
        assert!(
            l.contains("1970-01-02 00:00") && l.contains("1970-01-03 00:00"),
            "{l}"
        );
        assert!(l.contains("opened 1970-01-02 01:00"), "{l}");
        assert!(report_line(&row(None, 172_800, None), now).ends_with("expired unopened"));
        assert!(report_line(&row(None, 300_000, None), now).ends_with("not yet"));
        // A chain-only row: no recipient, no expiry known.
        let l = report_line(&row(None, 0, None), now);
        assert!(l.contains(" - ") && l.ends_with('-'), "{l}");
    }

    #[test]
    fn view_window_flag() {
        let a = |v: &str| vec!["--view-window".to_string(), v.to_string()];
        assert_eq!(view_window_arg(&a("5m")).unwrap(), Some(300));
        assert_eq!(view_window_arg(&[]).unwrap(), None);
        assert!(view_window_arg(&a("soon")).is_err());
    }

    #[test]
    fn contact_usage() {
        for bad in [&[][..], &["add".to_string()][..], &["frob".to_string()][..]] {
            assert!(matches!(cmd_contact(bad), Response::Err { .. }));
        }
    }
}
