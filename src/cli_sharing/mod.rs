// cli_sharing/ — CLI side of the `share` ticket batch (registered in
// cli_more.rs): `kepr device …`. The extra `kepr share …` subcommands
// are reached from cli_share.rs through `share_ext`.

mod contacts;
mod device;
mod emergency;
mod jwt;
mod oidc;
mod once;
mod qr;

pub(crate) use contacts::view_window_arg;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_sharing::{SharingRequest, SharingResponse};

pub const VERBS: &[&str] = &["device", "emergency"];

pub const HELP: &str =
    "  device add LABEL [--oidc ISSUER]     single-use token (15 min) for enrolling another machine
  device enroll TOKEN [-o FILE]        (new machine) write its enrolment request for the token
  device enroll --from FILE            (first machine) check the request and pin the new device
  device enroll … --oidc ISSUER --client-id ID [--subject WHO]
                                       prove the user via the IdP (device-code login) first
  device ls | device rm ID|LABEL       enrolled devices (what sync encrypts to)
  share send KEY --once [--ttl 1h] [--relay URL | -o FILE] [--qr] [--self-destruct]
                                       one-time link kepr://share/…#key (key only in the #fragment);
                                       --self-destruct deletes KEY once the link is opened or expires
  share check                          ask the relays which of your links were opened
  share contact add NAME KEY | contact ls | contact rm NAME
                                       pin a contact's share key; then `share send KEY --to NAME`
  share send KEY --to NAME|PUBKEY [--qr] [--view-window 5m]
                                       --qr: the envelope as QR codes (chunked; receive joins them);
                                       --view-window: their copy deletes itself 5m after first get
  share report                         sent shares: to whom, when, expiry, opened?
  emergency add CONTACT --delay 7d (--names A,B | --all)
                                       let a contact request access; granted after the delay
                                       unless you deny it (max 5 contacts, 90 days)
  emergency ls | deny CONTACT | rm CONTACT
  emergency request OWNER_KEY [-o FILE] | request --proof FILE
                                       (contact) ask for access; -o makes a file for their machine
  emergency fetch [-o DIR]             (contact) store what was released to you
  share open LINK [--from FILE] [--as KEY]
                                       fetch (relay) or read (file) a one-time link and store it
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "device" => device::cmd_device(args),
        "emergency" => emergency::cmd_emergency(args),
        other => Response::fail(format!("unknown command: {other}")),
    }
}

/// `kepr share …` subcommands added by this batch (called from
/// cli_share.rs); `None` leaves the arguments to cli_share.
pub fn share_ext(args: &[String]) -> Option<Response> {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("send") if rest.iter().any(|a| a == "--once") => Some(once::send_once(rest)),
        Some("open") => Some(once::open(rest)),
        Some("check") => Some(once::check()),
        Some("contact") => Some(contacts::cmd_contact(rest)),
        Some("report") => Some(contacts::cmd_report()),
        _ => None,
    }
}

/// `90`, `90s`, `15m`, `1h`, `7d` → seconds.
pub(crate) fn parse_duration(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let (num, unit) = match t.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => t.split_at(i),
        None => (t, "s"),
    };
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => 0,
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|s| *s > 0)
        .ok_or_else(|| format!("{text}: not a duration (like 90s, 15m, 1h, 7d)"))
}

/// `YYYY-MM-DD HH:MM` (UTC).
pub(crate) fn fmt_time(unix: u64) -> String {
    let d = kepr_core::sigv4::format_amz_date(unix); // YYYYMMDDTHHMMSSZ
    format!(
        "{}-{}-{} {}:{}",
        &d[..4],
        &d[4..6],
        &d[6..8],
        &d[9..11],
        &d[11..13]
    )
}

/// Print `text` as QR codes (chunked when long) on stderr.
pub(crate) fn print_qr(text: &str) -> Result<(), String> {
    qr::print(text)
}

/// Undo `print_qr`'s chunking on scanned input (plain text passes through).
pub(crate) fn join_qr(text: &str) -> Result<String, String> {
    qr::join(text)
}

/// `90s`, `15m`, `1h`, `7d`: the largest unit that divides `secs`.
pub(crate) fn human_secs(secs: u64) -> String {
    match secs {
        s if s > 0 && s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s > 0 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s > 0 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

pub(crate) fn done_line(message: String) -> Response {
    SharingResponse::SharingDone { message }.into()
}

/// `kepr status` (text mode): pending emergency requests (T6.06).
pub fn print_status() {
    if let Response::Sharing(SharingResponse::EmergencyListing { grants }) =
        send(SharingRequest::EmergencyList)
    {
        for g in grants.iter().filter(|g| g.state == "requested") {
            crate::cli_ui::warn(&format!(
                "Emergency access requested by {}: released {} UTC unless you run \
                 `kepr emergency deny {}`",
                g.contact,
                g.release_at.as_deref().unwrap_or("soon"),
                g.contact
            ));
        }
    }
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn send(req: SharingRequest) -> Response {
    crate::client::send_request(&Request::Sharing(req)).unwrap_or_else(Response::fail)
}

/// Write `text` to a new file (0600); never replaces an existing one.
pub(crate) fn write_new(path: &str, text: &str) -> Result<(), Response> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| writeln!(f, "{text}"))
        .map_err(|e| Response::fail(format!("{path}: {e}")))
}

/// Read a file, or stdin for `-` / no path.
pub(crate) fn read_input(path: Option<&str>) -> Result<String, Response> {
    let mut text = String::new();
    let r = match path {
        None | Some("-") => std::io::Read::read_to_string(&mut std::io::stdin(), &mut text),
        Some(p) => std::fs::read_to_string(p).map(|t| {
            text = t;
            0
        }),
    };
    r.map(|_| text)
        .map_err(|e| Response::fail(format!("cannot read the input: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lines_are_indented_and_end_in_newline() {
        assert!(HELP.ends_with('\n'));
        assert!(HELP.lines().all(|l| l.starts_with("  ")));
        for v in VERBS {
            assert!(HELP.contains(v), "{v} missing from help");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        for bad in ["", "0", "1w", "h", "-5m", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn human_durations() {
        assert_eq!(human_secs(7 * 86_400), "7d");
        assert_eq!(human_secs(7200), "2h");
        assert_eq!(human_secs(300), "5m");
        assert_eq!(human_secs(90), "90s");
        assert_eq!(human_secs(0), "0s");
    }

    #[test]
    fn unknown_verb_fails() {
        assert!(matches!(dispatch("nope", &[]), Response::Err { .. }));
    }
}
