// cli_sharing/ — CLI side of the `share` ticket batch (registered in
// cli_more.rs): `kepr device …`. The extra `kepr share …` subcommands
// are reached from cli_share.rs through `share_ext`.

mod device;
mod jwt;
mod oidc;
mod once;
mod qr;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_sharing::SharingRequest;

pub const VERBS: &[&str] = &["device"];

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
  share open LINK [--from FILE] [--as KEY]
                                       fetch (relay) or read (file) a one-time link and store it
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "device" => device::cmd_device(args),
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
    fn unknown_verb_fails() {
        assert!(matches!(dispatch("nope", &[]), Response::Err { .. }));
    }
}
