// cli_sharing/ — CLI side of the `share` ticket batch (registered in
// cli_more.rs): `kepr device …`. The extra `kepr share …` subcommands
// are reached from cli_share.rs through `share_ext`.

mod device;
mod jwt;
mod oidc;

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
";

pub fn dispatch(verb: &str, args: &[String]) -> Response {
    match verb {
        "device" => device::cmd_device(args),
        other => Response::fail(format!("unknown command: {other}")),
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
    fn unknown_verb_fails() {
        assert!(matches!(dispatch("nope", &[]), Response::Err { .. }));
    }
}
