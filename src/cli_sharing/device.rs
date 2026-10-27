// cli_sharing/device.rs — `kepr device add|enroll|ls|rm` (T6.03).
//
//   first machine:  kepr device add laptop          → KD1-… (15 min, once)
//   new machine:    kepr device enroll KD1-… -o enroll.json
//   first machine:  kepr device enroll --from enroll.json
//
// The new machine's request carries its share public key and an HMAC
// keyed by the token's hash; the first machine's daemon checks it, burns
// the token and pins the key.

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_sharing::{
    normalize_token, DeviceInfo, EnrolRequest, OidcIdentity, SharingRequest, SharingResponse,
};

use super::{oidc, read_input, send, write_new};
use crate::cli_extra::{flag, positionals};
use crate::{cli_mode, cli_ui, client};

const USAGE: &str = "usage: kepr device add LABEL [--oidc ISSUER] | enroll TOKEN [-o FILE] \
     | enroll --from FILE | ls | rm ID|LABEL  (enroll takes --oidc ISSUER --client-id ID)";

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "device".into())
}

fn add(args: &[String]) -> Response {
    let [label] = positionals(args, &["--oidc"])
        .try_into()
        .unwrap_or_default();
    if label.is_empty() {
        return Response::fail(USAGE);
    }
    let r = send(SharingRequest::DeviceAdd {
        label,
        oidc_issuer: flag(args, "--oidc").map(str::to_string),
    });
    if let (
        Response::Sharing(SharingResponse::DeviceToken {
            token, expires_at, ..
        }),
        false,
    ) = (&r, cli_mode::json_mode())
    {
        println!("{}", token.as_str());
        cli_ui::einfo(&format!(
            "single use, valid until {expires_at} UTC. On the new machine: \
             kepr device enroll {} -o enroll.json; then here: kepr device enroll --from enroll.json",
            token.as_str()
        ));
    }
    r
}

/// The new machine: build the enrolment request for `token`.
pub(crate) fn request_for(token: &str, id_token: Option<String>) -> Result<EnrolRequest, Response> {
    let token =
        normalize_token(token).ok_or_else(|| Response::fail("not a device token (KD1-…)"))?;
    match client::send_request(&Request::ShareKey { create: true }) {
        Ok(Response::ShareKeyOk { public }) => {
            Ok(EnrolRequest::new(&token, &hostname(), &public, id_token))
        }
        Ok(Response::Err { error }) | Err(error) => Err(Response::fail(error)),
        Ok(_) => Err(Response::fail("unexpected response")),
    }
}

/// `--oidc ISSUER --client-id ID`: both or neither.
fn oidc_flags(args: &[String]) -> Result<Option<(&str, &str)>, Response> {
    match (flag(args, "--oidc"), flag(args, "--client-id")) {
        (Some(i), Some(c)) => Ok(Some((i, c))),
        (None, None) => Ok(None),
        _ => Err(Response::fail(
            "--oidc ISSUER and --client-id ID go together",
        )),
    }
}

/// The first machine: re-check the ID token in the request against the
/// issuer's JWKS and say who logged in.
fn verified_identity(
    request: &str,
    (issuer, client): (&str, &str),
    subject: Option<&str>,
) -> Result<OidcIdentity, Response> {
    let id = oidc::verify_request(request, issuer, client, subject).map_err(Response::fail)?;
    cli_ui::einfo(&format!(
        "IdP login verified: {} @ {}",
        id.subject, id.issuer
    ));
    Ok(id)
}

fn enroll(args: &[String]) -> Response {
    let r = (|| -> Result<Response, Response> {
        let oidc = oidc_flags(args)?;
        if let Some(path) = flag(args, "--from") {
            let request = read_input(Some(path))?;
            let id = match oidc {
                Some(o) => Some(verified_identity(
                    request.trim(),
                    o,
                    flag(args, "--subject"),
                )?),
                None => None,
            };
            return Ok(accept(request.trim(), id));
        }
        let pos = positionals(args, &["-o", "--oidc", "--client-id", "--subject"]);
        let token = pos.first().ok_or_else(|| Response::fail(USAGE))?;
        normalize_token(token).ok_or_else(|| Response::fail("not a device token (KD1-…)"))?;
        let id_token = match oidc {
            Some((issuer, client)) => {
                Some(oidc::device_login(issuer, client).map_err(Response::fail)?)
            }
            None => None,
        };
        let req = request_for(token, id_token)?;
        let text = serde_json::to_string(&req).map_err(|e| Response::fail(e.to_string()))?;
        match flag(args, "-o") {
            Some(path) => {
                write_new(path, &text)?;
                cli_ui::ok(&format!(
                    "enrolment request written to {path}; on the first machine run: \
                     kepr device enroll --from {path}"
                ));
            }
            None => println!("{text}"),
        }
        Ok(Response::Pong)
    })();
    r.unwrap_or_else(|e| e)
}

/// The first machine: hand the request to the daemon.
pub(crate) fn accept(request: &str, oidc: Option<OidcIdentity>) -> Response {
    let r = send(SharingRequest::DeviceEnroll {
        request: request.to_string(),
        oidc,
    });
    if let (Response::Sharing(SharingResponse::DeviceListing { devices, .. }), false) =
        (&r, cli_mode::json_mode())
    {
        for d in devices {
            cli_ui::ok(&format!("enrolled {} ({})", d.label, d.id));
        }
    }
    r
}

fn print_device(d: &DeviceInfo) {
    let who = d
        .identity
        .as_deref()
        .map(|i| format!("  [{i}]"))
        .unwrap_or_default();
    println!("  {:<10} {:<24} added {}{who}", d.id, d.label, d.added);
}

fn ls() -> Response {
    let r = send(SharingRequest::DeviceList);
    if let (Response::Sharing(SharingResponse::DeviceListing { devices, pending }), false) =
        (&r, cli_mode::json_mode())
    {
        if devices.is_empty() && pending.is_empty() {
            cli_ui::info("No devices enrolled (kepr device add LABEL).");
        }
        devices.iter().for_each(print_device);
        for p in pending {
            println!(
                "  {:<10} {:<24} token valid until {}",
                "(pending)", p.label, p.expires_at
            );
        }
    }
    r
}

pub fn cmd_device(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("add") => add(rest),
        Some("enroll") => enroll(rest),
        Some("ls" | "list") => ls(),
        Some("rm" | "remove") => match positionals(rest, &[]).as_slice() {
            [d] => {
                let r = send(SharingRequest::DeviceRemove { device: d.clone() });
                if let (Response::Sharing(SharingResponse::SharingDone { message }), false) =
                    (&r, cli_mode::json_mode())
                {
                    cli_ui::ok(message);
                }
                r
            }
            _ => Response::fail(USAGE),
        },
        _ => Response::fail(USAGE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn usage_errors_need_no_daemon() {
        for a in [&[][..], &["add"], &["rm"], &["enroll"], &["bogus"]] {
            assert!(matches!(cmd_device(&v(a)), Response::Err { .. }), "{a:?}");
        }
        let r = cmd_device(&v(&["enroll", "not-a-token"]));
        assert!(matches!(r, Response::Err { error } if error.contains("KD1")));
        let r = cmd_device(&v(&["enroll", "--from", "x", "--oidc", "https://idp"]));
        assert!(matches!(r, Response::Err { error } if error.contains("--client-id")));
    }
}
