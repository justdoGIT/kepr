// cli_share.rs — `kepr share` (agent vault P6.1 / P6.2): hand one
// credential to another kepr user without a server.
//
//   kepr share key                                 your public key (made on first use;
//                                                  kepr-pk2-…, X25519 + ML-KEM-768)
//   kepr share send NAME --to KEY|CONTACT [--ttl SECS] [-o FILE] [--qr]
//                   [--view-window 5m]
//   kepr share receive [FILE] [--as NAME]          FILE or stdin (QR chunks too)
//
// The sender's daemon encrypts to the recipient's public key; the
// recipient's daemon decrypts and stores it. Shares expire (default 24 h)
// and are single-use. Sealed keys, SSH keys and the share key can't be sent.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::protocol::{Request, Response};

use crate::cli_extra::{flag as value, positionals as positional};
use crate::{cli_mode, cli_ui, client};

const USAGE: &str =
    "usage: kepr share key | send NAME --to KEY|CONTACT [--ttl SECS] [-o FILE] [--qr] \
                     [--view-window 5m] | receive [FILE] [--as NAME] | contact … | report";

fn send(req: &Request) -> Response {
    client::send_request(req).unwrap_or_else(Response::fail)
}

fn cmd_send(args: &[String]) -> Response {
    let pos = positional(args, &["--to", "--ttl", "-o", "--view-window"]);
    let (Some(name), Some(to)) = (pos.first(), value(args, "--to")) else {
        return Response::fail(USAGE);
    };
    let ttl_secs = match value(args, "--ttl").map(str::parse::<u64>) {
        Some(Ok(t)) => Some(t),
        Some(Err(_)) => return Response::fail("--ttl needs a number of seconds"),
        None => None,
    };
    let view_window_secs = match crate::cli_sharing::view_window_arg(args) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let r = send(&Request::ShareSend {
        name: name.to_uppercase(),
        to: to.to_string(),
        ttl_secs,
        view_window_secs,
    });
    let Response::ShareOk {
        envelope,
        expires_at,
    } = &r
    else {
        return r;
    };
    if cli_mode::json_mode() {
        return r;
    }
    match value(args, "-o") {
        Some(path) => {
            let written = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .and_then(|mut f| writeln!(f, "{envelope}"));
            if let Err(e) = written {
                return Response::fail(format!("{path}: {e}"));
            }
            cli_ui::ok(&format!(
                "share written to {path}; expires {expires_at} UTC, single use"
            ));
        }
        None => {
            println!("{envelope}");
            cli_ui::einfo(&format!(
                "only the recipient can open this; expires {expires_at} UTC, single use"
            ));
        }
    }
    // T11.15: the envelope as (chunked) QR codes, for a phone or an air gap.
    if args.iter().any(|a| a == "--qr") {
        if let Err(e) = crate::cli_sharing::print_qr(envelope) {
            return Response::fail(e);
        }
    }
    if let Some(w) = view_window_secs {
        cli_ui::einfo(&format!(
            "their copy deletes itself {} after its first get",
            crate::cli_sharing::human_secs(w)
        ));
    }
    Response::Pong
}

fn cmd_receive(args: &[String]) -> Response {
    let pos = positional(args, &["--as"]);
    let mut text = String::new();
    let read = match pos.first().map(String::as_str) {
        None | Some("-") => std::io::stdin().read_to_string(&mut text).map(|_| ()),
        Some(path) => std::fs::read_to_string(path).map(|t| text = t),
    };
    if let Err(e) = read {
        return Response::fail(format!("cannot read the share: {e}"));
    }
    // T11.15: scanned QR chunks (KQ<i>/<n>:…, one per line) are joined.
    let envelope = match crate::cli_sharing::join_qr(&text) {
        Ok(e) => e,
        Err(e) => return Response::fail(e),
    };
    let r = send(&Request::ShareReceive {
        envelope,
        name: value(args, "--as").map(str::to_uppercase),
    });
    if let (Response::SetOk { name, .. }, false) = (&r, cli_mode::json_mode()) {
        cli_ui::ok(&format!("received and stored as {name}"));
    }
    r
}

pub fn cmd_share(args: &[String]) -> Response {
    // batch: share — one-time links and the other new subcommands.
    if let Some(r) = crate::cli_sharing::share_ext(args) {
        return r;
    }
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("key") => {
            let r = send(&Request::ShareKey { create: true });
            if let (Response::ShareKeyOk { public }, false) = (&r, cli_mode::json_mode()) {
                println!("{public}");
            }
            r
        }
        Some("send") => cmd_send(rest),
        Some("receive") => cmd_receive(rest),
        _ => Response::fail(USAGE),
    }
}
