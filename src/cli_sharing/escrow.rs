// cli_sharing/escrow.rs — T6.14 `kepr escrow`.
//
//   kepr escrow enable ADMIN_KEY|CONTACT   (asks for the store passphrase)
//   kepr escrow disable | status
//   kepr escrow open FILE [--out-dir DIR]  (admin) the escrowed key as a
//                                          2-of-2 recovery kit; restore it with
//                                          `kepr recovery-kit restore` on the
//                                          machine with the old credential files

use std::os::unix::fs::OpenOptionsExt;

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{SharingRequest, SharingResponse};

use super::{read_input, send};
use crate::cli_extra::{flag, positionals};
use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui};

const USAGE: &str =
    "usage: kepr escrow enable ADMIN_KEY | disable | status | open FILE [--out-dir DIR]";

/// The `kepr status` line, when escrow is on.
pub(crate) fn status_line(r: &Response) -> Option<String> {
    let Response::Sharing(SharingResponse::EscrowState {
        enabled: true,
        admin,
        admin_fingerprint,
        since,
    }) = r
    else {
        return None;
    };
    Some(format!(
        "Escrow: on, to {} ({}) since {} UTC",
        admin.as_deref().unwrap_or("?"),
        admin_fingerprint.as_deref().unwrap_or("?"),
        since.as_deref().unwrap_or("?")
    ))
}

fn write_share(dir: &str, i: usize, text: &str) -> Result<String, Response> {
    use std::io::Write;
    let path = format!("{}/kepr-escrow-share-{i}.txt", dir.trim_end_matches('/'));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{text}"))
        .map_err(|e| Response::fail(format!("{path}: {e}")))?;
    Ok(path)
}

fn open(args: &[String]) -> Result<Response, Response> {
    let pos = positionals(args, &["--out-dir"]);
    let file = pos.first().ok_or_else(|| Response::fail(USAGE))?;
    let escrow = read_input(Some(file))?;
    let r = send(SharingRequest::EscrowOpen { escrow });
    let (
        Response::RecoveryKitOk {
            fingerprint,
            shares,
        },
        false,
    ) = (&r, cli_mode::json_mode())
    else {
        return Ok(r);
    };
    for (i, s) in shares.iter().enumerate() {
        match flag(args, "--out-dir") {
            Some(dir) => println!("{}", write_share(dir, i + 1, s.as_str())?),
            None => println!("{}", s.as_str()),
        }
    }
    cli_ui::einfo(&format!(
        "key {fingerprint}: on the machine with the old credential files, run \
         `kepr recovery-kit restore` and paste both shares"
    ));
    Ok(Response::Pong)
}

pub fn cmd_escrow(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    let r = match (args.first().map(String::as_str), rest) {
        (Some("enable"), [admin_key]) => {
            let password = read_masked("  Store passphrase: ");
            Ok(send(SharingRequest::EscrowEnable {
                admin_key: admin_key.clone(),
                password,
            }))
        }
        (Some("disable"), []) => Ok(send(SharingRequest::EscrowDisable)),
        (Some("status"), []) => Ok(send(SharingRequest::EscrowStatus)),
        (Some("open"), _) => open(rest),
        _ => Err(Response::fail(USAGE)),
    };
    let r = r.unwrap_or_else(|e| e);
    if cli_mode::json_mode() {
        return r;
    }
    match &r {
        Response::Sharing(SharingResponse::SharingDone { message }) => cli_ui::ok(message),
        Response::Sharing(SharingResponse::EscrowState { .. }) => {
            cli_ui::info(&status_line(&r).unwrap_or_else(|| "Escrow: off".into()))
        }
        _ => {}
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_only_when_on() {
        let on = SharingResponse::EscrowState {
            enabled: true,
            admin: Some("it".into()),
            admin_fingerprint: Some("ab12".into()),
            since: Some("2026-10-07 10:00".into()),
        }
        .into();
        assert_eq!(
            status_line(&on).unwrap(),
            "Escrow: on, to it (ab12) since 2026-10-07 10:00 UTC"
        );
        let off = SharingResponse::EscrowState {
            enabled: false,
            admin: None,
            admin_fingerprint: None,
            since: None,
        }
        .into();
        assert!(status_line(&off).is_none());
    }

    #[test]
    fn usage_errors() {
        for bad in [
            &[][..],
            &["enable".to_string()][..],
            &["open".to_string()][..],
        ] {
            assert!(matches!(cmd_escrow(bad), Response::Err { .. }));
        }
    }
}
