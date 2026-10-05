// cli_recovery.rs — `kepr recovery-kit create|restore` (agent vault P6.3).
//
//   kepr recovery-kit create [--threshold K] [--shares N] [--out-dir DIR]
//       Needs the store passphrase. Prints N shares (or writes
//       DIR/kepr-share-<x>.txt, mode 0600); any K rebuild the master key.
//   kepr recovery-kit restore
//       On a machine with the old credential files but no usable master
//       key: paste K shares (one per line, blank line to finish), then a
//       new passphrase. The store comes back passphrase-protected.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};

use crate::cli_extra::flag as flag_value;
use crate::cli_input::read_masked;
use crate::{cli_mode, cli_ui, client};

const USAGE: &str =
    "usage: kepr recovery-kit create [--threshold K] [--shares N] [--out-dir DIR] | restore";

fn number(args: &[String], flag: &str, default: u8) -> Result<u8, Response> {
    match flag_value(args, flag) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| Response::fail(format!("{flag} needs a number"))),
    }
}

fn write_share(dir: &str, x: usize, share: &ZeroString) -> Result<String, String> {
    let path = std::path::Path::new(dir).join(format!("kepr-share-{x}.txt"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{}", share.as_str()).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

fn create(args: &[String]) -> Result<Response, Response> {
    let threshold = number(args, "--threshold", 3)?;
    let shares = number(args, "--shares", 5)?;
    let password = read_masked("  Store passphrase: ");
    let r = client::send_request(&Request::RecoveryKitCreate {
        password,
        threshold,
        shares,
    })
    .unwrap_or_else(Response::fail);
    let Response::RecoveryKitOk {
        fingerprint,
        shares,
    } = &r
    else {
        return Ok(r);
    };
    if cli_mode::json_mode() {
        return Ok(r);
    }
    match flag_value(args, "--out-dir") {
        Some(dir) => {
            for (i, s) in shares.iter().enumerate() {
                let path = write_share(dir, i + 1, s).map_err(Response::fail)?;
                println!("{path}");
            }
        }
        None => {
            for s in shares {
                println!("{}", s.as_str());
            }
        }
    }
    cli_ui::einfo(&format!(
        "kit {fingerprint}: any {threshold} of these {} shares rebuild your master key. \
         Keep them apart (different people / places) and never next to the machine.",
        shares.len()
    ));
    Ok(Response::Pong)
}

fn restore() -> Response {
    let mut shares = Vec::new();
    loop {
        let s = read_masked(&format!(
            "  Share {} (blank line when done): ",
            shares.len() + 1
        ));
        if s.as_str().trim().is_empty() {
            break;
        }
        shares.push(ZeroString::from_string(s.as_str().trim().to_string()));
    }
    if shares.len() < 2 {
        return Response::fail("paste at least the threshold number of shares");
    }
    let first = read_masked("  New store passphrase: ");
    let second = read_masked("  Confirm passphrase: ");
    if first.as_str() != second.as_str() {
        return Response::fail("passphrases do not match");
    }
    let r = client::send_request(&Request::RecoveryRestore {
        shares,
        new_password: first,
    })
    .unwrap_or_else(Response::fail);
    if let Response::RecoveryRestoreOk {
        fingerprint,
        credentials_opened,
    } = &r
    {
        if !cli_mode::json_mode() {
            cli_ui::ok(&format!(
                "restored kit {fingerprint}: the key opens {credentials_opened} credential file(s); \
                 the store is now protected by the new passphrase"
            ));
        }
    }
    r
}

pub fn cmd_recovery_kit(args: &[String]) -> Response {
    match args.first().map(String::as_str) {
        Some("create") => create(&args[1..]).unwrap_or_else(|e| e),
        Some("restore") => restore(),
        _ => Response::fail(USAGE),
    }
}
