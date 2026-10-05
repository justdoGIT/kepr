// cli_vault — `kepr vault init|migrate|verify|status` (T4.07): the P4
// vault image, one fixed-size file in which names, sizes, policies and
// values are all ciphertext. The daemon does the work; this parses argv
// and prints the reply.

use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_vault::{VaultRequest, VaultResponse};

use crate::{cli_mode, cli_ui, client};

pub const VERBS: &[&str] = &["vault"];

pub const HELP: &str = "  vault init [--size MIB]              create the vault image (fixed size, default 16 MiB)\n  vault migrate                        move per-file credentials into the image (KEPR_STORE=image)\n  vault verify                         check every used slot of the image and its Merkle root\n  vault status                         active store, image size and fill, files left to move\n";

/// Size of `kepr vault init` without `--size` (the daemon's default).
const DEFAULT_MIB: u32 = 16;

pub fn dispatch(_verb: &str, args: &[String]) -> Response {
    let req = match parse(args) {
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let r = client::send_request(&Request::Vault(req)).unwrap_or_else(Response::fail);
    if !cli_mode::json_mode() {
        if let Response::Vault(v) = &r {
            show(v);
        }
    }
    r
}

fn parse(args: &[String]) -> Result<VaultRequest, String> {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect();
    match args.as_slice() {
        ["init"] => Ok(VaultRequest::VaultInit {
            size_mib: DEFAULT_MIB,
        }),
        ["init", "--size", n] => n
            .parse()
            .map(|size_mib| VaultRequest::VaultInit { size_mib })
            .map_err(|_| "--size takes a whole number of MiB".to_string()),
        ["migrate"] => Ok(VaultRequest::VaultMigrate),
        ["verify"] => Ok(VaultRequest::VaultVerify),
        ["status"] => Ok(VaultRequest::VaultStatus),
        _ => Err("usage: kepr vault init [--size MIB] | migrate | verify | status".into()),
    }
}

fn show(v: &VaultResponse) {
    match v {
        VaultResponse::VaultInitOk { size_mib } => {
            cli_ui::ok(&format!("vault image created ({size_mib} MiB)"));
            cli_ui::info("the daemon uses it when started with KEPR_STORE=image");
        }
        VaultResponse::VaultMigrateOk { migrated, skipped } => {
            cli_ui::ok(&format!(
                "{migrated} credential file(s) moved into the image"
            ));
            if *skipped > 0 {
                cli_ui::warn(&format!(
                    "{skipped} left in per-file storage (already in the image, or unreadable)"
                ));
            }
        }
        VaultResponse::VaultVerifyOk { records, slots } => match (records, slots) {
            (Some(r), Some(s)) => cli_ui::ok(&format!(
                "vault image intact: {r} record(s), {s} slot(s) checked"
            )),
            _ => cli_ui::ok("vault image intact"),
        },
        VaultResponse::VaultStatusOk { .. } => show_status(v),
    }
}

fn show_status(v: &VaultResponse) {
    let VaultResponse::VaultStatusOk {
        backend,
        image,
        size_mib,
        used_percent,
        used_slots,
        epoch,
        legacy_files,
    } = v
    else {
        return;
    };
    let store = if backend == "image" {
        "vault image"
    } else {
        "per-file"
    };
    cli_ui::info(&format!("credential store: {store}"));
    match (image, size_mib) {
        (false, _) => cli_ui::info("vault image: none (kepr vault init)"),
        (true, None) => cli_ui::info("vault image: present (unlock the store to see its fill)"),
        (true, Some(mib)) => {
            let pct = used_percent.map_or("?".into(), |p| p.to_string());
            let exact = used_slots.map_or(String::new(), |n| format!(", {n} slot(s)"));
            let ep = epoch.map_or(String::new(), |e| format!(", {e} commit(s)"));
            cli_ui::info(&format!("vault image: {mib} MiB, {pct}% used{exact}{ep}"));
        }
    }
    if *legacy_files > 0 {
        cli_ui::info(&format!(
            "{legacy_files} credential file(s) in per-file storage{}",
            if backend == "image" {
                " (move them with `kepr vault migrate`)"
            } else {
                ""
            }
        ));
    }
    if *image {
        cli_ui::dim(
            "  deleting from the image destroys the record's key and pages in the\n  \
             current image; an older copy of the image plus the master key can\n  \
             still open values that were in it then",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_each_subcommand() {
        assert!(matches!(
            parse(&args(&["init"])),
            Ok(VaultRequest::VaultInit { size_mib: 16 })
        ));
        assert!(matches!(
            parse(&args(&["init", "--size", "64"])),
            Ok(VaultRequest::VaultInit { size_mib: 64 })
        ));
        assert!(matches!(
            parse(&args(&["--json", "migrate"])),
            Ok(VaultRequest::VaultMigrate)
        ));
        assert!(matches!(
            parse(&args(&["verify"])),
            Ok(VaultRequest::VaultVerify)
        ));
        assert!(matches!(
            parse(&args(&["status", "--json"])),
            Ok(VaultRequest::VaultStatus)
        ));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            &["init", "--size"][..],
            &["init", "--size", "big"],
            &["init", "--size", "-1"],
            &[],
            &["status", "extra"],
            &["shred"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn help_lines_are_indented_and_end_in_newlines() {
        assert!(HELP.ends_with('\n'));
        for line in HELP.lines() {
            assert!(line.starts_with("  vault "), "{line}");
        }
    }
}
