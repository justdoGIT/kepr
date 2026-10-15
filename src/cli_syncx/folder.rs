// cli_syncx/folder.rs — T6.02 shared folders.
//
//   kepr folder share FOLDER --to NAME|KEY [--to …] -o FILE [--sealed]
//   kepr folder import FILE [--overwrite] [--yes]   (also `kepr import FILE`)
//
// The daemon seals and opens the bundle (daemon_syncx/folder*.rs); this
// side moves ciphertext in chunks and prints the outcome. Put the file on
// any shared path (a git repo, a network drive): only the recipients'
// share keys open it, and only a pinned contact's bundle is imported.

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{
    BundleRow, SyncxRequest, SyncxResponse, BUNDLE_MAGIC, MAX_BUNDLE_BYTES,
};

use super::bundle::{fetch, print_row, send, upload};
use crate::cli_ui;

const USAGE: &str = "usage: kepr folder share FOLDER --to NAME|KEY [--to …] -o FILE [--sealed] \
     | folder import FILE [--overwrite] [--yes]";

/// True when `bytes` is a folder bundle (its manifest names its kind first).
pub fn is_folder(bytes: &[u8]) -> bool {
    bytes
        .strip_prefix(BUNDLE_MAGIC)
        .is_some_and(|rest| rest.starts_with(br#"{"kind":"folder""#))
}

/// Every value of a repeatable flag.
fn all<'a>(args: &'a [String], f: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|w| w[0] == f)
        .map(|w| w[1].as_str())
        .collect()
}

/// Arguments that are neither flags nor flag values.
fn positionals<'a>(args: &'a [String], value_flags: &[&str]) -> Vec<&'a str> {
    let (mut out, mut skip) = (Vec::new(), false);
    for a in args {
        if skip {
            skip = false;
        } else if value_flags.contains(&a.as_str()) {
            skip = true;
        } else if !a.starts_with('-') {
            out.push(a.as_str());
        }
    }
    out
}

fn share(args: &[String]) -> Result<Response, String> {
    super::check_flags(args, &["--to", "-o", "--output"], &["--sealed"])?;
    let [folder] = positionals(args, &["--to", "-o", "--output"])[..] else {
        return Err(USAGE.into());
    };
    let out = crate::cli_extra::flag(args, "-o")
        .or_else(|| crate::cli_extra::flag(args, "--output"))
        .ok_or(USAGE)?;
    let to = all(args, "--to");
    if to.is_empty() {
        return Err(format!("{USAGE} (name at least one recipient)"));
    }
    let sealed = args.iter().any(|a| a == "--sealed");
    let req = SyncxRequest::FolderExport {
        folder: folder.to_string(),
        recipients: to.iter().map(|s| s.to_string()).collect(),
        sealed,
    };
    let ready = send(req)?;
    let Response::Syncx(SyncxResponse::BundleReady {
        id,
        size,
        chunks,
        items,
        omitted,
        omitted_count,
    }) = &ready
    else {
        return Err("unexpected daemon response".into());
    };
    let bytes = fetch(id, *chunks)?;
    if bytes.len() as u64 != *size {
        return Err("the bundle came back short; share again".into());
    }
    super::atomic_file::write(&super::bundle::out_path(out), &bytes, 0o600)?;
    if !cli_ui::json_mode() {
        for o in omitted {
            cli_ui::warn(&format!("left out {} ({})", o.name, o.omitted));
        }
        let more = *omitted_count as usize - omitted.len();
        if more > 0 {
            cli_ui::warn(&format!("… and {more} more left out"));
        }
        let how = if sealed {
            " (stored sealed on import)"
        } else {
            ""
        };
        cli_ui::ok(&format!(
            "shared {items} credential(s) of {folder} with {} recipient(s) in {out}{how}",
            to.len()
        ));
        cli_ui::info("names and the folder path are visible in the file; values are not");
    }
    Ok(ready)
}

/// Import a folder bundle's bytes (`kepr folder import` / `kepr import`).
pub fn import_bytes(bytes: &[u8], overwrite: bool, yes: bool) -> Response {
    let r = (|| {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err("over 16 MiB, not a bundle kepr made".to_string());
        }
        let id = upload(bytes)?;
        let (mut rows, mut unchanged, mut start) = (Vec::<BundleRow>::new(), 0u32, 0u32);
        loop {
            let req = SyncxRequest::FolderImport {
                upload: id.clone(),
                overwrite,
                apply: yes,
                start,
            };
            let Response::Syncx(SyncxResponse::FolderImported {
                from,
                folder,
                sealed,
                rows: got,
                unchanged: u,
                next,
                ..
            }) = send(req)?
            else {
                return Err("unexpected daemon response".into());
            };
            if start == 0 && !cli_ui::json_mode() {
                let how = if sealed { ", stored sealed" } else { "" };
                cli_ui::info(&format!(
                    "folder {folder} from {from} (signature checked{how})"
                ));
            }
            if !cli_ui::json_mode() {
                got.iter().for_each(print_row);
            }
            rows.extend(got);
            unchanged += u;
            match next {
                Some(n) => start = n,
                None => return Ok((from, folder, sealed, rows, unchanged)),
            }
        }
    })();
    let (from, folder, sealed, rows, unchanged) = match r {
        Ok(x) => x,
        Err(e) => return Response::fail(e),
    };
    let count = |c: &str| rows.iter().filter(|r| r.change == c).count();
    let (create, update, failed) = (count("create"), count("update"), count("failed"));
    if !cli_ui::json_mode() {
        if yes {
            cli_ui::ok(&format!(
                "imported {create} new, {update} updated, {unchanged} unchanged"
            ));
        } else {
            cli_ui::info(&format!(
                "{} credential(s) to import, {unchanged} unchanged; re-run with --yes",
                create + update
            ));
        }
    }
    if failed > 0 {
        return Response::fail(format!("{failed} credential(s) failed to import"));
    }
    SyncxResponse::FolderImported {
        from,
        folder,
        sealed,
        applied: yes,
        rows,
        unchanged,
        next: None,
    }
    .into()
}

fn import(args: &[String]) -> Result<Response, String> {
    super::check_flags(args, &[], &["--overwrite", "--yes"])?;
    let [file] = positionals(args, &[])[..] else {
        return Err(USAGE.into());
    };
    let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    if !is_folder(&bytes) {
        return Err(format!(
            "{file}: not a folder bundle (kepr folder share makes one)"
        ));
    }
    let flag = |f: &str| args.iter().any(|a| a == f);
    Ok(import_bytes(&bytes, flag("--overwrite"), flag("--yes")))
}

pub fn cmd_folder(args: &[String]) -> Response {
    let rest = args.get(1..).unwrap_or_default();
    let r = match args.first().map(String::as_str) {
        Some("share") => share(rest),
        Some("import") => import(rest),
        _ => Err(USAGE.into()),
    };
    r.unwrap_or_else(Response::fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_are_checked_before_the_daemon_is_asked() {
        for bad in [
            &["share"][..],
            &["share", "team", "-o", "f"],
            &["share", "team", "--to", "bob"],
            &["share", "a", "b", "--to", "bob", "-o", "f"],
            &["share", "team", "--to", "bob", "-o", "f", "--seal"],
            &["import"],
            &["bogus"],
        ] {
            assert!(cmd_folder(&v(bad)).err_msg().is_some(), "{bad:?}");
        }
        assert_eq!(
            all(&v(&["--to", "a", "x", "--to", "b"]), "--to"),
            ["a", "b"]
        );
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("b");
        std::fs::write(&f, [BUNDLE_MAGIC, b"{\"kdf\":\"argon2id\"}\n"].concat()).unwrap();
        let e = cmd_folder(&v(&["import", f.to_str().unwrap()]));
        assert!(e.err_msg().unwrap().contains("not a folder bundle"));
        assert!(is_folder(
            &[BUNDLE_MAGIC, br#"{"kind":"folder","v":1}"#].concat()
        ));
    }
}
