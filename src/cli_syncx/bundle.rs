// cli_syncx/bundle.rs — T6.09 encrypted bundles.
//
//   kepr export --encrypted -o FILE
//   kepr import FILE [--prefix P] [--overwrite] [--yes]   (a bundle is
//                                         detected by its first line)
//
// The daemon builds and opens bundles (daemon_syncx/); this side asks for
// the passphrase, moves the bytes in chunks and prints the outcome. It
// never sees a value: the bundle is ciphertext on both legs.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::{Request, Response};
use kepr_core::protocol_syncx::{
    BundleRow, SyncxRequest, SyncxResponse, BUNDLE_CHUNK_BYTES, BUNDLE_MAGIC, MAX_BUNDLE_BYTES,
};

use crate::cli_import::Opts;
use crate::cli_input::read_masked;
use crate::{cli_ui, client};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const EXPORT_USAGE: &str = "usage: kepr export --encrypted -o FILE";

/// One request, retried while the daemon's rate limit refuses it (a big
/// bundle takes many chunks).
pub(super) fn send(req: SyncxRequest) -> Result<Response, String> {
    let req = Request::from(req);
    for _ in 0..50 {
        match client::send_request(&req)? {
            Response::Err { error } if error.contains("rate limited") => {
                std::thread::sleep(Duration::from_millis(250))
            }
            Response::Err { error } => return Err(error),
            other => return Ok(other),
        }
    }
    Err("the daemon is busy; try again".into())
}

/// True when `file` starts like a bundle.
pub fn is_bundle(file: &str) -> bool {
    let mut head = vec![0u8; BUNDLE_MAGIC.len()];
    std::fs::File::open(file)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| head == BUNDLE_MAGIC)
}

/// A bare file name has an empty parent: the current directory.
fn out_path(file: &str) -> PathBuf {
    let p = PathBuf::from(file);
    match p.parent() {
        Some(d) if d.as_os_str().is_empty() => PathBuf::from(".").join(p),
        _ => p,
    }
}

pub(super) fn fetch(id: &str, chunks: u32) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for index in 0..chunks {
        let req = SyncxRequest::ExportChunk {
            id: id.to_string(),
            index,
        };
        match send(req)? {
            Response::Syncx(SyncxResponse::BundleChunk { data, .. }) => bytes.extend(
                B64.decode(data)
                    .map_err(|_| "damaged chunk from the daemon")?,
            ),
            _ => return Err("unexpected daemon response".into()),
        }
    }
    Ok(bytes)
}

pub fn cmd_export(args: &[String]) -> Response {
    let r = (|| {
        super::check_flags(args, &["-o", "--output"], &["--encrypted"])?;
        let out = crate::cli_extra::flag(args, "-o")
            .or_else(|| crate::cli_extra::flag(args, "--output"))
            .ok_or(EXPORT_USAGE)?;
        if !args.iter().any(|a| a == "--encrypted") {
            return Err(format!("{EXPORT_USAGE} (bundles are always encrypted)"));
        }
        let passphrase = read_masked("  Bundle passphrase: ");
        if read_masked("  Again: ").as_str() != passphrase.as_str() {
            return Err("the passphrases differ".into());
        }
        let ready = send(SyncxRequest::ExportBundle { passphrase })?;
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
            return Err("the bundle came back short; export again".into());
        }
        super::atomic_file::write(&out_path(out), &bytes, 0o600)?;
        if !cli_ui::json_mode() {
            for o in omitted {
                cli_ui::warn(&format!("left out {} ({})", o.name, o.omitted));
            }
            let more = *omitted_count as usize - omitted.len();
            if more > 0 {
                cli_ui::warn(&format!("… and {more} more left out"));
            }
            cli_ui::ok(&format!("exported {items} credential(s) to {out}"));
        }
        Ok(ready)
    })();
    r.unwrap_or_else(Response::fail)
}

pub(super) fn upload(bytes: &[u8]) -> Result<String, String> {
    let parts: Vec<&[u8]> = match bytes.len() {
        0 => vec![&[]],
        _ => bytes.chunks(BUNDLE_CHUNK_BYTES).collect(),
    };
    let mut upload = None;
    for (i, c) in parts.iter().enumerate() {
        let req = SyncxRequest::ImportPut {
            upload: upload.take(),
            index: i as u32,
            chunk: B64.encode(c),
            last: i + 1 == parts.len(),
        };
        match send(req)? {
            Response::Syncx(SyncxResponse::ImportPutOk { upload: u, .. }) => upload = Some(u),
            _ => return Err("unexpected daemon response".into()),
        }
    }
    upload.ok_or_else(|| "nothing was uploaded".into())
}

pub(super) fn print_row(r: &BundleRow) {
    let why = r.reason.as_deref().map(|w| format!("  ({w})"));
    let line = format!("{:<9}  {}{}", r.change, r.name, why.unwrap_or_default());
    match r.change.as_str() {
        "create" | "update" | "delete" => println!("{line}"),
        _ => cli_ui::warn(&line),
    }
}

/// `kepr import FILE` for a bundle file.
pub fn cmd_import(file: &str, o: &Opts) -> Response {
    let r = (|| {
        if o.seal {
            return Err("--seal does not apply to a bundle".to_string());
        }
        let bytes = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(format!("{file}: over 16 MiB, not a bundle kepr made"));
        }
        let passphrase = read_masked("  Bundle passphrase: ");
        let id = upload(&bytes)?;
        let prefix = o.prefix.map(crate::cli_import_parse::kepr_name);
        let (mut rows, mut unchanged, mut start) = (Vec::new(), 0u32, 0u32);
        loop {
            let req = SyncxRequest::ImportBundle {
                upload: id.clone(),
                passphrase: ZeroString::from(passphrase.as_str()),
                prefix: prefix.clone(),
                overwrite: o.overwrite,
                apply: o.yes,
                start,
            };
            let Response::Syncx(SyncxResponse::BundleImported {
                rows: got,
                unchanged: u,
                next,
                ..
            }) = send(req)?
            else {
                return Err("unexpected daemon response".into());
            };
            if !cli_ui::json_mode() {
                got.iter().for_each(print_row);
            }
            rows.extend(got);
            unchanged += u;
            match next {
                Some(n) => start = n,
                None => break,
            }
        }
        Ok((rows, unchanged))
    })();
    let (rows, unchanged) = match r {
        Ok(x) => x,
        Err(e) => return Response::fail(e),
    };
    let count = |c: &str| rows.iter().filter(|r| r.change == c).count();
    let (create, update, failed) = (count("create"), count("update"), count("failed"));
    if !cli_ui::json_mode() {
        if o.yes {
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
    SyncxResponse::BundleImported {
        applied: o.yes,
        rows,
        unchanged,
        next: None,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_are_detected_by_their_first_line() {
        let d = tempfile::tempdir().unwrap();
        let (b, csv) = (d.path().join("b"), d.path().join("c.csv"));
        std::fs::write(&b, [BUNDLE_MAGIC, b"{}\n\x00\xff"].concat()).unwrap();
        std::fs::write(&csv, "name,value\nA,1\n").unwrap();
        assert!(is_bundle(b.to_str().unwrap()));
        assert!(!is_bundle(csv.to_str().unwrap()));
        assert!(!is_bundle(d.path().join("missing").to_str().unwrap()));
    }

    #[test]
    fn export_needs_encrypted_and_an_output() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            cmd_export(&v(&["--encrypted"])).err_msg(),
            Some(EXPORT_USAGE)
        );
        assert!(cmd_export(&v(&["-o", "f"]))
            .err_msg()
            .unwrap()
            .contains("always encrypted"));
        assert_eq!(
            cmd_export(&v(&["-o", "f", "--encrypt"])).err_msg(),
            Some("unknown option --encrypt")
        );
        assert_eq!(out_path("b.bundle"), PathBuf::from("./b.bundle"));
        assert_eq!(out_path("/tmp/b"), PathBuf::from("/tmp/b"));
    }
}
