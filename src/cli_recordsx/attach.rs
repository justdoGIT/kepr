// cli_recordsx/attach.rs — T5.03 `kepr attach`:
//
//   kepr attach add KEY FILE [--as NAME]       upload, chunk by chunk
//   kepr attach get KEY NAME [-o OUT] [--force]
//   kepr attach ls KEY
//   kepr attach rm KEY NAME
//
// `get` checks the whole file against the manifest's size and SHA-256
// before writing, then writes OUT (default: NAME in the current
// directory) with mode 0600 through a temporary file, refusing to replace
// an existing file without --force. `-o -` writes to stdout. The bytes
// stay in zeroized buffers; `download` also serves `kepr://KEY/file/NAME`.

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_records::{RecordsRequest, RecordsResponse, CHUNK_BYTES, MAX_FILE_BYTES};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cli_extra::{flag, positionals};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr attach add KEY FILE [--as NAME] | get KEY NAME [-o OUT] [--force] | ls KEY | rm KEY NAME";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn cmd_attach(args: &[String]) -> Response {
    let pos = positionals(args, &["-o", "--output", "--as"]);
    let out = flag(args, "-o").or_else(|| flag(args, "--output"));
    let force = args.iter().any(|a| a == "--force" || a == "-f");
    match pos
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["add", key, path] => add(key, path, flag(args, "--as")),
        ["get", key, file] => get(key, file, out.unwrap_or(file), force),
        ["ls", key] => ls(key),
        ["rm", key, file] => {
            let r = super::send(RecordsRequest::AttachRemove {
                name: key.to_uppercase(),
                file: file.to_string(),
            });
            if r.is_success() && !cli_mode::json_mode() {
                cli_ui::ok(&format!("removed {file} from {}", key.to_uppercase()));
            }
            r
        }
        _ => Response::fail(USAGE),
    }
}

fn add(key: &str, path: &str, label: Option<&str>) -> Response {
    let file = match label.or_else(|| Path::new(path).file_name()?.to_str()) {
        Some(f) => f.to_string(),
        None => return Response::fail("give the attachment a name with --as NAME"),
    };
    let bytes = match read_file(path) {
        Ok(b) => b,
        Err(e) => return Response::fail(e),
    };
    let r = upload(key, &file, &bytes);
    if r.is_success() && !cli_mode::json_mode() {
        cli_ui::ok(&format!(
            "{}: attached {file} ({} bytes)",
            key.to_uppercase(),
            bytes.len()
        ));
    }
    r
}

fn read_file(path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let len = f.metadata().map_err(|e| format!("{path}: {e}"))?.len();
    if len > MAX_FILE_BYTES {
        return Err(format!(
            "{path}: attachments are at most {} MiB",
            MAX_FILE_BYTES >> 20
        ));
    }
    // Exact capacity: a reallocation would leave unwiped copies behind.
    let mut buf = Zeroizing::new(Vec::with_capacity(len as usize + 1));
    f.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{path}: {e}"))?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("{path}: grew past the attachment limit"));
    }
    Ok(buf)
}

/// Send `bytes` as attachment `file` of `key`, one chunk per request.
pub fn upload(key: &str, file: &str, bytes: &[u8]) -> Response {
    let chunks: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[]]
    } else {
        bytes.chunks(CHUNK_BYTES).collect()
    };
    let mut upload = None;
    for (i, c) in chunks.iter().enumerate() {
        let r = super::send(RecordsRequest::AttachPut {
            name: key.to_uppercase(),
            file: file.to_string(),
            upload: upload.take(),
            index: i as u32,
            chunk: ZeroString::from_string(B64.encode(c)),
            last: i + 1 == chunks.len(),
        });
        match r {
            Response::Records(RecordsResponse::AttachPutOk { done: true, .. }) => return r,
            Response::Records(RecordsResponse::AttachPutOk { upload: u, .. }) => upload = Some(u),
            other => return other,
        }
    }
    Response::fail("the upload did not finish")
}

/// The whole attachment, checked against the manifest's size and digest.
pub fn download(key: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out: Option<Zeroizing<Vec<u8>>> = None;
    let mut index = 0;
    loop {
        let r = super::send(RecordsRequest::AttachGet {
            name: key.to_uppercase(),
            file: file.to_string(),
            index,
        });
        let (chunks, size, sha256, data) = match r {
            Response::Records(RecordsResponse::AttachChunkOk {
                chunks,
                size,
                sha256,
                data,
                ..
            }) => (chunks, size, sha256, data),
            Response::Err { error } => return Err(error),
            _ => return Err("unexpected daemon response".into()),
        };
        if size > MAX_FILE_BYTES {
            return Err("attachment larger than the limit".into());
        }
        let buf = out.get_or_insert_with(|| Zeroizing::new(Vec::with_capacity(size as usize + 3)));
        let bytes = Zeroizing::new(
            B64.decode(data.as_bytes())
                .map_err(|_| "attachment chunk is damaged".to_string())?,
        );
        if buf.len() + bytes.len() > buf.capacity() {
            return Err(format!("attachment {file}: size mismatch (damaged)"));
        }
        buf.extend_from_slice(&bytes);
        index += 1;
        if index >= chunks {
            let buf = out.unwrap_or_default();
            check_digest(file, &buf, size, &sha256)?;
            return Ok(buf);
        }
    }
}

/// The reassembled bytes must match the manifest.
pub fn check_digest(file: &str, bytes: &[u8], size: u64, sha256: &str) -> Result<(), String> {
    if bytes.len() as u64 != size {
        return Err(format!("attachment {file}: size mismatch (damaged)"));
    }
    if hex::encode(Sha256::digest(bytes)) != sha256 {
        return Err(format!(
            "attachment {file}: sha256 mismatch (damaged or tampered)"
        ));
    }
    Ok(())
}

fn get(key: &str, file: &str, out: &str, force: bool) -> Response {
    let bytes = match download(key, file) {
        Ok(b) => b,
        Err(e) => return Response::fail(e),
    };
    if let Err(e) = write_out(out, &bytes, force) {
        return Response::fail(e);
    }
    if out != "-" && !cli_mode::json_mode() {
        cli_ui::ok(&format!(
            "{file} → {out} ({} bytes, mode 0600)",
            bytes.len()
        ));
    }
    Response::Pong
}

/// Write `bytes` to `out` (0600, via a temporary file; `-` = stdout).
pub fn write_out(out: &str, bytes: &[u8], force: bool) -> Result<(), String> {
    if out == "-" {
        return std::io::stdout()
            .write_all(bytes)
            .map_err(|e| format!("write: {e}"));
    }
    let path = Path::new(out);
    if path.symlink_metadata().is_ok() && !force {
        return Err(format!("{out} exists; add --force to replace it"));
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let base = path.file_name().and_then(|f| f.to_str()).unwrap_or("out");
    let tmp = dir.join(format!(".{base}.kepr-{}", std::process::id()));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| {
            if force {
                std::fs::rename(&tmp, path)
            } else {
                std::fs::hard_link(&tmp, path)
            }
        });
    let _ = std::fs::remove_file(&tmp);
    written.map_err(|e| format!("{out}: {e}"))
}

fn ls(key: &str) -> Response {
    let r = super::send(RecordsRequest::AttachList {
        name: key.to_uppercase(),
    });
    if let Response::Records(RecordsResponse::AttachListOk { name, files }) = &r {
        if !cli_mode::json_mode() {
            if files.is_empty() {
                cli_ui::info(&format!("{name} has no attachments"));
            }
            for f in files {
                println!("{:<40} {:>10}  sha256:{}", f.file, f.size, &f.sha256[..12]);
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_check_reports_tampering() {
        let data = b"hello attachment";
        let sha = hex::encode(Sha256::digest(data));
        assert!(check_digest("a", data, 16, &sha).is_ok());
        let e = check_digest("a", b"hellO attachment", 16, &sha).unwrap_err();
        assert!(e.contains("sha256 mismatch"), "{e}");
        assert!(check_digest("a", data, 17, &sha)
            .unwrap_err()
            .contains("size"));
    }

    #[test]
    fn write_out_is_0600_and_refuses_to_clobber() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("o.bin");
        let o = out.to_str().unwrap();
        write_out(o, b"one", false).unwrap();
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(write_out(o, b"two", false).unwrap_err().contains("--force"));
        assert_eq!(std::fs::read(&out).unwrap(), b"one");
        write_out(o, b"two", true).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"two");
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn bad_usage_is_refused() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(!cmd_attach(&v(&["add", "K"])).is_success());
        assert!(!cmd_attach(&v(&["nope"])).is_success());
    }
}
