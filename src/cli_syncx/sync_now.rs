// cli_syncx/sync_now.rs — T6.10 multi-device sync, the CLI side.
//
//   kepr sync remote add URL | remote ls | remote rm URL
//   kepr sync now [--remote URL]
//
// Remotes are kept one per line in ~/.config/kepr/sync-remotes (0600).
// `sync now`, for each remote: merge every other device's bundle
// (`<id>.bundle`, opened and applied by the daemon: last writer wins per
// credential), then push this device's own bundle, built after the merge
// so it carries what it learned. Bundles are encrypted to the devices
// enrolled with `kepr device` (T6.03); one from a device that isn't
// enrolled here, or not encrypted to this one, is left alone with a
// warning. This side only moves ciphertext.

use std::path::PathBuf;

use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{BundleRow, SyncxRequest, SyncxResponse};

use super::bundle::{fetch, print_row, send, upload};
use super::transport;
use crate::cli_ui;

pub const REMOTE_USAGE: &str = "usage: kepr sync remote add URL | remote ls | remote rm URL \
     (URL: dir:PATH, git:URL or s3:BUCKET[/PREFIX])";

/// Human output only (JSON mode prints the response alone).
fn note(f: fn(&str), m: &str) {
    if !cli_ui::json_mode() {
        f(m)
    }
}

fn remotes_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        })
        .join("kepr/sync-remotes")
}

fn load_remotes() -> Result<Vec<String>, String> {
    let path = remotes_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save_remotes(list: &[String]) -> Result<(), String> {
    let path = remotes_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let text: String = list.iter().map(|r| format!("{r}\n")).collect();
    super::atomic_file::write(&path, text.as_bytes(), 0o600)
}

pub fn cmd_remote(args: &[String]) -> Response {
    let r = (|| {
        let mut list = load_remotes()?;
        let url = args.get(1).map(String::as_str);
        match (args.first().map(String::as_str), url, args.len()) {
            (Some("ls"), None, 1) => {
                if !cli_ui::json_mode() {
                    if list.is_empty() {
                        cli_ui::info("No sync remotes (kepr sync remote add URL).");
                    }
                    list.iter().for_each(|r| println!("{r}"));
                }
            }
            (Some("add"), Some(url), 2) => {
                transport::check(url)?;
                if list.iter().any(|r| r == url) {
                    return Err(format!("{url} is already a remote"));
                }
                list.push(url.to_string());
                save_remotes(&list)?;
                note(cli_ui::ok, &format!("added sync remote {url}"));
            }
            (Some("rm"), Some(url), 2) => {
                let before = list.len();
                list.retain(|r| r != url);
                if list.len() == before {
                    return Err(format!("{url} is not a remote (kepr sync remote ls)"));
                }
                save_remotes(&list)?;
                note(cli_ui::ok, &format!("removed sync remote {url}"));
            }
            _ => return Err(REMOTE_USAGE.to_string()),
        }
        Ok(SyncxResponse::SyncRemotes { remotes: list }.into())
    })();
    r.unwrap_or_else(Response::fail)
}

/// Upload `bytes` and merge them in rounds.
fn merge(bytes: &[u8]) -> Result<(Vec<BundleRow>, u32), String> {
    let upload = upload(bytes)?;
    let (mut rows, mut unchanged, mut start) = (Vec::new(), 0u32, 0u32);
    loop {
        let req = SyncxRequest::SyncMerge {
            upload: upload.clone(),
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
        rows.extend(got);
        unchanged += u;
        match next {
            Some(n) => start = n,
            None => return Ok((rows, unchanged)),
        }
    }
}

/// This device's bundle, built now.
fn build() -> Result<Vec<u8>, String> {
    let Response::Syncx(SyncxResponse::BundleReady {
        id, size, chunks, ..
    }) = send(SyncxRequest::SyncBuild)?
    else {
        return Err("unexpected daemon response".into());
    };
    let bytes = fetch(&id, chunks)?;
    if bytes.len() as u64 != size {
        return Err("the bundle came back short; try again".into());
    }
    Ok(bytes)
}

#[derive(Default)]
struct Outcome {
    rows: Vec<BundleRow>,
    unchanged: u32,
    ignored: Vec<String>,
}

/// Merge every other device's bundle on `url`, then push ours.
fn sync_one(url: &str, device: &str, out: &mut Outcome) -> Result<(), String> {
    let mut remote = transport::open(url)?;
    let own = format!("{device}.bundle");
    for name in remote.list()? {
        if name == own {
            continue;
        }
        match remote.get(&name).and_then(|b| merge(&b)) {
            Ok((rows, unchanged)) => {
                if !cli_ui::json_mode() {
                    rows.iter().for_each(print_row);
                }
                out.rows.extend(rows);
                out.unchanged += unchanged;
            }
            Err(e) => {
                note(cli_ui::warn, &format!("ignored {name} on {url}: {e}"));
                out.ignored.push(format!("{url} {name}: {e}"));
            }
        }
    }
    remote.put(&own, &build()?)
}

pub fn cmd_now(args: &[String]) -> Response {
    let remotes = match crate::cli_extra::flag(args, "--remote") {
        Some(url) => transport::check(url).map(|()| vec![url.to_string()]),
        None if args.is_empty() => load_remotes(),
        None => Err("usage: kepr sync now [--remote URL]".into()),
    };
    let remotes = match remotes {
        Ok(r) if r.is_empty() => {
            return Response::fail("no sync remotes: kepr sync remote add URL")
        }
        Ok(r) => r,
        Err(e) => return Response::fail(e),
    };
    let device = match send(SyncxRequest::SyncDevice) {
        Ok(Response::Syncx(SyncxResponse::SyncDeviceOk { devices: 0, .. })) => {
            return Response::fail(
                "no devices enrolled: pair them first (kepr device add / enroll)",
            )
        }
        Ok(Response::Syncx(SyncxResponse::SyncDeviceOk { device, .. })) => device,
        Ok(_) => return Response::fail("unexpected daemon response"),
        Err(e) => return Response::fail(e),
    };
    let mut out = Outcome::default();
    let mut failed = Vec::new();
    for url in &remotes {
        if let Err(e) = sync_one(url, &device, &mut out) {
            note(cli_ui::warn, &format!("{url}: {e}"));
            failed.push(url.as_str());
        }
    }
    let bad = out.rows.iter().filter(|r| r.change == "failed").count();
    let changed = out.rows.len() - bad;
    if !cli_ui::json_mode() && failed.len() < remotes.len() {
        cli_ui::ok(&format!(
            "synced as device {device}: {changed} change(s), {} unchanged",
            out.unchanged
        ));
    }
    if !failed.is_empty() {
        return Response::fail(format!("sync failed for {}", failed.join(", ")));
    }
    if bad > 0 {
        return Response::fail(format!("{bad} credential(s) failed to merge"));
    }
    SyncxResponse::SyncDone {
        device,
        rows: out.rows,
        unchanged: out.unchanged,
        ignored: out.ignored,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bad_remote_commands_are_refused_before_anything_is_written() {
        for bad in [
            &["add"][..],
            &["add", "ftp:x"],
            &["rm"],
            &["ls", "x"],
            &["bogus"],
            &[],
        ] {
            assert!(cmd_remote(&v(bad)).err_msg().is_some(), "{bad:?}");
        }
        assert!(cmd_now(&v(&["--remote", "nope:x"]))
            .err_msg()
            .unwrap()
            .contains("unsupported remote"));
        assert!(cmd_now(&v(&["extra"])).err_msg().unwrap().contains("usage"));
    }
}
