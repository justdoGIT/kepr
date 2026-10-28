// cli_agent_shim.rs — `kepr agent shim HARNESS [--dir DIR] [--remove]` (T12.17).
// Writes a launcher named after the harness's own command (`claude`,
// `codex`, `omp`, …) into DIR, so with DIR first on PATH, typing the
// command starts it through `kepr agent run`. DIR defaults to
// ${XDG_DATA_HOME:-~/.local/share}/kepr/shims, never ~/.local/bin, where
// some harnesses (Claude Code, for one) install their real binary. The
// script holds paths only; inside a session (KEPR_GATE_URL set) it runs
// the real binary directly, so sessions never nest. The agent sandbox
// hides the shim dir along with the rest of ~/.local/share/kepr.
// Only files carrying MARKER are ever replaced or removed.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use kepr_core::protocol::Response;

use crate::cli_envdump::shell_escape;
use crate::{cli_agent_adapters, cli_ui};

const USAGE: &str = "usage: kepr agent shim HARNESS [--dir DIR] [--remove]";
const MARKER: &str = "# kepr agent shim: remove this file to undo";

pub fn script(kepr: &Path, harness: &str, real: &Path) -> String {
    let k = shell_escape(&kepr.to_string_lossy());
    let r = shell_escape(&real.to_string_lossy());
    format!(
        "#!/bin/sh\n{MARKER}\n[ -n \"$KEPR_GATE_URL\" ] && exec {r} \"$@\"\n\
         exec {k} agent run {harness} -- {r} \"$@\"\n"
    )
}

/// A file whose first 4 KiB hold the marker line.
fn is_shim(path: &Path) -> bool {
    let mut head = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| f.take(4096).read_to_end(&mut head));
    read.is_ok() && String::from_utf8_lossy(&head).lines().any(|l| l == MARKER)
}

fn executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The first executable `program` on `path_var` outside `skip` (the shim
/// dir) that isn't a kepr shim; relative PATH entries are ignored. The
/// checks use canonical paths; the PATH spelling is returned, so a
/// harness that updates itself by moving a symlink keeps working.
pub fn find_real(program: &str, path_var: &OsStr, skip: &Path) -> Option<PathBuf> {
    let skip = std::fs::canonicalize(skip).unwrap_or_else(|_| skip.to_path_buf());
    std::env::split_paths(path_var)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(program))
        .find(|cand| {
            std::fs::canonicalize(cand)
                .is_ok_and(|c| !c.starts_with(&skip) && executable(&c) && !is_shim(&c))
        })
}

pub fn default_dir(home: &Path, xdg_data_home: Option<String>) -> PathBuf {
    xdg_data_home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"))
        .join("kepr/shims")
}

fn not_a_shim(path: &Path) -> String {
    format!("{} is not a kepr shim; left alone", path.display())
}

/// Write `body` to `path` (0755): a new file, or over a kepr shim only.
/// Returns whether anything changed.
pub fn write_shim(path: &Path, body: &str) -> Result<bool, String> {
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && is_shim(path) => {
            if std::fs::read_to_string(path).ok().as_deref() == Some(body) {
                return Ok(false);
            }
            std::fs::write(path, body).map_err(io)?;
        }
        Ok(_) => return Err(not_a_shim(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .open(path)
                .and_then(|mut f| f.write_all(body.as_bytes()))
                .map_err(io)?;
        }
        Err(e) => return Err(io(e)),
    }
    // The umask may have narrowed the mode.
    let mode = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(path, mode).map_err(io)?;
    Ok(true)
}

pub fn remove_shim(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && is_shim(path) => {
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))
        }
        Ok(_) => Err(not_a_shim(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("no shim at {}", path.display()))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// (harness, --dir, --remove)
fn parse(raw: &[String]) -> Result<(String, Option<PathBuf>, bool), String> {
    let (mut harness, mut dir, mut remove) = (None, None, false);
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => {
                let d = it
                    .next()
                    .ok_or(format!("--dir needs a directory\n{USAGE}"))?;
                dir = Some(std::path::absolute(d).map_err(|e| format!("{d}: {e}"))?);
            }
            "--remove" => remove = true,
            h if !h.starts_with('-') && harness.is_none() => harness = Some(h.to_string()),
            other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
        }
    }
    Ok((harness.ok_or(USAGE)?, dir, remove))
}

fn run(raw: &[String]) -> Result<(), String> {
    let (harness, dir, remove) = parse(raw)?;
    let adapter = cli_agent_adapters::lookup(&harness)?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let dir = match (dir, home) {
        (Some(d), _) => d,
        (None, Some(h)) => default_dir(&h, std::env::var("XDG_DATA_HOME").ok()),
        (None, None) => return Err("HOME is not set; pass --dir".into()),
    };
    let shim = dir.join(adapter.program);
    if remove {
        remove_shim(&shim)?;
        cli_ui::ok(&format!("removed {}", shim.display()));
        return Ok(());
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let real = find_real(adapter.program, &path_var, &dir).ok_or_else(|| {
        format!(
            "{} not found on PATH (outside {})",
            adapter.program,
            dir.display()
        )
    })?;
    let kepr = std::env::current_exe().map_err(|e| format!("can't locate kepr: {e}"))?;
    if let Some(p) = [&kepr, &real, &dir]
        .into_iter()
        .find(|p| p.to_str().is_none())
    {
        return Err(format!(
            "{} is not valid UTF-8; no shim written",
            p.display()
        ));
    }
    let changed = write_shim(&shim, &script(&kepr, &harness, &real))?;
    let what = if changed { "written" } else { "up to date" };
    cli_ui::ok(&format!(
        "shim {what}: {} → kepr agent run {harness} -- {}",
        shim.display(),
        real.display()
    ));
    if std::env::split_paths(&path_var).next().as_deref() != Some(dir.as_path()) {
        let d = dir.to_string_lossy();
        let line = if d.contains(['"', '$', '`', '\\']) {
            format!("export PATH={}:\"$PATH\"", shell_escape(&d))
        } else {
            format!("export PATH=\"{d}:$PATH\"")
        };
        cli_ui::info("put the shim dir first on PATH (add this to your shell profile):");
        println!("{line}");
    }
    Ok(())
}

pub fn cmd_shim(raw: &[String]) -> Response {
    match run(raw) {
        Ok(()) => Response::Pong,
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kepr-shim-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(path: &Path, body: &str, mode: u32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn script_is_exact() {
        let s = script(
            Path::new("/usr/bin/kepr"),
            "claude",
            Path::new("/opt/claude/bin/claude"),
        );
        assert_eq!(
            s,
            "#!/bin/sh\n\
             # kepr agent shim: remove this file to undo\n\
             [ -n \"$KEPR_GATE_URL\" ] && exec '/opt/claude/bin/claude' \"$@\"\n\
             exec '/usr/bin/kepr' agent run claude -- '/opt/claude/bin/claude' \"$@\"\n"
        );
    }

    #[test]
    fn paths_with_a_quote_are_escaped() {
        let s = script(Path::new("/o'k/kepr"), "codex", Path::new("/it's/codex"));
        assert!(s.contains("exec '/it'\\''s/codex' \"$@\""), "{s}");
        assert!(s.contains("exec '/o'\\''k/kepr' agent run codex -- '/it'\\''s/codex'"));
    }

    #[test]
    fn find_real_skips_the_shim_dir_shims_and_non_executables() {
        let d = tmp("find");
        let shims = d.join("shims");
        put(
            &shims.join("claude"),
            &script(Path::new("/k"), "claude", Path::new("/r")),
            0o755,
        );
        put(&d.join("a/claude"), "not executable", 0o644);
        put(
            &d.join("old/claude"),
            &script(Path::new("/k"), "claude", Path::new("/r")),
            0o755,
        );
        std::fs::create_dir_all(d.join("link")).unwrap();
        std::os::unix::fs::symlink(shims.join("claude"), d.join("link/claude")).unwrap();
        let only_shims =
            std::env::join_paths([shims.clone(), d.join("a"), d.join("old"), d.join("link")])
                .unwrap();
        assert_eq!(find_real("claude", &only_shims, &shims), None);
        put(&d.join("b/claude"), "#!/bin/sh\n", 0o755);
        let path = std::env::join_paths([
            shims.clone(),
            PathBuf::from("rel"),
            d.join("a"),
            d.join("old"),
            d.join("link"),
            d.join("b"),
        ])
        .unwrap();
        assert_eq!(find_real("claude", &path, &shims), Some(d.join("b/claude")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn write_and_remove_only_touch_kepr_shims() {
        let d = tmp("write");
        let shim = d.join("claude");
        let body = script(Path::new("/k"), "claude", Path::new("/r"));
        assert!(write_shim(&shim, &body).unwrap());
        let mode = std::fs::metadata(&shim).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert!(!write_shim(&shim, &body).unwrap(), "unchanged");
        let newer = script(Path::new("/k2"), "claude", Path::new("/r"));
        assert!(
            write_shim(&shim, &newer).unwrap(),
            "a kepr shim is replaced"
        );
        assert_eq!(std::fs::read_to_string(&shim).unwrap(), newer);
        remove_shim(&shim).unwrap();
        assert!(!shim.exists());
        assert!(remove_shim(&shim).unwrap_err().contains("no shim"));
        let real = d.join("codex");
        put(&real, "#!/bin/sh\necho real\n", 0o755);
        assert!(write_shim(&real, &body)
            .unwrap_err()
            .contains("not a kepr shim"));
        assert!(remove_shim(&real).unwrap_err().contains("not a kepr shim"));
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "#!/bin/sh\necho real\n"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn default_dir_is_never_local_bin() {
        let home = Path::new("/h");
        assert_eq!(
            default_dir(home, None),
            PathBuf::from("/h/.local/share/kepr/shims")
        );
        assert_eq!(
            default_dir(home, Some("/x".into())),
            PathBuf::from("/x/kepr/shims")
        );
        assert_eq!(
            default_dir(home, Some("relative".into())),
            PathBuf::from("/h/.local/share/kepr/shims")
        );
    }

    #[test]
    fn unknown_harness_lists_the_adapters() {
        let r = cmd_shim(&["nope".to_string()]);
        match r {
            Response::Err { error } => {
                assert!(
                    error.contains("claude") && error.contains("aider"),
                    "{error}"
                )
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(cmd_shim(&[]), Response::Err { .. }));
        let bad = ["claude", "--dir"].map(String::from);
        assert!(matches!(cmd_shim(&bad), Response::Err { .. }));
    }
}
