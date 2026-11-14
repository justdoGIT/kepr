//! Snapshot contents are captured once; export uses these same bytes.

use super::{io::Dir, paths, screen};
use kepr_core::workspace::FileIdentity;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(super) struct Input {
    pub bytes: Zeroizing<Vec<u8>>,
    pub identity: FileIdentity,
}

fn make_input(bytes: Zeroizing<Vec<u8>>, mode: u32, normalize: bool) -> Input {
    Input {
        identity: FileIdentity {
            size: bytes.len() as u64,
            sha256: hash(&bytes),
            mode: if normalize {
                0o600 | (mode & 0o100)
            } else {
                mode
            },
        },
        bytes,
    }
}

pub(super) struct SourceCapture {
    pub capture: Capture,
    pub skipped: usize,
}

pub(super) type Capture = BTreeMap<String, Input>;

pub(super) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn input(dir: &Dir, path: &str, private: bool, normalize: bool) -> Result<Input, &'static str> {
    let (bytes, mode) = dir.read(path, paths::MAX_FILE_BYTES, private)?;
    screen::check(&bytes)?;
    Ok(make_input(bytes, mode, normalize))
}

fn source_input(dir: &Dir, path: &str, normalize: bool) -> Result<Option<Input>, &'static str> {
    let (bytes, mode) = match dir.read(path, paths::MAX_FILE_BYTES, false) {
        Ok(value) => value,
        Err("workspace file byte limit reached") => return Ok(None),
        Err(error) => return Err(error),
    };
    match screen::source(&bytes) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Ok(None),
    }
    Ok(Some(make_input(bytes, mode, normalize)))
}

pub(super) fn selected(dir: &Dir, files: &[&str]) -> Result<Capture, &'static str> {
    if files.is_empty() {
        return Err("workspace prepare requires explicit --file inputs");
    }
    if files.len() > paths::MAX_FILES {
        return Err("workspace file-count limit reached");
    }
    // Reject every excluded path before reading any input.
    for file in files {
        paths::relative(file)?;
    }
    let mut captured = Capture::new();
    let mut total = 0;
    for file in files {
        if captured.contains_key(*file) {
            return Err("workspace inputs must be unique");
        }
        let data = input(dir, file, false, true)?;
        total += data.bytes.len();
        if total > paths::MAX_TOTAL_BYTES {
            return Err("workspace total byte limit reached");
        }
        captured.insert((*file).into(), data);
    }
    Ok(captured)
}

struct Limits {
    bytes: usize,
    entries: usize,
    skipped: usize,
}

#[derive(Clone, Copy)]
enum TreeMode {
    Strict,
    Source,
}

pub(super) fn tree(dir: &Dir) -> Result<Capture, &'static str> {
    let mut output = Capture::new();
    visit(
        dir,
        "",
        &mut output,
        &mut Limits {
            bytes: 0,
            entries: 0,
            skipped: 0,
        },
        TreeMode::Strict,
    )?;
    Ok(output)
}

pub(super) fn source_tree(dir: &Dir) -> Result<SourceCapture, &'static str> {
    let mut output = Capture::new();
    let mut limits = Limits {
        bytes: 0,
        entries: 0,
        skipped: 0,
    };
    visit(dir, "", &mut output, &mut limits, TreeMode::Source)?;
    Ok(SourceCapture {
        capture: output,
        skipped: limits.skipped,
    })
}

fn visit(
    dir: &Dir,
    prefix: &str,
    output: &mut Capture,
    limits: &mut Limits,
    mode: TreeMode,
) -> Result<(), &'static str> {
    let entries = std::fs::read_dir(dir.descriptor_path())
        .map_err(|_| "workspace directory cannot be inspected")?;
    for entry in entries {
        limits.entries += 1;
        if limits.entries > paths::MAX_SNAPSHOT_ENTRIES {
            return Err("workspace directory-entry limit reached");
        }
        let entry = entry.map_err(|_| "workspace directory entry unavailable")?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) if matches!(mode, TreeMode::Source) => continue,
            Err(_) => return Err("workspace paths require plain names"),
        };
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if matches!(mode, TreeMode::Source) {
            if !paths::source_tree_path(&path)? {
                continue;
            }
        } else {
            paths::relative(&path)?;
        }
        let kind = entry
            .file_type()
            .map_err(|_| "workspace file type unavailable")?;
        let private = matches!(mode, TreeMode::Strict);
        let normalize = matches!(mode, TreeMode::Source);
        if kind.is_dir() {
            visit(
                &dir.child(&name, false, private)?,
                &path,
                output,
                limits,
                mode,
            )?;
        } else if kind.is_file() {
            if output.len() >= paths::MAX_SNAPSHOT_FILES {
                return Err("workspace file-count limit reached");
            }
            let data = if matches!(mode, TreeMode::Source) {
                source_input(dir, &name, normalize)?
            } else {
                Some(input(dir, &name, private, normalize)?)
            };
            let Some(data) = data else {
                limits.skipped += 1;
                continue;
            };
            limits.bytes += data.bytes.len();
            if limits.bytes > paths::MAX_SNAPSHOT_BYTES {
                return Err("workspace total byte limit reached");
            }
            output.insert(path, data);
        } else {
            return Err("workspace links and special files are excluded");
        }
    }
    Ok(())
}

pub(super) fn identities(captured: &Capture) -> BTreeMap<String, FileIdentity> {
    captured
        .iter()
        .map(|(name, data)| (name.clone(), data.identity.clone()))
        .collect()
}

pub(super) fn copy(dir: &Dir, captured: &Capture, baseline: bool) -> Result<(), &'static str> {
    for (path, data) in captured {
        dir.write(
            path,
            &data.bytes,
            if baseline { 0o400 } else { data.identity.mode },
        )?;
    }
    Ok(())
}
