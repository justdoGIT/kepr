//! Operator-owned authority is a sibling of the root exposed to the harness.

use super::{
    capture,
    io::{self, Dir},
    paths,
};
use kepr_core::workspace::{FileIdentity, WorkspaceResponse};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Prepared,
    Running,
    Finished,
    Consumed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub version: u32,
    pub session: String,
    pub uid: u32,
    pub created_at: u64,
    pub phase: Phase,
    pub exit_code: Option<i32>,
    pub baseline: BTreeMap<String, FileIdentity>,
}

pub(crate) struct Session {
    pub(super) path: PathBuf,
    pub(super) control: Dir,
    pub(super) root: Dir,
    pub(super) manifest: Manifest,
    _lock: File,
}

fn store() -> Result<PathBuf, &'static str> {
    let state = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or("workspace state home unavailable")?)
            .join(".local/state"),
    };
    paths::absolute(&state)?;
    let profile = kepr_core::profile::current().map_err(|_| "workspace profile is invalid")?;
    Ok(kepr_core::profile::nest_for(state.join("kepr"), &Ok(profile)).join("workspaces"))
}

pub(super) fn now() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "workspace clock unavailable")
}

impl Session {
    pub(crate) fn load(id: &str) -> Result<Self, &'static str> {
        paths::session_id(id)?;
        let path = store()?.join(id);
        let root = path.parent().ok_or("workspace session root unavailable")?;
        let parent = Dir::absolute(root, false, true)?;
        let dir = parent.child(id, false, true)?;
        let control = dir.child("control", false, true)?;
        let lock = control.new_lock()?;
        let (bytes, _) = control.read("session.json", MAX_METADATA_BYTES, true)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| "workspace session metadata invalid")?;
        // SAFETY: geteuid has no arguments or failure mode.
        let uid = unsafe { libc::geteuid() };
        if manifest.version != 1
            || manifest.session != id
            || manifest.uid != uid
            || manifest.baseline.len() > paths::MAX_SNAPSHOT_FILES
        {
            return Err("workspace session identity is invalid");
        }
        for (name, data) in &manifest.baseline {
            paths::relative(name)?;
            if data.size > paths::MAX_FILE_BYTES as u64
                || data.sha256.len() != 64
                || !data.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                || !matches!(data.mode, 0o600 | 0o700)
            {
                return Err("workspace baseline metadata invalid");
            }
        }
        let root = dir.child("root", false, true)?;
        Ok(Self {
            path,
            control,
            root,
            manifest,
            _lock: lock,
        })
    }

    pub(crate) fn root_path(&self) -> PathBuf {
        self.path.join("root")
    }

    pub(super) fn workspace(&self) -> Result<Dir, &'static str> {
        self.root.child("workspace", false, true)
    }

    pub(super) fn reviewable(&self) -> Result<(), &'static str> {
        match self.manifest.phase {
            Phase::Prepared | Phase::Finished => Ok(()),
            Phase::Running => Err("workspace session completion is unconfirmed"),
            Phase::Consumed => Err("workspace export approval already consumed"),
        }
    }

    pub(super) fn baseline(&self) -> Result<capture::Capture, &'static str> {
        let baseline = capture::tree(&self.control.child("baseline", false, true)?)?;
        if baseline.len() != self.manifest.baseline.len() {
            return Err("workspace baseline changed");
        }
        for (path, original) in &self.manifest.baseline {
            let Some(data) = baseline.get(path) else {
                return Err("workspace baseline changed");
            };
            if data.identity.sha256 != original.sha256
                || data.identity.size != original.size
                || data.identity.mode != 0o400
            {
                return Err("workspace baseline changed");
            }
        }
        Ok(baseline)
    }

    pub(super) fn save(&self) -> Result<(), &'static str> {
        let bytes =
            serde_json::to_vec(&self.manifest).map_err(|_| "workspace metadata encoding failed")?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err("workspace metadata byte limit reached");
        }
        self.control.atomic("session.json", &bytes)
    }
}

pub(super) fn prepare(source: &Path, files: &[&str]) -> Result<WorkspaceResponse, &'static str> {
    paths::source_root(source)?;
    let source = Dir::absolute(source, false, false)?;
    let (captured, skipped) = if files.is_empty() {
        let source = capture::source_tree(&source)?;
        (source.capture, source.skipped)
    } else {
        (capture::selected(&source, files)?, 0)
    };
    let store_path = store()?;
    let parent = Dir::absolute(
        store_path.parent().ok_or("workspace state unavailable")?,
        true,
        true,
    )?;
    let store = parent.child("workspaces", true, true)?;
    let id = io::random_id()?;
    let path = store_path.join(&id);
    let dir = store.new_child(&id)?;
    let create = || -> Result<Session, &'static str> {
        let control = dir.new_child("control")?;
        let lock = control.new_lock()?;
        let baseline = control.new_child("baseline")?;
        capture::copy(&baseline, &captured, true)?;
        let root = dir.new_child("root")?;
        for name in ["home", "tmp", "config"] {
            root.new_child(name)?;
        }
        capture::copy(&root.new_child("workspace")?, &captured, false)?;
        // SAFETY: geteuid has no arguments or failure mode.
        let uid = unsafe { libc::geteuid() };
        let session = Session {
            path: path.clone(),
            control,
            root,
            _lock: lock,
            manifest: Manifest {
                version: 1,
                session: id.clone(),
                uid,
                created_at: now()?,
                phase: Phase::Prepared,
                exit_code: None,
                baseline: capture::identities(&captured),
            },
        };
        session.save()?;
        Ok(session)
    };
    let session = match create() {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&path);
            return Err(e);
        }
    };
    Ok(WorkspaceResponse::WorkspacePreparedOk {
        session: id,
        workspace: session
            .root_path()
            .join("workspace")
            .to_str()
            .ok_or("workspace state path must be UTF-8")?
            .into(),
        files: captured.len(),
        skipped,
    })
}
