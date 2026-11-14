//! Publish a new bundle from captured bytes, without touching original files.

use super::{
    capture,
    io::{self, Dir},
    paths, review,
    session::{Phase, Session},
};
use kepr_core::workspace::WorkspaceResponse;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Bundle<'a> {
    version: u32,
    session: &'a str,
    digest: &'a str,
    changes: &'a [kepr_core::workspace::Change],
    baseline: &'a super::session::Manifest,
    files: std::collections::BTreeMap<String, kepr_core::workspace::FileIdentity>,
    approval: &'a review::Approval,
}

pub(super) fn export(
    id: &str,
    supplied: &str,
    output: &Path,
) -> Result<WorkspaceResponse, &'static str> {
    let mut session = Session::load(id)?;
    session.reviewable()?;
    paths::absolute(output)?;
    if output.starts_with(&session.path) {
        return Err("workspace export must be outside the session");
    }
    let destination = output
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("workspace export requires a plain destination name")?;
    paths::component(destination)?;
    let parent_path = output
        .parent()
        .ok_or("workspace export parent unavailable")?;
    let parent = Dir::absolute(parent_path, false, true)?;
    if std::fs::symlink_metadata(output).is_ok() {
        return Err("workspace export destination must be new");
    }
    // Baseline and approval authority are checked again while holding the lock.
    session.baseline()?;
    let current = capture::tree(&session.workspace()?)?;
    let approval = review::approved(&session, &current, supplied)?;
    let changes = review::changes(&session, &current);
    let bundle = Bundle {
        version: 1,
        session: id,
        digest: supplied,
        changes: &changes,
        baseline: &session.manifest,
        files: capture::identities(&current),
        approval: &approval,
    };
    let manifest = serde_json::to_vec_pretty(&bundle)
        .map_err(|_| "workspace export manifest encoding failed")?;
    let temp = format!(".export-{}", io::random_id()?);
    let staging = parent.new_child(&temp)?;
    let stage = || -> Result<(), &'static str> {
        let files = staging.new_child("files")?;
        for change in &changes {
            if let Some(data) = current.get(&change.path) {
                files.write(&change.path, &data.bytes, data.identity.mode)?;
            }
        }
        staging.write("manifest.json", &manifest, 0o600)?;
        staging.sync()
    };
    if let Err(e) = stage() {
        let _ = std::fs::remove_dir_all(parent_path.join(&temp));
        return Err(e);
    }
    // Persist consumption before publication: crashes cannot replay authority.
    session.manifest.phase = Phase::Consumed;
    if let Err(e) = session
        .save()
        .and_then(|()| parent.publish(&temp, destination))
    {
        let _ = std::fs::remove_dir_all(parent_path.join(&temp));
        return Err(e);
    }
    Ok(WorkspaceResponse::WorkspaceExportedOk {
        session: id.into(),
        digest: supplied.into(),
        output: output
            .to_str()
            .ok_or("workspace export path must be UTF-8")?
            .into(),
    })
}
