//! Reviews bind a fresh, expiring nonce to every captured file and mode.

use super::{
    capture::{self, Capture},
    io,
    session::{self, Manifest, Session, MAX_METADATA_BYTES},
};
use kepr_core::workspace::{Change, ChangeKind, ReviewReport, WorkspaceResponse};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write;
use zeroize::Zeroizing;

pub(super) const APPROVAL_TTL: u64 = 3600;
const MAX_PATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Approval {
    pub version: u32,
    pub session: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub digest: String,
}

pub(super) fn digest(
    manifest: &Manifest,
    captured: &Capture,
    approval: &Approval,
) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(&(
        "kepr-workspace-export-v1",
        manifest,
        capture::identities(captured),
        &approval.nonce,
        approval.issued_at,
        approval.expires_at,
    ))
    .map_err(|_| "workspace review identity encoding failed")?;
    Ok(capture::hash(&bytes))
}

pub(super) fn changes(session: &Session, captured: &Capture) -> Vec<Change> {
    let files = capture::identities(captured);
    let paths: BTreeSet<_> = session
        .manifest
        .baseline
        .keys()
        .chain(files.keys())
        .collect();
    paths
        .into_iter()
        .filter_map(|path| {
            let before = session.manifest.baseline.get(path);
            let after = files.get(path);
            if before == after {
                return None;
            }
            let action = match (before, after) {
                (None, Some(_)) => ChangeKind::Added,
                (Some(_), None) => ChangeKind::Deleted,
                _ => ChangeKind::Modified,
            };
            Some(Change {
                path: path.clone(),
                action,
                before: before.cloned(),
                after: after.cloned(),
            })
        })
        .collect()
}

fn lines(output: &mut String, bytes: &[u8], prefix: char) -> Result<(), &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "workspace review requires text")?;
    for line in text.lines() {
        writeln!(output, "{prefix}{line}").map_err(|_| "workspace patch encoding failed")?;
        if output.len() > MAX_PATCH_BYTES {
            return Err("workspace review patch byte limit reached");
        }
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        output.push_str("\\ No newline at end of file\n");
    }
    Ok(())
}

fn patch(
    changes: &[Change],
    baseline: &Capture,
    current: &Capture,
) -> Result<Zeroizing<String>, &'static str> {
    let mut output = Zeroizing::new(String::new());
    for change in changes {
        let before = baseline
            .get(&change.path)
            .map(|v| v.bytes.as_slice())
            .unwrap_or_default();
        let after = current
            .get(&change.path)
            .map(|v| v.bytes.as_slice())
            .unwrap_or_default();
        let before_lines = std::str::from_utf8(before)
            .map_err(|_| "workspace review requires text")?
            .lines()
            .count();
        let after_lines = std::str::from_utf8(after)
            .map_err(|_| "workspace review requires text")?
            .lines()
            .count();
        writeln!(output, "diff --git a/{0} b/{0}", change.path)
            .map_err(|_| "workspace patch encoding failed")?;
        if let Some(v) = &change.before {
            writeln!(output, "old mode {:06o}", 0o100000 | v.mode)
                .map_err(|_| "workspace patch encoding failed")?;
        }
        if let Some(v) = &change.after {
            writeln!(output, "new mode {:06o}", 0o100000 | v.mode)
                .map_err(|_| "workspace patch encoding failed")?;
        }
        let from = if change.before.is_some() {
            format!("a/{}", change.path)
        } else {
            "/dev/null".into()
        };
        let to = if change.after.is_some() {
            format!("b/{}", change.path)
        } else {
            "/dev/null".into()
        };
        writeln!(
            output,
            "--- {from}\n+++ {to}\n@@ -{},{} +{},{} @@",
            usize::from(before_lines > 0),
            before_lines,
            usize::from(after_lines > 0),
            after_lines
        )
        .map_err(|_| "workspace patch encoding failed")?;
        lines(&mut output, before, '-')?;
        lines(&mut output, after, '+')?;
    }
    if output.len() > MAX_PATCH_BYTES {
        return Err("workspace review patch byte limit reached");
    }
    Ok(output)
}

pub(super) fn review(id: &str) -> Result<WorkspaceResponse, &'static str> {
    let session = Session::load(id)?;
    session.reviewable()?;
    let baseline = session.baseline()?;
    let current = capture::tree(&session.workspace()?)?;
    let changes = changes(&session, &current);
    let patch = patch(&changes, &baseline, &current)?;
    let issued_at = session::now()?;
    let mut approval = Approval {
        version: 1,
        session: id.into(),
        nonce: io::random_id()?,
        issued_at,
        expires_at: issued_at
            .checked_add(APPROVAL_TTL)
            .ok_or("workspace approval clock invalid")?,
        digest: String::new(),
    };
    approval.digest = digest(&session.manifest, &current, &approval)?;
    let bytes = serde_json::to_vec(&approval).map_err(|_| "workspace approval encoding failed")?;
    session.control.atomic("review.patch", patch.as_bytes())?;
    session.control.atomic("approval.json", &bytes)?;
    Ok(WorkspaceResponse::WorkspaceReviewOk {
        report: Box::new(ReviewReport {
            session: id.into(),
            digest: approval.digest,
            changes,
            expires_at: approval.expires_at,
            patch_file: session
                .path
                .join("control/review.patch")
                .to_str()
                .ok_or("workspace state path must be UTF-8")?
                .into(),
        }),
    })
}

pub(super) fn approved(
    session: &Session,
    current: &Capture,
    supplied: &str,
) -> Result<Approval, &'static str> {
    let (bytes, _) = session
        .control
        .read("approval.json", MAX_METADATA_BYTES, true)?;
    let approval: Approval =
        serde_json::from_slice(&bytes).map_err(|_| "workspace approval metadata invalid")?;
    let now = session::now()?;
    if approval.version != 1
        || approval.session != session.manifest.session
        || approval.nonce.len() != 32
        || !approval.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || now < approval.issued_at
        || now > approval.expires_at
        || approval.expires_at.checked_sub(approval.issued_at) != Some(APPROVAL_TTL)
    {
        return Err("workspace approval expired or invalid; review again");
    }
    if supplied != approval.digest
        || digest(&session.manifest, current, &approval)? != approval.digest
    {
        return Err("workspace approval is stale; review the current changes again");
    }
    Ok(approval)
}
