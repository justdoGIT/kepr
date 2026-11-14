//! Local workspace reports. These operations never ask the daemon for secrets.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub path: String,
    pub action: ChangeKind,
    pub before: Option<FileIdentity>,
    pub after: Option<FileIdentity>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReviewReport {
    pub session: String,
    pub digest: String,
    pub changes: Vec<Change>,
    pub patch_file: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkspaceResponse {
    WorkspacePreparedOk {
        session: String,
        workspace: String,
        files: usize,
        skipped: usize,
    },
    WorkspaceReviewOk {
        #[serde(flatten)]
        report: Box<ReviewReport>,
    },
    WorkspaceExportedOk {
        session: String,
        digest: String,
        output: String,
    },
}
