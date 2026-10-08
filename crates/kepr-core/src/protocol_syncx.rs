// protocol_syncx.rs — wire types of the `sync` ticket batch: sync maps
// (T11.17), encrypted bundles (T6.09), multi-device sync (T6.10), shared
// folders (T6.02) and M-of-N approvals (T7.12).
// batch: sync
//
// Carried inside `Request::Syncx` / `Response::Syncx` (untagged, tried
// after every tagged variant), so the `cmd` and `kind` names here must not
// repeat one used elsewhere.

use serde::{Deserialize, Serialize};

use crate::generate::ZeroString;

/// T6.09: the first bytes of an encrypted bundle file.
pub const BUNDLE_MAGIC: &[u8] = b"kepr_bundle1\n";
/// T6.09: bundle bytes per transfer chunk (its base64 fits one frame).
pub const BUNDLE_CHUNK_BYTES: usize = 45 * 1024;
/// T6.09: the largest bundle; the daemon builds and opens it in memory.
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

/// Chunks of a `size`-byte transfer (an empty one still has chunk 0).
pub fn bundle_chunks(size: usize) -> u32 {
    u32::try_from(size.div_ceil(BUNDLE_CHUNK_BYTES).max(1)).unwrap_or(u32::MAX)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SyncxRequest {
    /// T6.09: encrypt every exportable credential under `passphrase`.
    /// Replies `BundleReady`; the bytes then come in `ExportChunk`s.
    ExportBundle { passphrase: ZeroString },
    /// T6.09: chunk `index` of export `id` (fetching the last one ends it).
    ExportChunk { id: String, index: u32 },
    /// T6.09: chunk `index` (base64) of a bundle to import. `upload` is
    /// absent on chunk 0 and the id from `ImportPutOk` after it.
    ImportPut {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upload: Option<String>,
        index: u32,
        chunk: String,
        #[serde(default)]
        last: bool,
    },
    /// T6.09: open upload `upload` with `passphrase` and import its
    /// entries from `start` on, as many as fit one reply (`apply: false`:
    /// only report what would change). Names get `PREFIX_` in front when
    /// `prefix` is set. The upload is dropped after the last entry.
    ImportBundle {
        upload: String,
        passphrase: ZeroString,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        #[serde(default)]
        overwrite: bool,
        #[serde(default)]
        apply: bool,
        #[serde(default)]
        start: u32,
    },
    /// T6.10: this device's id (its bundle's name on a sync remote) and
    /// how many devices are enrolled.
    SyncDevice,
    /// T6.10: record local changes and build this device's sync bundle
    /// for every enrolled device; replies `BundleReady`, fetched with
    /// `ExportChunk`.
    SyncBuild,
    /// T6.10: merge another device's bundle, uploaded with `ImportPut`,
    /// from entry `start` on (last writer wins); replies `BundleImported`.
    SyncMerge {
        upload: String,
        #[serde(default)]
        start: u32,
    },
    /// T6.02: seal every credential of `folder` (and below) that `get`
    /// could read now for `recipients` (pinned contact names or share
    /// keys); `sealed`: importers store them sealed. Replies
    /// `BundleReady`, fetched with `ExportChunk`.
    FolderExport {
        folder: String,
        recipients: Vec<String>,
        #[serde(default)]
        sealed: bool,
    },
    /// T6.02: open a folder bundle uploaded with `ImportPut` (from a
    /// pinned contact, signature checked) and import its credentials from
    /// `start` on (`apply: false`: only report). Replies `FolderImported`.
    FolderImport {
        upload: String,
        #[serde(default)]
        overwrite: bool,
        #[serde(default)]
        apply: bool,
        #[serde(default)]
        start: u32,
    },
}

impl From<SyncxRequest> for crate::protocol::Request {
    fn from(r: SyncxRequest) -> Self {
        crate::protocol::Request::Syncx(r)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncxResponse {
    /// T11.17 (CLI-local): `kepr sync push --map FILE [--dry-run]`.
    SyncPlan { dry_run: bool, rows: Vec<SyncRow> },
    /// T6.09: an export is built: `items` credentials in `size` bytes,
    /// fetched as `chunks` chunks of `id`. `omitted` lists what was left
    /// out and why (the first MAX_REPORT_ROWS of `omitted_count`).
    BundleReady {
        id: String,
        size: u64,
        chunks: u32,
        items: u32,
        omitted: Vec<BundleOmitted>,
        omitted_count: u32,
    },
    /// T6.09: one chunk (base64) of a built bundle.
    BundleChunk {
        id: String,
        index: u32,
        data: String,
    },
    /// T6.09: an import chunk is stored; `done` after the last one.
    ImportPutOk { upload: String, done: bool },
    /// T6.09: what one round of an import changed, or would change
    /// (`applied: false`). Unchanged credentials are only counted. Ask
    /// again from `next` while it is set.
    BundleImported {
        applied: bool,
        rows: Vec<BundleRow>,
        unchanged: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next: Option<u32>,
    },
    /// T6.10: this device's id and the number of enrolled devices.
    SyncDeviceOk { device: String, devices: u32 },
    /// T6.02: one round of a folder import: who sent it, the folder, and
    /// whether its credentials are stored sealed; as `BundleImported`.
    FolderImported {
        from: String,
        folder: String,
        sealed: bool,
        applied: bool,
        rows: Vec<BundleRow>,
        unchanged: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next: Option<u32>,
    },
    /// T6.10 (CLI-local): `kepr sync remote add|ls|rm`.
    SyncRemotes { remotes: Vec<String> },
    /// T6.10 (CLI-local): `kepr sync now`: what the merges changed, and
    /// the bundles left alone (`REMOTE NAME: why`, e.g. an unknown device).
    SyncDone {
        device: String,
        rows: Vec<BundleRow>,
        unchanged: u32,
        ignored: Vec<String>,
    },
}

/// T6.09: rows in one bundle reply (keeps it inside a frame).
pub const MAX_REPORT_ROWS: usize = 200;

/// T6.09: a credential a bundle does not carry, and why (`sealed`,
/// `ssh`, `share_key`, `consent`, `fido2`, `expired`, …).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleOmitted {
    pub name: String,
    pub omitted: String,
}

/// T6.09: one credential of an import: `create`, `update`, `unchanged`,
/// `skipped` (exists, policy, reserved name), `omitted` (not in the
/// bundle; `reason` says why) or `failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleRow {
    pub name: String,
    pub change: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<SyncxResponse> for crate::protocol::Response {
    fn from(r: SyncxResponse) -> Self {
        crate::protocol::Response::Syncx(r)
    }
}

/// One credential of a sync map: `create`, `update` or `unchanged`
/// (local and remote compared by hash only), `skipped` (no local value,
/// e.g. a sealed key) or `failed`. `error` says why for the last two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRow {
    pub name: String,
    pub url: String,
    pub change: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    fn req_round_trip(r: SyncxRequest, cmd: &str) {
        let v = serde_json::to_value(Request::from(r)).unwrap();
        assert_eq!(v["cmd"], cmd, "{v}");
        let back: Request = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(back, Request::Syncx(_)), "{v}");
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
    }

    #[test]
    fn bundle_requests_survive_json() {
        req_round_trip(
            SyncxRequest::ExportBundle {
                passphrase: "correct horse".into(),
            },
            "export_bundle",
        );
        req_round_trip(
            SyncxRequest::ExportChunk {
                id: "ab".into(),
                index: 3,
            },
            "export_chunk",
        );
        req_round_trip(
            SyncxRequest::ImportPut {
                upload: None,
                index: 0,
                chunk: "aGk=".into(),
                last: true,
            },
            "import_put",
        );
        req_round_trip(
            SyncxRequest::ImportBundle {
                upload: "ab".into(),
                passphrase: "p".into(),
                prefix: Some("OLD".into()),
                overwrite: true,
                apply: false,
                start: 2,
            },
            "import_bundle",
        );
        req_round_trip(SyncxRequest::SyncDevice, "sync_device");
        req_round_trip(SyncxRequest::SyncBuild, "sync_build");
        req_round_trip(
            SyncxRequest::SyncMerge {
                upload: "ab".into(),
                start: 0,
            },
            "sync_merge",
        );
        req_round_trip(
            SyncxRequest::FolderExport {
                folder: "team".into(),
                recipients: vec!["bob".into()],
                sealed: true,
            },
            "folder_export",
        );
        req_round_trip(
            SyncxRequest::FolderImport {
                upload: "ab".into(),
                overwrite: false,
                apply: true,
                start: 0,
            },
            "folder_import",
        );
    }

    #[test]
    fn chunk_counts() {
        assert_eq!(bundle_chunks(0), 1);
        assert_eq!(bundle_chunks(BUNDLE_CHUNK_BYTES), 1);
        assert_eq!(bundle_chunks(BUNDLE_CHUNK_BYTES + 1), 2);
        // A chunk's base64 plus its envelope fits one frame.
        assert!(BUNDLE_CHUNK_BYTES.div_ceil(3) * 4 + 512 < crate::protocol::MAX_MSG_BYTES);
    }

    fn round_trip(r: SyncxResponse) {
        let wire = serde_json::to_string(&Response::from(r.clone())).unwrap();
        match serde_json::from_str::<Response>(&wire).unwrap() {
            Response::Syncx(back) => assert_eq!(back, r, "{wire}"),
            other => panic!("{wire} came back as {other:?}"),
        }
    }

    #[test]
    fn responses_survive_json() {
        round_trip(SyncxResponse::SyncPlan {
            dry_run: true,
            rows: vec![
                SyncRow {
                    name: "DB".into(),
                    url: "aws-sm:prod/db".into(),
                    change: "create".into(),
                    error: None,
                },
                SyncRow {
                    name: "K".into(),
                    url: "json:x#k".into(),
                    change: "skipped".into(),
                    error: Some("credential unavailable".into()),
                },
            ],
        });
        round_trip(SyncxResponse::BundleReady {
            id: "ab".into(),
            size: 10,
            chunks: 1,
            items: 2,
            omitted: vec![BundleOmitted {
                name: "S".into(),
                omitted: "sealed".into(),
            }],
            omitted_count: 1,
        });
        round_trip(SyncxResponse::BundleChunk {
            id: "ab".into(),
            index: 0,
            data: "aGk=".into(),
        });
        round_trip(SyncxResponse::ImportPutOk {
            upload: "ab".into(),
            done: false,
        });
        round_trip(SyncxResponse::BundleImported {
            applied: true,
            rows: vec![BundleRow {
                name: "A".into(),
                change: "create".into(),
                reason: None,
            }],
            unchanged: 4,
            next: Some(9),
        });
        round_trip(SyncxResponse::SyncDeviceOk {
            device: "0a1b2c3d".into(),
            devices: 2,
        });
        round_trip(SyncxResponse::FolderImported {
            from: "alice".into(),
            folder: "team".into(),
            sealed: false,
            applied: true,
            rows: vec![],
            unchanged: 2,
            next: None,
        });
        round_trip(SyncxResponse::SyncRemotes {
            remotes: vec!["dir:/x".into()],
        });
        round_trip(SyncxResponse::SyncDone {
            device: "0a1b2c3d".into(),
            rows: vec![],
            unchanged: 1,
            ignored: vec!["dir:/x ffffffff.bundle: from an unknown device".into()],
        });
    }
}
