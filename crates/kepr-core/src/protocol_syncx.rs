// protocol_syncx.rs — wire types of the `sync` ticket batch: sync maps
// (T11.17), encrypted bundles (T6.09), multi-device sync (T6.10), shared
// folders (T6.02) and M-of-N approvals (T7.12).
// batch: sync
//
// Carried inside `Response::Syncx` (untagged, tried after every tagged
// variant), so the `kind` names here must not repeat one used elsewhere.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncxResponse {
    /// T11.17 (CLI-local): `kepr sync push --map FILE [--dry-run]`.
    SyncPlan { dry_run: bool, rows: Vec<SyncRow> },
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
    use crate::protocol::Response;

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
    }
}
