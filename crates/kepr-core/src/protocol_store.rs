// protocol_store.rs — wire types of the `store` ticket batch: tags and
// folders (T5.01), search (T11.1), trash (T11.2), aliases (T11.5),
// delete-all (T11.9), duplicates (T11.4). Wrapped by `Request::Store` /
// `Response::Store`, which are `#[serde(untagged)]` and tried after every
// tagged variant, so the `cmd` / `kind` names here must not repeat one in
// protocol.rs.
//
// Nothing here carries a secret value: names, tags and folder paths only.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum StoreRequest {
    /// T5.01: add / remove tags, and set the folder (`"/"` clears it).
    Organize {
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        add_tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        remove_tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
    },
    /// T11.1: substring or `/regex/` over names, tags, folders, record
    /// types and non-secret record fields.
    Search { pattern: String },
    /// T11.2: the caller's trash.
    TrashList,
    /// T11.2: put the newest trashed `name` back (refused if it exists).
    TrashRestore { name: String },
    /// T11.2: drop `name`'s trash entries, or every entry.
    TrashPurge {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// T11.2: `rm --force`: delete at once, skipping the trash. Answered
    /// with `Response::DeleteOk`.
    DeleteNow { name: String },
    /// T11.5: make `alias` resolve to `target` (one hop, no value copy).
    Link { alias: String, target: String },
    /// T11.9: delete every credential of the caller, its history, trash
    /// and aliases. `confirm` must be true (`--yes`).
    DeleteAll {
        #[serde(default)]
        confirm: bool,
    },
    /// T11.4: groups of credentials holding the same value.
    Dupes,
    /// T11.4: turn the rest of `keep`'s group into aliases of it.
    DupesMerge { keep: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreResponse {
    /// The credential's tags and folder after an `Organize`.
    OrganizeOk {
        name: String,
        tags: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
    },
    SearchOk {
        hits: Vec<SearchHit>,
    },
    TrashListOk {
        items: Vec<TrashItem>,
    },
    TrashRestoreOk {
        name: String,
    },
    TrashPurgeOk {
        purged: usize,
    },
    LinkOk {
        alias: String,
        target: String,
    },
    DeleteAllOk {
        deleted: usize,
    },
    DupesOk {
        groups: Vec<Vec<String>>,
    },
    DupesMergeOk {
        keep: String,
        aliased: Vec<String>,
    },
}

/// One trash entry (no value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrashItem {
    pub name: String,
    /// `YYYY-MM-DD HH:MM` UTC.
    pub trashed_at: String,
    /// When the sweeper deletes it for good.
    pub purge_at: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
}

/// One `kepr search` result: the credential and what matched
/// (`name`, `tag`, `folder`, `type` or a record field name).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub name: String,
    pub matched: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};
    use serde_json::{json, Value};

    fn req_round_trip(r: Request) -> Value {
        let v = serde_json::to_value(&r).unwrap();
        let back: Request = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(back, Request::Store(_)), "{v}");
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        v
    }

    fn resp_round_trip(r: Response) -> Value {
        let v = serde_json::to_value(&r).unwrap();
        let back: Response = serde_json::from_value(v.clone()).unwrap();
        assert!(matches!(back, Response::Store(_)), "{v}");
        assert_eq!(serde_json::to_value(&back).unwrap(), v);
        v
    }

    #[test]
    fn organize_round_trips_through_the_request_enum() {
        let v = req_round_trip(Request::Store(StoreRequest::Organize {
            name: "API".into(),
            add_tags: vec!["work".into()],
            remove_tags: vec![],
            folder: Some("/".into()),
        }));
        assert_eq!(v["cmd"], json!("organize"));
        assert!(v.get("remove_tags").is_none(), "{v}");
        let v = resp_round_trip(Response::Store(StoreResponse::OrganizeOk {
            name: "API".into(),
            tags: vec!["work".into()],
            folder: None,
        }));
        assert_eq!(v["kind"], json!("organize_ok"));
    }

    #[test]
    fn search_round_trips() {
        let v = req_round_trip(Request::Store(StoreRequest::Search {
            pattern: "/^a/".into(),
        }));
        assert_eq!(v["cmd"], json!("search"));
        resp_round_trip(Response::Store(StoreResponse::SearchOk {
            hits: vec![SearchHit {
                name: "A".into(),
                matched: vec!["name".into()],
            }],
        }));
    }

    #[test]
    fn trash_round_trips() {
        for (r, cmd) in [
            (StoreRequest::TrashList, "trash_list"),
            (
                StoreRequest::TrashRestore { name: "A".into() },
                "trash_restore",
            ),
            (StoreRequest::TrashPurge { name: None }, "trash_purge"),
            (StoreRequest::DeleteNow { name: "A".into() }, "delete_now"),
        ] {
            assert_eq!(req_round_trip(Request::Store(r))["cmd"], json!(cmd));
        }
        let item = TrashItem {
            name: "A".into(),
            trashed_at: "2026-01-01 00:00".into(),
            purge_at: "2026-01-31 00:00".into(),
            size: 40,
            sealed: Some(true),
            record_type: None,
        };
        for r in [
            StoreResponse::TrashListOk { items: vec![item] },
            StoreResponse::TrashRestoreOk { name: "A".into() },
            StoreResponse::TrashPurgeOk { purged: 2 },
        ] {
            resp_round_trip(Response::Store(r));
        }
    }

    #[test]
    fn link_round_trips() {
        let v = req_round_trip(Request::Store(StoreRequest::Link {
            alias: "A".into(),
            target: "B".into(),
        }));
        assert_eq!(v["cmd"], json!("link"));
        let v = resp_round_trip(Response::Store(StoreResponse::LinkOk {
            alias: "A".into(),
            target: "B".into(),
        }));
        assert_eq!(v["kind"], json!("link_ok"));
    }

    #[test]
    fn delete_all_round_trips() {
        let v = req_round_trip(Request::Store(StoreRequest::DeleteAll { confirm: true }));
        assert_eq!(v["cmd"], json!("delete_all"));
        // A request without the field is not a confirmation.
        let back: Request = serde_json::from_value(json!({"cmd": "delete_all"})).unwrap();
        assert!(matches!(
            back,
            Request::Store(StoreRequest::DeleteAll { confirm: false })
        ));
        resp_round_trip(Response::Store(StoreResponse::DeleteAllOk { deleted: 3 }));
    }

    #[test]
    fn dupes_round_trip() {
        let v = req_round_trip(Request::Store(StoreRequest::Dupes));
        assert_eq!(v["cmd"], json!("dupes"));
        let v = req_round_trip(Request::Store(StoreRequest::DupesMerge {
            keep: "A".into(),
        }));
        assert_eq!(v["cmd"], json!("dupes_merge"));
        resp_round_trip(Response::Store(StoreResponse::DupesOk {
            groups: vec![vec!["A".into(), "B".into()]],
        }));
        resp_round_trip(Response::Store(StoreResponse::DupesMergeOk {
            keep: "A".into(),
            aliased: vec!["B".into()],
        }));
    }

    #[test]
    fn existing_variants_still_win_over_the_untagged_one() {
        let back: Request = serde_json::from_value(json!({"cmd": "list"})).unwrap();
        assert!(matches!(back, Request::List));
        let back: Response = serde_json::from_value(json!({"kind": "pong"})).unwrap();
        assert!(matches!(back, Response::Pong));
    }
}
