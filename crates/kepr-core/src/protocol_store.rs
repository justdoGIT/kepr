// protocol_store.rs — wire types of the `store` ticket batch: tags and
// folders (T5.01), search (T11.1). Wrapped by `Request::Store` /
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
    fn existing_variants_still_win_over_the_untagged_one() {
        let back: Request = serde_json::from_value(json!({"cmd": "list"})).unwrap();
        assert!(matches!(back, Request::List));
        let back: Response = serde_json::from_value(json!({"kind": "pong"})).unwrap();
        assert!(matches!(back, Response::Pong));
    }
}
