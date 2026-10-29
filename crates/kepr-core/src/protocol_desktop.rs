// protocol_desktop.rs — wire types of the `desktop` ticket batch (T13.28):
// the item store behind kepr's Secret Service (D-Bus) front end.
// Wrapped by `Request::Desktop` / `Response::Desktop`, which are
// `#[serde(untagged)]` and tried after every tagged variant, so the
// `cmd` / `kind` names here (all `ss_…`) must not repeat one elsewhere.
//
// An item is a Secret Service item: a label, string attributes the
// application looks it up by, a content type and a secret. The daemon
// keeps each as one encrypted credential and decrypts it only to match
// attributes or to answer `SsItemSecret`; the front end never holds more
// than the item it was asked for. Secrets travel base64-encoded in
// `ZeroString`s.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generate::ZeroString;

/// The collection every store has, and the alias `default` points at.
pub const LOGIN: &str = "login";
/// The folder the daemon files items under (`kepr ls --folder secret-service`).
pub const FOLDER: &str = "secret-service";
/// `Response::Err` text of any call that needs the key while locked.
pub const ERR_LOCKED: &str = "credential store is locked";
pub const ERR_NO_ITEM: &str = "no such item";
pub const ERR_NO_COLLECTION: &str = "no such collection";

pub const MAX_LABEL: usize = 256;
pub const MAX_ATTRS: usize = 64;
pub const MAX_ATTR_KEY: usize = 128;
pub const MAX_ATTR_VALUE: usize = 4096;
pub const MAX_CONTENT_TYPE: usize = 128;
/// Raw secret bytes; base64 of this must fit one frame with its envelope.
pub const MAX_SECRET_BYTES: usize = 32 * 1024;
pub const MAX_ITEMS: usize = 10_000;
pub const MAX_COLLECTIONS: usize = 64;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DesktopRequest {
    /// CreateItem. With `replace`, an item of the collection whose
    /// attributes are exactly these is updated instead of a second one made.
    SsItemCreate {
        collection: String,
        label: String,
        attributes: BTreeMap<String, String>,
        content_type: String,
        secret: ZeroString,
        #[serde(default)]
        replace: bool,
    },
    /// SearchItems: items (of `collection`, or any) whose attributes
    /// include every pair given; no pairs = all of them.
    SsItemSearch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        collection: Option<String>,
        #[serde(default)]
        attributes: BTreeMap<String, String>,
    },
    /// GetSecret. Audited; the policy applies as to a `get`.
    SsItemSecret {
        id: String,
    },
    /// SetSecret / label / attributes changes; absent fields stay.
    SsItemUpdate {
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attributes: Option<BTreeMap<String, String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<ZeroString>,
    },
    SsItemDelete {
        id: String,
    },
    /// Collections and aliases (`default` → `login` unless changed).
    SsCollections,
    SsCollectionCreate {
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
    },
    SsCollectionSet {
        id: String,
        label: String,
    },
    /// Deletes the collection and every item in it.
    SsCollectionDelete {
        id: String,
    },
    /// Point `alias` at `collection`, or (None) remove it.
    SsAliasSet {
        alias: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        collection: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsItemInfo {
    pub id: String,
    pub collection: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsCollectionInfo {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub items: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DesktopResponse {
    // Boxed: `Response` must stay under 128 bytes (clippy::result_large_err).
    SsItem {
        item: Box<SsItemInfo>,
    },
    SsItems {
        items: Vec<SsItemInfo>,
    },
    SsSecret {
        id: String,
        content_type: String,
        secret: ZeroString,
    },
    SsDeleted {
        id: String,
        items: u32,
    },
    SsCollections {
        collections: Vec<SsCollectionInfo>,
        aliases: BTreeMap<String, String>,
    },
    SsCollection {
        collection: Box<SsCollectionInfo>,
    },
    SsAliasOk,
}

/// 26 characters of RFC 4648 base32 (an item's random 128-bit id).
pub fn valid_item_id(id: &str) -> bool {
    id.len() == 26 && id.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7'))
}

/// Collection ids and aliases appear in D-Bus object paths.
pub fn valid_collection_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

pub fn valid_alias(a: &str) -> bool {
    valid_collection_id(a)
}

pub fn validate_label(l: &str) -> Result<(), String> {
    if l.len() > MAX_LABEL || l.contains('\0') {
        return Err(format!(
            "the label is too long (at most {MAX_LABEL} bytes) or holds a NUL"
        ));
    }
    Ok(())
}

pub fn validate_content_type(c: &str) -> Result<(), String> {
    if c.is_empty() || c.len() > MAX_CONTENT_TYPE || c.chars().any(char::is_control) {
        return Err("the content type is empty, too long or holds a control character".into());
    }
    Ok(())
}

pub fn validate_attributes(a: &BTreeMap<String, String>) -> Result<(), String> {
    if a.len() > MAX_ATTRS {
        return Err(format!("too many attributes (at most {MAX_ATTRS})"));
    }
    for (k, v) in a {
        if k.is_empty() || k.len() > MAX_ATTR_KEY || v.len() > MAX_ATTR_VALUE {
            return Err("an attribute name is empty or too long, or a value is too long".into());
        }
        if k.contains('\0') || v.contains('\0') {
            return Err("an attribute holds a NUL byte".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, Response};

    #[test]
    fn requests_round_trip_through_the_core_enum() {
        let attrs = BTreeMap::from([("xdg:schema".to_string(), "x.Y".to_string())]);
        let reqs = [
            Request::Desktop(DesktopRequest::SsItemCreate {
                collection: LOGIN.into(),
                label: "L".into(),
                attributes: attrs.clone(),
                content_type: "text/plain".into(),
                secret: ZeroString::from("c2VjcmV0"),
                replace: true,
            }),
            Request::Desktop(DesktopRequest::SsItemSearch {
                collection: None,
                attributes: attrs,
            }),
            Request::Desktop(DesktopRequest::SsItemSecret { id: "A".repeat(26) }),
            Request::Desktop(DesktopRequest::SsItemUpdate {
                id: "A".repeat(26),
                label: Some("n".into()),
                attributes: None,
                content_type: None,
                secret: Some(ZeroString::from("eA==")),
            }),
            Request::Desktop(DesktopRequest::SsItemDelete { id: "A".repeat(26) }),
            Request::Desktop(DesktopRequest::SsCollections),
            Request::Desktop(DesktopRequest::SsCollectionCreate {
                label: "L".into(),
                alias: Some("work".into()),
            }),
            Request::Desktop(DesktopRequest::SsCollectionSet {
                id: "work".into(),
                label: "W".into(),
            }),
            Request::Desktop(DesktopRequest::SsCollectionDelete { id: "work".into() }),
            Request::Desktop(DesktopRequest::SsAliasSet {
                alias: "default".into(),
                collection: None,
            }),
        ];
        for r in reqs {
            let wire = serde_json::to_string(&r).unwrap();
            assert!(wire.contains("\"ss_"), "{wire}");
            let back: Request = serde_json::from_str(&wire).unwrap();
            assert!(matches!(back, Request::Desktop(_)), "{wire}");
            assert_eq!(serde_json::to_string(&back).unwrap(), wire);
        }
    }

    #[test]
    fn responses_round_trip_and_stay_small() {
        let info = SsItemInfo {
            id: "A".repeat(26),
            collection: LOGIN.into(),
            label: "L".into(),
            attributes: BTreeMap::new(),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
        };
        let resps = [
            Response::Desktop(DesktopResponse::SsItem {
                item: Box::new(info.clone()),
            }),
            Response::Desktop(DesktopResponse::SsItems { items: vec![info] }),
            Response::Desktop(DesktopResponse::SsSecret {
                id: "A".repeat(26),
                content_type: "text/plain".into(),
                secret: ZeroString::from("eA=="),
            }),
            Response::Desktop(DesktopResponse::SsDeleted {
                id: "x".into(),
                items: 3,
            }),
            Response::Desktop(DesktopResponse::SsCollections {
                collections: vec![],
                aliases: BTreeMap::from([("default".to_string(), LOGIN.to_string())]),
            }),
            Response::Desktop(DesktopResponse::SsAliasOk),
        ];
        for r in resps {
            let wire = serde_json::to_string(&r).unwrap();
            let back: Response = serde_json::from_str(&wire).unwrap();
            assert!(matches!(back, Response::Desktop(_)), "{wire}");
        }
        // Core variants still win over the untagged wrapper.
        assert!(matches!(
            serde_json::from_str::<Response>(
                r#"{"kind":"err","error":"credential store is locked"}"#
            ),
            Ok(Response::Err { .. })
        ));
        assert!(std::mem::size_of::<Response>() < 128);
    }

    #[test]
    fn validators() {
        assert!(valid_item_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(
            !valid_item_id("abcdefghijklmnopqrstuvwxyz") && !valid_item_id("A".repeat(25).as_str())
        );
        assert!(
            !valid_item_id(&format!("{}1", "A".repeat(25))),
            "1 is not base32"
        );
        assert!(valid_collection_id("login") && valid_collection_id("c_1f"));
        assert!(
            !valid_collection_id("")
                && !valid_collection_id("Login")
                && !valid_collection_id("a-b")
        );
        assert!(!valid_collection_id(&"a".repeat(33)));
        assert!(validate_label("x").is_ok() && validate_label(&"x".repeat(257)).is_err());
        assert!(validate_label("a\0b").is_err());
        assert!(validate_content_type("text/plain").is_ok());
        assert!(validate_content_type("").is_err() && validate_content_type("a\nb").is_err());
        let mut a = BTreeMap::new();
        assert!(validate_attributes(&a).is_ok());
        a.insert("k".into(), "v".into());
        assert!(validate_attributes(&a).is_ok());
        a.insert("".into(), "v".into());
        assert!(validate_attributes(&a).is_err());
        let many: BTreeMap<_, _> = (0..65)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(validate_attributes(&many).is_err());
        assert!(
            validate_attributes(&BTreeMap::from([("k".to_string(), "v".repeat(5000))])).is_err()
        );
        assert!(
            validate_attributes(&BTreeMap::from([("k".to_string(), "a\0".to_string())])).is_err()
        );
    }
}
