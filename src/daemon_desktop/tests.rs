// daemon_desktop/tests.rs — the Secret Service item store against a temp
// store. The whole file is test code: the attribute below is where
// tests/file_size_limit.rs stops counting production lines.

#[cfg(test)]
use std::collections::BTreeMap;

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::{
    self as pd, DesktopRequest as Q, DesktopResponse as R, SsItemInfo,
};

use super::dispatch;
use crate::daemon_store::testkit;

fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn b64(s: &str) -> ZeroString {
    use base64::Engine;
    ZeroString::from_string(base64::engine::general_purpose::STANDARD.encode(s))
}

fn ask(uid: u32, q: Q) -> Result<R, String> {
    match dispatch(uid, 0, "t", q) {
        Response::Desktop(r) => Ok(r),
        Response::Err { error } => Err(error),
        other => panic!("{other:?}"),
    }
}

fn create(
    uid: u32,
    coll: &str,
    label: &str,
    a: &[(&str, &str)],
    secret: &str,
    replace: bool,
) -> Result<SsItemInfo, String> {
    match ask(
        uid,
        Q::SsItemCreate {
            collection: coll.into(),
            label: label.into(),
            attributes: attrs(a),
            content_type: "text/plain".into(),
            secret: b64(secret),
            replace,
        },
    )? {
        R::SsItem { item } => Ok(*item),
        other => panic!("{other:?}"),
    }
}

fn search(uid: u32, coll: Option<&str>, a: &[(&str, &str)]) -> Vec<SsItemInfo> {
    match ask(
        uid,
        Q::SsItemSearch {
            collection: coll.map(String::from),
            attributes: attrs(a),
        },
    )
    .unwrap()
    {
        R::SsItems { items } => items,
        other => panic!("{other:?}"),
    }
}

fn secret_of(uid: u32, id: &str) -> Result<(String, String), String> {
    use base64::Engine;
    match ask(uid, Q::SsItemSecret { id: id.into() })? {
        R::SsSecret {
            secret,
            content_type,
            ..
        } => Ok((
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(secret.as_str())
                    .unwrap(),
            )
            .unwrap(),
            content_type,
        )),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_item_is_found_by_a_subset_of_its_attributes_and_gives_its_secret_back() {
    let uid = testkit::uid();
    let a = create(
        uid,
        "login",
        "Mail",
        &[
            ("xdg:schema", "x.Net"),
            ("user", "alice"),
            ("server", "m.example"),
        ],
        "s3cret",
        false,
    )
    .unwrap();
    let b = create(
        uid,
        "login",
        "Other",
        &[("xdg:schema", "x.Net"), ("user", "bob")],
        "other",
        false,
    )
    .unwrap();
    assert!(pd::valid_item_id(&a.id) && a.id != b.id);
    assert_eq!(search(uid, None, &[]).len(), 2);
    let got = search(uid, None, &[("user", "alice")]);
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].label.as_str(), got[0].id.as_str()),
        ("Mail", a.id.as_str())
    );
    assert_eq!(search(uid, None, &[("xdg:schema", "x.Net")]).len(), 2);
    assert!(search(uid, None, &[("user", "alice"), ("server", "other")]).is_empty());
    assert!(
        search(uid, None, &[("user", "ALICE")]).is_empty(),
        "values match exactly"
    );
    assert_eq!(
        secret_of(uid, &a.id).unwrap(),
        ("s3cret".into(), "text/plain".into())
    );
    assert_eq!(secret_of(uid, &b.id).unwrap().0, "other");
}

#[test]
fn items_are_ordinary_credentials_marked_and_filed() {
    let uid = testkit::uid();
    let a = create(uid, "login", "L", &[("k", "v")], "x", false).unwrap();
    let name = format!("SSI_{}", a.id);
    let meta = testkit::meta(uid, &name);
    assert_eq!(meta.desktop_item, Some(true));
    assert_eq!(meta.folder.as_deref(), Some(pd::FOLDER));
    // The stored text is the JSON document, encrypted like any value.
    let doc = testkit::value(uid, &name).unwrap();
    assert!(doc.contains("\"label\":\"L\"") && doc.contains("\"k\":\"v\""));
    // And other users' items are invisible.
    let other = testkit::uid();
    assert!(search(other, None, &[]).is_empty());
    assert_eq!(secret_of(other, &a.id).unwrap_err(), pd::ERR_NO_ITEM);
}

#[test]
fn a_plain_get_refuses_an_item_but_backups_still_see_it() {
    let uid = testkit::uid();
    let a = create(uid, "login", "L", &[("k", "v")], "s3cret", false).unwrap();
    let name = format!("SSI_{}", a.id);
    assert!(super::is_item(uid, &name));
    assert!(!super::is_item(uid, "NOT_AN_ITEM"));
    let r = crate::daemon_handlers_get::handle_get(uid, 0, "t", &name, None);
    match r {
        Response::Err { error } => {
            assert!(
                error.contains("kepr secret lookup") && !error.contains("s3cret"),
                "{error}"
            );
        }
        other => panic!("a plain get returned {other:?}"),
    }
    // Export and share use the policy check, which does not refuse it.
    assert!(crate::daemon_handlers_get::precheck_meta(uid, 0, &name).is_ok());
    // The Secret Service route still reads it.
    assert_eq!(secret_of(uid, &a.id).unwrap().0, "s3cret");
}

#[test]
fn replace_updates_the_item_with_identical_attributes_and_nothing_else() {
    let uid = testkit::uid();
    let first = create(uid, "login", "v1", &[("a", "1"), ("b", "2")], "old", true).unwrap();
    let again = create(uid, "login", "v2", &[("a", "1"), ("b", "2")], "new", true).unwrap();
    assert_eq!(
        first.id, again.id,
        "same attributes, replace: the same item"
    );
    assert_eq!(again.created, first.created);
    assert_eq!(search(uid, None, &[]).len(), 1);
    assert_eq!(secret_of(uid, &first.id).unwrap().0, "new");
    // Different attributes (even a superset) are another item.
    let other = create(uid, "login", "v3", &[("a", "1")], "x", true).unwrap();
    assert_ne!(other.id, first.id);
    // Without replace a duplicate is made.
    let dup = create(uid, "login", "v4", &[("a", "1")], "y", false).unwrap();
    assert_ne!(dup.id, other.id);
    assert_eq!(search(uid, None, &[]).len(), 3);
}

#[test]
fn updates_change_only_what_is_given_and_deletes_are_final() {
    let uid = testkit::uid();
    let it = create(uid, "login", "L", &[("k", "v")], "s1", false).unwrap();
    ask(
        uid,
        Q::SsItemUpdate {
            id: it.id.clone(),
            label: Some("L2".into()),
            attributes: None,
            content_type: None,
            secret: None,
        },
    )
    .unwrap();
    assert_eq!(secret_of(uid, &it.id).unwrap().0, "s1");
    assert_eq!(search(uid, None, &[("k", "v")])[0].label, "L2");
    ask(
        uid,
        Q::SsItemUpdate {
            id: it.id.clone(),
            label: None,
            attributes: Some(attrs(&[("k2", "v2")])),
            content_type: Some("application/json".into()),
            secret: Some(b64("s2")),
        },
    )
    .unwrap();
    assert_eq!(
        secret_of(uid, &it.id).unwrap(),
        ("s2".into(), "application/json".into())
    );
    assert!(search(uid, None, &[("k", "v")]).is_empty());
    assert_eq!(search(uid, None, &[("k2", "v2")]).len(), 1);
    assert_eq!(search(uid, None, &[])[0].created, it.created);

    match ask(uid, Q::SsItemDelete { id: it.id.clone() }).unwrap() {
        R::SsDeleted { items, .. } => assert_eq!(items, 1),
        other => panic!("{other:?}"),
    }
    assert!(search(uid, None, &[]).is_empty());
    assert_eq!(secret_of(uid, &it.id).unwrap_err(), pd::ERR_NO_ITEM);
    assert_eq!(
        ask(uid, Q::SsItemDelete { id: it.id.clone() }).unwrap_err(),
        pd::ERR_NO_ITEM
    );
    // A deleted item leaves no value behind and no history.
    assert!(testkit::value(uid, &format!("SSI_{}", it.id)).is_none());
    assert!(ask(
        uid,
        Q::SsItemUpdate {
            id: "NOT-AN-ID".into(),
            label: None,
            attributes: None,
            content_type: None,
            secret: None
        }
    )
    .is_err());
}

#[test]
fn collections_hold_items_and_deleting_one_deletes_them() {
    let uid = testkit::uid();
    let listed = |uid| match ask(uid, Q::SsCollections).unwrap() {
        R::SsCollections {
            collections,
            aliases,
        } => (collections, aliases),
        other => panic!("{other:?}"),
    };
    let (cs, aliases) = listed(uid);
    assert_eq!(cs.len(), 1);
    assert_eq!(
        (cs[0].id.as_str(), cs[0].label.as_str()),
        ("login", "Login")
    );
    assert_eq!(aliases["default"], "login");

    let work = match ask(
        uid,
        Q::SsCollectionCreate {
            label: "Work".into(),
            alias: Some("work".into()),
        },
    )
    .unwrap()
    {
        R::SsCollection { collection } => *collection,
        other => panic!("{other:?}"),
    };
    assert!(pd::valid_collection_id(&work.id));
    assert_eq!(listed(uid).1["work"], work.id);
    let w = create(uid, &work.id, "W", &[("k", "v")], "w", false).unwrap();
    create(uid, "login", "L", &[("k", "v")], "l", false).unwrap();
    assert_eq!(search(uid, Some(&work.id), &[("k", "v")]).len(), 1);
    assert_eq!(search(uid, None, &[("k", "v")]).len(), 2);
    assert_eq!(
        listed(uid)
            .0
            .iter()
            .find(|c| c.id == work.id)
            .unwrap()
            .items,
        1
    );

    assert_eq!(
        create(uid, "nope", "x", &[], "x", false).unwrap_err(),
        pd::ERR_NO_COLLECTION
    );
    ask(
        uid,
        Q::SsCollectionSet {
            id: work.id.clone(),
            label: "Work 2".into(),
        },
    )
    .unwrap();
    assert_eq!(
        listed(uid)
            .0
            .iter()
            .find(|c| c.id == work.id)
            .unwrap()
            .label,
        "Work 2"
    );

    // The default alias can be moved, and the login collection stays.
    ask(
        uid,
        Q::SsAliasSet {
            alias: "default".into(),
            collection: Some(work.id.clone()),
        },
    )
    .unwrap();
    assert_eq!(listed(uid).1["default"], work.id);
    assert!(ask(uid, Q::SsCollectionDelete { id: "login".into() }).is_err());
    match ask(
        uid,
        Q::SsCollectionDelete {
            id: work.id.clone(),
        },
    )
    .unwrap()
    {
        R::SsDeleted { items, .. } => assert_eq!(items, 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(secret_of(uid, &w.id).unwrap_err(), pd::ERR_NO_ITEM);
    let (cs, aliases) = listed(uid);
    assert_eq!(cs.len(), 1);
    assert_eq!(
        aliases["default"], "login",
        "an alias to a deleted collection is gone, default resets"
    );
    assert!(!aliases.contains_key("work"));
    assert_eq!(search(uid, None, &[("k", "v")]).len(), 1);
    assert!(ask(
        uid,
        Q::SsAliasSet {
            alias: "bad alias".into(),
            collection: None
        }
    )
    .is_err());
    assert!(ask(
        uid,
        Q::SsAliasSet {
            alias: "x".into(),
            collection: Some("zzz".into())
        }
    )
    .is_err());
}

#[test]
fn limits_and_bad_input_are_refused_before_anything_is_stored() {
    let uid = testkit::uid();
    let long = "x".repeat(pd::MAX_LABEL + 1);
    assert!(create(uid, "login", &long, &[], "s", false).is_err());
    let many: Vec<(String, String)> = (0..65)
        .map(|i| (format!("k{i}"), "v".to_string()))
        .collect();
    let refs: Vec<(&str, &str)> = many.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert!(create(uid, "login", "L", &refs, "s", false).is_err());
    let r = ask(
        uid,
        Q::SsItemCreate {
            collection: "login".into(),
            label: "L".into(),
            attributes: BTreeMap::new(),
            content_type: "text/plain".into(),
            secret: ZeroString::from("not base64!"),
            replace: false,
        },
    );
    assert!(r.unwrap_err().contains("base64"));
    let big = "x".repeat(pd::MAX_SECRET_BYTES + 1);
    assert!(create(uid, "login", "L", &[], &big, false)
        .unwrap_err()
        .contains("too large"));
    let edge = "x".repeat(pd::MAX_SECRET_BYTES);
    let it = create(uid, "login", "L", &[], &edge, false).unwrap();
    assert_eq!(
        secret_of(uid, &it.id).unwrap().0.len(),
        pd::MAX_SECRET_BYTES
    );
    let r = ask(
        uid,
        Q::SsItemCreate {
            collection: "login".into(),
            label: "L".into(),
            attributes: BTreeMap::new(),
            content_type: "".into(),
            secret: b64("s"),
            replace: false,
        },
    );
    assert!(r.is_err());
    assert_eq!(search(uid, None, &[]).len(), 1, "nothing half stored");
}

#[test]
fn binary_secrets_and_odd_text_survive() {
    use base64::Engine;
    let uid = testkit::uid();
    let raw = (0..=255u8).collect::<Vec<_>>();
    let enc = ZeroString::from_string(base64::engine::general_purpose::STANDARD.encode(&raw));
    let it = match ask(
        uid,
        Q::SsItemCreate {
            collection: "login".into(),
            label: "日本語 ✓".into(),
            attributes: attrs(&[("ключ", "значение \"quoted\" \\ \n newline")]),
            content_type: "application/octet-stream".into(),
            secret: enc,
            replace: false,
        },
    )
    .unwrap()
    {
        R::SsItem { item } => *item,
        other => panic!("{other:?}"),
    };
    let got = search(uid, None, &[("ключ", "значение \"quoted\" \\ \n newline")]);
    assert_eq!(got[0].label, "日本語 ✓");
    match ask(uid, Q::SsItemSecret { id: it.id }).unwrap() {
        R::SsSecret {
            secret,
            content_type,
            ..
        } => {
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(secret.as_str())
                    .unwrap(),
                raw
            );
            assert_eq!(content_type, "application/octet-stream");
        }
        other => panic!("{other:?}"),
    }
}
