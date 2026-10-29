// daemon_desktop/items.rs — create, search, read, change and delete
// Secret Service items. Every call that touches the key fails with
// `ERR_LOCKED` while the store is locked, so the front end can offer an
// unlock. Secrets are audited (op `ss-secret`, the item's credential name,
// never a label or attribute) like any other read.

use std::collections::BTreeMap;

use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::{self as pd, DesktopResponse as R};

use super::doc::{self, Failure, ItemDoc};
use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::now_unix;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn audit_op<T>(
    op: &'static str,
    name: Option<&str>,
    uid: u32,
    username: &str,
    r: &Result<T, Failure>,
) {
    audit::log(&AuditEvent {
        op,
        name,
        uid,
        username,
        result: match r {
            Ok(_) => AuditResult::Ok,
            Err(e) => AuditResult::Fail(e.text()),
        },
    });
}

/// A secret that decodes to at most `MAX_SECRET_BYTES`.
fn check_secret(b64: &ZeroString) -> Result<(), Failure> {
    if b64.len() > pd::MAX_SECRET_BYTES.div_ceil(3) * 4 {
        return Err(Failure::Invalid("the secret is too large".into()));
    }
    let raw = B64
        .decode(b64.as_bytes())
        .map(zeroize::Zeroizing::new)
        .map_err(|_| Failure::Invalid("the secret is not valid base64".into()))?;
    if raw.len() > pd::MAX_SECRET_BYTES {
        return Err(Failure::Invalid("the secret is too large".into()));
    }
    Ok(())
}

fn check_meta(label: &str, attrs: &BTreeMap<String, String>, ct: &str) -> Result<(), Failure> {
    pd::validate_label(label).map_err(Failure::Invalid)?;
    pd::validate_attributes(attrs).map_err(Failure::Invalid)?;
    pd::validate_content_type(ct).map_err(Failure::Invalid)
}

/// Does `doc` carry every pair of `want`?
pub fn matches(doc_attrs: &BTreeMap<String, String>, want: &BTreeMap<String, String>) -> bool {
    want.iter().all(|(k, v)| doc_attrs.get(k) == Some(v))
}

/// Every item of the caller, newest last. Items that cannot be read are skipped.
fn all(uid: u32) -> Result<Vec<(String, ItemDoc)>, Failure> {
    if doc::locked() {
        return Err(Failure::Locked);
    }
    let mut out: Vec<_> = doc::ids(uid)
        .into_iter()
        .filter_map(|id| doc::load(uid, &id).ok().map(|d| (id, d)))
        .collect();
    out.sort_by(|a, b| (a.1.created, &a.0).cmp(&(b.1.created, &b.0)));
    Ok(out)
}

pub fn count_in(uid: u32, collection: &str) -> usize {
    all(uid).map_or(0, |v| {
        v.iter().filter(|(_, d)| d.collection == collection).count()
    })
}

pub fn create(
    uid: u32,
    username: &str,
    (collection, label, attributes): (&str, &str, &BTreeMap<String, String>),
    (content_type, secret): (&str, &ZeroString),
    replace: bool,
) -> Result<R, Failure> {
    let r = (|| -> Result<(String, pd::SsItemInfo), Failure> {
        check_meta(label, attributes, content_type)?;
        check_secret(secret)?;
        super::collections::require(uid, collection)?;
        let items = all(uid)?;
        if items.len() >= pd::MAX_ITEMS {
            return Err(Failure::Invalid(format!(
                "too many items (at most {})",
                pd::MAX_ITEMS
            )));
        }
        let now = now_unix();
        // `replace`: the item with exactly these attributes, if any.
        let same = items
            .into_iter()
            .find(|(_, d)| replace && d.collection == collection && d.attributes == *attributes);
        let (id, created) = match &same {
            Some((id, d)) => (id.clone(), d.created),
            None => (doc::new_id().map_err(Failure::Other)?, now),
        };
        let d = ItemDoc {
            v: 1,
            collection: collection.to_string(),
            label: label.to_string(),
            attributes: attributes.clone(),
            content_type: content_type.to_string(),
            secret: ZeroString::from(secret.as_str()),
            created,
            modified: now,
        };
        doc::save(uid, &id, &d)?;
        Ok((id, doc::info("", &d)))
    })();
    match r {
        Ok((id, mut info)) => {
            info.id = id.clone();
            audit_op(
                "ss-create",
                Some(&doc::cred_name(&id)),
                uid,
                username,
                &Ok(()),
            );
            Ok(R::SsItem {
                item: Box::new(info),
            })
        }
        Err(e) => {
            audit_op::<()>(
                "ss-create",
                None,
                uid,
                username,
                &Err(Failure::Other(e.text())),
            );
            Err(e)
        }
    }
}

pub fn search(
    uid: u32,
    collection: Option<&str>,
    want: &BTreeMap<String, String>,
) -> Result<R, Failure> {
    let items = all(uid)?
        .into_iter()
        .filter(|(_, d)| {
            collection.is_none_or(|c| d.collection == c) && matches(&d.attributes, want)
        })
        .map(|(id, d)| doc::info(&id, &d))
        .collect();
    Ok(R::SsItems { items })
}

pub fn secret(uid: u32, username: &str, id: &str) -> Result<R, Failure> {
    let r = doc::load(uid, id);
    let name = doc::cred_name(id);
    audit_op("ss-secret", Some(&name), uid, username, &r);
    let d = r?;
    Ok(R::SsSecret {
        id: id.to_string(),
        content_type: d.content_type.clone(),
        secret: ZeroString::from(d.secret.as_str()),
    })
}

/// What `SsItemUpdate` may change: label, attributes, content type, secret.
pub type Changes<'a> = (
    Option<&'a str>,
    Option<&'a BTreeMap<String, String>>,
    Option<&'a str>,
    Option<&'a ZeroString>,
);

pub fn update(
    uid: u32,
    username: &str,
    id: &str,
    (label, attributes, content_type, new_secret): Changes<'_>,
) -> Result<R, Failure> {
    let name = doc::cred_name(id);
    let _lock = crate::daemon_credlock::lock(uid, &name);
    let r = (|| -> Result<pd::SsItemInfo, Failure> {
        let mut d = doc::load(uid, id)?;
        check_meta(
            label.unwrap_or(&d.label),
            attributes.unwrap_or(&d.attributes),
            content_type.unwrap_or(&d.content_type),
        )?;
        if let Some(s) = new_secret {
            check_secret(s)?;
            d.secret = ZeroString::from(s.as_str());
        }
        if let Some(l) = label {
            d.label = l.to_string();
        }
        if let Some(a) = attributes {
            d.attributes = a.clone();
        }
        if let Some(c) = content_type {
            d.content_type = c.to_string();
        }
        d.modified = now_unix();
        doc::save(uid, id, &d)?;
        Ok(doc::info(id, &d))
    })();
    audit_op("ss-update", Some(&name), uid, username, &r);
    r.map(|info| R::SsItem {
        item: Box::new(info),
    })
}

pub fn delete(uid: u32, username: &str, id: &str) -> Result<R, Failure> {
    let name = doc::cred_name(id);
    let r = if pd::valid_item_id(id) {
        doc::remove(uid, &name)
    } else {
        Err(Failure::Invalid("not an item id".into()))
    };
    audit_op("ss-delete", Some(&name), uid, username, &r);
    r.map(|()| R::SsDeleted {
        id: id.to_string(),
        items: 1,
    })
}

/// Delete every item of `collection`; how many went.
pub fn delete_in(uid: u32, username: &str, collection: &str) -> Result<u32, Failure> {
    let mut n = 0;
    for (id, d) in all(uid)? {
        if d.collection == collection {
            delete(uid, username, &id)?;
            n += 1;
        }
    }
    Ok(n)
}

pub fn to_response(r: Result<R, Failure>) -> Response {
    match r {
        Ok(r) => Response::Desktop(r),
        Err(e) => e.response(),
    }
}
