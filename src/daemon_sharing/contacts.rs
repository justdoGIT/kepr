// daemon_sharing/contacts.rs — T11.15 pinned share contacts.
//
//   kepr share contact add NAME KEY   pin KEY (kepr-pk2-… / kepr-pub1-…)
//   kepr share contact ls | rm NAME
//   kepr share send CRED --to NAME    encrypts to the pinned key
//
// A name is pinned to one key: adding the same name with another key is
// refused until the old one is removed, so a key swapped in by someone
// else can't silently take over a name the user trusts. Sending to a
// name that isn't pinned is refused (a typo never falls through to
// anything). Public keys only; one JSON file per uid.

use kepr_core::protocol::Response;
use kepr_core::protocol_sharing::{ContactInfo, SharingResponse};
use sha2::{Digest, Sha256};

use super::kem::{Recipient, PUB1, PUB2};
use super::{audit_r, load, save, state_path, LOCK};
use crate::expiry::{format_expires_at, now_unix};

const KIND: &str = "share-contacts";
const MAX_CONTACTS: usize = 256;

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Book {
    #[serde(default)]
    contacts: Vec<Contact>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Contact {
    name: String,
    public: String,
    added: u64,
}

/// Short SHA-256 of a public key's canonical text, in 4-digit groups.
pub(crate) fn fingerprint(public: &str) -> String {
    let d = Sha256::digest(public.as_bytes());
    d[..8]
        .chunks(2)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join("-")
}

/// Contact names: 1-64 of `a-z 0-9 . _ @ -`, case-insensitive (kept in
/// lower case); never shaped like a key.
pub(crate) fn normalize_name(name: &str) -> Result<String, String> {
    let n = name.trim().to_ascii_lowercase();
    let ok = (1..=64).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
        && !n.starts_with("kepr-");
    ok.then_some(n)
        .ok_or_else(|| "a contact name is 1-64 of a-z 0-9 . _ @ -".into())
}

fn is_key(text: &str) -> bool {
    let t = text.trim();
    t.starts_with(PUB1) || t.starts_with(PUB2)
}

impl Book {
    fn add(&mut self, name: &str, key: &str, now: u64) -> Result<bool, String> {
        let name = normalize_name(name)?;
        let public = Recipient::parse(key)?.text();
        if let Some(c) = self.contacts.iter().find(|c| c.name == name) {
            if c.public == public {
                return Ok(false);
            }
            return Err(format!(
                "{name} is pinned to another key ({}); remove it first \
                 (kepr share contact rm {name})",
                fingerprint(&c.public)
            ));
        }
        if self.contacts.len() >= MAX_CONTACTS {
            return Err(format!("at most {MAX_CONTACTS} contacts"));
        }
        self.contacts.push(Contact {
            name,
            public,
            added: now,
        });
        Ok(true)
    }

    fn get(&self, name: &str) -> Option<&Contact> {
        let name = normalize_name(name).ok()?;
        self.contacts.iter().find(|c| c.name == name)
    }

    fn infos(&self) -> Vec<ContactInfo> {
        self.contacts
            .iter()
            .map(|c| ContactInfo {
                name: c.name.clone(),
                public: c.public.clone(),
                fingerprint: fingerprint(&c.public),
                added: format_expires_at(c.added),
            })
            .collect()
    }
}

fn book(uid: u32) -> Book {
    let _g = LOCK.lock();
    load(&state_path(KIND, uid))
}

/// A `--to` value: a public key, or the name of a pinned contact.
/// Returns the recipient and a label for the ledger (the contact name,
/// or `key:<fingerprint>`).
pub(crate) fn resolve(uid: u32, to: &str) -> Result<(Recipient, String), String> {
    if is_key(to) {
        let r = Recipient::parse(to)?;
        let label = format!("key:{}", fingerprint(&r.text()));
        return Ok((r, label));
    }
    let b = book(uid);
    let c = b.get(to).ok_or_else(|| {
        format!(
            "no pinned contact named {}: pin their key first \
             (kepr share contact add NAME KEY)",
            to.trim()
        )
    })?;
    Ok((Recipient::parse(&c.public)?, c.name.clone()))
}

pub fn handle_add(uid: u32, username: &str, name: &str, key: &str) -> Response {
    let r = (|| {
        let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
        let path = state_path(KIND, uid);
        let mut b: Book = load(&path);
        let added = b.add(name, key, now_unix())?;
        if added {
            save(&path, &b)?;
        }
        Ok(added)
    })();
    audit_r("share-contact-add", uid, username, None, &r);
    match r {
        Ok(true) => super::done("contact pinned"),
        Ok(false) => super::done("already pinned to this key"),
        Err(e) => Response::fail(e),
    }
}

pub fn handle_list(uid: u32) -> Response {
    SharingResponse::ShareContacts {
        contacts: book(uid).infos(),
    }
    .into()
}

pub fn handle_remove(uid: u32, username: &str, name: &str) -> Response {
    let r = (|| {
        let name = normalize_name(name)?;
        let _g = LOCK.lock().map_err(|_| "state lock poisoned")?;
        let path = state_path(KIND, uid);
        let mut b: Book = load(&path);
        let before = b.contacts.len();
        b.contacts.retain(|c| c.name != name);
        if b.contacts.len() == before {
            return Err(format!("no contact named {name}"));
        }
        save(&path, &b)
    })();
    audit_r("share-contact-rm", uid, username, None, &r);
    match r {
        Ok(()) => super::done("contact removed"),
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_sharing::kem::ShareSecret;
    use crate::daemon_store::testkit;

    fn key() -> String {
        ShareSecret::generate().unwrap().recipient().text()
    }

    fn names(uid: u32) -> Vec<String> {
        match handle_list(uid) {
            Response::Sharing(SharingResponse::ShareContacts { contacts }) => {
                contacts.into_iter().map(|c| c.name).collect()
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn add_list_remove() {
        let u = testkit::uid();
        let (k1, k2) = (key(), key());
        assert!(handle_add(u, "t", "Bob", &k1).is_success());
        assert!(handle_add(u, "t", "carol@example.org", &k2).is_success());
        assert_eq!(names(u), ["bob", "carol@example.org"]);
        // Same name, same key: fine; another key: refused (pinned).
        assert!(handle_add(u, "t", "bob", &k1).is_success());
        let r = handle_add(u, "t", "BOB", &k2);
        assert!(matches!(&r, Response::Err { error } if error.contains("pinned to another key")));
        assert!(handle_remove(u, "t", "bob").is_success());
        assert!(!handle_remove(u, "t", "bob").is_success());
        assert_eq!(names(u), ["carol@example.org"]);
        // Now the name can be pinned to the other key.
        assert!(handle_add(u, "t", "bob", &k2).is_success());
        // Another user sees none of them.
        assert!(names(testkit::uid()).is_empty());
    }

    #[test]
    fn bad_names_and_keys_are_refused() {
        let u = testkit::uid();
        for bad in ["", "a b", "kepr-pk2-x", "x/y", &"a".repeat(65)] {
            assert!(!handle_add(u, "t", bad, &key()).is_success(), "{bad:?}");
        }
        assert!(!handle_add(u, "t", "dave", "kepr-pk2-notakey").is_success());
    }

    #[test]
    fn resolve_takes_a_key_or_a_pinned_name_only() {
        let u = testkit::uid();
        let k = key();
        let (r, label) = resolve(u, &k).unwrap();
        assert_eq!(r.text(), k);
        assert!(label.starts_with("key:"));
        let err = resolve(u, "erin").err().unwrap();
        assert!(err.contains("no pinned contact named erin"), "{err}");
        assert!(handle_add(u, "t", "erin", &k).is_success());
        let (r, label) = resolve(u, "Erin").unwrap();
        assert_eq!((r.text(), label.as_str()), (k, "erin"));
    }

    #[test]
    fn send_to_a_contact_lands_in_the_ledger_and_carries_the_view_window() {
        use crate::daemon_share::{handle_key, handle_receive, handle_send, SendOptions};
        let (a, b) = (testkit::uid(), testkit::uid());
        let Response::ShareKeyOk { public } = handle_key(b, "t", true) else {
            panic!("no share key");
        };
        testkit::set(a, "CT_API", "v1");
        let opts = || SendOptions {
            ttl: Some(600),
            view_window: Some(120),
        };
        // Not pinned yet: refused, nothing sent.
        let r = handle_send((a, 0), "t", "CT_API", "bob", opts());
        assert!(matches!(&r, Response::Err { error } if error.contains("no pinned contact")));
        assert!(crate::daemon_sharing::sent::rows(a).is_empty());
        assert!(handle_add(a, "t", "bob", &public).is_success());
        let Response::ShareOk { envelope, .. } = handle_send((a, 0), "t", "CT_API", "bob", opts())
        else {
            panic!("send failed");
        };
        let rows = crate::daemon_sharing::sent::rows(a);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].kind.as_str(), rows[0].to.as_deref()),
            ("envelope", Some("bob"))
        );
        assert!(rows[0].opened_unix.is_none());
        assert!(handle_receive(b, "t", &envelope, None).is_success());
        assert_eq!(testkit::value(b, "CT_API").as_deref(), Some("v1"));
        assert_eq!(testkit::meta(b, "CT_API").view_window_secs, Some(120));
        // Received on this daemon: the sender's row shows it opened.
        assert!(crate::daemon_sharing::sent::rows(a)[0]
            .opened_unix
            .is_some());
    }

    #[test]
    fn fingerprints_are_short_and_stable() {
        let f = fingerprint("kepr-pk2-AAAA");
        assert_eq!(f.len(), 19);
        assert_eq!(f, fingerprint("kepr-pk2-AAAA"));
        assert_ne!(f, fingerprint("kepr-pk2-AAAB"));
    }
}
