// daemon_store/search.rs — `kepr search PATTERN` (T11.1). Matches the
// caller's credential names, tags, folders, record types and a few
// non-secret record fields. Only those field names are ever read out of
// a record (the rest is skipped by the deserializer), the response holds
// names and the sources that matched (never a value), and a record is
// opened only when a plain `get` would succeed without a prompt: sealed,
// SSH, share-key, consent / FIDO2-gated and expired credentials match on
// their name, tags, folder and type only.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{SearchHit, StoreResponse};

use super::pattern::{self, Pattern};
use crate::audit::{self, AuditEvent, AuditResult};
use crate::expiry::{self, CredMeta};
use crate::{crypto, daemon_cache};

/// Record fields search may look at (none of them holds a secret).
#[derive(Default, serde::Deserialize)]
struct Searchable {
    username: Option<String>,
    user: Option<String>,
    url: Option<String>,
    host: Option<String>,
    holder: Option<String>,
}

impl Searchable {
    fn fields(&self) -> [(&'static str, &Option<String>); 5] {
        [
            ("username", &self.username),
            ("user", &self.user),
            ("url", &self.url),
            ("host", &self.host),
            ("holder", &self.holder),
        ]
    }
}

/// May search open this record's value? Only when `get` could, with
/// no prompt.
fn openable(meta: &CredMeta, now: u64) -> bool {
    meta.record_type.is_some()
        && meta.sealed != Some(true)
        && meta.ssh.is_none()
        && meta.share_key != Some(true)
        && meta.requires_consent != Some(true)
        && meta.requires_fido2 != Some(true)
        && meta.expires_at_unix.is_none_or(|t| now < t)
}

/// The sources of `name` / `meta` that match (empty = no hit).
fn matched(p: &Pattern, name: &str, meta: &CredMeta, record: &Searchable) -> Vec<String> {
    let mut out = Vec::new();
    let mut hit = |src: &str, text: &str| {
        if p.is_match(text) && !out.iter().any(|s| s == src) {
            out.push(src.to_string());
        }
    };
    hit("name", name);
    for t in meta.tags.iter().flatten() {
        hit("tag", t);
    }
    if let Some(f) = &meta.folder {
        hit("folder", f);
    }
    if let Some(t) = &meta.record_type {
        hit("type", t);
    }
    for (field, v) in record.fields() {
        if let Some(v) = v {
            hit(field, v);
        }
    }
    out
}

fn record_of(uid: u32, name: &str, meta: &CredMeta) -> Searchable {
    if !openable(meta, expiry::now_unix()) {
        return Searchable::default();
    }
    let _lock = crate::daemon_credlock::lock(uid, name);
    match crypto::default_backend().decrypt(uid, name) {
        Ok(v) => serde_json::from_str(v.as_str()).unwrap_or_default(),
        Err(_) => Searchable::default(),
    }
}

pub fn handle_search(uid: u32, username: &str, pattern: &str) -> Response {
    let p = match pattern::parse(pattern) {
        Ok(p) => p,
        Err(e) => return Response::fail(e),
    };
    let mut hits = Vec::new();
    for (name, path) in daemon_cache::list_for_uid(uid) {
        let meta = expiry::read_meta(&expiry::meta_path_for(&path))
            .and_then(Result::ok)
            .unwrap_or_default();
        let matched = matched(&p, &name, &meta, &record_of(uid, &name, &meta));
        if !matched.is_empty() {
            hits.push(SearchHit { name, matched });
        }
    }
    audit::log(&AuditEvent {
        op: "search",
        name: None,
        uid,
        username,
        result: AuditResult::Ok,
    });
    Response::Store(StoreResponse::SearchOk { hits })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_store::testkit;

    fn hits(uid: u32, p: &str) -> Vec<SearchHit> {
        match handle_search(uid, "t", p) {
            Response::Store(StoreResponse::SearchOk { hits }) => hits,
            other => panic!("unexpected {other:?}"),
        }
    }

    fn record(uid: u32, name: &str, ty: &str, fields: &str, consent: bool) {
        let r = crate::daemon_records::handle_record_set(
            uid,
            "t",
            name,
            (ty, &fields.into()),
            (consent.then_some(true), false),
        );
        assert!(r.is_success(), "{r:?}");
    }

    #[test]
    fn matches_each_source() {
        let uid = testkit::uid();
        testkit::set(uid, "STRIPE_KEY", "sk_live_zzz");
        record(
            uid,
            "BANK",
            "login",
            r#"{"username":"alice@example.com","password":"hunter2","url":"https://bank.example"}"#,
            false,
        );
        record(
            uid,
            "DB",
            "database",
            r#"{"host":"db.internal","user":"app","password":"p","database":"d"}"#,
            false,
        );
        super::super::organize::handle_organize(
            uid,
            "t",
            "STRIPE_KEY",
            (&["billing".into()], &[]),
            Some("pay/live"),
        );

        let names = |p: &str| -> Vec<(String, Vec<String>)> {
            hits(uid, p)
                .into_iter()
                .map(|h| (h.name, h.matched))
                .collect()
        };
        assert_eq!(
            names("stripe"),
            vec![("STRIPE_KEY".into(), vec!["name".to_string()])]
        );
        assert_eq!(
            names("billing"),
            vec![("STRIPE_KEY".into(), vec!["tag".to_string()])]
        );
        assert_eq!(
            names("pay/"),
            vec![("STRIPE_KEY".into(), vec!["folder".to_string()])]
        );
        assert_eq!(
            names("login"),
            vec![("BANK".into(), vec!["type".to_string()])]
        );
        assert_eq!(
            names("alice"),
            vec![("BANK".into(), vec!["username".to_string()])]
        );
        assert_eq!(
            names("bank.example"),
            vec![("BANK".into(), vec!["url".to_string()])]
        );
        assert_eq!(
            names("/^db\\.int/"),
            vec![("DB".into(), vec!["host".to_string()])]
        );
        assert_eq!(
            names("/^app$/"),
            vec![("DB".into(), vec!["user".to_string()])]
        );
    }

    #[test]
    fn secret_values_never_match() {
        let uid = testkit::uid();
        testkit::set(uid, "PLAIN", "needle-in-value");
        record(
            uid,
            "LOGIN",
            "login",
            r#"{"username":"bob","password":"needle-pw"}"#,
            false,
        );
        record(
            uid,
            "GUARDED",
            "login",
            r#"{"username":"needle-user"}"#,
            true,
        );
        assert!(hits(uid, "needle").is_empty());
        assert!(hits(uid, "sk_").is_empty());
        // A consent-gated record is not opened; its name still matches.
        assert_eq!(hits(uid, "guarded").len(), 1);
    }

    #[test]
    fn bad_pattern_is_an_error() {
        let uid = testkit::uid();
        assert!(!handle_search(uid, "t", "/[/").is_success());
    }
}
