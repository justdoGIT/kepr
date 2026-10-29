// cli_desktop/import.rs — `kepr secret-service import`: copy the items of
// the session's current Secret Service provider (GNOME Keyring, KWallet,
// another kepr) into kepr's store.
//
//   * the provider's default collection goes to kepr's default (`login`),
//     the others to a kepr collection of the same id or label, made when
//     missing;
//   * an item kepr already has (same collection, same attributes) is kept
//     as it is, unless --overwrite;
//   * --dry-run reads labels and attributes only, never a secret;
//   * nothing is deleted from the provider.
//
// Secrets pass through memory that wipes itself and are never printed.

use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::{self as pd, SsCollectionInfo};
use zeroize::Zeroizing;

use super::ss::daemon_store::DaemonStore;
use super::ss::store::{Attrs, Store, StoreError};
use super::ss_client::{Client, RemoteItem};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "usage: kepr secret-service import [--dry-run] [--overwrite]";

/// What an import needs from the provider being read.
pub trait Source {
    /// The path of the collection the `default` alias names.
    fn default_collection(&self) -> Option<String>;
    fn collections(&self) -> Result<Vec<(String, String)>, String>;
    fn unlock(&self, collection: &str) -> Result<(), String>;
    fn items(&self, collection: &str) -> Result<Vec<RemoteItem>, String>;
    fn secret(&self, item: &str) -> Result<(Zeroizing<Vec<u8>>, String), String>;
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub imported: u32,
    pub replaced: u32,
    pub kept: u32,
    pub failed: Vec<String>,
    pub lines: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Existing(String),
    Create(String),
}

/// Where a provider's collection goes in kepr.
pub fn target(
    path: &str,
    label: &str,
    is_default: bool,
    local: &[SsCollectionInfo],
    local_default: &str,
) -> Target {
    if is_default {
        return Target::Existing(local_default.to_string());
    }
    let id = path.rsplit('/').next().unwrap_or("");
    if let Some(c) = local.iter().find(|c| c.id == id) {
        return Target::Existing(c.id.clone());
    }
    match local.iter().find(|c| c.label == label) {
        Some(c) => Target::Existing(c.id.clone()),
        None => Target::Create(label.to_string()),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Keep,
    Replace,
}

pub fn decide(has_same: bool, overwrite: bool) -> Action {
    match (has_same, overwrite) {
        (false, _) => Action::Create,
        (true, false) => Action::Keep,
        (true, true) => Action::Replace,
    }
}

fn tidy(label: &str) -> String {
    let t: String = label.chars().filter(|c| !c.is_control()).collect();
    if t.is_empty() {
        "(no label)".into()
    } else {
        t
    }
}

pub fn run(
    src: &dyn Source,
    store: &dyn Store,
    dry: bool,
    overwrite: bool,
) -> Result<Report, String> {
    let mut rep = Report::default();
    let (mut local, aliases) = store.collections().map_err(|e| e.to_string())?;
    let local_default = aliases
        .get("default")
        .cloned()
        .unwrap_or_else(|| pd::LOGIN.to_string());
    let remote_default = src.default_collection();
    for (path, label) in src.collections()? {
        let is_default = remote_default.as_deref() == Some(path.as_str());
        let dest = match target(&path, &label, is_default, &local, &local_default) {
            Target::Existing(id) => id,
            Target::Create(l) if dry => {
                rep.lines
                    .push(format!("would make the collection {:?}", tidy(&l)));
                format!("the new collection {:?}", tidy(&l))
            }
            Target::Create(l) => {
                let made = store
                    .create_collection(&l, None)
                    .map_err(|e| e.to_string())?;
                local.push(made.clone());
                made.id
            }
        };
        if let Err(e) = src.unlock(&path) {
            rep.failed.push(format!("{}: {e}", tidy(&label)));
            continue;
        }
        for item in src.items(&path)? {
            import_one(src, store, &dest, &item, (dry, overwrite), &mut rep);
        }
    }
    Ok(rep)
}

fn import_one(
    src: &dyn Source,
    store: &dyn Store,
    dest: &str,
    item: &RemoteItem,
    (dry, overwrite): (bool, bool),
    rep: &mut Report,
) {
    let label = tidy(&item.label);
    let same = store
        .items(Some(dest), &item.attributes)
        .map(|v| v.iter().any(|i| i.attributes == item.attributes))
        .unwrap_or(false);
    let action = decide(same, overwrite);
    if action == Action::Keep {
        rep.kept += 1;
        return;
    }
    if dry {
        rep.lines.push(format!(
            "would {} {label:?} in {dest}",
            if action == Action::Create {
                "import"
            } else {
                "replace"
            }
        ));
        return;
    }
    let result = src.secret(&item.path).and_then(|(secret, ct)| {
        let attrs: Attrs = item.attributes.clone();
        store
            .create_item(
                (dest, &item.label, &attrs),
                (&ct, &secret),
                action == Action::Replace,
            )
            .map_err(|e| match e {
                StoreError::Locked => "kepr is locked: run `kepr unlock` first".to_string(),
                other => other.to_string(),
            })
    });
    match (result, action) {
        (Ok(_), Action::Replace) => rep.replaced += 1,
        (Ok(_), _) => rep.imported += 1,
        (Err(e), _) => rep.failed.push(format!("{label}: {e}")),
    }
}

impl Source for Client {
    fn default_collection(&self) -> Option<String> {
        self.read_alias("default")
    }
    fn collections(&self) -> Result<Vec<(String, String)>, String> {
        Client::collections(self)?
            .into_iter()
            .map(|p| Ok((p.clone(), self.collection_label(&p)?)))
            .collect()
    }
    fn unlock(&self, collection: &str) -> Result<(), String> {
        if self.is_locked(collection, super::ss::names::I_COLLECTION)? {
            Client::unlock(self, vec![collection.to_string()])?;
        }
        Ok(())
    }
    fn items(&self, collection: &str) -> Result<Vec<RemoteItem>, String> {
        Client::items(self, collection)?
            .iter()
            .map(|p| self.item(p))
            .collect()
    }
    fn secret(&self, item: &str) -> Result<(Zeroizing<Vec<u8>>, String), String> {
        Client::secret(self, item)
    }
}

fn say(m: &str) {
    if !cli_mode::json_mode() {
        cli_ui::info(m);
    }
}

/// `import` from the provider on the session bus; also used by takeover.
pub fn from_session(dry: bool, overwrite: bool) -> Result<Report, String> {
    let store = DaemonStore;
    if !dry && store.locked().unwrap_or(true) {
        return Err("kepr is locked: run `kepr unlock` first, then import".into());
    }
    let client =
        Client::open().map_err(|e| format!("cannot read the current Secret Service: {e}"))?;
    let r = run(&client, &store, dry, overwrite);
    client.close();
    r
}

pub fn print(rep: &Report, dry: bool) {
    for l in &rep.lines {
        say(l);
    }
    let kept = if rep.kept > 0 {
        format!(", {} already in kepr kept as they are", rep.kept)
    } else {
        String::new()
    };
    if dry {
        say(&format!("dry run: nothing written{kept}"));
    } else {
        say(&format!(
            "imported {}, replaced {}{kept}",
            rep.imported, rep.replaced
        ));
    }
    for f in &rep.failed {
        cli_ui::warn(&format!("not imported: {f}"));
    }
}

pub fn cmd(args: &[&str]) -> Response {
    let (mut dry, mut overwrite) = (false, false);
    for a in args {
        match *a {
            "--dry-run" => dry = true,
            "--overwrite" => overwrite = true,
            _ => return Response::fail(USAGE),
        }
    }
    match from_session(dry, overwrite) {
        Ok(rep) => {
            print(&rep, dry);
            if rep.failed.is_empty() {
                Response::Pong
            } else {
                Response::fail(format!(
                    "{} item(s) could not be imported",
                    rep.failed.len()
                ))
            }
        }
        Err(e) => Response::fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_desktop::ss::store::MemStore;
    use std::collections::BTreeMap;

    type Items = Vec<(String, BTreeMap<String, String>, &'static [u8])>;

    struct Fake {
        colls: Vec<(String, String, Items)>,
        default: &'static str,
        locked: bool,
    }

    impl Source for Fake {
        fn default_collection(&self) -> Option<String> {
            Some(self.default.into())
        }
        fn collections(&self) -> Result<Vec<(String, String)>, String> {
            Ok(self
                .colls
                .iter()
                .map(|c| (c.0.clone(), c.1.clone()))
                .collect())
        }
        fn unlock(&self, _: &str) -> Result<(), String> {
            if self.locked {
                Err("the unlock was dismissed".into())
            } else {
                Ok(())
            }
        }
        fn items(&self, coll: &str) -> Result<Vec<RemoteItem>, String> {
            let c = self
                .colls
                .iter()
                .find(|c| c.0 == coll)
                .ok_or("no such collection")?;
            Ok(c.2
                .iter()
                .map(|(l, a, _)| RemoteItem {
                    path: format!("{coll}/{l}"),
                    label: l.clone(),
                    attributes: a.clone(),
                    created: 1,
                })
                .collect())
        }
        fn secret(&self, item: &str) -> Result<(Zeroizing<Vec<u8>>, String), String> {
            for c in &self.colls {
                for (l, _, s) in &c.2 {
                    if format!("{}/{l}", c.0) == item {
                        return Ok((Zeroizing::new(s.to_vec()), "text/plain".into()));
                    }
                }
            }
            Err("no such item".into())
        }
    }

    fn attrs(k: &str, v: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(k.to_string(), v.to_string())])
    }

    fn fake() -> Fake {
        Fake {
            colls: vec![
                (
                    "/c/kdewallet".into(),
                    "Wallet".into(),
                    vec![
                        ("Mail".into(), attrs("user", "a"), b"one"),
                        ("Git".into(), attrs("host", "gh"), b"two"),
                    ],
                ),
                (
                    "/c/work".into(),
                    "Work".into(),
                    vec![("VPN".into(), attrs("vpn", "x"), b"three")],
                ),
            ],
            default: "/c/kdewallet",
            locked: false,
        }
    }

    #[test]
    fn the_default_collection_lands_in_login_and_others_get_their_own() {
        let store = MemStore::new(&["login"]);
        let rep = run(&fake(), &store, false, false).unwrap();
        assert_eq!((rep.imported, rep.kept, rep.failed.len()), (3, 0, 0));
        let login = store.items(Some("login"), &Attrs::new()).unwrap();
        assert_eq!(login.len(), 2);
        let (colls, _) = store.collections().unwrap();
        let work = colls
            .iter()
            .find(|c| c.label == "Work")
            .expect("a collection for Work");
        assert_eq!(store.items(Some(&work.id), &Attrs::new()).unwrap().len(), 1);
        let id = &login.iter().find(|i| i.label == "Mail").unwrap().id;
        assert_eq!(&store.secret(id).unwrap().0[..], b"one");
    }

    #[test]
    fn a_second_run_changes_nothing_and_overwrite_replaces() {
        let store = MemStore::new(&["login"]);
        run(&fake(), &store, false, false).unwrap();
        let again = run(&fake(), &store, false, false).unwrap();
        assert_eq!((again.imported, again.kept), (0, 3));
        assert_eq!(store.items(None, &Attrs::new()).unwrap().len(), 3);
        let over = run(&fake(), &store, false, true).unwrap();
        assert_eq!((over.imported, over.replaced), (0, 3));
        assert_eq!(
            store.items(None, &Attrs::new()).unwrap().len(),
            3,
            "replaced, not doubled"
        );
    }

    #[test]
    fn a_dry_run_writes_nothing_and_reads_no_secret() {
        let store = MemStore::new(&["login"]);
        let rep = run(&fake(), &store, true, false).unwrap();
        assert!(store.items(None, &Attrs::new()).unwrap().is_empty());
        assert_eq!(
            store.collections().unwrap().0.len(),
            1,
            "no collection made either"
        );
        assert_eq!(rep.lines.len(), 4, "{:?}", rep.lines);
        assert!(rep
            .lines
            .iter()
            .all(|l| !l.contains("one") && !l.contains("two")));
    }

    #[test]
    fn a_collection_the_person_would_not_unlock_is_reported_and_the_rest_goes_on() {
        let store = MemStore::new(&["login"]);
        let mut f = fake();
        f.locked = true;
        let rep = run(&f, &store, false, false).unwrap();
        assert_eq!(rep.imported, 0);
        assert_eq!(rep.failed.len(), 2);
    }

    #[test]
    fn collections_map_by_default_id_then_label() {
        let local = vec![
            SsCollectionInfo {
                id: "login".into(),
                label: "Login".into(),
                created: 0,
                modified: 0,
                items: 0,
            },
            SsCollectionInfo {
                id: "work".into(),
                label: "Work".into(),
                created: 0,
                modified: 0,
                items: 0,
            },
        ];
        assert_eq!(
            target("/c/x", "X", true, &local, "login"),
            Target::Existing("login".into())
        );
        assert_eq!(
            target("/c/work", "Anything", false, &local, "login"),
            Target::Existing("work".into())
        );
        assert_eq!(
            target("/c/other", "Work", false, &local, "login"),
            Target::Existing("work".into())
        );
        assert_eq!(
            target("/c/other", "Other", false, &local, "login"),
            Target::Create("Other".into())
        );
        assert_eq!(decide(false, false), Action::Create);
        assert_eq!(decide(true, false), Action::Keep);
        assert_eq!(decide(true, true), Action::Replace);
    }

    #[test]
    fn a_locked_kepr_is_named_not_hidden() {
        let store = MemStore::new(&["login"]);
        store.set_locked(true);
        // MemStore refuses everything but the question while locked.
        assert!(run(&fake(), &store, false, false).is_err());
    }
}
