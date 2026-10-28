// cli_store/list.rs — `kepr ls` additions: client-side `--tag` /
// `--folder` filtering and the tags / folder column (T5.01).

use kepr_core::protocol::{CredInfo, Response};

use super::flags::StoreFlags;
use crate::cli_args::Args;

/// Keep only the entries `ls --tag/--folder` asked for. The Secret Service
/// items programs keep through `kepr secret-service` (T13.28) are folded into
/// one line unless `--folder` names their folder: a browser can hold hundreds.
pub fn filter_list(a: &Args, resp: Response) -> Response {
    filter(&a.store, resp)
}

fn filter(f: &StoreFlags, resp: Response) -> Response {
    match resp {
        Response::ListOk { credentials, .. } => {
            let asked = f.folder.is_some();
            let (items, rest): (Vec<CredInfo>, Vec<CredInfo>) = credentials
                .into_iter()
                .partition(|c| !asked && is_secret_service(&c.name));
            if !items.is_empty() && !crate::cli_mode::json_mode() {
                let n = items.iter().filter(|c| c.name.starts_with("SSI_")).count();
                crate::cli_ui::info(&format!(
                    "{n} Secret Service item(s) are not listed here: kepr secret ls"
                ));
            }
            let credentials: Vec<CredInfo> = rest.into_iter().filter(|c| wanted(f, c)).collect();
            Response::ListOk {
                count: credentials.len(),
                credentials,
            }
        }
        other => other,
    }
}

/// The credentials behind the Secret Service front end.
fn is_secret_service(name: &str) -> bool {
    name.starts_with("SSI_") || name == "SSCOLLECTIONS"
}

fn wanted(f: &StoreFlags, c: &CredInfo) -> bool {
    let tag_ok = f
        .tag
        .as_ref()
        .is_none_or(|t| c.tags.as_ref().is_some_and(|ts| ts.contains(t)));
    let folder_ok = f
        .folder
        .as_ref()
        .is_none_or(|w| in_folder(c.folder.as_deref(), w));
    tag_ok && folder_ok
}

/// `a` matches folders `a` and `a/b`; `/` matches keys with no folder.
fn in_folder(have: Option<&str>, want: &str) -> bool {
    match (have, want.trim_matches('/')) {
        (None, w) => w.is_empty(),
        (Some(_), "") => false,
        (Some(h), w) => h == w || h.strip_prefix(w).is_some_and(|r| r.starts_with('/')),
    }
}

/// Extra `kepr ls` columns: `  -> TARGET  work/ci/  #prod #team`.
pub fn list_tail(c: &CredInfo) -> String {
    let mut t = String::new();
    if let Some(target) = &c.alias_of {
        t.push_str(&format!("  -> {target}"));
    }
    if let Some(f) = &c.folder {
        t.push_str(&format!("  {f}/"));
    }
    if let Some(tags) = c.tags.as_ref().filter(|t| !t.is_empty()) {
        let tags: Vec<String> = tags.iter().map(|x| format!("#{x}")).collect();
        t.push_str(&format!("  {}", tags.join(" ")));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, tags: &[&str], folder: Option<&str>) -> CredInfo {
        let mut c: CredInfo = serde_json::from_value(serde_json::json!({
            "name": name, "cred_name": "", "size": 1, "modified": ""
        }))
        .unwrap();
        c.tags = (!tags.is_empty()).then(|| tags.iter().map(|t| t.to_string()).collect());
        c.folder = folder.map(str::to_string);
        c
    }

    #[test]
    fn folder_matching() {
        assert!(in_folder(Some("a"), "a"));
        assert!(in_folder(Some("a/b"), "a"));
        assert!(in_folder(Some("a/b"), "/a/"));
        assert!(!in_folder(Some("ab"), "a"));
        assert!(!in_folder(None, "a"));
        assert!(in_folder(None, "/"));
        assert!(!in_folder(Some("a"), "/"));
    }

    #[test]
    fn secret_service_items_fold_away_unless_their_folder_is_asked_for() {
        let creds = vec![
            cred("A", &[], None),
            cred(
                "SSI_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                &[],
                Some("secret-service"),
            ),
            cred("SSCOLLECTIONS", &[], Some("secret-service")),
        ];
        let list = |folder: Option<&str>| {
            let f = StoreFlags {
                folder: folder.map(String::from),
                ..Default::default()
            };
            match filter(
                &f,
                Response::ListOk {
                    count: 3,
                    credentials: creds.clone(),
                },
            ) {
                Response::ListOk { count, credentials } => (count, credentials.len()),
                _ => unreachable!(),
            }
        };
        assert_eq!(list(None), (1, 1));
        assert_eq!(list(Some("secret-service")), (2, 2));
        assert!(is_secret_service("SSI_X") && !is_secret_service("SSH_KEY"));
    }

    #[test]
    fn tag_and_folder_filters_combine() {
        let f = StoreFlags {
            tag: Some("prod".into()),
            folder: Some("team".into()),
            ..Default::default()
        };
        assert!(wanted(&f, &cred("A", &["prod"], Some("team/x"))));
        assert!(!wanted(&f, &cred("B", &["dev"], Some("team"))));
        assert!(!wanted(&f, &cred("C", &["prod"], None)));
        assert!(wanted(&StoreFlags::default(), &cred("D", &[], None)));
    }

    #[test]
    fn tail_shows_folder_and_tags() {
        assert_eq!(
            list_tail(&cred("A", &["a", "b"], Some("w/c"))),
            "  w/c/  #a #b"
        );
        assert_eq!(list_tail(&cred("A", &[], None)), "");
        let mut a = cred("AL", &[], None);
        a.alias_of = Some("A".into());
        assert_eq!(list_tail(&a), "  -> A");
    }
}
