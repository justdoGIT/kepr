// cli_store/list.rs — `kepr ls` additions: client-side `--tag` /
// `--folder` filtering and the tags / folder column (T5.01).

use kepr_core::protocol::{CredInfo, Response};

use super::flags::StoreFlags;
use crate::cli_args::Args;

/// Keep only the entries `ls --tag/--folder` asked for.
pub fn filter_list(a: &Args, resp: Response) -> Response {
    let f = &a.store;
    if f.tag.is_none() && f.folder.is_none() {
        return resp;
    }
    match resp {
        Response::ListOk { credentials, .. } => {
            let credentials: Vec<CredInfo> =
                credentials.into_iter().filter(|c| wanted(f, c)).collect();
            Response::ListOk {
                count: credentials.len(),
                credentials,
            }
        }
        other => other,
    }
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
    fn tag_and_folder_filters_combine() {
        let f = StoreFlags {
            tag: Some("prod".into()),
            folder: Some("team".into()),
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
