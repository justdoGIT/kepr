// cli_store/organize.rs — `kepr tag NAME [+T|-T|T]...` and
// `kepr mv NAME FOLDER` (T5.01). The daemon validates; tags are
// lower-cased here for convenience.

use kepr_core::protocol::Response;
use kepr_core::protocol_store::{StoreRequest, StoreResponse};

use super::{plain_args, send};
use crate::{cli_mode, cli_ui};

/// `(add, remove)` from `+t` / `-t` / `t` words.
fn tag_changes(words: &[&str]) -> (Vec<String>, Vec<String>) {
    let (mut add, mut remove) = (Vec::new(), Vec::new());
    for w in words {
        match (w.strip_prefix('+'), w.strip_prefix('-')) {
            (Some(t), _) => add.push(t.to_lowercase()),
            (_, Some(t)) => remove.push(t.to_lowercase()),
            _ => add.push(w.to_lowercase()),
        }
    }
    (add, remove)
}

pub fn cmd_tag(args: &[String]) -> Response {
    let words = plain_args(args);
    let Some((name, changes)) = words.split_first() else {
        return Response::fail("usage: kepr tag NAME [+TAG|-TAG]...");
    };
    let (add_tags, remove_tags) = tag_changes(changes);
    show(send(StoreRequest::Organize {
        name: name.to_uppercase(),
        add_tags,
        remove_tags,
        folder: None,
    }))
}

pub fn cmd_mv(args: &[String]) -> Response {
    let [name, folder] = plain_args(args)[..] else {
        return Response::fail("usage: kepr mv NAME FOLDER   (kepr mv NAME / clears it)");
    };
    show(send(StoreRequest::Organize {
        name: name.to_uppercase(),
        add_tags: vec![],
        remove_tags: vec![],
        folder: Some(folder.to_string()),
    }))
}

fn show(r: Response) -> Response {
    if cli_mode::json_mode() {
        return r;
    }
    if let Response::Store(StoreResponse::OrganizeOk { name, tags, folder }) = &r {
        let tags = if tags.is_empty() {
            "no tags".to_string()
        } else {
            let t: Vec<String> = tags.iter().map(|t| format!("#{t}")).collect();
            t.join(" ")
        };
        let folder = folder
            .as_deref()
            .map_or("no folder".to_string(), |f| format!("{f}/"));
        cli_ui::ok(&format!("{name}  {tags}  {folder}"));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plus_minus_and_bare_words() {
        let (a, r) = tag_changes(&["+Work", "-old", "ci"]);
        assert_eq!(a, vec!["work", "ci"]);
        assert_eq!(r, vec!["old"]);
    }

    #[test]
    fn usage_errors() {
        assert!(matches!(cmd_tag(&[]), Response::Err { .. }));
        assert!(matches!(cmd_mv(&["A".to_string()]), Response::Err { .. }));
    }
}
