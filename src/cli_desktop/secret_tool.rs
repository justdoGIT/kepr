// cli_desktop/secret_tool.rs — `kepr secret store|lookup|search|clear|ls`:
// the libsecret `secret-tool` verbs, straight against kepr's item store
// (no D-Bus, no libsecret-tools needed). The items are the same ones
// programs reach through the Secret Service.
//
//   printf %s "$TOKEN" | kepr secret store --label "GitHub" service gh user me
//   kepr secret lookup service gh user me        # the secret, no newline
//   kepr secret search service gh                # labels and attributes only
//   kepr secret clear service gh user me

use std::io::{IsTerminal, Read, Write};

use kepr_core::protocol::Response;
use kepr_core::protocol_desktop::{self as pd, DesktopResponse, SsItemInfo};
use zeroize::Zeroizing;

use super::ss::caller::printable;
use super::ss::daemon_store::DaemonStore;
use super::ss::store::{Attrs, Store, StoreError};
use crate::{cli_mode, cli_ui};

const USAGE: &str = "\
usage: kepr secret store [--label TEXT] [--collection ID] ATTR VALUE [ATTR VALUE…]   (secret on stdin)
       kepr secret lookup ATTR VALUE [ATTR VALUE…]
       kepr secret search [--all] [--secrets] ATTR VALUE [ATTR VALUE…]
       kepr secret clear ATTR VALUE [ATTR VALUE…]
       kepr secret ls [--collection ID]";

/// `KEY VALUE KEY VALUE…`
pub fn parse_attrs(args: &[&str]) -> Result<Attrs, String> {
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return Err("give attribute pairs: ATTRIBUTE VALUE [ATTRIBUTE VALUE…]".into());
    }
    let attrs: Attrs = args
        .chunks(2)
        .map(|p| (p[0].to_string(), p[1].to_string()))
        .collect();
    if attrs.len() != args.len() / 2 {
        return Err("an attribute is given twice".into());
    }
    pd::validate_attributes(&attrs)?;
    Ok(attrs)
}

fn read_secret() -> Result<Zeroizing<Vec<u8>>, String> {
    if std::io::stdin().is_terminal() {
        let s = crate::cli_input::read_masked("Secret: ");
        return Ok(Zeroizing::new(s.as_str().as_bytes().to_vec()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(pd::MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading the secret: {e}"))?;
    Ok(buf)
}

fn fail(e: StoreError) -> Response {
    Response::fail(match e {
        StoreError::Locked => "kepr is locked: run `kepr unlock` first".to_string(),
        other => other.to_string(),
    })
}

pub fn store_item(
    store: &dyn Store,
    collection: &str,
    label: &str,
    attrs: &Attrs,
    secret: &[u8],
) -> Result<SsItemInfo, StoreError> {
    if secret.len() > pd::MAX_SECRET_BYTES {
        return Err(StoreError::Invalid(format!(
            "the secret is longer than {} bytes",
            pd::MAX_SECRET_BYTES
        )));
    }
    store.create_item((collection, label, attrs), ("text/plain", secret), true)
}

/// Items whose attributes include every given pair, oldest first.
pub fn find(store: &dyn Store, attrs: &Attrs) -> Result<Vec<SsItemInfo>, StoreError> {
    let mut v = store.items(None, attrs)?;
    v.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
    Ok(v)
}

fn describe(i: &SsItemInfo) -> String {
    // Labels and attributes are whatever the program that stored the item
    // chose; an escape sequence in one must not act on this terminal.
    let attrs: Vec<String> = i
        .attributes
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect();
    printable(&format!(
        "[{}/{}] {}  ({})",
        i.collection,
        i.id,
        i.label,
        attrs.join(", ")
    ))
}

fn open() -> DaemonStore {
    DaemonStore
}

pub fn cmd(args: &[&str]) -> Response {
    let Some((sub, rest)) = args.split_first() else {
        return Response::fail(USAGE);
    };
    let store = open();
    match *sub {
        "store" => do_store(&store, rest),
        "lookup" => do_lookup(&store, rest),
        "search" => do_search(&store, rest),
        "clear" => do_clear(&store, rest),
        "ls" => do_ls(&store, rest),
        _ => Response::fail(USAGE),
    }
}

fn do_store(store: &dyn Store, args: &[&str]) -> Response {
    let (mut label, mut coll) = (None, pd::LOGIN.to_string());
    let mut i = 0;
    while i < args.len() && args[i].starts_with("--") {
        let Some(v) = args.get(i + 1) else {
            return Response::fail(USAGE);
        };
        match args[i] {
            "--label" => label = Some(v.to_string()),
            "--collection" => coll = v.to_string(),
            _ => return Response::fail(USAGE),
        }
        i += 2;
    }
    let attrs = match parse_attrs(&args[i..]) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let label = label.unwrap_or_else(|| {
        attrs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    });
    let secret = match read_secret() {
        Ok(s) => s,
        Err(e) => return Response::fail(e),
    };
    match store_item(store, &coll, &label, &attrs, &secret) {
        Ok(_) => Response::Pong,
        Err(e) => fail(e),
    }
}

fn do_lookup(store: &dyn Store, args: &[&str]) -> Response {
    let attrs = match parse_attrs(args) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let found = match find(store, &attrs) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let Some(first) = found.first() else {
        return Response::fail("no such secret");
    };
    match store.secret(&first.id) {
        Ok((secret, _)) => {
            let mut out = std::io::stdout().lock();
            if out.write_all(&secret).and_then(|()| out.flush()).is_err() {
                return Response::fail("could not write the secret");
            }
            Response::Pong
        }
        Err(e) => fail(e),
    }
}

fn do_search(store: &dyn Store, args: &[&str]) -> Response {
    let (mut all, mut secrets) = (false, false);
    let mut i = 0;
    while i < args.len() && args[i].starts_with("--") {
        match args[i] {
            "--all" => all = true,
            "--secrets" => secrets = true,
            _ => return Response::fail(USAGE),
        }
        i += 1;
    }
    let attrs = match parse_attrs(&args[i..]) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let mut found = match find(store, &attrs) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    if !all {
        found.truncate(1);
    }
    if found.is_empty() {
        return Response::fail("no matching items");
    }
    if cli_mode::json_mode() {
        return Response::Desktop(DesktopResponse::SsItems { items: found });
    }
    for item in &found {
        println!("{}", describe(item));
        if secrets {
            match store.secret(&item.id) {
                Ok((s, _)) => println!("  secret = {}", String::from_utf8_lossy(&s)),
                Err(e) => return fail(e),
            }
        }
    }
    Response::Pong
}

fn do_clear(store: &dyn Store, args: &[&str]) -> Response {
    let attrs = match parse_attrs(args) {
        Ok(a) => a,
        Err(e) => return Response::fail(e),
    };
    let found = match find(store, &attrs) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    for item in &found {
        if let Err(e) = store.delete_item(&item.id) {
            return fail(e);
        }
    }
    if !cli_mode::json_mode() {
        cli_ui::info(&format!("deleted {} item(s)", found.len()));
    }
    Response::Pong
}

fn do_ls(store: &dyn Store, args: &[&str]) -> Response {
    let coll = match args {
        [] => None,
        ["--collection", c] => Some(*c),
        _ => return Response::fail(USAGE),
    };
    match store.items(coll, &Attrs::new()) {
        Ok(items) if cli_mode::json_mode() => Response::Desktop(DesktopResponse::SsItems { items }),
        Ok(items) => {
            for i in &items {
                println!("{}", describe(i));
            }
            if items.is_empty() {
                cli_ui::info("no items");
            }
            Response::Pong
        }
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_desktop::ss::store::MemStore;

    #[test]
    fn attribute_pairs() {
        assert_eq!(parse_attrs(&["a", "1", "b", "2"]).unwrap().len(), 2);
        assert!(parse_attrs(&[]).is_err() && parse_attrs(&["a"]).is_err());
        assert!(parse_attrs(&["a", "1", "a", "2"])
            .unwrap_err()
            .contains("twice"));
        assert!(parse_attrs(&["", "1"]).is_err());
    }

    #[test]
    fn store_replaces_find_matches_and_clear_deletes() {
        let m = MemStore::new(&["login"]);
        let a = parse_attrs(&["service", "gh", "user", "me"]).unwrap();
        store_item(&m, "login", "GitHub", &a, b"one").unwrap();
        store_item(&m, "login", "GitHub", &a, b"two").unwrap();
        let found = find(&m, &parse_attrs(&["service", "gh"]).unwrap()).unwrap();
        assert_eq!(found.len(), 1, "same attributes: replaced");
        assert_eq!(&m.secret(&found[0].id).unwrap().0[..], b"two");
        store_item(
            &m,
            "login",
            "Other",
            &parse_attrs(&["service", "gh", "user", "you"]).unwrap(),
            b"three",
        )
        .unwrap();
        assert_eq!(
            find(&m, &parse_attrs(&["service", "gh"]).unwrap())
                .unwrap()
                .len(),
            2
        );
        assert!(find(&m, &parse_attrs(&["service", "nope"]).unwrap())
            .unwrap()
            .is_empty());
        assert!(describe(&found[0]).contains("GitHub") && !describe(&found[0]).contains("two"));
        assert!(store_item(&m, "login", "Big", &a, &vec![0u8; pd::MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    fn a_hostile_label_or_attribute_prints_without_control_characters() {
        let m = MemStore::new(&[pd::LOGIN]);
        let a = parse_attrs(&["user", "x\x1b]0;pwned\x07"]).unwrap();
        let it = store_item(&m, "login", "\x1b[2Jlabel\r", &a, b"pw").unwrap();
        let line = describe(&it);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.contains("label") && line.contains("pwned"));
    }
}
