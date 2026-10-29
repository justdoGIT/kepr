// cli_desktop/ss/names.rs — the names of the Secret Service API
// (org.freedesktop.Secret, specification 0.2): bus name, interfaces,
// error names and the object tree
//
//   /org/freedesktop/secrets                          Service
//   /org/freedesktop/secrets/collection/<id>          Collection
//   /org/freedesktop/secrets/collection/<id>/<item>   Item
//   /org/freedesktop/secrets/aliases/<alias>          a Collection, by alias
//   /org/freedesktop/secrets/session/<id>             Session
//   /org/freedesktop/secrets/prompt/<id>              Prompt

pub const BUS_NAME: &str = "org.freedesktop.secrets";
pub const ROOT: &str = "/org/freedesktop/secrets";
pub const NONE: &str = "/";

pub const I_SERVICE: &str = "org.freedesktop.Secret.Service";
pub const I_COLLECTION: &str = "org.freedesktop.Secret.Collection";
pub const I_ITEM: &str = "org.freedesktop.Secret.Item";
pub const I_SESSION: &str = "org.freedesktop.Secret.Session";
pub const I_PROMPT: &str = "org.freedesktop.Secret.Prompt";
pub const I_PROPS: &str = "org.freedesktop.DBus.Properties";
pub const I_INTRO: &str = "org.freedesktop.DBus.Introspectable";
pub const I_PEER: &str = "org.freedesktop.DBus.Peer";

pub const P_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const P_ATTRS: &str = "org.freedesktop.Secret.Item.Attributes";
pub const P_COLL_LABEL: &str = "org.freedesktop.Secret.Collection.Label";

pub const E_LOCKED: &str = "org.freedesktop.Secret.Error.IsLocked";
pub const E_NO_SESSION: &str = "org.freedesktop.Secret.Error.NoSession";
pub const E_NO_OBJECT: &str = "org.freedesktop.Secret.Error.NoSuchObject";
pub const E_UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
pub const E_UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
pub const E_UNKNOWN_IFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
pub const E_UNKNOWN_PROP: &str = "org.freedesktop.DBus.Error.UnknownProperty";
pub const E_READ_ONLY: &str = "org.freedesktop.DBus.Error.PropertyReadOnly";
pub const E_INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";
pub const E_NOT_SUPPORTED: &str = "org.freedesktop.DBus.Error.NotSupported";
pub const E_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
pub const E_FAILED: &str = "org.freedesktop.DBus.Error.Failed";

/// A D-Bus error to send back: name and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DErr(pub &'static str, pub String);

impl DErr {
    pub fn new(name: &'static str, text: impl Into<String>) -> DErr {
        DErr(name, text.into())
    }

    pub fn args(text: impl Into<String>) -> DErr {
        DErr(E_INVALID_ARGS, text.into())
    }
}

impl From<super::store::StoreError> for DErr {
    fn from(e: super::store::StoreError) -> DErr {
        use super::store::StoreError as S;
        match e {
            S::Locked => DErr(
                E_LOCKED,
                "the kepr store is locked; unlock it with `kepr unlock`".into(),
            ),
            S::NotFound => DErr(E_NO_OBJECT, "no such object".into()),
            S::Invalid(t) => DErr(E_INVALID_ARGS, t),
            S::Other(t) => DErr(E_FAILED, t),
        }
    }
}

pub type DResult<T> = Result<T, DErr>;

/// What an object path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Obj {
    Service,
    Collection(String),
    /// A collection reached through `/aliases/<alias>`.
    Alias(String),
    Item(String, String),
    Session(String),
    Prompt(String),
}

pub fn collection_path(id: &str) -> String {
    format!("{ROOT}/collection/{id}")
}

pub fn item_path(collection: &str, id: &str) -> String {
    format!("{ROOT}/collection/{collection}/{id}")
}

pub fn alias_path(alias: &str) -> String {
    format!("{ROOT}/aliases/{alias}")
}

pub fn session_path(id: &str) -> String {
    format!("{ROOT}/session/{id}")
}

pub fn prompt_path(id: &str) -> String {
    format!("{ROOT}/prompt/{id}")
}

pub fn parse(path: &str) -> Option<Obj> {
    if path == ROOT {
        return Some(Obj::Service);
    }
    let rest = path.strip_prefix(ROOT)?.strip_prefix('/')?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        ["collection", c] => Some(Obj::Collection((*c).into())),
        ["collection", c, i] => Some(Obj::Item((*c).into(), (*i).into())),
        ["aliases", a] => Some(Obj::Alias((*a).into())),
        ["session", s] => Some(Obj::Session((*s).into())),
        ["prompt", p] => Some(Obj::Prompt((*p).into())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_parse_and_build_both_ways() {
        assert_eq!(parse(ROOT), Some(Obj::Service));
        assert_eq!(
            parse(&collection_path("login")),
            Some(Obj::Collection("login".into()))
        );
        assert_eq!(
            parse(&item_path("login", "ABC")),
            Some(Obj::Item("login".into(), "ABC".into()))
        );
        assert_eq!(
            parse(&alias_path("default")),
            Some(Obj::Alias("default".into()))
        );
        assert_eq!(parse(&session_path("s1")), Some(Obj::Session("s1".into())));
        assert_eq!(parse(&prompt_path("p1")), Some(Obj::Prompt("p1".into())));
        for bad in [
            "/",
            "/org/freedesktop/secret",
            "/org/freedesktop/secrets/collection",
            "/org/freedesktop/secrets/collection/a/b/c",
            "/org/freedesktop/secrets/other/x",
            "/org/freedesktop/secretsX",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn built_paths_are_valid_object_paths() {
        use super::super::super::dbus::marshal::valid_path;
        for p in [
            collection_path("login"),
            item_path("c1f", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            alias_path("default"),
            session_path("s0a1"),
            prompt_path("p9"),
        ] {
            assert!(valid_path(&p), "{p}");
        }
    }

    #[test]
    fn store_errors_become_the_spec_s_errors() {
        use super::super::store::StoreError as S;
        assert_eq!(DErr::from(S::Locked).0, E_LOCKED);
        assert_eq!(DErr::from(S::NotFound).0, E_NO_OBJECT);
        assert_eq!(
            DErr::from(S::Invalid("x".into())),
            DErr(E_INVALID_ARGS, "x".into())
        );
        assert_eq!(DErr::from(S::Other("y".into())).0, E_FAILED);
    }
}
