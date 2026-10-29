// cli_desktop/ss/intro.rs — org.freedesktop.DBus.Introspectable: the XML
// that `busctl introspect`, `gdbus introspect` and D-Spy show. Clients of
// the Secret Service do not need it (their libraries know the interfaces);
// people debugging one do.

use super::names::{self as n, DErr, DResult, Obj};
use super::server::Server;

const HEAD: &str = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n<node>\n";

const STANDARD: &str = r#"  <interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg type="s" direction="out"/></method></interface>
  <interface name="org.freedesktop.DBus.Peer"><method name="Ping"/><method name="GetMachineId"><arg type="s" direction="out"/></method></interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
    <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
    <method name="Set"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/></method>
    <signal name="PropertiesChanged"><arg type="s"/><arg type="a{sv}"/><arg type="as"/></signal>
  </interface>
"#;

const SERVICE: &str = r#"  <interface name="org.freedesktop.Secret.Service">
    <property name="Collections" type="ao" access="read"/>
    <method name="OpenSession"><arg name="algorithm" type="s" direction="in"/><arg name="input" type="v" direction="in"/><arg name="output" type="v" direction="out"/><arg name="result" type="o" direction="out"/></method>
    <method name="CreateCollection"><arg name="properties" type="a{sv}" direction="in"/><arg name="alias" type="s" direction="in"/><arg name="collection" type="o" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
    <method name="SearchItems"><arg name="attributes" type="a{ss}" direction="in"/><arg name="unlocked" type="ao" direction="out"/><arg name="locked" type="ao" direction="out"/></method>
    <method name="Unlock"><arg name="objects" type="ao" direction="in"/><arg name="unlocked" type="ao" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
    <method name="Lock"><arg name="objects" type="ao" direction="in"/><arg name="locked" type="ao" direction="out"/><arg name="Prompt" type="o" direction="out"/></method>
    <method name="GetSecrets"><arg name="items" type="ao" direction="in"/><arg name="session" type="o" direction="in"/><arg name="secrets" type="a{o(oayays)}" direction="out"/></method>
    <method name="ReadAlias"><arg name="name" type="s" direction="in"/><arg name="collection" type="o" direction="out"/></method>
    <method name="SetAlias"><arg name="name" type="s" direction="in"/><arg name="collection" type="o" direction="in"/></method>
    <signal name="CollectionCreated"><arg name="collection" type="o"/></signal>
    <signal name="CollectionDeleted"><arg name="collection" type="o"/></signal>
    <signal name="CollectionChanged"><arg name="collection" type="o"/></signal>
  </interface>
"#;

const COLLECTION: &str = r#"  <interface name="org.freedesktop.Secret.Collection">
    <property name="Items" type="ao" access="read"/>
    <property name="Label" type="s" access="readwrite"/>
    <property name="Locked" type="b" access="read"/>
    <property name="Created" type="t" access="read"/>
    <property name="Modified" type="t" access="read"/>
    <method name="Delete"><arg name="prompt" type="o" direction="out"/></method>
    <method name="SearchItems"><arg name="attributes" type="a{ss}" direction="in"/><arg name="results" type="ao" direction="out"/></method>
    <method name="CreateItem"><arg name="properties" type="a{sv}" direction="in"/><arg name="secret" type="(oayays)" direction="in"/><arg name="replace" type="b" direction="in"/><arg name="item" type="o" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
    <signal name="ItemCreated"><arg name="item" type="o"/></signal>
    <signal name="ItemDeleted"><arg name="item" type="o"/></signal>
    <signal name="ItemChanged"><arg name="item" type="o"/></signal>
  </interface>
"#;

const ITEM: &str = r#"  <interface name="org.freedesktop.Secret.Item">
    <property name="Locked" type="b" access="read"/>
    <property name="Attributes" type="a{ss}" access="readwrite"/>
    <property name="Label" type="s" access="readwrite"/>
    <property name="Type" type="s" access="read"/>
    <property name="Created" type="t" access="read"/>
    <property name="Modified" type="t" access="read"/>
    <method name="Delete"><arg name="Prompt" type="o" direction="out"/></method>
    <method name="GetSecret"><arg name="session" type="o" direction="in"/><arg name="secret" type="(oayays)" direction="out"/></method>
    <method name="SetSecret"><arg name="secret" type="(oayays)" direction="in"/></method>
  </interface>
"#;

const SESSION: &str =
    "  <interface name=\"org.freedesktop.Secret.Session\"><method name=\"Close\"/></interface>\n";

const PROMPT: &str = r#"  <interface name="org.freedesktop.Secret.Prompt">
    <method name="Prompt"><arg name="window-id" type="s" direction="in"/></method>
    <method name="Dismiss"/>
    <signal name="Completed"><arg name="dismissed" type="b"/><arg name="result" type="v"/></signal>
  </interface>
"#;

fn node(interfaces: &str, children: &[&str]) -> String {
    let kids: String = children
        .iter()
        .map(|c| format!("  <node name=\"{c}\"/>\n"))
        .collect();
    format!("{HEAD}{STANDARD}{interfaces}{kids}</node>\n")
}

/// The path is above the Secret Service's tree: an object-less node that
/// lists its child.
fn ancestor(path: &str) -> Option<&'static str> {
    match path {
        "/" => Some("org"),
        "/org" => Some("freedesktop"),
        "/org/freedesktop" => Some("secrets"),
        _ => None,
    }
}

pub fn introspect(srv: &Server, path: &str) -> DResult<String> {
    if let Some(child) = ancestor(path) {
        return Ok(format!("{HEAD}  <node name=\"{child}\"/>\n</node>\n"));
    }
    let _ = srv;
    match n::parse(path) {
        Some(Obj::Service) => Ok(node(
            SERVICE,
            &["collection", "aliases", "session", "prompt"],
        )),
        Some(Obj::Collection(_) | Obj::Alias(_)) => Ok(node(COLLECTION, &[])),
        Some(Obj::Item(..)) => Ok(node(ITEM, &[])),
        Some(Obj::Session(_)) => Ok(node(SESSION, &[])),
        Some(Obj::Prompt(_)) => Ok(node(PROMPT, &[])),
        None if ["collection", "aliases", "session", "prompt"]
            .iter()
            .any(|d| path == format!("{}/{d}", n::ROOT)) =>
        {
            Ok(format!("{HEAD}</node>\n"))
        }
        None => Err(DErr::new(
            n::E_UNKNOWN_OBJECT,
            format!("no object at {path}"),
        )),
    }
}
