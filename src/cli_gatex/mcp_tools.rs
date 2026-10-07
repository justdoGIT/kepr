// cli_gatex/mcp_tools.rs — `kepr mcp`'s database and SSH tools (T9.05),
// and the gate session the MCP server runs its tools through.
//
//   db_query(target, sql[, read_only])  one SQL statement on a sealed
//       PostgreSQL login, through the gate's database proxy (P7.1)
//   ssh_run(host, cmd)  a command over ssh with keys the daemon holds
//       (P2.4); hosts must be listed with `--ssh`
//
//   kepr mcp [--read-only] [--ssh [USER@]HOST]... [--context TARGET=NOTE]...
//
// `--read-only` makes every db_query read-only; `--context` attaches an
// ai_context note to a target (a database NAME or an ssh host) that is
// returned with every result for it. No tool returns a credential: the
// gate holds the database password, the daemon the SSH key, and results
// have key-shaped strings and the session's placeholders masked.

use std::collections::HashMap;
use std::net::TcpStream;

use kepr_core::gate_protocol::{GateRoute, TargetKind};
use kepr_core::protocol::{CredInfo, Request, Response};
use serde_json::{json, Value};

use super::{mcp_pg, mcp_ssh};
use crate::cli_mcp::Backend;
use crate::client;

const MAX_TEXT: usize = 64 * 1024;
const MAX_NOTE: usize = 4096;
const MAX_INPUT: usize = 64 * 1024;
const USAGE: &str =
    "usage: kepr mcp [--read-only] [--ssh [USER@]HOST]... [--context TARGET=NOTE]...";

/// `kepr mcp`'s flags.
#[derive(Debug, Default, PartialEq)]
pub struct McpConfig {
    pub read_only: bool,
    pub ssh_hosts: Vec<String>,
    /// (target, ai_context note)
    pub context: Vec<(String, String)>,
}

pub static NO_CONFIG: McpConfig = McpConfig {
    read_only: false,
    ssh_hosts: Vec::new(),
    context: Vec::new(),
};

impl McpConfig {
    pub fn parse(raw: &[String]) -> Result<Self, String> {
        let mut c = McpConfig::default();
        let mut it = raw.iter();
        while let Some(arg) = it.next() {
            let mut value = || it.next().ok_or(format!("{arg} needs a value\n{USAGE}"));
            match arg.as_str() {
                "--read-only" => c.read_only = true,
                "--ssh" => {
                    let h = value()?;
                    if !mcp_ssh::valid_host(h) {
                        return Err(format!("--ssh {h}: not a [USER@]HOST"));
                    }
                    c.ssh_hosts.push(h.clone());
                }
                "--context" => {
                    let (t, note) = value()?
                        .split_once('=')
                        .filter(|(t, n)| !t.is_empty() && n.chars().count() <= MAX_NOTE)
                        .ok_or(format!(
                            "--context: TARGET=NOTE, the note at most {MAX_NOTE} characters"
                        ))?;
                    c.context.push((t.to_string(), note.to_string()));
                }
                "--json" => {}
                other => return Err(format!("unexpected argument: {other}\n{USAGE}")),
            }
        }
        Ok(c)
    }

    /// The note for a database NAME (any case) or an ssh host.
    pub fn context_for(&self, target: &str) -> Option<&str> {
        self.context
            .iter()
            .rev()
            .find(|(t, _)| t.eq_ignore_ascii_case(target))
            .map(|(_, n)| n.as_str())
    }
}

/// `kepr mcp`'s own arguments: everything after the verb.
pub fn own_args() -> Vec<String> {
    let raw: Vec<String> = std::env::args().collect();
    let verb = raw.iter().skip(1).position(|a| !a.starts_with("--"));
    verb.map(|i| raw[i + 2..].to_vec()).unwrap_or_default()
}

pub fn tools(cfg: &McpConfig) -> Vec<Value> {
    let ro = match cfg.read_only {
        true => " This server runs every statement read-only.",
        false => "",
    };
    let mut out = vec![json!({
        "name": "db_query",
        "description": format!("Run one SQL statement on one of the user's sealed PostgreSQL logins. kepr logs in for you; you never get the password. Results include the target's ai_context note when the user set one.{ro}"),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "The database login's kepr NAME (see list_secrets)"},
                "sql": {"type": "string", "description": "One SQL statement"},
                "read_only": {"type": "boolean", "description": "Run it read-only"}
            },
            "required": ["target", "sql"]
        }
    })];
    if !cfg.ssh_hosts.is_empty() {
        out.push(json!({
            "name": "ssh_run",
            "description": "Run a shell command on one of the allowed hosts over ssh, signed with the user's kepr-held key (you never get it). Returns the exit status, stdout and stderr, and the host's ai_context note when the user set one.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "enum": cfg.ssh_hosts},
                    "cmd": {"type": "string", "description": "Command line for the remote shell"}
                },
                "required": ["host", "cmd"]
            }
        }));
    }
    out
}

/// Key-shaped strings and `extra` (placeholders) masked; at most MAX_TEXT.
pub fn scrub(text: &str, extra: &[&str]) -> String {
    let mut text = text.to_string();
    for e in extra.iter().filter(|e| !e.is_empty()) {
        text = text.replace(e, "[redacted]");
    }
    // Hits come sorted by offset and may overlap (one key, two shapes).
    let (mut out, mut at) = (String::new(), 0);
    for h in kepr_core::leak::find_all(text.as_bytes()) {
        let end = h.offset + h.len;
        if h.offset >= at {
            out.push_str(text.get(at..h.offset).unwrap_or_default());
            out.push_str("[redacted]");
        }
        at = at.max(end);
    }
    out.push_str(text.get(at..).unwrap_or_default());
    if out.len() > MAX_TEXT {
        let mut cut = MAX_TEXT;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n…[truncated]");
    }
    out
}

fn result(text: String, note: Option<&str>, is_error: bool) -> Value {
    let mut content = Vec::new();
    if let Some(n) = note {
        content.push(json!({"type": "text", "text": format!("ai_context: {n}")}));
    }
    content.push(json!({"type": "text", "text": scrub(&text, &[])}));
    json!({"content": content, "isError": is_error})
}

/// db_query / ssh_run; `None` for any other tool.
pub fn call(backend: &mut dyn Backend, name: &str, args: &Value) -> Option<Value> {
    let s = |k: &str| args.get(k).and_then(Value::as_str);
    let too_long = |v: &str| v.len() > MAX_INPUT;
    let reply = |r: Result<String, String>, note| match r {
        Ok(t) => result(t, note, false),
        Err(e) => result(e, note, true),
    };
    match name {
        "db_query" => {
            let (Some(target), Some(sql)) = (s("target"), s("sql")) else {
                return Some(result("target and sql are required".into(), None, true));
            };
            let valid = (1..=128).contains(&target.len())
                && target
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !valid || sql.trim().is_empty() || too_long(sql) {
                return Some(result(
                    "target must be a kepr NAME and sql one statement".into(),
                    None,
                    true,
                ));
            }
            let target = target.to_ascii_uppercase();
            let read_only =
                backend.config().read_only || args.get("read_only") == Some(&json!(true));
            let note = backend.config().context_for(&target).map(str::to_string);
            let r = backend.db_query(&target, sql, read_only);
            Some(reply(r, note.as_deref()))
        }
        "ssh_run" => {
            let (Some(host), Some(cmd)) = (s("host"), s("cmd")) else {
                return Some(result("host and cmd are required".into(), None, true));
            };
            if !backend.config().ssh_hosts.iter().any(|h| h == host) {
                let msg =
                    format!("{host} is not an allowed host; the user can allow it with `kepr mcp --ssh {host}`");
                return Some(result(msg, None, true));
            }
            if cmd.trim().is_empty() || too_long(cmd) {
                return Some(result("cmd is empty or too long".into(), None, true));
            }
            let note = backend.config().context_for(host).map(str::to_string);
            let r = backend.ssh_run(host, cmd);
            Some(reply(r, note.as_deref()))
        }
        _ => None,
    }
}

/// The MCP server's gate session.
pub struct Gate {
    pub port: u16,
    /// Route key (provider name or `db:NAME`) → placeholder.
    pub placeholders: HashMap<String, String>,
    /// `db:NAME` → the gate's loopback port for it.
    pub db_ports: HashMap<String, u16>,
}

pub enum Attempt<T> {
    Done(T),
    /// The gate is gone or lacks the route: start a fresh one (once).
    Restart(String),
}

/// The caller's sealed credentials.
pub fn sealed() -> Result<Vec<CredInfo>, String> {
    match client::send_request(&Request::List)? {
        Response::ListOk { credentials, .. } => Ok(credentials
            .into_iter()
            .filter(|c| c.sealed == Some(true))
            .collect()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

/// A route per provider (its first sealed key) and per sealed database login.
pub fn session_routes(sealed: &[CredInfo]) -> Vec<GateRoute> {
    let mut routes: Vec<GateRoute> = Vec::new();
    for c in sealed.iter().filter(|c| c.record_type.is_none()) {
        for h in c.bound_hosts.iter().flatten() {
            let host = h.split(':').next().unwrap_or_default();
            if let Some(p) = kepr_core::providers::by_host(host) {
                if !routes.iter().any(|r| r.provider == p.name) {
                    routes.push(GateRoute {
                        provider: p.name.into(),
                        cred: c.name.clone(),
                        slot: routes.len() as u16,
                        target: None,
                    });
                }
            }
        }
    }
    // db_query speaks PostgreSQL only.
    let dbs = crate::cli_agent_db::routes(&routes, sealed);
    routes.extend(dbs.into_iter().filter(|r| {
        r.target
            .as_ref()
            .is_some_and(|t| t.kind == TargetKind::Postgres)
    }));
    routes
}

impl Gate {
    pub fn start() -> Result<Gate, String> {
        let routes = session_routes(&sealed()?);
        if routes.is_empty() {
            return Err("no sealed keys or database logins; add one with `kepr agent add` or `kepr agent add-db`".into());
        }
        let req = Request::StartGate {
            routes,
            port: None,
            limits: Default::default(),
            tunnel: false,
            record: false,
        };
        match client::send_request(&req)? {
            Response::GateStarted {
                port,
                placeholders,
                extras,
                ..
            } => Ok(Gate {
                port,
                placeholders,
                db_ports: extras.db_ports,
            }),
            Response::Err { error } => Err(error),
            _ => Err("unexpected daemon response".into()),
        }
    }
}

/// Start the gate if needed and run `f`; on `Restart` start a fresh
/// session and try once more.
pub fn with_gate<T>(
    gate: &mut Option<Gate>,
    mut f: impl FnMut(&Gate) -> Result<Attempt<T>, String>,
) -> Result<T, String> {
    let mut why = String::new();
    for _ in 0..2 {
        if gate.is_none() {
            *gate = Some(Gate::start()?);
        }
        match f(gate.as_ref().expect("started"))? {
            Attempt::Done(v) => return Ok(v),
            Attempt::Restart(reason) => (*gate, why) = (None, reason),
        }
    }
    Err(why)
}

pub const GATE_GONE: &str = "kepr gate unavailable; is the store locked? (`kepr unlock`)";

/// One db_query on `gate`'s route for `target`.
pub fn db_attempt(
    gate: &Gate,
    target: &str,
    sql: &str,
    read_only: bool,
) -> Result<Attempt<String>, String> {
    let key = kepr_core::gate_protocol::db_route_key(target);
    let (Some(port), Some(ph)) = (gate.db_ports.get(&key), gate.placeholders.get(&key)) else {
        return Ok(Attempt::Restart(format!(
            "no sealed PostgreSQL login {target}; add one with `kepr agent add-db {target} --url postgres://…`"
        )));
    };
    let Ok(conn) = TcpStream::connect(("127.0.0.1", *port)) else {
        return Ok(Attempt::Restart(GATE_GONE.into()));
    };
    mcp_pg::query(conn, ph, sql, read_only)
        .map(|o| Attempt::Done(scrub(&mcp_pg::format(&o), &[ph])))
        .map_err(|e| scrub(&e, &[ph]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_gatex::mcp_pg::tests::{fake_gate, PH};
    use crate::cli_mcp::SecretInfo;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[derive(Default)]
    struct Fake {
        cfg: McpConfig,
        db: Vec<(String, String, bool)>,
        ssh: Vec<(String, String)>,
        reply: String,
    }
    impl Backend for Fake {
        fn list(&mut self) -> Result<Vec<SecretInfo>, String> {
            Ok(Vec::new())
        }
        fn call(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: &HashMap<String, String>,
        ) -> Result<(u16, String), String> {
            Err("no".into())
        }
        fn config(&self) -> &McpConfig {
            &self.cfg
        }
        fn db_query(&mut self, t: &str, sql: &str, ro: bool) -> Result<String, String> {
            self.db.push((t.into(), sql.into(), ro));
            Ok(self.reply.clone())
        }
        fn ssh_run(&mut self, host: &str, cmd: &str) -> Result<String, String> {
            self.ssh.push((host.into(), cmd.into()));
            Ok(self.reply.clone())
        }
    }

    fn texts(r: &Value) -> Vec<String> {
        r["content"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["text"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn parses_flags() {
        let c = McpConfig::parse(&v(&[
            "--read-only",
            "--ssh",
            "deploy@web1",
            "--context",
            "app_db=Analytics replica; tables orders, users",
        ]))
        .unwrap();
        assert!(c.read_only);
        assert_eq!(c.ssh_hosts, ["deploy@web1"]);
        assert_eq!(
            c.context_for("APP_DB"),
            Some("Analytics replica; tables orders, users")
        );
        assert_eq!(c.context_for("web1"), None);
        assert_eq!(McpConfig::parse(&[]).unwrap(), McpConfig::default());
        for bad in [
            &["--ssh"][..],
            &["--ssh", "-oProxyCommand=x"],
            &["--context", "=x"],
            &["--nope"],
        ] {
            assert!(McpConfig::parse(&v(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tool_schemas() {
        let t = tools(&McpConfig::default());
        assert_eq!(t.len(), 1, "no ssh_run without --ssh hosts");
        assert_eq!(t[0]["name"], "db_query");
        assert_eq!(t[0]["inputSchema"]["required"], json!(["target", "sql"]));
        let cfg = McpConfig {
            read_only: true,
            ssh_hosts: v(&["web1", "deploy@web2"]),
            ..Default::default()
        };
        let t = tools(&cfg);
        assert!(t[0]["description"].as_str().unwrap().contains("read-only"));
        assert_eq!(t[1]["name"], "ssh_run");
        assert_eq!(
            t[1]["inputSchema"]["properties"]["host"]["enum"],
            json!(["web1", "deploy@web2"])
        );
        assert_eq!(t[1]["inputSchema"]["required"], json!(["host", "cmd"]));
    }

    #[test]
    fn read_only_is_forwarded_and_the_server_flag_cannot_be_lifted() {
        let mut b = Fake::default();
        let q = |b: &mut Fake, ro: Value| {
            call(
                b,
                "db_query",
                &json!({"target": "app_db", "sql": "select 1", "read_only": ro}),
            )
            .unwrap()
        };
        q(&mut b, json!(false));
        q(&mut b, json!(true));
        b.cfg.read_only = true;
        q(&mut b, json!(false));
        let ro: Vec<bool> = b.db.iter().map(|d| d.2).collect();
        assert_eq!(ro, [false, true, true]);
        assert_eq!(b.db[0].0, "APP_DB");
        let bad = call(
            &mut b,
            "db_query",
            &json!({"target": "../x", "sql": "select 1"}),
        )
        .unwrap();
        assert_eq!(bad["isError"], true);
        assert_eq!(b.db.len(), 3);
        assert!(call(&mut b, "list_secrets", &json!({})).is_none());
    }

    #[test]
    fn results_carry_the_targets_ai_context() {
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&[
                "--ssh",
                "web1",
                "--context",
                "APP_DB=prod replica",
                "--context",
                "web1=ubuntu host",
            ]))
            .unwrap(),
            reply: "(SELECT 0)".into(),
            ..Default::default()
        };
        let r = call(
            &mut b,
            "db_query",
            &json!({"target": "APP_DB", "sql": "select 1"}),
        )
        .unwrap();
        assert_eq!(texts(&r), ["ai_context: prod replica", "(SELECT 0)"]);
        let r = call(&mut b, "ssh_run", &json!({"host": "web1", "cmd": "uptime"})).unwrap();
        assert_eq!(texts(&r)[0], "ai_context: ubuntu host");
        let r = call(&mut b, "ssh_run", &json!({"host": "web2", "cmd": "uptime"})).unwrap();
        assert_eq!(r["isError"], true, "unlisted host");
        assert_eq!(b.ssh, [("web1".to_string(), "uptime".to_string())]);
    }

    #[test]
    fn scrub_masks_keys_and_placeholders_once() {
        let key = format!("sk-proj-{}", "Ab1".repeat(10));
        let t = format!("a {key} b ph-1 c é {key}");
        assert_eq!(
            scrub(&t, &["ph-1"]),
            "a [redacted] b [redacted] c é [redacted]"
        );
        assert_eq!(scrub("plain", &[]), "plain");
        let long = "x".repeat(MAX_TEXT + 10);
        assert!(scrub(&long, &[]).ends_with("…[truncated]"));
    }

    #[test]
    fn no_tool_returns_a_credential() {
        let key = format!("sk-ant-api03-{}", "k".repeat(40));
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&["--ssh", "web1"])).unwrap(),
            reply: format!("token | {key}\nssh says {key}"),
            ..Default::default()
        };
        for (tool, args) in [
            (
                "db_query",
                json!({"target": "T", "sql": "select token from t"}),
            ),
            ("ssh_run", json!({"host": "web1", "cmd": "cat .env"})),
        ] {
            let r = call(&mut b, tool, &args).unwrap();
            let all = texts(&r).join("\n");
            assert!(!all.contains("sk-ant-"), "{tool}: {all}");
            assert!(all.contains("[redacted]"));
        }
        // Through a gate: the session placeholder never comes back, not
        // even when the server's error message quotes it.
        let (port, _rx) = fake_gate();
        let gate = Gate {
            port: 0,
            placeholders: HashMap::from([("db:APP_DB".into(), PH.into())]),
            db_ports: HashMap::from([("db:APP_DB".into(), port)]),
        };
        let e = match db_attempt(&gate, "APP_DB", "select fail", true) {
            Err(e) => e,
            _ => panic!("expected the server error"),
        };
        assert!(
            e.contains("bad password [redacted]") && !e.contains(PH),
            "{e}"
        );
    }

    #[test]
    fn db_attempt_runs_through_the_gate_route_or_asks_for_a_restart() {
        let (port, rx) = fake_gate();
        let gate = Gate {
            port: 0,
            placeholders: HashMap::from([("db:APP_DB".into(), PH.into())]),
            db_ports: HashMap::from([("db:APP_DB".into(), port)]),
        };
        match db_attempt(&gate, "APP_DB", "select id, name from t", true).unwrap() {
            Attempt::Done(t) => assert_eq!(t, "id | name\n1 | alice\n2 | NULL\n(SELECT 2)"),
            Attempt::Restart(w) => panic!("{w}"),
        }
        assert_eq!(
            rx.recv().unwrap(),
            "Q SET default_transaction_read_only = on"
        );
        match db_attempt(&gate, "OTHER", "select 1", false).unwrap() {
            Attempt::Restart(w) => assert!(w.contains("no sealed PostgreSQL login OTHER"), "{w}"),
            Attempt::Done(_) => panic!("unknown target"),
        }
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = Gate {
            db_ports: HashMap::from([("db:APP_DB".into(), closed.local_addr().unwrap().port())]),
            ..gate
        };
        drop(closed);
        match db_attempt(&dead, "APP_DB", "select 1", false).unwrap() {
            Attempt::Restart(w) => assert_eq!(w, GATE_GONE),
            Attempt::Done(_) => panic!("gate is gone"),
        }
    }

    #[test]
    fn session_routes_take_providers_and_postgres_logins_only() {
        let key = CredInfo {
            name: "ANTHROPIC_API_KEY".into(),
            sealed: Some(true),
            bound_hosts: Some(vec!["api.anthropic.com:443".into()]),
            ..Default::default()
        };
        let db = |name: &str, kind: &str| CredInfo {
            name: name.into(),
            sealed: Some(true),
            record_type: Some("database".into()),
            db_kind: Some(kind.into()),
            bound_hosts: Some(vec!["db.internal:5432".into()]),
            ..Default::default()
        };
        let r = session_routes(&[key, db("APP_DB", "postgres"), db("CACHE", "redis")]);
        let names: Vec<(&str, u16)> = r.iter().map(|r| (r.provider.as_str(), r.slot)).collect();
        assert_eq!(names, [("anthropic", 0), ("db:APP_DB", 1)]);
    }
}
