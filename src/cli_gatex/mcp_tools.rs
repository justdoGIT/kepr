// cli_gatex/mcp_tools.rs — `kepr mcp`'s database and SSH tools (T9.05),
// and the gate session the MCP server runs its tools through.
//
//   db_query(target, sql[, read_only])  one SQL statement on a sealed
//       PostgreSQL login, through the gate's database proxy (P7.1)
//   ssh_run(host, cmd)  a command over ssh with keys the daemon holds
//       (P2.4); hosts must be listed with `--ssh`
//
//   kepr mcp --credential NAME... [--allow-writes] [--ssh HOST --ssh-key NAME]...
//
// Queries default to read-only; the operator can opt in to writes.
// `--read-only` rejects a conflicting write opt-in; `--context` attaches an
// ai_context note to a target (a database NAME or an ssh host) that is
// returned with every result for it. No tool returns a credential: the
// gate holds the database password, the daemon the SSH key, and results
// have key-shaped strings and the session's placeholders masked.

use std::net::TcpStream;

use kepr_core::authz::{self, Grant, GrantRequest};
use kepr_core::gate_protocol::{GateRoute, TargetKind};
use kepr_core::protocol::{CredInfo, Request, Response};
use serde_json::{json, Map, Value};

use super::mcp_pg;
use crate::cli_mcp::Backend;
use crate::client;

#[path = "mcp_config.rs"]
mod config;
#[path = "mcp_session.rs"]
mod session;
pub use config::{Budget, McpConfig, NO_CONFIG};
pub use session::{with_gate, Attempt, Gate, GateSession};

const MAX_TEXT: usize = 64 * 1024;
const MAX_INPUT: usize = 64 * 1024;
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

fn object<'a>(args: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let object = args
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown argument `{key}`"));
    }
    Ok(object)
}

fn db_args(args: &Value) -> Result<(&str, &str, bool), String> {
    let object = object(args, &["target", "sql", "read_only"])?;
    let target = object
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| "target is required and must be a string".to_string())?;
    let sql = object
        .get("sql")
        .and_then(Value::as_str)
        .ok_or_else(|| "sql is required and must be a string".to_string())?;
    let read_only = object
        .get("read_only")
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| "read_only must be a boolean".to_string())
        })
        .transpose()?
        .unwrap_or(false);
    Ok((target, sql, read_only))
}

fn ssh_args(args: &Value) -> Result<(&str, &str), String> {
    let object = object(args, &["host", "cmd"])?;
    let host = object
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| "host is required and must be a string".to_string())?;
    let cmd = object
        .get("cmd")
        .and_then(Value::as_str)
        .ok_or_else(|| "cmd is required and must be a string".to_string())?;
    Ok((host, cmd))
}

fn authorize_grant(
    grant: &Grant,
    tool: &str,
    resource: &str,
    action: &str,
) -> Result<(), String> {
    let request = GrantRequest {
        tenant: grant.tenant.clone(),
        workspace: grant.workspace.clone(),
        tool: tool.to_string(),
        connector_account: grant.connector_account.clone(),
        resource: resource.to_string(),
        action: action.to_string(),
    };
    match authz::decide(grant, &request) {
        authz::Decision::Allow => Ok(()),
        authz::Decision::NeedsApproval => {
            Err("MCP authorization requires operator approval".into())
        }
        authz::Decision::Deny(reason) => Err(format!("MCP authorization denied: {reason}")),
    }
}

/// db_query / ssh_run; `None` for any other tool.
pub fn call(backend: &mut dyn Backend, name: &str, args: &Value) -> Option<Value> {
    let too_long = |v: &str| v.len() > MAX_INPUT;
    let reply = |r: Result<String, String>, note| match r {
        Ok(t) => result(t, note, false),
        Err(e) => result(e, note, true),
    };
    match name {
        "db_query" => {
            let (target, sql, requested) = match db_args(args) {
                Ok(parsed) => parsed,
                Err(e) => return Some(result(e, None, true)),
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
            let class = match super::mcp_sql::classify(sql) {
                Ok(class) => class,
                Err(e) => return Some(result(e, None, true)),
            };
            let target = target.to_ascii_uppercase();
            if !backend.config().permits_credential(&target) {
                return Some(result(
                    "database target is outside the MCP credential grant".into(),
                    None,
                    true,
                ));
            }
            let read_only = backend.config().read_only || requested;
            if let Err(e) = backend.config().authorize_db(&target, class.action(), read_only) {
                return Some(result(e, None, true));
            }
            let note = backend.config().context_for(&target).map(str::to_string);
            let r = backend.db_query(&target, sql, read_only);
            Some(reply(r, note.as_deref()))
        }
        "ssh_run" => {
            let (host, cmd) = match ssh_args(args) {
                Ok(parsed) => parsed,
                Err(e) => return Some(result(e, None, true)),
            };
            if !backend.config().ssh_hosts.iter().any(|h| h == host) {
                let msg =
                    format!("{host} is not an allowed host; the user can allow it with `kepr mcp --ssh {host}`");
                return Some(result(msg, None, true));
            }
            if backend.config().ssh_keys.is_empty() {
                return Some(result(
                    "no SSH keys granted; operator must pass --ssh-key NAME".into(),
                    None,
                    true,
                ));
            }
            if cmd.trim().is_empty() || too_long(cmd) {
                return Some(result("cmd is empty or too long".into(), None, true));
            }
            if let Err(e) = backend.config().authorize("ssh_run", host, "exec") {
                return Some(result(e, None, true));
            }
            let note = backend.config().context_for(host).map(str::to_string);
            let r = backend.ssh_run(host, cmd);
            Some(reply(r, note.as_deref()))
        }
        _ => None,
    }
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

pub const GATE_GONE: &str = "MCP gate unavailable; operator must start a new session";

/// One db_query on `gate`'s route for `target`.
pub fn db_attempt(
    gate: &Gate,
    target: &str,
    sql: &str,
    read_only: bool,
) -> Result<Attempt<String>, String> {
    let class = super::mcp_sql::classify(sql)?;
    if read_only && class != super::mcp_sql::StatementClass::Query {
        return Err("read-only MCP calls may run query statements only".into());
    }
    authorize_grant(&gate.grant, "db_query", target, class.action())?;
    let key = kepr_core::gate_protocol::db_route_key(target);
    let (Some(port), Some(ph)) = (gate.db_ports.get(&key), gate.placeholders.get(&key)) else {
        return Err("PostgreSQL login is outside this MCP session grant".into());
    };
    let Ok(conn) = TcpStream::connect(("127.0.0.1", *port)) else {
        return Ok(Attempt::Unavailable(GATE_GONE.into()));
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
    use std::collections::HashMap;

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

    fn gate_for(cfg: &McpConfig, port: u16) -> Gate {
        Gate {
            port: 0,
            placeholders: HashMap::from([("db:APP_DB".into(), PH.into())]),
            db_ports: HashMap::from([("db:APP_DB".into(), port)]),
            grant: cfg.grant_for("db_query"),
        }
    }

    fn db_cfg() -> McpConfig {
        McpConfig::parse(&v(&["--credential", "APP_DB"])).unwrap()
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
    fn sec_003_defaults_to_read_only() {
        assert!(McpConfig::default().read_only);
        assert!(McpConfig::parse(&[]).unwrap().read_only);
    }

    #[test]
    fn sec_003_ungranted_database_is_denied_before_backend() {
        let mut b = Fake::default();
        let r = call(
            &mut b,
            "db_query",
            &json!({"target": "UNGRANTED", "sql": "select 1"}),
        )
        .unwrap();
        assert_eq!(r["isError"], true);
        assert!(b.db.is_empty());
    }

    #[test]
    fn sec_003_operator_can_select_credentials_and_finite_limits() {
        assert!(McpConfig::parse(&v(&[
            "--credential",
            "APP_DB",
            "--max-requests",
            "10",
            "--max-tokens",
            "1000",
            "--per-minute",
            "5",
            "--allow-writes",
        ]))
        .is_ok());
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
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&["--credential", "APP_DB", "--allow-writes"])).unwrap(),
            ..Default::default()
        };
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
        b.cfg.read_only = true; // The operator's flag cannot be lifted.
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
    fn sec_003_scope_mismatch_and_write_without_the_action_are_refused() {
        // Scope mismatch is enforced by `authorize_grant` (the check in
        // `db_attempt` that uses the gate's pinned grant). Build a grant
        // with one workspace and verify a divergent request is denied.
        let cfg = McpConfig::parse(&v(&[
            "--credential", "APP_DB",
            "--workspace", "/work/acme",
            "--connector-account", "work",
        ]))
        .unwrap();
        let grant = cfg.grant_for("db_query");
        assert!(authorize_grant(&grant, "db_query", "APP_DB", "query").is_ok());
        // Workspace mismatch: request from "/work/other" against pinned grant.
        let mut bad_ws = cfg.request_for("db_query", "APP_DB", "query");
        bad_ws.workspace = "/work/other".into();
        assert!(!authz::decide(&grant, &bad_ws).allowed(), "workspace mismatch");
        // Connector-account crossover.
        let mut bad_acct = cfg.request_for("db_query", "APP_DB", "query");
        bad_acct.connector_account = "personal".into();
        assert!(!authz::decide(&grant, &bad_acct).allowed(), "account crossover");
        // Write and admin without the action (default is query-only).
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&[
                "--credential", "APP_DB",
                "--workspace", "/work/acme",
                "--connector-account", "work",
            ])).unwrap(),
            ..Default::default()
        };
        let q = |b: &mut Fake, sql: &str| {
            call(b, "db_query", &json!({"target": "APP_DB", "sql": sql})).unwrap()
        };
        assert_eq!(q(&mut b, "select 1")["isError"], false);
        assert_eq!(q(&mut b, "update t set a = 1")["isError"], true, "no write action");
        assert_eq!(q(&mut b, "drop table t")["isError"], true, "no admin action");
        assert_eq!(b.db.len(), 1, "only the allowed tuple reached the backend");
    }

    #[test]
    fn sec_003_arguments_and_statement_class_are_validated() {
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&["--credential", "APP_DB", "--allow-writes"])).unwrap(),
            ..Default::default()
        };
        for (args, why) in [
            (json!({"target": "APP_DB", "sql": "select 1", "read_only": "yes"}), "type"),
            (json!({"target": "APP_DB", "sql": "select 1", "extra": 1}), "unknown key"),
            (json!({"target": "APP_DB", "sql": "select 1; select 2"}), "chaining"),
            (json!({"target": "APP_DB", "sql": "select 1;"}), "trailing semicolon"),
            (json!({"target": "APP_DB", "sql": "drop table t"}), "DDL without admin"),
        ] {
            let r = call(&mut b, "db_query", &args).unwrap();
            assert_eq!(r["isError"], true, "{why}");
        }
        assert!(b.db.is_empty());
        assert_eq!(
            call(&mut b, "ssh_run", &json!({"host": "web1"})).unwrap()["isError"],
            true
        );
        assert!(b.ssh.is_empty());
    }

    #[test]
    fn results_carry_the_targets_ai_context() {
        let mut b = Fake {
            cfg: McpConfig::parse(&v(&[
                "--ssh",
                "web1",
                "--ssh-key",
                "DEPLOY",
                "--credential",
                "APP_DB",
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
            cfg: McpConfig::parse(&v(&[
                "--ssh",
                "web1",
                "--ssh-key",
                "DEPLOY",
                "--credential",
                "T",
            ]))
            .unwrap(),
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
        let gate = gate_for(&db_cfg(), port);
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
    fn db_attempt_runs_through_the_granted_gate_or_reports_unavailable() {
        let (port, rx) = fake_gate();
        let gate = gate_for(&db_cfg(), port);
        match db_attempt(&gate, "APP_DB", "select id, name from t", true).unwrap() {
            Attempt::Done(t) => assert_eq!(t, "id | name\n1 | alice\n2 | NULL\n(SELECT 2)"),
            Attempt::Unavailable(w) => panic!("{w}"),
        }
        assert_eq!(
            rx.recv().unwrap(),
            "Q SET default_transaction_read_only = on"
        );
        assert!(db_attempt(&gate, "OTHER", "select 1", false).is_err());
        assert!(db_attempt(&gate, "APP_DB", "select 1; select 2", false).is_err());
        assert!(db_attempt(&gate, "APP_DB", "drop table t", false).is_err());
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = Gate {
            db_ports: HashMap::from([("db:APP_DB".into(), closed.local_addr().unwrap().port())]),
            ..gate
        };
        drop(closed);
        match db_attempt(&dead, "APP_DB", "select 1", false).unwrap() {
            Attempt::Unavailable(w) => assert_eq!(w, GATE_GONE),
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
