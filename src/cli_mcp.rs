// cli_mcp.rs — `kepr mcp`: a Model Context Protocol server on stdio
// (agent vault T1.21). Tools never return secret values:
//   list_secrets  names, sealed flag and bound hosts
//   call_api      make a provider API call; the key is injected by a
//                 kepr-gate session this server starts on first use
// Newline-delimited JSON-RPC 2.0, as MCP's stdio transport specifies.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use kepr_core::gate_protocol::GateRoute;
use kepr_core::protocol::{Request, Response};
use serde_json::{json, Value};

use crate::client;

const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY: usize = 64 * 1024;

pub struct SecretInfo {
    pub name: String,
    pub hosts: Vec<String>,
}

pub trait Backend {
    fn list(&mut self) -> Result<Vec<SecretInfo>, String>;
    fn call(
        &mut self,
        provider: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        headers: &HashMap<String, String>,
    ) -> Result<(u16, String), String>;
}

fn tools() -> Value {
    let providers: Vec<&str> = kepr_core::providers::PROVIDERS
        .iter()
        .map(|p| p.name)
        .collect();
    json!([
        {
            "name": "list_secrets",
            "description": "List the user's sealed API keys (names and the hosts each may be sent to). Never returns values.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "call_api",
            "description": "Call a model provider's HTTP API using the user's sealed key for that provider. The key is added by kepr; never include keys yourself.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "provider": {"type": "string", "enum": providers},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                    "path": {"type": "string", "description": "Path on the provider's API host, e.g. /v1/models"},
                    "body": {"type": "string", "description": "Request body (usually JSON)"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}}
                },
                "required": ["provider", "method", "path"]
            }
        }
    ])
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

fn call_tool(backend: &mut dyn Backend, name: &str, args: &Value) -> Value {
    match name {
        "list_secrets" => match backend.list() {
            Ok(list) => {
                let lines: Vec<String> = list
                    .iter()
                    .map(|s| format!("{} → {}", s.name, s.hosts.join(", ")))
                    .collect();
                text_result(
                    if lines.is_empty() {
                        "no sealed keys".into()
                    } else {
                        lines.join("\n")
                    },
                    false,
                )
            }
            Err(e) => text_result(e, true),
        },
        "call_api" => {
            let s = |k: &str| args.get(k).and_then(Value::as_str);
            let (Some(provider), Some(method), Some(path)) =
                (s("provider"), s("method"), s("path"))
            else {
                return text_result("provider, method and path are required".into(), true);
            };
            if !path.starts_with('/') || path.contains("://") {
                return text_result(
                    "path must start with / (a path on the provider's host)".into(),
                    true,
                );
            }
            let headers: HashMap<String, String> = args
                .get("headers")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            Some((k.to_ascii_lowercase(), v.as_str()?.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            match backend.call(provider, method, path, s("body"), &headers) {
                Ok((status, mut body)) => {
                    if body.len() > MAX_BODY {
                        let mut cut = MAX_BODY;
                        while !body.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        body.truncate(cut);
                        body.push_str("\n…[truncated]");
                    }
                    text_result(format!("HTTP {status}\n{body}"), status >= 400)
                }
                Err(e) => text_result(e, true),
            }
        }
        other => text_result(format!("unknown tool {other}"), true),
    }
}

/// Handle one JSON-RPC message; `None` for notifications.
pub fn handle(backend: &mut dyn Backend, msg: &Value) -> Option<Value> {
    let id = msg.get("id")?.clone();
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let asked = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kepr", "version": env!("CARGO_PKG_VERSION")}
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            call_tool(
                backend,
                name,
                params.get("arguments").unwrap_or(&Value::Null),
            )
        }
        _ => {
            return Some(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}}),
            )
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// Production backend: the daemon for listing; a lazily started gate
/// session (owned by this process) for API calls.
struct GateSession {
    port: u16,
    /// provider → placeholder
    placeholders: HashMap<String, String>,
}

#[derive(Default)]
struct Live {
    gate: Option<GateSession>,
}

fn list_sealed() -> Result<Vec<SecretInfo>, String> {
    match client::send_request(&Request::List)? {
        Response::ListOk { credentials, .. } => Ok(credentials
            .into_iter()
            .filter(|c| c.sealed == Some(true))
            .map(|c| SecretInfo {
                name: c.name,
                hosts: c.bound_hosts.unwrap_or_default(),
            })
            .collect()),
        Response::Err { error } => Err(error),
        _ => Err("unexpected daemon response".into()),
    }
}

impl Live {
    fn ensure_gate(&mut self) -> Result<(), String> {
        if self.gate.is_some() {
            return Ok(());
        }
        let mut routes = Vec::new();
        let mut by_provider = HashMap::new();
        for s in list_sealed()? {
            for h in &s.hosts {
                let host = h.split(':').next().unwrap_or_default();
                if let Some(p) = kepr_core::providers::by_host(host) {
                    if !by_provider.contains_key(p.name) {
                        by_provider.insert(p.name.to_string(), s.name.clone());
                        routes.push(GateRoute {
                            provider: p.name.into(),
                            cred: s.name.clone(),
                            slot: routes.len() as u16,
                            target: None,
                        });
                    }
                }
            }
        }
        if routes.is_empty() {
            return Err("no sealed provider keys; add one with `kepr agent add`".into());
        }
        match client::send_request(&Request::StartGate {
            routes,
            port: None,
            limits: Default::default(),
            tunnel: false,
            record: false,
        })? {
            Response::GateStarted {
                port, placeholders, ..
            } => {
                self.gate = Some(GateSession { port, placeholders });
                Ok(())
            }
            Response::Err { error } => Err(error),
            _ => Err("unexpected daemon response".into()),
        }
    }
}

enum Attempt {
    Done(u16, String),
    /// The gate is not answering (stopped by `kepr panic`, crashed).
    GateGone,
}

impl Live {
    fn attempt(
        &self,
        provider: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        headers: &HashMap<String, String>,
    ) -> Result<Attempt, String> {
        let GateSession { port, placeholders } = self.gate.as_ref().ok_or("no gate session")?;
        let ph = placeholders
            .get(provider)
            .ok_or_else(|| format!("no sealed key for provider {provider}"))?;
        let mut req = ureq::request(method, &format!("http://127.0.0.1:{port}/{provider}{path}"));
        for (k, v) in headers {
            if !matches!(
                k.as_str(),
                "authorization" | "x-api-key" | "x-goog-api-key" | "host"
            ) {
                req = req.set(k, v);
            }
        }
        req = req.set("authorization", &format!("Bearer {ph}"));
        let resp = match body {
            Some(b) => req.send_string(b),
            None => req.call(),
        };
        match resp {
            Ok(r) | Err(ureq::Error::Status(_, r)) => {
                let status = r.status();
                Ok(Attempt::Done(status, r.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(_)) => Ok(Attempt::GateGone),
        }
    }
}

impl Backend for Live {
    fn list(&mut self) -> Result<Vec<SecretInfo>, String> {
        list_sealed()
    }

    fn call(
        &mut self,
        provider: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        headers: &HashMap<String, String>,
    ) -> Result<(u16, String), String> {
        for _ in 0..2 {
            self.ensure_gate()?;
            match self.attempt(provider, method, path, body, headers)? {
                Attempt::Done(status, text) => return Ok((status, text)),
                Attempt::GateGone => self.gate = None, // start a fresh session and retry once
            }
        }
        Err("kepr gate unavailable; is the store locked? (`kepr unlock`)".into())
    }
}

pub fn cmd_mcp() -> Response {
    let mut backend = Live::default();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&mut backend, &msg),
            Err(_) => Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}),
            ),
        };
        if let Some(r) = reply {
            if writeln!(out, "{r}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
    Response::Pong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        calls: Vec<(String, String, String, HashMap<String, String>)>,
    }
    impl Backend for Fake {
        fn list(&mut self) -> Result<Vec<SecretInfo>, String> {
            Ok(vec![SecretInfo {
                name: "ANTHROPIC_API_KEY".into(),
                hosts: vec!["api.anthropic.com:443".into()],
            }])
        }
        fn call(
            &mut self,
            p: &str,
            m: &str,
            path: &str,
            _: Option<&str>,
            h: &HashMap<String, String>,
        ) -> Result<(u16, String), String> {
            self.calls
                .push((p.into(), m.into(), path.into(), h.clone()));
            Ok((200, "{\"ok\":true}".into()))
        }
    }

    fn rpc(b: &mut Fake, method: &str, params: Value) -> Value {
        handle(
            b,
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        )
        .unwrap()
    }

    #[test]
    fn initialize_and_list_tools() {
        let mut b = Fake::default();
        let r = rpc(
            &mut b,
            "initialize",
            json!({"protocolVersion": "2025-03-26"}),
        );
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        let r = rpc(&mut b, "tools/list", json!({}));
        let names: Vec<&str> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["list_secrets", "call_api"]);
        assert!(handle(
            &mut b,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .is_none());
        assert_eq!(rpc(&mut b, "nope", json!({}))["error"]["code"], -32601);
    }

    #[test]
    fn list_secrets_never_contains_values() {
        let mut b = Fake::default();
        let r = rpc(
            &mut b,
            "tools/call",
            json!({"name": "list_secrets", "arguments": {}}),
        );
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ANTHROPIC_API_KEY") && text.contains("api.anthropic.com"));
    }

    #[test]
    fn call_api_validates_and_forwards() {
        let mut b = Fake::default();
        let bad = rpc(
            &mut b,
            "tools/call",
            json!({"name": "call_api", "arguments": {"provider": "openai", "method": "GET", "path": "https://evil.example/x"}}),
        );
        assert_eq!(bad["result"]["isError"], true);
        let ok = rpc(
            &mut b,
            "tools/call",
            json!({"name": "call_api", "arguments": {"provider": "openai", "method": "GET", "path": "/v1/models", "headers": {"X-Trace": "1"}}}),
        );
        assert_eq!(ok["result"]["isError"], false);
        assert!(ok["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("HTTP 200"));
        assert_eq!(b.calls[0].2, "/v1/models");
        assert_eq!(b.calls[0].3.get("x-trace").map(String::as_str), Some("1"));
    }
}
