//! One MCP authorization: disappearing gates are never reauthorized.

use std::collections::HashMap;

use kepr_core::authz::Grant;
use kepr_core::protocol::{Request, Response};

use super::{sealed, session_routes, McpConfig};
use crate::client;

pub struct Gate {
    pub port: u16,
    pub placeholders: HashMap<String, String>,
    pub db_ports: HashMap<String, u16>,
    /// The operator grant is fixed when this gate session starts.
    pub grant: Grant,
}

pub enum Attempt<T> {
    Done(T),
    Unavailable(String),
}

impl Gate {
    pub fn start(cfg: &McpConfig) -> Result<Self, String> {
        let all = sealed()?;
        let selected = selected(&all, cfg)?;
        let routes = session_routes(&selected);
        if selected
            .iter()
            .any(|c| !routes.iter().any(|r| r.cred == c.name))
        {
            return Err(
                "a selected credential is not a supported provider or PostgreSQL login".into(),
            );
        }
        if routes.is_empty() {
            return Err("no MCP credentials granted; operator must pass --credential NAME".into());
        }
        match client::send_request(&Request::StartGate {
            routes,
            port: None,
            limits: cfg.limits,
            tunnel: false,
            record: false,
            harness: None,
            privacy: None,
        })? {
            Response::GateStarted {
                port,
                placeholders,
                extras,
                ..
            } => Ok(Self {
                port,
                placeholders,
                db_ports: extras.db_ports,
                grant: cfg.grant_for("db_query"),
            }),
            _ => Err("unexpected daemon response".into()),
        }
    }
}

fn selected(
    all: &[kepr_core::protocol::CredInfo],
    cfg: &McpConfig,
) -> Result<Vec<kepr_core::protocol::CredInfo>, String> {
    cfg.credentials
        .iter()
        .map(|name| {
            all.iter()
                .find(|c| c.name.eq_ignore_ascii_case(name) && c.sealed == Some(true))
                .cloned()
                .ok_or_else(|| "a selected MCP credential is unavailable".into())
        })
        .collect()
}

#[derive(Default)]
pub enum GateSession {
    #[default]
    Fresh,
    Active(Gate),
    Closed,
}

pub fn with_gate<T>(
    session: &mut GateSession,
    cfg: &McpConfig,
    f: impl FnOnce(&Gate) -> Result<Attempt<T>, String>,
) -> Result<T, String> {
    run(session, cfg, Gate::start, f)
}

fn run<T>(
    session: &mut GateSession,
    cfg: &McpConfig,
    start: impl FnOnce(&McpConfig) -> Result<Gate, String>,
    f: impl FnOnce(&Gate) -> Result<Attempt<T>, String>,
) -> Result<T, String> {
    if matches!(session, GateSession::Fresh) {
        *session = GateSession::Closed;
        *session = GateSession::Active(start(cfg)?);
    }
    let GateSession::Active(gate) = session else {
        return Err("MCP gate authorization ended; operator must start a new session".into());
    };
    match f(gate)? {
        Attempt::Done(value) => Ok(value),
        Attempt::Unavailable(reason) => {
            drop(reason);
            *session = GateSession::Closed;
            Err("MCP gate authorization ended; operator must start a new session".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::protocol::CredInfo;
    use std::cell::Cell;

    #[test]
    fn only_explicit_sealed_credentials_are_selected() {
        let all = [
            CredInfo {
                name: "A".into(),
                sealed: Some(true),
                ..Default::default()
            },
            CredInfo {
                name: "B".into(),
                sealed: Some(true),
                ..Default::default()
            },
            CredInfo {
                name: "C".into(),
                sealed: Some(false),
                ..Default::default()
            },
        ];
        let mut cfg = McpConfig::default();
        assert!(selected(&all, &cfg).unwrap().is_empty());
        cfg.credentials = vec!["B".into()];
        assert_eq!(selected(&all, &cfg).unwrap()[0].name, "B");
        cfg.credentials.push("C".into());
        assert!(selected(&all, &cfg).is_err());
    }

    #[test]
    fn vanished_gate_never_starts_another_authorization() {
        let starts = Cell::new(0);
        let start = |cfg: &McpConfig| {
            starts.set(starts.get() + 1);
            Ok(Gate {
                port: 0,
                placeholders: HashMap::new(),
                db_ports: HashMap::new(),
                grant: cfg.grant_for("db_query"),
            })
        };
        let mut s = GateSession::Fresh;
        let cfg = McpConfig::default();
        let gone = |_: &Gate| Ok::<_, String>(Attempt::<()>::Unavailable("gone".into()));
        assert!(run(&mut s, &cfg, start, gone).is_err());
        assert!(run(&mut s, &cfg, start, |_| Ok(Attempt::Done(()))).is_err());
        assert_eq!(starts.get(), 1);
        assert!(matches!(s, GateSession::Closed));
    }

    #[test]
    fn failed_initial_authorization_is_terminal() {
        let mut s = GateSession::Fresh;
        let cfg = McpConfig::default();
        let r = run(
            &mut s,
            &cfg,
            |_| Err("locked".into()),
            |_| Ok(Attempt::Done(())),
        );
        assert!(r.is_err());
        assert!(run(
            &mut s,
            &cfg,
            |_| panic!("must not retry"),
            |_| Ok(Attempt::Done(()))
        )
        .is_err());
    }
}
