//! cli_agent.rs — `kepr protect-agent` (disabled pending kepr-gate).
//!
//! The original implementation exec'd the harness with only
//! `KEPR_FD_<KEY>` set. No supported harness reads that variable, so the
//! agent started without credentials, and the secret memfd (FD_CLOEXEC
//! cleared) was inherited by every tool the agent spawned, readable with
//! `cat <&3`. See docs/content/docs/agent-vault-plan.mdx §3.
//!
//! Until `kepr agent run` + `kepr-gate` ship (plan P1), the command refuses
//! and names the explicit, env-exposing alternative instead of pretending
//! to protect the agent.

use kepr_core::protocol::Response;

/// Supported AI agent harnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    Claude,
    Cursor,
    Windsurf,
    Aider,
}

impl AgentKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "claude" | "claude-code" => Some(Self::Claude),
            "cursor" => Some(Self::Cursor),
            "windsurf" => Some(Self::Windsurf),
            "aider" => Some(Self::Aider),
            _ => None,
        }
    }

    pub fn default_keys(&self) -> &'static [&'static str] {
        match self {
            Self::Claude => &["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
            Self::Cursor => &["CURSOR_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
            Self::Windsurf => &["WINDSURF_API_KEY", "OPENAI_API_KEY"],
            Self::Aider => &["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY"],
        }
    }
}
pub fn cmd_protect_agent(agent_name: Option<&str>, argv: &[String]) -> Response {
    let name = agent_name.unwrap_or("claude");
    let kind = match AgentKind::from_str(name) {
        Some(k) => k,
        None => {
            return Response::fail(format!(
                "unknown agent: {name} (supported: claude|cursor|windsurf|aider)"
            ))
        }
    };
    let _ = argv; // never exec'd: see module docs
    Response::fail(refusal_message(name, kind))
}

fn refusal_message(name: &str, kind: AgentKind) -> String {
    let keys = kind.default_keys().join(",");
    format!(
        "protect-agent is disabled: {name} reads {keys} from environment variables, \
         and kepr cannot yet hand them over without exposing them to the agent. \
         Sealed agent sessions (`kepr agent run`) are planned. If you accept that \
         the agent and its tools can read the keys, run: \
         kepr exec --env {keys} -- {name}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_kind_parsing() {
        assert_eq!(AgentKind::from_str("claude"), Some(AgentKind::Claude));
        assert_eq!(AgentKind::from_str("cursor"), Some(AgentKind::Cursor));
        assert_eq!(AgentKind::from_str("windsurf"), Some(AgentKind::Windsurf));
        assert_eq!(AgentKind::from_str("aider"), Some(AgentKind::Aider));
        assert_eq!(AgentKind::from_str("invalid"), None);
    }

    #[test]
    fn test_agent_default_keys() {
        assert!(AgentKind::Claude
            .default_keys()
            .contains(&"ANTHROPIC_API_KEY"));
        assert!(AgentKind::Aider
            .default_keys()
            .contains(&"DEEPSEEK_API_KEY"));
    }

    fn err_text(r: Response) -> String {
        match r {
            Response::Err { error } => error,
            other => panic!("expected Response::Err, got {other:?}"),
        }
    }

    // P0 (agent-vault-plan §3): protect-agent used to exec the harness with
    // only KEPR_FD_<KEY> set, which no harness reads, and with the secret
    // memfd inherited by every tool the agent spawns. It must now refuse
    // before contacting the daemon or exec'ing anything.
    #[test]
    fn protect_agent_refuses_without_exec() {
        let argv = vec!["/bin/false".to_string()];
        let msg = err_text(cmd_protect_agent(Some("claude"), &argv));
        assert!(msg.contains("ANTHROPIC_API_KEY"), "names the keys: {msg}");
        assert!(
            msg.contains("kepr exec --env"),
            "offers explicit opt-in: {msg}"
        );
    }

    #[test]
    fn protect_agent_refusal_never_mentions_memfd_as_safe() {
        let msg = err_text(cmd_protect_agent(Some("aider"), &[]));
        assert!(!msg.contains("KEPR_FD_"), "{msg}");
    }

    #[test]
    fn protect_agent_unknown_agent_still_rejected() {
        let msg = err_text(cmd_protect_agent(Some("nope"), &[]));
        assert!(msg.contains("unknown agent"), "{msg}");
    }
}
