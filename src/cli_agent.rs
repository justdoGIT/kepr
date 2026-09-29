//! cli_agent.rs — AI Agent protection wrappers (`kepr protect-agent`).
//!
//! Intercepts AI agent invocations (Claude Code, Cursor, Windsurf, Aider)
//! and provisions required API keys via sealed memfd file descriptors
//! (`KEPR_FD_*`) so secrets exist strictly in RAM and are protected
//! against LLM context leakage.

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
    let memfd_keys: Vec<String> = kind.default_keys().iter().map(|s| s.to_string()).collect();
    crate::cli_exec::cmd_exec(&[], &memfd_keys, argv)
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
        assert!(AgentKind::Claude.default_keys().contains(&"ANTHROPIC_API_KEY"));
        assert!(AgentKind::Aider.default_keys().contains(&"DEEPSEEK_API_KEY"));
    }
}
