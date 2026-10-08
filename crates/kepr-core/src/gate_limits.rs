//! Per-session caps a gate enforces (P9.5), and the per-day caps per
//! credential that hold across a user's sessions (T9.06). Carried in
//! the gate's `SessionConfig`; re-exported from `gate_protocol`.

use serde::{Deserialize, Serialize};

/// Per-session caps the gate enforces (P9.5). `None` = no cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLimits {
    /// Total forwarded requests.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_requests: Option<u64>,
    /// Total tokens, as reported in the providers' `usage` fields.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_tokens: Option<u64>,
    /// Requests per rolling minute.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub per_minute: Option<u32>,
    /// T9.06: requests per credential per local day, across sessions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_requests_day: Option<u64>,
    /// T9.06: tokens per credential per local day, across sessions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_tokens_day: Option<u64>,
}

impl GateLimits {
    pub fn is_none(&self) -> bool {
        *self == Self::default()
    }

    /// Caps must be positive; the per-minute rate at most 10 000.
    pub fn validate(&self) -> Result<(), String> {
        let caps = [
            self.max_requests,
            self.max_tokens,
            self.max_requests_day,
            self.max_tokens_day,
        ];
        if caps.contains(&Some(0)) {
            return Err("request and token limits must be at least 1".into());
        }
        if self.per_minute.is_some_and(|r| r == 0 || r > 10_000) {
            return Err("the per-minute rate must be 1-10000".into());
        }
        Ok(())
    }
}
