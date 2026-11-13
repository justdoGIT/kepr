//! Local, bounded privacy transformations. Originals never leave this session.

use crate::generate::ZeroString;
use serde::{Deserialize, Serialize};

mod detect;
mod encoded;
mod report;
mod routes;
pub use report::{PrivacyResponse, TransformReport};
pub use routes::supports_provider;

pub const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    #[default]
    PrivateCloud,
    LocalOnly,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u8,
    pub preset: Preset,
    #[serde(default)]
    pub identifiers: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: 1,
            preset: Preset::PrivateCloud,
            identifiers: Vec::new(),
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1 {
            return Err("unsupported privacy policy version");
        }
        if self.identifiers.len() > 128
            || self.identifiers.iter().any(|s| {
                s.len() < 2
                    || s.len() > 256
                    || s.chars().any(char::is_control)
                    || !crate::leak::find_all(s.as_bytes()).is_empty()
            })
        {
            return Err("invalid personal identifier policy");
        }
        Ok(())
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("version", &self.version)
            .field("preset", &self.preset)
            .field("identifier_count", &self.identifiers.len())
            .finish()
    }
}

struct Mapping {
    original: ZeroString,
    token: String,
}

pub struct Session {
    policy: Policy,
    mappings: Vec<Mapping>,
    mapping_bytes: usize,
}

impl Session {
    pub fn preset(&self) -> Preset {
        self.policy.preset
    }
    pub fn new(policy: Policy) -> Result<Self, &'static str> {
        policy.validate()?;
        Ok(Self {
            policy,
            mappings: Vec::new(),
            mapping_bytes: 0,
        })
    }

    pub fn transform(&mut self, text: &str) -> Result<(String, usize), &'static str> {
        let report = self.transform_with_counts(text)?;
        Ok((report.text, report.redactions))
    }

    pub fn transform_with_counts(&mut self, text: &str) -> Result<TransformReport, &'static str> {
        if text.len() > MAX_TEXT_BYTES {
            return Err("privacy input too large");
        }
        if detect::has_url_userinfo(text) {
            return Err("credential-bearing URL blocked");
        }
        let (text, keys) = crate::redact::text(text);
        let spans = detect::spans(&text, &self.policy.identifiers)?;
        let mut counts = std::collections::BTreeMap::new();
        if keys > 0 {
            counts.insert("credential".into(), keys);
        }
        let mut out = String::with_capacity(text.len());
        let mut offset = 0;
        for span in &spans {
            *counts.entry(span.kind.to_string()).or_insert(0) += 1;
            out.push_str(&text[offset..span.start]);
            let original = &text[span.start..span.end];
            let token = if let Some(m) = self
                .mappings
                .iter()
                .find(|m| m.original.as_str() == original)
            {
                m.token.clone()
            } else {
                if self.mappings.len() >= 4096 || self.mapping_bytes + original.len() > 1024 * 1024
                {
                    return Err("privacy session mapping limit reached");
                }
                let mut random = [0u8; 16];
                getrandom::fill(&mut random).map_err(|_| "privacy random source unavailable")?;
                let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
                let token = format!("kepr-private-{}-{suffix}", span.kind);
                self.mapping_bytes += original.len();
                self.mappings.push(Mapping {
                    original: ZeroString::from_string(original.to_string()),
                    token: token.clone(),
                });
                token
            };
            out.push_str(&token);
            offset = span.end;
        }
        out.push_str(&text[offset..]);
        if out.len() > MAX_TEXT_BYTES {
            return Err("transformed privacy text too large");
        }
        encoded::check(&out, &self.policy.identifiers)?;
        Ok(TransformReport {
            text: out,
            redactions: keys + spans.len(),
            counts,
        })
    }
}

#[cfg(test)]
mod tests;
