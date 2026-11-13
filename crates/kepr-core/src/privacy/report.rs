//! Preview and configuration reports contain counts, never identifier originals.

use super::Preset;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub struct TransformReport {
    pub text: String,
    pub redactions: usize,
    pub counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrivacyResponse {
    PrivacyStatusOk {
        configured: bool,
        preset: Preset,
        identifier_count: usize,
        device_enforcement_available: bool,
        local_inference_available: bool,
    },
    PrivacyConfiguredOk {
        preset: Preset,
        identifier_count: usize,
    },
    PrivacyPreviewOk {
        preset: Preset,
        text: String,
        redactions: usize,
        counts: BTreeMap<String, usize>,
    },
}
