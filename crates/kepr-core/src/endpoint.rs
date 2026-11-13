//! Evidence contracts for endpoint adapters. Execution adapters must establish
//! privacy outside engine output; an invocation alone never verifies locality.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyState {
    LocalVerified,
    CloudPossible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanVerdict {
    Clean,
    Detected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanReason {
    Complete,
    EngineUnavailable,
    IsolationUnavailable,
    InputRejected,
    Timeout,
    OutputLimit,
    ScanLimit,
    EngineError,
    Incomplete,
    UnverifiedPrivacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub engine: String,
    pub sha256: Option<String>,
    pub bytes: u64,
    pub privacy: PrivacyState,
    pub verdict: ScanVerdict,
    pub reason: ScanReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointCapabilities {
    pub adapter: String,
    pub engine_installed: bool,
    pub engine_trusted: bool,
    pub isolation_helper_trusted: bool,
    pub immutable_input_supported: bool,
    pub definitions_ready: bool,
    pub privacy: PrivacyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EndpointResponse {
    EndpointStatusOk { capabilities: EndpointCapabilities },
    EndpointScanResult { report: ScanReport },
}

/// Facts parsed by a trusted adapter from one bounded engine execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEvidence {
    pub exit_code: Option<i32>,
    pub privacy: PrivacyState,
    pub scanned_files: u64,
    pub known_signatures: u64,
    pub infected_files: u64,
    pub timed_out: bool,
    pub output_limited: bool,
    pub scan_limit_hit: bool,
    pub warnings: bool,
}

impl ScanEvidence {
    pub fn decision(&self, strict: bool) -> (ScanVerdict, ScanReason) {
        let unknown = |reason| (ScanVerdict::Unknown, reason);
        if self.timed_out {
            return unknown(ScanReason::Timeout);
        }
        if self.output_limited {
            return unknown(ScanReason::OutputLimit);
        }
        if self.scan_limit_hit {
            return unknown(ScanReason::ScanLimit);
        }
        if strict && self.privacy != PrivacyState::LocalVerified {
            return unknown(ScanReason::UnverifiedPrivacy);
        }
        if !matches!(self.exit_code, Some(0 | 1)) {
            return unknown(ScanReason::EngineError);
        }
        if self.warnings
            || self.scanned_files == 0
            || self.known_signatures == 0
            || self.infected_files > self.scanned_files
        {
            return unknown(ScanReason::Incomplete);
        }
        match (self.exit_code, self.infected_files) {
            (Some(0), 0) => (ScanVerdict::Clean, ScanReason::Complete),
            (Some(1), n) if n > 0 => (ScanVerdict::Detected, ScanReason::Complete),
            _ => unknown(ScanReason::Incomplete),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> ScanEvidence {
        ScanEvidence {
            exit_code: Some(0),
            privacy: PrivacyState::LocalVerified,
            scanned_files: 1,
            known_signatures: 100,
            infected_files: 0,
            timed_out: false,
            output_limited: false,
            scan_limit_hit: false,
            warnings: false,
        }
    }

    #[test]
    fn complete_local_execution_can_report_clean_or_detected() {
        let mut e = complete();
        assert_eq!(e.decision(true), (ScanVerdict::Clean, ScanReason::Complete));
        e.exit_code = Some(1);
        e.infected_files = 1;
        assert_eq!(
            e.decision(true),
            (ScanVerdict::Detected, ScanReason::Complete)
        );
    }

    #[test]
    fn incomplete_errors_and_resource_limits_never_report_clean() {
        let mut cases = Vec::new();
        let mut e = complete();
        e.timed_out = true;
        cases.push((e, ScanReason::Timeout));
        let mut e = complete();
        e.output_limited = true;
        cases.push((e, ScanReason::OutputLimit));
        let mut e = complete();
        e.scan_limit_hit = true;
        cases.push((e, ScanReason::ScanLimit));
        let mut e = complete();
        e.exit_code = Some(2);
        cases.push((e, ScanReason::EngineError));
        let mut e = complete();
        e.scanned_files = 0;
        cases.push((e, ScanReason::Incomplete));
        let mut e = complete();
        e.known_signatures = 0;
        cases.push((e, ScanReason::Incomplete));
        let mut e = complete();
        e.warnings = true;
        cases.push((e, ScanReason::Incomplete));
        let mut e = complete();
        e.infected_files = 1;
        cases.push((e, ScanReason::Incomplete));
        for (e, reason) in cases {
            assert_eq!(e.decision(true), (ScanVerdict::Unknown, reason));
        }
    }

    #[test]
    fn strict_policy_requires_verified_local_execution() {
        for privacy in [PrivacyState::CloudPossible, PrivacyState::Unknown] {
            let mut e = complete();
            e.privacy = privacy;
            assert_eq!(
                e.decision(true),
                (ScanVerdict::Unknown, ScanReason::UnverifiedPrivacy)
            );
        }
    }
}
