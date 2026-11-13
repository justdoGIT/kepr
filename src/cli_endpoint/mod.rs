//! Local endpoint scanning adapters; strict scanning requires enforced isolation.
#[cfg(target_os = "linux")]
mod clamav;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod staging;

use kepr_core::endpoint::{
    EndpointCapabilities, EndpointResponse, PrivacyState, ScanReason, ScanReport, ScanVerdict,
};
use kepr_core::protocol::Response;
pub const VERBS: &[&str] = &["endpoint"];
pub const HELP: &str = "  endpoint status                     show local scanner and isolation capabilities\n  endpoint scan FILE                  scan an immutable copy with isolated local ClamAV\n";

pub fn dispatch(_verb: &str, args: &[String]) -> Response {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !matches!(*a, "--json" | "--color" | "--no-color"))
        .collect();
    let result = match args.as_slice() {
        ["status"] => EndpointResponse::EndpointStatusOk {
            capabilities: capabilities(),
        },
        ["scan", path] => EndpointResponse::EndpointScanResult {
            report: scan_path(path),
        },
        _ => return Response::fail("usage: kepr endpoint status | scan FILE"),
    };
    if !crate::cli_mode::json_mode() {
        show(&result);
    }
    Response::Endpoint(result)
}

fn capabilities() -> EndpointCapabilities {
    #[cfg(target_os = "linux")]
    {
        engine::capabilities()
    }
    #[cfg(not(target_os = "linux"))]
    {
        EndpointCapabilities {
            adapter: "unavailable".into(),
            engine_installed: false,
            engine_trusted: false,
            isolation_helper_trusted: false,
            immutable_input_supported: false,
            definitions_ready: false,
            privacy: PrivacyState::Unknown,
        }
    }
}

fn scan_path(path: &str) -> ScanReport {
    #[cfg(target_os = "linux")]
    {
        let caps = capabilities();
        // Check trusted setup before reading any private bytes.
        if !caps.engine_trusted || !caps.definitions_ready {
            return engine::unknown(ScanReason::EngineUnavailable, None);
        }
        if !caps.isolation_helper_trusted || !caps.immutable_input_supported {
            return engine::unknown(ScanReason::IsolationUnavailable, None);
        }
        match staging::Staged::from_path(std::path::Path::new(path)) {
            Ok(staged) => engine::scan(&staged),
            Err(_) => engine::unknown(ScanReason::InputRejected, None),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        ScanReport {
            engine: "unavailable".into(),
            sha256: None,
            bytes: 0,
            privacy: PrivacyState::Unknown,
            verdict: ScanVerdict::Unknown,
            reason: ScanReason::EngineUnavailable,
        }
    }
}

fn show(result: &EndpointResponse) {
    match result {
        EndpointResponse::EndpointStatusOk { capabilities: c } => {
            println!("endpoint adapter: {}", c.adapter);
            println!(
                "engine installed: {}; trusted: {}; definitions ready: {}",
                c.engine_installed, c.engine_trusted, c.definitions_ready
            );
            println!(
                "isolation helper trusted: {}; immutable input supported: {}",
                c.isolation_helper_trusted, c.immutable_input_supported
            );
            println!("local privacy is verified separately for each completed scan");
        }
        EndpointResponse::EndpointScanResult { report } => {
            let verdict = match report.verdict {
                ScanVerdict::Clean => "clean",
                ScanVerdict::Detected => "detected",
                ScanVerdict::Unknown => "unknown",
            };
            let privacy = match report.privacy {
                PrivacyState::LocalVerified => "local_verified",
                PrivacyState::CloudPossible => "cloud_possible",
                PrivacyState::Unknown => "unknown",
            };
            println!(
                "endpoint scan: {verdict}; privacy: {privacy}; reason: {:?}",
                report.reason
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_status_returns_structured_capabilities_without_claiming_locality() {
        let response = dispatch("endpoint", &["status".into(), "--json".into()]);
        assert!(matches!(response, Response::Endpoint(
            kepr_core::endpoint::EndpointResponse::EndpointStatusOk { capabilities }
        ) if capabilities.privacy == kepr_core::endpoint::PrivacyState::Unknown));
    }

    #[test]
    fn unavailable_or_rejected_input_reports_unknown_without_a_digest() {
        let response = dispatch(
            "endpoint",
            &[
                "scan".into(),
                "/nonexistent-kepr-endpoint-fixture/input".into(),
                "--json".into(),
            ],
        );
        assert!(matches!(response, Response::Endpoint(
            kepr_core::endpoint::EndpointResponse::EndpointScanResult { report }
        ) if report.verdict == kepr_core::endpoint::ScanVerdict::Unknown && report.sha256.is_none()));
    }
}
