//! A fixed local ClamAV engine; engine output is never returned to the caller.
use super::process::Captured;
use kepr_core::endpoint::{PrivacyState, ScanEvidence};

pub fn evidence(output: &Captured, isolated: bool) -> ScanEvidence {
    let mut e = ScanEvidence {
        exit_code: output.exit_code,
        privacy: if isolated {
            PrivacyState::LocalVerified
        } else {
            PrivacyState::Unknown
        },
        scanned_files: 0,
        known_signatures: 0,
        infected_files: 0,
        timed_out: output.timed_out,
        output_limited: output.output_limited,
        scan_limit_hit: false,
        warnings: output.incomplete || !output.stderr.is_empty(),
    };
    let Ok(text) = std::str::from_utf8(&output.stdout) else {
        e.warnings = true;
        return e;
    };
    e.scan_limit_hit = text.contains("Heuristics.Limits.Exceeded");
    e.warnings |= text.contains("Heuristics.Encrypted.");
    let mut found = std::collections::HashSet::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let field = match key.trim() {
            "Known viruses" => &mut e.known_signatures,
            "Scanned files" => &mut e.scanned_files,
            "Infected files" => &mut e.infected_files,
            _ => continue,
        };
        if !found.insert(key.trim()) {
            e.warnings = true;
        }
        match value.trim().parse::<u64>() {
            Ok(n) => *field = n,
            Err(_) => e.warnings = true,
        }
    }
    if found.len() != 3 {
        e.warnings = true;
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use kepr_core::endpoint::{ScanReason, ScanVerdict};
    fn output(text: &str, code: i32) -> Captured {
        Captured {
            stdout: zeroize::Zeroizing::new(text.as_bytes().to_vec()),
            stderr: zeroize::Zeroizing::new(Vec::new()),
            exit_code: Some(code),
            timed_out: false,
            output_limited: false,
            incomplete: false,
        }
    }
    #[test]
    fn complete_summary_required_for_clean_and_incomplete_or_limit_never_passes() {
        let out = output(
            "Known viruses: 100\nScanned files: 1\nInfected files: 0\n",
            0,
        );
        assert_eq!(
            evidence(&out, true).decision(true),
            (ScanVerdict::Clean, ScanReason::Complete)
        );
        assert_eq!(evidence(&out, false).decision(true).0, ScanVerdict::Unknown);
        for text in ["fixture: OK\n", "Known viruses: 0\nScanned files: 1\nInfected files: 0\n",
            "Heuristics.Limits.Exceeded FOUND\nKnown viruses: 100\nScanned files: 1\nInfected files: 1\n"] {
            assert_eq!(evidence(&output(text, 0), true).decision(true).0, ScanVerdict::Unknown);
        }
    }

    #[test]
    fn encrypted_content_is_incomplete_even_when_engine_reports_a_detection() {
        let out = output(
            "/input: Heuristics.Encrypted.Zip FOUND\nKnown viruses: 100\nScanned files: 1\nInfected files: 1\n",
            1,
        );
        assert_eq!(
            evidence(&out, true).decision(true),
            (ScanVerdict::Unknown, ScanReason::Incomplete)
        );
    }
}
