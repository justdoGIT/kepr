//! Trusted fixed ClamAV/bubblewrap adapter. Reports describe this execution,
//! never authorize later actions or attest an untrusted harness's JSON.
use super::{clamav, network, process, staging::Staged};
use kepr_core::endpoint::{
    EndpointCapabilities, PrivacyState, ScanReason, ScanReport, ScanVerdict,
};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const SCANNER: &str = "/usr/bin/clamscan";
const ISOLATOR: &str = "/usr/bin/bwrap";
const DATABASE: &str = "/var/lib/clamav";
const OUTPUT_LIMIT: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

fn native_namespace() -> bool {
    // A root-looking uid inside an agent-owned user namespace is not proof of
    // host ownership. This operator adapter refuses those contexts entirely.
    std::fs::read_to_string("/proc/self/uid_map")
        .is_ok_and(|text| text.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"])
}

fn trusted_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

fn trusted_executable(path: &str) -> bool {
    let path = Path::new(path);
    if !native_namespace() || !path.ancestors().skip(1).all(trusted_directory) {
        return false;
    }
    std::fs::symlink_metadata(path).is_ok_and(|m| {
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0
    })
}

fn definitions_ready() -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(DATABASE) else {
        return false;
    };
    // Root allocates the fixed directory to root or its dedicated update user.
    // The invoking user cannot own or modify the directory or definition files.
    // SAFETY: getuid has no arguments and cannot fail.
    let caller = unsafe { libc::getuid() };
    if !native_namespace()
        || !metadata.is_dir()
        || metadata.mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() == caller)
        || !Path::new(DATABASE)
            .ancestors()
            .skip(1)
            .all(trusted_directory)
    {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(DATABASE) else {
        return false;
    };
    let mut official_database = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let Ok(m) = std::fs::symlink_metadata(entry.path()) else {
            return false;
        };
        if !m.is_file() || m.mode() & 0o022 != 0 || (m.uid() != 0 && m.uid() != metadata.uid()) {
            return false;
        }
        if matches!(
            entry.path().extension().and_then(|e| e.to_str()),
            Some("cvd" | "cld")
        ) && m.len() > 0
        {
            official_database = true;
        }
    }
    official_database
}

pub fn capabilities() -> EndpointCapabilities {
    EndpointCapabilities {
        adapter: "clamav-isolated".into(),
        engine_installed: Path::new(SCANNER).is_file(),
        engine_trusted: trusted_executable(SCANNER),
        isolation_helper_trusted: trusted_executable(ISOLATOR),
        immutable_input_supported: Staged::from_bytes(&[]).is_ok(),
        definitions_ready: definitions_ready(),
        privacy: PrivacyState::Unknown,
    }
}

fn command(staged: &Staged) -> Result<Command, String> {
    let mut command = Command::new(ISOLATOR);
    command.env_clear().current_dir("/").args([
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--ro-bind",
        DATABASE,
        DATABASE,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "134217728",
        "--tmpfs",
        "/tmp",
        "--ro-bind-fd",
        "3",
        "/input",
        "--seccomp",
        "4",
        "--chdir",
        "/",
        "--",
        SCANNER,
        "--database=/var/lib/clamav",
        "--official-db-only=yes",
        "--fail-if-cvd-older-than=7",
        "--tempdir=/tmp",
        "--max-filesize=64M",
        "--max-scansize=128M",
        "--max-files=10000",
        "--max-recursion=16",
        "--alert-exceeds-max=yes",
        "--alert-encrypted=yes",
        "--follow-file-symlinks=0",
        "/input",
    ]);
    staged.attach_filtered(&mut command, network::filter_fd()?)?;
    // SAFETY: only resource-limit syscalls run after fork; no allocation/locking.
    unsafe {
        command.pre_exec(|| {
            for (resource, limit) in [
                (libc::RLIMIT_AS, 4u64 * 1024 * 1024 * 1024),
                (libc::RLIMIT_FSIZE, 128u64 * 1024 * 1024),
                (libc::RLIMIT_CPU, 35),
                (libc::RLIMIT_NPROC, 256),
                (libc::RLIMIT_NOFILE, 256),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: limit as libc::rlim_t,
                    rlim_max: limit as libc::rlim_t,
                };
                if libc::setrlimit(resource, &limit) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(command)
}

pub fn unknown(reason: ScanReason, staged: Option<&Staged>) -> ScanReport {
    ScanReport {
        engine: "clamav-isolated".into(),
        sha256: staged.map(|s| s.sha256.clone()),
        bytes: staged.map_or(0, |s| s.bytes),
        privacy: PrivacyState::Unknown,
        verdict: ScanVerdict::Unknown,
        reason,
    }
}

pub fn scan(staged: &Staged) -> ScanReport {
    let caps = capabilities();
    if !caps.engine_trusted || !caps.definitions_ready {
        return unknown(ScanReason::EngineUnavailable, Some(staged));
    }
    if !caps.isolation_helper_trusted {
        return unknown(ScanReason::IsolationUnavailable, Some(staged));
    }
    let Ok(mut command) = command(staged) else {
        return unknown(ScanReason::IsolationUnavailable, Some(staged));
    };
    let Ok(output) = process::run(&mut command, TIMEOUT, OUTPUT_LIMIT) else {
        return unknown(ScanReason::EngineError, Some(staged));
    };
    let mut facts = clamav::evidence(&output, false);
    // Trusted bubblewrap executes the fixed engine only after all requested
    // namespaces and mounts succeed. A complete engine summary proves it ran;
    // setup errors and incomplete output cannot claim verified local privacy.
    if matches!(output.exit_code, Some(0 | 1))
        && facts.known_signatures > 0
        && facts.scanned_files > 0
        && !facts.warnings
    {
        facts.privacy = PrivacyState::LocalVerified;
    }
    let (verdict, reason) = facts.decision(true);
    ScanReport {
        engine: "clamav-isolated".into(),
        sha256: Some(staged.sha256.clone()),
        bytes: staged.bytes,
        privacy: facts.privacy,
        verdict,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "optional real engine: requires native operator namespace, trusted ClamAV/bubblewrap and current official definitions"]
    fn real_local_engine_detects_harmless_eicar_without_a_host_file() {
        let fixture = [
            "X5O!P%@AP[",
            "4\\PZX54(P^)7CC)7}",
            "$EICAR-",
            "STANDARD-",
            "ANTIVIRUS-",
            "TEST-",
            "FILE!$H+H*",
        ]
        .concat();
        let staged = Staged::from_bytes(fixture.as_bytes()).unwrap();
        let result = scan(&staged);
        assert_eq!(result.privacy, PrivacyState::LocalVerified);
        assert_eq!(result.verdict, ScanVerdict::Detected);
    }
}
