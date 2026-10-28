// crypto_seam.rs — T12.39: the daemon's AES-GCM, HKDF and HMAC go through
// `daemon_eco::cipher`, so a `fips` build runs them in aws-lc-rs. This test
// scans the production part of the daemon's sources for the RustCrypto
// crates' paths and fails on any file that uses them directly.
//
// `PENDING` lists the files still to move (T12.40-T12.42). It only shrinks:
// a second test fails when a listed file no longer matches, so the entry has
// to be deleted in the same change that converts the file.

use std::fs;
use std::path::{Path, PathBuf};

/// Paths that must only appear in the seam itself.
const FORBIDDEN: &[&str] = &["aes_gcm::", "hkdf::", "Hkdf::", "hmac::", "Hmac<"];

/// The seam: the only production files allowed to name those crates.
const ALLOWED: &[&str] = &["src/daemon_eco/cipher.rs", "src/daemon_eco/crypto_fips.rs"];

/// Files that still use the crates directly. Shrink only.
const PENDING: &[&str] = &[
    "src/daemon_vault/keys.rs",
    "src/daemon_vault/place.rs",
    "src/daemon_sharing/kem.rs",
    "src/daemon_sharing/link.rs",
    "src/daemon_sharing/emergency_proof.rs",
    "src/daemon_gatex/recfile.rs",
    "src/daemon_seal/fido2_kek.rs",
    "src/daemon_syncx/device_bundle.rs",
    "src/daemon_syncx/folder_bundle.rs",
    "src/daemon_syncx/folder_state.rs",
    "src/daemon_syncx/quorum_device.rs",
    "src/daemon_syncx/sync_state.rs",
];

/// The part of a source file before its first `#[cfg(test)]` (the same rule
/// as tests/file_size_limit.rs).
fn production_part(path: &Path) -> String {
    let text = fs::read_to_string(path).expect("read source file");
    let mut out = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// A line that is not a comment and names a forbidden path.
fn offending_lines(src: &str) -> Vec<String> {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| FORBIDDEN.iter().any(|f| l.contains(f)))
        .map(|l| l.trim().to_string())
        .collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// Daemon sources the rule covers, as repo-relative `/` paths.
fn daemon_sources() -> Vec<(String, PathBuf)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut all = Vec::new();
    walk(&root.join("src"), &mut all);
    let mut out: Vec<(String, PathBuf)> = all
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, p)
        })
        .filter(|(rel, _)| {
            let name = rel.trim_start_matches("src/");
            let in_daemon_tree = name.starts_with("daemon_") && rel.matches('/').count() >= 2;
            name.starts_with("daemon")
                && (name.ends_with(".rs") && !name.contains('/') || in_daemon_tree)
                || matches!(
                    rel.as_str(),
                    "src/crypto_inproc.rs"
                        | "src/key_unlock.rs"
                        | "src/master_key.rs"
                        | "src/audit_chain.rs"
                )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn crypto_seam() {
    let mut bad = Vec::new();
    for (rel, path) in daemon_sources() {
        if ALLOWED.contains(&rel.as_str()) || PENDING.contains(&rel.as_str()) {
            continue;
        }
        let lines = offending_lines(&production_part(&path));
        if !lines.is_empty() {
            bad.push(format!("{rel}: {}", lines.join(" | ")));
        }
    }
    assert!(
        bad.is_empty(),
        "these files use the RustCrypto crates directly; route them through daemon_eco::cipher:\n{}",
        bad.join("\n")
    );
}

#[test]
fn pending_lists_only_files_that_still_match() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut stale = Vec::new();
    for rel in PENDING {
        let path = root.join(rel);
        assert!(path.exists(), "PENDING names a missing file: {rel}");
        if offending_lines(&production_part(&path)).is_empty() {
            stale.push(*rel);
        }
    }
    assert!(
        stale.is_empty(),
        "remove these from PENDING (they no longer use the crates directly): {stale:?}"
    );
}
