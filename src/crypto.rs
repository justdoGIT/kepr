// crypto.rs — credential-backend wrapper (daemon-side only)
//
// This module is only compiled into credman-daemon.
// The user-facing binary never invokes the backend directly —
// it only speaks to the daemon over a Unix socket.
//
// The backend is never visible in the user's process list.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use crate::generate::ZeroString;
use crate::store;

// Path to the credential backend. The literal name appears here and in
// `sanitize_error` below because that function must recognise the
// backend's own stderr output; everywhere else in the codebase we call
// it "the credential backend".
const BACKEND_BIN: &str = "/usr/bin/systemd-creds";
const KEY_TYPE: &str = "host";

// ── Encrypt ───────────────────────────────────────────────────────────────────

/// Encrypt a secret value and store it in /etc/credstore.encrypted/
/// Called only from the daemon (running as root).
pub fn encrypt(uid: u32, name: &str, value: &[u8]) -> Result<(), String> {
    let cred_name = store::to_cred_name(uid, name);
    let out_path = store::cred_path(uid, name);

    // Ensure credstore exists with correct permissions
    let store = store::store_path();
    if !store.exists() {
        fs::create_dir_all(store).map_err(|e| format!("cannot create credstore: {e}"))?;
        fs::set_permissions(store, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot chmod credstore: {e}"))?;
    }

    // Write to a per-pid temp path in the same directory, then atomically
    // rename over the target. Prevents concurrent `set NAME` calls from
    // interleaving partial writes — rename(2) is atomic on the same fs,
    // so any reader either sees the old file or the whole new one.
    let tmp_path = out_path.with_extension(format!("tmp.{}", std::process::id()));

    let mut child = Command::new(BACKEND_BIN)
        .args([
            "encrypt",
            &format!("--with-key={KEY_TYPE}"),
            "--name",
            &cred_name,
            "-",                        // read from stdin
            tmp_path.to_str().unwrap(), // write to temp file
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start encryption backend: {e}"))?;

    // Write secret to stdin
    {
        let stdin = child.stdin.take().unwrap();
        let mut stdin = stdin;
        if let Err(e) = stdin.write_all(value) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("write error: {e}"));
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("encryption backend error: {e}"));
        }
    };

    if !output.status.success() {
        let _ = fs::remove_file(&tmp_path);
        // Sanitize error — don't leak internal tool names in the message
        // that gets sent back to the user
        let raw = String::from_utf8_lossy(&output.stderr);
        let clean = sanitize_error(&raw);
        return Err(format!("encryption failed: {clean}"));
    }

    // Lock down the temp file BEFORE rename — rename preserves source mode.
    if let Err(e) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("cannot secure credential file: {e}"));
    }

    fs::rename(&tmp_path, &out_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("cannot install credential: {e}")
    })
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt a credential. Returns ZeroString so memory is cleared on drop.
/// Called only from the daemon (running as root).
pub fn decrypt(uid: u32, name: &str) -> Result<ZeroString, String> {
    let cred_path = store::cred_path(uid, name);

    if !cred_path.exists() {
        return Err(format!("credential not found: {name}"));
    }

    let output = Command::new(BACKEND_BIN)
        .args([
            "decrypt",
            cred_path.to_str().unwrap(),
            "-", // write to stdout
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed to start decryption backend: {e}"))?;

    if !output.status.success() {
        let raw = String::from_utf8_lossy(&output.stderr);
        let clean = sanitize_error(&raw);
        return Err(format!("decryption failed: {clean}"));
    }

    let s = String::from_utf8(output.stdout)
        .map_err(|_| "credential contains invalid UTF-8".to_string())?;

    Ok(ZeroString::from_string(
        s.trim_end_matches('\n').to_string(),
    ))
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub fn delete(uid: u32, name: &str) -> Result<(), String> {
    let cred_path = store::cred_path(uid, name);
    if !cred_path.exists() {
        return Err(format!("credential not found: {name}"));
    }
    fs::remove_file(&cred_path).map_err(|e| format!("cannot delete credential: {e}"))
}

// ── Error sanitizer ───────────────────────────────────────────────────────────

/// Remove any mention of internal tooling from error messages
/// before they are sent back to the user.
fn sanitize_error(raw: &str) -> String {
    raw.replace("systemd-creds", "credential backend")
        .replace(BACKEND_BIN, "credential backend")
        .replace("--with-key", "")
        .replace(KEY_TYPE, "")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("; ")
        .trim()
        .to_string()
}

// ── Check ─────────────────────────────────────────────────────────────────────

/// Verify a credential can be decrypted. Returns true/false.
pub fn verify(uid: u32, name: &str) -> bool {
    decrypt(uid, name).is_ok()
}

// ── Credential exists ─────────────────────────────────────────────────────────

pub fn exists(uid: u32, name: &str) -> bool {
    store::cred_path(uid, name).exists()
}
