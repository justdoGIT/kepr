// crypto.rs — systemd-creds wrapper (daemon-side only)
//
// This module is only compiled into credman-daemon.
// The user-facing binary never touches systemd-creds directly —
// it only speaks to the daemon over a Unix socket.
//
// systemd-creds is never visible in the user's process list.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use crate::generate::ZeroString;
use crate::store;

const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
const KEY_TYPE:      &str = "host";   // --with-key=host

// ── Encrypt ───────────────────────────────────────────────────────────────────

/// Encrypt a secret value and store it in /etc/credstore.encrypted/
/// Called only from the daemon (running as root).
pub fn encrypt(uid: u32, name: &str, value: &[u8]) -> Result<(), String> {
    let cred_name = store::to_cred_name(uid, name);
    let out_path  = store::cred_path(uid, name);

    // Ensure credstore exists with correct permissions
    let store = store::store_path();
    if !store.exists() {
        fs::create_dir_all(store)
            .map_err(|e| format!("cannot create credstore: {e}"))?;
        fs::set_permissions(store, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot chmod credstore: {e}"))?;
    }

    let mut child = Command::new(SYSTEMD_CREDS)
        .args([
            "encrypt",
            &format!("--with-key={KEY_TYPE}"),
            "--name", &cred_name,
            "-",                                // read from stdin
            out_path.to_str().unwrap(),         // write to file
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
        stdin.write_all(value)
            .map_err(|e| format!("write error: {e}"))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("encryption backend error: {e}"))?;

    if !output.status.success() {
        // Sanitize error — don't leak internal tool names in the message
        // that gets sent back to the user
        let raw = String::from_utf8_lossy(&output.stderr);
        let clean = sanitize_error(&raw);
        return Err(format!("encryption failed: {clean}"));
    }

    // Lock down the credential file
    fs::set_permissions(&out_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot secure credential file: {e}"))?;

    Ok(())
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt a credential. Returns ZeroString so memory is cleared on drop.
/// Called only from the daemon (running as root).
pub fn decrypt(uid: u32, name: &str) -> Result<ZeroString, String> {
    let cred_path = store::cred_path(uid, name);

    if !cred_path.exists() {
        return Err(format!("credential not found: {name}"));
    }

    let output = Command::new(SYSTEMD_CREDS)
        .args([
            "decrypt",
            cred_path.to_str().unwrap(),
            "-",    // write to stdout
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

    Ok(ZeroString::from_string(s.trim_end_matches('\n').to_string()))
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub fn delete(uid: u32, name: &str) -> Result<(), String> {
    let cred_path = store::cred_path(uid, name);
    if !cred_path.exists() {
        return Err(format!("credential not found: {name}"));
    }
    fs::remove_file(&cred_path)
        .map_err(|e| format!("cannot delete credential: {e}"))
}

// ── Error sanitizer ───────────────────────────────────────────────────────────

/// Remove any mention of internal tooling from error messages
/// before they are sent back to the user.
fn sanitize_error(raw: &str) -> String {
    raw.replace("systemd-creds", "credential backend")
       .replace(SYSTEMD_CREDS,   "credential backend")
       .replace("--with-key",    "")
       .replace(KEY_TYPE,        "")
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
