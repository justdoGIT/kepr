// crypto.rs — the credential-backend seam (daemon-side only).
//
// Every credential operation goes through `default_backend()`: the
// in-process AES-256-GCM backend (crypto_inproc.rs), installed at daemon
// start once the master key is loaded. Before that, every call fails:
// there is no fallback to another backend. The user-facing binary never
// touches this module; it only speaks to the daemon over its socket.

use std::sync::Arc;
use std::sync::OnceLock;

use crate::crypto_inproc::InProcBackend;
use crate::version_state::VersionState;
use kepr_core::generate::ZeroString;

// ── Wire-error sanitiser ──────────────────────────────────────────────────────
//
// Distinguishable get/delete errors leak credential existence: a "credential
// not found" tells the caller the cred is absent, while "decryption failed"
// tells the caller it exists but is unreadable. Either is enough to enumerate
// names by trial. Collapse both into a single user-facing message; the
// precise reason still goes to the audit log via the handler.

pub const SANITIZED_LOOKUP_ERROR: &str = "credential unavailable";

pub fn sanitize_lookup_error(precise: &str) -> String {
    if precise.starts_with("credential not found") || precise.starts_with("decryption failed") {
        SANITIZED_LOOKUP_ERROR.to_string()
    } else {
        precise.to_string()
    }
}

// ── Backend trait ────────────────────────────────────────────────────────────

pub trait Backend: Send + Sync {
    fn encrypt(&self, uid: u32, name: &str, value: &[u8]) -> Result<(), String>;
    fn decrypt(&self, uid: u32, name: &str) -> Result<ZeroString, String>;
    fn delete(&self, uid: u32, name: &str) -> Result<(), String>;

    fn verify(&self, uid: u32, name: &str) -> bool {
        self.decrypt(uid, name).is_ok()
    }
}

/// What `default_backend()` returns before start-up has installed the
/// real one: every operation fails closed.
struct Uninitialised;

impl Backend for Uninitialised {
    fn encrypt(&self, _: u32, _: &str, _: &[u8]) -> Result<(), String> {
        Err(NOT_READY.into())
    }
    fn decrypt(&self, _: u32, _: &str) -> Result<ZeroString, String> {
        Err(NOT_READY.into())
    }
    fn delete(&self, _: u32, _: &str) -> Result<(), String> {
        Err(NOT_READY.into())
    }
}

const NOT_READY: &str = "credential backend is not initialized";

/// Single per-process slot for the InProc backend instance. Initialised
/// at daemon startup via `initialize_inproc_backend` once the master key
/// has been loaded; thereafter every credential op routes through it.
/// The `OnceLock` is a one-shot — re-initialisation in the same process
/// returns Err and the existing backend is left in place.
static INPROC_BACKEND: OnceLock<InProcBackend> = OnceLock::new();

/// Install the in-process AEAD backend as the daemon's default. Called
/// from `kepr-daemon::main` after the master key + VersionState are
/// loaded; repeated calls return Err so a misconfigured restart cannot
/// silently swap backends mid-process.
pub fn initialize_inproc_backend(
    master_key: [u8; 32],
    versions: Arc<VersionState>,
) -> Result<(), String> {
    INPROC_BACKEND
        .set(InProcBackend::new(master_key, versions))
        .map_err(|_| "InProc backend already initialised".to_string())
}
pub fn lock_backend() -> Result<(), String> {
    INPROC_BACKEND
        .get()
        .ok_or_else(|| NOT_READY.to_string())?
        .lock();
    Ok(())
}

pub fn unlock_backend(master_key: [u8; 32]) -> Result<(), String> {
    INPROC_BACKEND
        .get()
        .ok_or_else(|| NOT_READY.to_string())?
        .unlock(master_key)
}

pub fn backend_is_locked() -> bool {
    INPROC_BACKEND
        .get()
        .map(InProcBackend::is_locked)
        .unwrap_or(true)
}
pub fn snapshot_key() -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let backend = INPROC_BACKEND.get().ok_or_else(|| NOT_READY.to_string())?;
    backend
        .snapshot_key()
        .map(zeroize::Zeroizing::new)
        .ok_or_else(|| "credential store is locked".to_string())
}

/// The daemon's credential backend (the in-process AEAD backend once
/// `initialize_inproc_backend` has run; a fail-closed stub before).
pub fn default_backend() -> &'static dyn Backend {
    match INPROC_BACKEND.get() {
        Some(b) => b as &dyn Backend,
        None => &Uninitialised,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninitialised_backend_fails_closed() {
        let b: &'static dyn Backend = &Uninitialised;
        assert!(b.decrypt(1, "X").is_err());
        assert!(b.encrypt(1, "X", b"v").is_err());
    }

    #[test]
    fn collapses_not_found() {
        let out = sanitize_lookup_error("credential not found: FOO");
        assert_eq!(out, SANITIZED_LOOKUP_ERROR);
    }

    #[test]
    fn collapses_decrypt_failed() {
        let out = sanitize_lookup_error("decryption failed: cred backend exited 1");
        assert_eq!(out, SANITIZED_LOOKUP_ERROR);
    }

    #[test]
    fn passes_unrelated_errors_through() {
        // Validation errors and operational errors are not lookup leaks; they
        // help the legitimate user diagnose their own bad input. Don't collapse.
        let raw = "name must match [A-Z0-9_]";
        assert_eq!(sanitize_lookup_error(raw), raw);
    }

    #[test]
    fn collapsed_message_contains_no_name() {
        // Defence-in-depth: the sanitised constant must never embed the
        // attempted name. Anyone changing SANITIZED_LOOKUP_ERROR should keep
        // it free of placeholders.
        assert!(!SANITIZED_LOOKUP_ERROR.contains("{}"));
        assert!(!SANITIZED_LOOKUP_ERROR.contains("FOO"));
    }
}
