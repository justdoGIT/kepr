// daemon_vault — the P4 vault image (tickets T4.01–T4.07).
//
// An optional second credential store: one fixed-size file of 4 KiB
// slots in which names, counts, sizes, policies and values are all
// ciphertext, and free space looks exactly like data. The per-file store
// stays the default; `KEPR_STORE=image` opts in (`store_dir()/vault.img`,
// one image for every uid the daemon serves; records are keyed by the
// per-file name `kepr-<uid>-<name>`, so the uid stays the boundary).
//
//   image.rs   the file: slots, noise fill, positioned IO (T4.01)
//   header.rs  the encrypted, authenticated header in slot 0 (T4.01)
//   keys.rs    HKDF key schedule from the master key, AEAD helpers
//   slot.rs    per-slot AES-256-GCM, AAD = image id ‖ slot ‖ epoch (T4.02)
//   merkle.rs  the header's Merkle root over used slots, verify (T4.02)
//   place.rs   HMAC slot placement with probing, decoy rewrites (T4.03)
//   journal.rs journal slot, two-phase commit, crash recovery (T4.04)
//   index.rs   index entries and record payload encodings (T4.05)
//   records.rs per-record keys, put/read/remove, crypto-shred (T4.05)
//   backend.rs the image as `crypto::Backend` + `expiry::MetaStore` (T4.06)
//   sweep.rs   TTL expiry inside the image (T4.06)
//   admin.rs   create / check / usage of the whole image (T4.07)
//   migrate.rs move the per-file store into the image (T4.07)
//   handlers.rs `kepr vault init|migrate|verify|status` (T4.07)
//   listing.rs every record, for the store features (T4.14)

pub mod admin;
pub mod backend;
mod handlers;
pub mod header;
pub mod image;
pub mod index;
pub mod journal;
pub mod keys;
pub mod listing;
pub mod merkle;
pub mod migrate;
pub mod place;
pub mod records;
pub mod slot;
pub mod sweep;
#[cfg(test)]
mod testio;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use backend::ImageBackend;

pub use handlers::dispatch;
pub use sweep::sweep_expired;

static ACTIVE: OnceLock<ImageBackend> = OnceLock::new();
/// The rollback state, kept in either mode so `kepr vault` commands run
/// against the per-file store still record and check the image's epoch.
static VERSIONS: OnceLock<Arc<crate::version_state::VersionState>> = OnceLock::new();

/// The image backend, when `KEPR_STORE=image` selected it at start-up.
pub fn active() -> Option<&'static ImageBackend> {
    ACTIVE.get()
}

fn versions() -> Option<Arc<crate::version_state::VersionState>> {
    VERSIONS.get().cloned()
}

pub fn image_path() -> PathBuf {
    crate::store::store_dir().join("vault.img")
}

/// Called once at start-up (from `crypto::initialize_inproc_backend`):
/// `KEPR_STORE` unset or `file` keeps the per-file store.
pub fn install_from_env(versions: Arc<crate::version_state::VersionState>) -> Result<(), String> {
    let _ = VERSIONS.set(Arc::clone(&versions));
    match std::env::var("KEPR_STORE").as_deref() {
        Err(_) | Ok("") | Ok("file") => Ok(()),
        Ok("image") => {
            let b = ImageBackend::new(image_path(), crate::crypto::snapshot_key, Some(versions));
            ACTIVE
                .set(b)
                .map_err(|_| "image backend already installed".to_string())?;
            eprintln!("[kepr-daemon] credential store: vault image");
            Ok(())
        }
        Ok(_) => Err("KEPR_STORE must be `file` or `image`".into()),
    }
}

fn in_image_dir(path: &Path) -> Option<&'static ImageBackend> {
    let b = active()?;
    (path.parent() == b.path().parent()).then_some(b)
}

/// The image's meta store for a sidecar path in the store directory.
pub fn meta_store_for(meta_path: &Path) -> Option<&'static dyn crate::expiry::MetaStore> {
    in_image_dir(meta_path).map(|b| b as &dyn crate::expiry::MetaStore)
}

/// (size, last write) of the credential behind a per-file path; for a
/// `.meta` path, (0, last write) of its record, meta-only ones (aliases)
/// included.
pub fn stat(path: &Path) -> Option<(u64, u64)> {
    let b = in_image_dir(path)?;
    let file = path.file_name()?.to_str()?;
    match file.strip_suffix(".meta") {
        Some(record) => b.updated(record).map(|t| (0, t)),
        None => b.stat(file),
    }
}

/// Recovery restore's proof: (1, 1) if `key` opens the image here,
/// (0, 1) if it doesn't, (0, 0) if there is no image.
pub fn probe_image(key: &[u8; 32]) -> (usize, usize) {
    let path = image_path();
    if !path.exists() {
        return (0, 0);
    }
    (usize::from(image::key_opens(&path, key)), 1)
}
