// daemon_vault — the P4 vault image (tickets T4.01–T4.07).
//
// An optional second credential store: one fixed-size file of 4 KiB
// slots in which names, counts, sizes, policies and values are all
// ciphertext, and free space looks exactly like data. The per-file store
// stays the default; `KEPR_STORE=image` opts in.
//
//   image.rs   the file: slots, noise fill, positioned IO (T4.01)
//   header.rs  the encrypted, authenticated header in slot 0 (T4.01)
//   keys.rs    HKDF key schedule from the master key, AEAD helpers
//   slot.rs    per-slot AES-256-GCM, AAD = image id ‖ slot ‖ epoch (T4.02)
//   merkle.rs  the header's Merkle root over used slots, verify (T4.02)
//   place.rs   HMAC slot placement with probing, decoy rewrites (T4.03)

// Only the tests use the image until T4.06 makes it a backend.
#[allow(dead_code)]
pub mod header;
#[allow(dead_code)]
pub mod image;
#[allow(dead_code)]
pub mod keys;
#[allow(dead_code)]
pub mod merkle;
#[allow(dead_code)]
pub mod place;
#[allow(dead_code)]
pub mod slot;
