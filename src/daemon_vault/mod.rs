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

// Only the tests use the image until T4.06 makes it a backend.
#[allow(dead_code)]
pub mod header;
#[allow(dead_code)]
pub mod image;
#[allow(dead_code)]
pub mod keys;
