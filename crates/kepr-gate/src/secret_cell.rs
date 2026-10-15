//! One cached value in secret memory (T12.02).
//!
//! Between requests the gate keeps resolved credentials and minted
//! tokens in `SecretRegion`s: `memfd_secret` pages when the kernel has
//! them (out of the direct map, never swapped, not in core dumps), or
//! mlocked, non-dumpable anonymous pages otherwise. Only when neither can
//! be had (RLIMIT_MEMLOCK spent) does a value stay on the heap, in a
//! `ZeroString`, and the gate says so once on stderr. A request gets a
//! transient `ZeroString` copy (`reveal`); hyper and rustls need those.
//!
//! No `Debug`: a cell is never printed or logged.

use std::sync::Once;

use kepr_core::generate::ZeroString;
use kepr_core::secmem::SecretRegion;

static HEAP_NOTICE: Once = Once::new();

pub struct SecretCell {
    region: Option<SecretRegion>,
    heap: Option<ZeroString>,
    len: usize,
}

impl SecretCell {
    /// Copy `v` into a fresh region (one page per cell).
    pub fn new(v: &str) -> SecretCell {
        match SecretRegion::new(v.len().max(1)) {
            Ok(mut region) => {
                region.as_mut_slice()[..v.len()].copy_from_slice(v.as_bytes());
                SecretCell {
                    region: Some(region),
                    heap: None,
                    len: v.len(),
                }
            }
            Err(_) => {
                HEAP_NOTICE.call_once(|| {
                    eprintln!("kepr-gate: secret memory unavailable; caching on the heap");
                });
                SecretCell {
                    region: None,
                    heap: Some(ZeroString::from(v)),
                    len: v.len(),
                }
            }
        }
    }

    /// A copy of the value for one use.
    pub fn reveal(&self) -> ZeroString {
        let bytes = match (&self.region, &self.heap) {
            (Some(r), _) => &r.as_slice()[..self.len],
            (None, Some(h)) => h.as_bytes(),
            (None, None) => &[],
        };
        // Sized up front, so the value is never copied by a reallocation.
        let mut s = String::with_capacity(self.len);
        // Always UTF-8: the bytes were copied from a `&str`.
        s.push_str(std::str::from_utf8(bytes).unwrap_or_default());
        ZeroString::from_string(s)
    }

    /// True iff the value lives in `memfd_secret` pages (tests and
    /// diagnostics).
    #[allow(dead_code)]
    pub fn is_secret_backed(&self) -> bool {
        self.region
            .as_ref()
            .is_some_and(SecretRegion::is_secret_backed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        let pem = "-----BEGIN PRIVATE KEY-----\n".to_string() + &"Ab3+/".repeat(1000);
        assert!(pem.len() > 4096, "over one page");
        for v in ["sk-ant-abc123", "pässwörd-日本語-🔑", "", pem.as_str()] {
            let c = SecretCell::new(v);
            assert_eq!(c.reveal().as_str(), v);
            assert_eq!(c.reveal().as_str(), v, "reveal leaves the cell intact");
        }
    }

    #[test]
    fn a_new_cell_is_secret_backed_when_the_kernel_allows() {
        if !kepr_core::secmem::memfd_secret_available() {
            eprintln!("skip: this kernel has no memfd_secret");
            return;
        }
        assert!(SecretCell::new("sk-ant-abc123").is_secret_backed());
    }
}
