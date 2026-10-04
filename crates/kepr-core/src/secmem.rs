//! Secret memory regions (agent vault plan §6.2, tickets T3.01–T3.03).
//!
//! `SecretRegion` owns one page-aligned region for key material:
//! - backed by `memfd_secret(2)` when the kernel offers it (pages are
//!   removed from the kernel direct map, never swapped, absent from core
//!   dumps, unreachable through /proc/PID/mem and process_vm_readv);
//! - otherwise anonymous memory with `mlock` + `MADV_DONTDUMP` +
//!   `MADV_WIPEONFORK`;
//! - one `PROT_NONE` guard page on each side, so an overrun faults
//!   instead of reading a neighbour;
//! - placed at a random page-aligned address.
//!
//! `SplitKey` keeps a key as two XOR shares in two regions and can move
//! them to fresh random addresses, so no single memory snapshot holds
//! the key in one place.

use std::ptr;
use zeroize::Zeroize;

/// True iff `memfd_secret(2)` works on this kernel (Linux 5.14+, and on
/// some kernels only with `secretmem.enable=1`).
pub fn memfd_secret_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: memfd_secret takes a flags integer and returns a new fd
        // or -1; we close any fd it returns.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd as i32) };
            return true;
        }
    }
    false
}

fn page_size() -> usize {
    // SAFETY: sysconf with a constant name has no memory effects.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p > 0 {
        p as usize
    } else {
        4096
    }
}

/// A CSPRNG-chosen, page-aligned address hint in the lower user range.
fn random_hint(page: usize, total: usize) -> *mut libc::c_void {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        return ptr::null_mut();
    }
    const LOW: usize = 0x1000_0000_0000;
    const SPAN: usize = 0x4000_0000_0000;
    let off = (usize::from_ne_bytes(b) % (SPAN - total)) & !(page - 1);
    (LOW + off) as *mut libc::c_void
}

pub struct SecretRegion {
    base: *mut u8,
    total: usize,
    data_len: usize,
    page: usize,
    secret_backed: bool,
}

// SAFETY: the region is exclusively owned; access goes through &self /
// &mut self, so the usual borrow rules prevent data races.
unsafe impl Send for SecretRegion {}
unsafe impl Sync for SecretRegion {}

impl SecretRegion {
    pub fn new(len: usize) -> Result<Self, String> {
        let page = page_size();
        let data_len = len.max(1).div_ceil(page) * page;
        let total = data_len + 2 * page;
        let prot_none_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        // SAFETY: reserving fresh address space; the hint is only a hint
        // (no MAP_FIXED), so existing mappings are never replaced.
        let mut base = unsafe {
            libc::mmap(
                random_hint(page, total),
                total,
                libc::PROT_NONE,
                prot_none_flags,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            // SAFETY: as above, without a hint.
            base = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    total,
                    libc::PROT_NONE,
                    prot_none_flags,
                    -1,
                    0,
                )
            };
        }
        if base == libc::MAP_FAILED {
            return Err("cannot reserve secret memory".into());
        }
        let mut region = Self {
            base: base as *mut u8,
            total,
            data_len,
            page,
            secret_backed: false,
        };
        // SAFETY: data = base + one guard page, inside our reservation.
        let data = unsafe { region.base.add(page) } as *mut libc::c_void;
        region.secret_backed = Self::map_secret(data, data_len);
        if !region.secret_backed {
            Self::map_locked(data, data_len)?;
        }
        Ok(region)
    }

    /// Replace the data pages with memfd_secret pages. False if unavailable.
    fn map_secret(data: *mut libc::c_void, len: usize) -> bool {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: memfd_secret/ftruncate/mmap/close on an fd we own;
            // MAP_FIXED only targets `data`, which lies inside the
            // reservation this SecretRegion owns.
            unsafe {
                let fd = libc::syscall(libc::SYS_memfd_secret, 0) as i32;
                if fd < 0 {
                    return false;
                }
                let ok = libc::ftruncate(fd, len as libc::off_t) == 0
                    && libc::mmap(
                        data,
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        fd,
                        0,
                    ) != libc::MAP_FAILED;
                libc::close(fd);
                return ok;
            }
        }
        #[allow(unreachable_code)]
        false
    }

    fn map_locked(data: *mut libc::c_void, len: usize) -> Result<(), String> {
        // SAFETY: MAP_FIXED inside our own reservation; mlock/madvise on
        // that same range.
        unsafe {
            let p = libc::mmap(
                data,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err("cannot map secret memory".into());
            }
            if libc::mlock(data, len) != 0 {
                return Err("cannot lock secret memory (RLIMIT_MEMLOCK?)".into());
            }
            libc::madvise(data, len, libc::MADV_DONTDUMP);
            #[cfg(target_os = "linux")]
            libc::madvise(data, len, libc::MADV_WIPEONFORK);
        }
        Ok(())
    }

    /// True iff backed by memfd_secret (hidden from the kernel direct map).
    pub fn is_secret_backed(&self) -> bool {
        self.secret_backed
    }

    pub fn len(&self) -> usize {
        self.data_len
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Address of the first data byte (for diagnostics and tests).
    pub fn data_addr(&self) -> usize {
        self.base as usize + self.page
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: data_len readable+writable bytes start one page past base.
        unsafe { std::slice::from_raw_parts(self.base.add(self.page), self.data_len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above; &mut self guarantees exclusive access.
        unsafe { std::slice::from_raw_parts_mut(self.base.add(self.page), self.data_len) }
    }
}

impl Drop for SecretRegion {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        // SAFETY: unmapping exactly the reservation we created.
        unsafe {
            let data = self.base.add(self.page) as *mut libc::c_void;
            if !self.secret_backed {
                libc::munlock(data, self.data_len);
            }
            libc::munmap(self.base as *mut libc::c_void, self.total);
        }
    }
}

/// A key held as two XOR shares in two secret regions (T3.03).
pub struct SplitKey<const N: usize> {
    a: SecretRegion,
    b: SecretRegion,
}

impl<const N: usize> SplitKey<N> {
    pub fn new(key: &[u8; N]) -> Result<Self, String> {
        let mut a = SecretRegion::new(N)?;
        let mut b = SecretRegion::new(N)?;
        getrandom::fill(&mut a.as_mut_slice()[..N]).map_err(|e| format!("CSPRNG failure: {e}"))?;
        let mask = &a.as_slice()[..N];
        for ((dst, k), m) in b.as_mut_slice()[..N].iter_mut().zip(key).zip(mask) {
            *dst = k ^ m;
        }
        Ok(Self { a, b })
    }

    /// Recombine into a zeroized stack buffer for the duration of `f`.
    pub fn with_key<R>(&self, f: impl FnOnce(&[u8; N]) -> R) -> R {
        let mut k = zeroize::Zeroizing::new([0u8; N]);
        for ((dst, a), b) in k.iter_mut().zip(self.a.as_slice()).zip(self.b.as_slice()) {
            *dst = a ^ b;
        }
        f(&k)
    }

    /// Move both shares to fresh random addresses with a fresh mask.
    pub fn relocate(&mut self) -> Result<(), String> {
        let fresh = self.with_key(Self::new)?;
        *self = fresh; // old regions are zeroized and unmapped on drop
        Ok(())
    }

    /// Share addresses (diagnostics and tests).
    pub fn addrs(&self) -> (usize, usize) {
        (self.a.data_addr(), self.b.data_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_consistent() {
        assert_eq!(memfd_secret_available(), memfd_secret_available());
    }

    #[test]
    fn region_round_trip_and_rounding() {
        let mut r = SecretRegion::new(10).unwrap();
        assert_eq!(r.len() % page_size(), 0);
        r.as_mut_slice()[..5].copy_from_slice(b"hello");
        assert_eq!(&r.as_slice()[..5], b"hello");
        assert_eq!(r.is_secret_backed(), memfd_secret_available());
    }

    #[test]
    fn guard_pages_surround_data() {
        let r = SecretRegion::new(32).unwrap();
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let (lo, hi) = (r.data_addr(), r.data_addr() + r.len());
        let page = page_size();
        let range = |l: &str| {
            let (a, b) = l.split_whitespace().next()?.split_once('-')?;
            Some((
                usize::from_str_radix(a, 16).ok()?,
                usize::from_str_radix(b, 16).ok()?,
                l.to_string(),
            ))
        };
        let lines: Vec<_> = maps.lines().filter_map(range).collect();
        let before = lines
            .iter()
            .find(|(a, b, _)| *a <= lo - page && lo - page < *b)
            .unwrap();
        let after = lines.iter().find(|(a, b, _)| *a <= hi && hi < *b).unwrap();
        assert!(before.2.contains("---p"), "{}", before.2);
        assert!(after.2.contains("---p"), "{}", after.2);
        drop(r);
    }

    #[test]
    fn secret_backed_pages_unreadable_via_proc_mem() {
        use std::io::{Read, Seek, SeekFrom};
        let mut r = SecretRegion::new(16).unwrap();
        if !r.is_secret_backed() {
            return; // kernel without memfd_secret: nothing to assert
        }
        r.as_mut_slice()[..6].copy_from_slice(b"secret");
        let mut f = std::fs::File::open("/proc/self/mem").unwrap();
        f.seek(SeekFrom::Start(r.data_addr() as u64)).unwrap();
        let mut buf = [0u8; 6];
        assert!(
            f.read_exact(&mut buf).is_err(),
            "memfd_secret page was readable via /proc/self/mem"
        );
    }

    #[test]
    fn split_key_survives_relocation_and_hides_key() {
        let key = [0x42u8; 32];
        let mut s = SplitKey::new(&key).unwrap();
        s.with_key(|k| assert_eq!(k, &key));
        assert_ne!(&s.a.as_slice()[..32], &key);
        assert_ne!(&s.b.as_slice()[..32], &key);
        let before = s.addrs();
        s.relocate().unwrap();
        s.with_key(|k| assert_eq!(k, &key));
        assert_ne!(s.addrs(), before);
    }
}
