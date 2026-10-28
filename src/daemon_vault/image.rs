// daemon_vault/image.rs — the vault image file (T4.01).
//
// A fixed-size file of 4 KiB slots (1..=4096 MiB), created O_EXCL at
// mode 0600 and filled with CSPRNG noise, so free space can't be told
// from data. Slot 0 is the header (header.rs), slot 1 the journal
// (T4.04); slots 2.. hold sealed index and record pages, or noise.
// `SlotIo` is the positioned-IO seam the crash tests inject faults into.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use super::header::{open_header, seal_header, Header, MAGIC, SEALED_AT};
use super::keys::{noise, Keys, SALT};

pub const SLOT: usize = 4096;
pub const MAX_MIB: u32 = 4096;
pub const SLOTS_PER_MIB: u32 = 256;
/// Slot 0 is the header; data starts after the journal slot (T4.04).
pub const FIRST_DATA_SLOT: u32 = 2;
const CHUNK: usize = 1 << 20;

/// Positioned IO on the image, so tests can inject faults (T4.04).
pub trait SlotIo {
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()>;
    fn write_at(&mut self, buf: &[u8], off: u64) -> std::io::Result<()>;
    fn sync(&mut self) -> std::io::Result<()>;
    fn size(&self) -> std::io::Result<u64>;
}

impl SlotIo for File {
    fn read_at(&self, buf: &mut [u8], off: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, off)
    }
    fn write_at(&mut self, buf: &[u8], off: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(self, buf, off)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }
    fn size(&self) -> std::io::Result<u64> {
        self.metadata().map(|m| m.len())
    }
}

fn slots_for(size_mib: u32) -> Result<u32, String> {
    if !(1..=MAX_MIB).contains(&size_mib) {
        return Err(format!("vault image size must be 1..={MAX_MIB} MiB"));
    }
    Ok(size_mib * SLOTS_PER_MIB)
}

/// An open image: its IO, salt and current (decrypted) header. Holds no
/// keys: callers derive them per operation with `keys(kek)`, so a locked
/// store leaves nothing usable behind.
pub struct VaultImage<I: SlotIo = File> {
    io: I,
    salt: [u8; SALT],
    pub header: Header,
}

impl VaultImage<File> {
    /// Create a new image at `path` (never over an existing file), mode
    /// 0600, every byte noise except the header's magic.
    pub fn create(path: &Path, size_mib: u32, kek: &[u8; 32]) -> Result<Self, String> {
        let slots = slots_for(size_mib)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create vault image: {e}"))?;
        let made = reserve(&file, u64::from(slots) * SLOT as u64)
            .and_then(|()| Self::format(file, slots, kek));
        if made.is_err() {
            let _ = std::fs::remove_file(path);
        }
        let img = made?;
        if let Some(dir) = path.parent() {
            crate::atomic_file::sync_dir(dir)?;
        }
        Ok(img)
    }

    pub fn open(path: &Path, kek: &[u8; 32]) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open vault image: {e}"))?;
        Self::load(file, kek)
    }
}

/// Does `kek` open the image header at `path`? Read-only: no recovery.
pub fn key_opens(path: &Path, kek: &[u8; 32]) -> bool {
    let Ok(f) = File::open(path) else {
        return false;
    };
    let mut slot0 = [0u8; SLOT];
    if SlotIo::read_at(&f, &mut slot0, 0).is_err() || &slot0[..8] != MAGIC {
        return false;
    }
    let salt: [u8; SALT] = slot0[8..SEALED_AT].try_into().expect("salt");
    open_header(&Keys::derive(kek, &salt), &slot0).is_ok()
}

/// Reserve the space up front so a full disk fails now, not mid-commit.
/// The noise is written either way: fallocate alone would leave zeros.
fn reserve(file: &File, len: u64) -> Result<(), String> {
    // SAFETY: fallocate(2) on a descriptor we own; no memory is passed.
    let rc = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, len as libc::off_t) };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => Ok(()),
        _ => Err(format!("cannot reserve space for the vault image: {e}")),
    }
}

impl<I: SlotIo> VaultImage<I> {
    /// Fill `io` with noise in 1 MiB chunks and write a fresh header.
    pub fn format(mut io: I, slot_count: u32, kek: &[u8; 32]) -> Result<Self, String> {
        let total = u64::from(slot_count) * SLOT as u64;
        let mut buf = vec![0u8; CHUNK];
        let mut off = 0u64;
        while off < total {
            let n = CHUNK.min((total - off) as usize);
            noise(&mut buf[..n])?;
            io.write_at(&buf[..n], off).map_err(io_err)?;
            off += n as u64;
        }
        let (mut salt, mut image_id) = ([0u8; SALT], [0u8; 16]);
        noise(&mut salt)?;
        noise(&mut image_id)?;
        let header = Header {
            image_id,
            slot_count,
            epoch: 0,
            root: super::merkle::merkle_root(&[]),
            index_len: 0,
            index_slots: Vec::new(),
            anchor: None,
        };
        let mut img = Self { io, salt, header };
        let keys = img.keys(kek);
        img.write_header(&keys)?;
        img.sync()?;
        Ok(img)
    }

    /// Read and authenticate the header of an existing image.
    pub fn load(io: I, kek: &[u8; 32]) -> Result<Self, String> {
        let len = io.size().map_err(io_err)?;
        let min = u64::from(SLOTS_PER_MIB) * SLOT as u64;
        if len < min || len % SLOT as u64 != 0 {
            return Err("vault image is truncated or damaged".into());
        }
        let mut slot0 = [0u8; SLOT];
        io.read_at(&mut slot0, 0).map_err(io_err)?;
        if &slot0[..8] != MAGIC {
            return Err("not a vault image".into());
        }
        let salt: [u8; SALT] = slot0[8..SEALED_AT].try_into().expect("salt");
        let keys = Keys::derive(kek, &salt);
        let current = open_header(&keys, &slot0);
        // Until recovery settles the real header, size reads by the file.
        let header = Header {
            image_id: [0u8; 16],
            slot_count: (len / SLOT as u64).min(u64::from(u32::MAX)) as u32,
            epoch: 0,
            root: [0u8; 32],
            index_len: 0,
            index_slots: Vec::new(),
            anchor: None,
        };
        let mut img = Self { io, salt, header };
        img.recover(&keys, current)?;
        if u64::from(img.header.slot_count) * SLOT as u64 != len {
            return Err("vault image size does not match its header".into());
        }
        Ok(img)
    }

    pub fn keys(&self, kek: &[u8; 32]) -> Keys {
        Keys::derive(kek, &self.salt)
    }

    pub fn read_slot(&self, idx: u32) -> Result<Box<[u8; SLOT]>, String> {
        self.check(idx)?;
        let mut b = Box::new([0u8; SLOT]);
        let off = u64::from(idx) * SLOT as u64;
        self.io.read_at(&mut b[..], off).map_err(io_err)?;
        Ok(b)
    }

    pub fn write_slot(&mut self, idx: u32, bytes: &[u8; SLOT]) -> Result<(), String> {
        self.check(idx)?;
        let off = u64::from(idx) * SLOT as u64;
        self.io.write_at(bytes, off).map_err(io_err)
    }

    /// Overwrite a slot with fresh noise.
    pub fn scrub_slot(&mut self, idx: u32) -> Result<(), String> {
        let mut b = Box::new([0u8; SLOT]);
        noise(&mut b[..])?;
        self.write_slot(idx, &b)
    }

    /// Write `self.header` to slot 0 (no fsync).
    pub fn write_header(&mut self, keys: &Keys) -> Result<(), String> {
        let slot = seal_header(keys, &self.salt, &self.header)?;
        self.write_slot(0, &slot)
    }

    pub fn sync(&mut self) -> Result<(), String> {
        self.io.sync().map_err(io_err)
    }

    pub(super) fn salt(&self) -> &[u8; SALT] {
        &self.salt
    }

    #[cfg(test)]
    pub(super) fn io_ref(&self) -> &I {
        &self.io
    }

    fn check(&self, idx: u32) -> Result<(), String> {
        if idx >= self.header.slot_count {
            return Err("vault slot out of range".into());
        }
        Ok(())
    }
}

pub(super) fn io_err(e: std::io::Error) -> String {
    format!("vault image IO failed: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const KEK: [u8; 32] = [7u8; 32];

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn created_image_has_exactly_the_requested_size_and_mode() {
        let d = tmp();
        for mib in [1u32, 3] {
            let p = d.path().join(format!("v{mib}.img"));
            let img = VaultImage::create(&p, mib, &KEK).unwrap();
            let md = std::fs::metadata(&p).unwrap();
            assert_eq!(md.len(), u64::from(mib) << 20);
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
            assert_eq!(img.header.slot_count, mib * 256);
            assert_eq!(img.header.epoch, 0);
        }
    }

    #[test]
    fn sizes_outside_the_range_are_refused() {
        let d = tmp();
        assert!(VaultImage::create(&d.path().join("a"), 0, &KEK).is_err());
        assert!(VaultImage::create(&d.path().join("b"), MAX_MIB + 1, &KEK).is_err());
        assert!(!d.path().join("a").exists() && !d.path().join("b").exists());
    }

    #[test]
    fn create_never_overwrites_an_existing_file() {
        let d = tmp();
        let p = d.path().join("v.img");
        std::fs::write(&p, b"keep me").unwrap();
        assert!(VaultImage::create(&p, 1, &KEK).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"keep me");
    }

    #[test]
    fn two_images_differ_everywhere_except_the_magic() {
        let d = tmp();
        let (pa, pb) = (d.path().join("a.img"), d.path().join("b.img"));
        VaultImage::create(&pa, 1, &KEK).unwrap();
        VaultImage::create(&pb, 1, &KEK).unwrap();
        let (a, b) = (std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
        assert_eq!(&a[..8], MAGIC);
        assert_eq!(&b[..8], MAGIC);
        // Equal bytes after the magic: what chance gives (1/256), not more.
        let same = a[8..].iter().zip(&b[8..]).filter(|(x, y)| x == y).count();
        assert!(same < a.len() / 128, "{same} equal bytes");
        // No 16-byte run is shared anywhere past the magic.
        for (ca, cb) in a[8..].chunks(16).zip(b[8..].chunks(16)) {
            assert_ne!(ca, cb);
        }
    }

    #[test]
    fn open_round_trips_the_header() {
        let d = tmp();
        let p = d.path().join("v.img");
        let made = VaultImage::create(&p, 2, &KEK).unwrap();
        let opened = VaultImage::open(&p, &KEK).unwrap();
        assert_eq!(made.header, opened.header);
        assert!(VaultImage::open(&p, &[8u8; 32]).is_err(), "wrong key");
    }

    #[test]
    fn open_refuses_a_wrong_magic() {
        let d = tmp();
        let p = d.path().join("v.img");
        VaultImage::create(&p, 1, &KEK).unwrap();
        let mut b = std::fs::read(&p).unwrap();
        b[3] ^= 1;
        std::fs::write(&p, &b).unwrap();
        assert!(VaultImage::open(&p, &KEK).is_err());
    }

    #[test]
    fn open_refuses_a_truncated_file() {
        let d = tmp();
        let p = d.path().join("v.img");
        VaultImage::create(&p, 1, &KEK).unwrap();
        for len in [100u64, SLOT as u64 * 10 + 7, (1 << 20) - 1] {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .unwrap()
                .set_len(len)
                .unwrap();
            assert!(VaultImage::open(&p, &KEK).is_err(), "len {len}");
        }
    }

    #[test]
    fn open_refuses_a_size_that_does_not_match_the_slot_count() {
        let d = tmp();
        let p = d.path().join("v.img");
        VaultImage::create(&p, 1, &KEK).unwrap();
        // One more whole slot: still slot-aligned, but not what the header says.
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_len((1 << 20) + SLOT as u64).unwrap();
        let err = VaultImage::open(&p, &KEK).err().unwrap();
        assert!(err.contains("size"), "{err}");
    }
}
