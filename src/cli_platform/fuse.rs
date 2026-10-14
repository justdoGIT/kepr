// cli_platform/fuse.rs — the FUSE kernel protocol, as much as a read-only
// flat directory needs (T10.01). Pure byte encoding and decoding of the
// structs in <linux/fuse.h> (native endianness, which is little-endian on
// every platform kepr builds for); mount.rs decides what to answer and
// mount_os.rs moves the bytes to and from /dev/fuse.

pub const ROOT: u64 = 1;
pub const HEADER_LEN: usize = 40;

pub const LOOKUP: u32 = 1;
pub const FORGET: u32 = 2;
pub const GETATTR: u32 = 3;
pub const OPEN: u32 = 14;
pub const READ: u32 = 15;
pub const STATFS: u32 = 17;
pub const RELEASE: u32 = 18;
pub const FLUSH: u32 = 25;
pub const INIT: u32 = 26;
pub const OPENDIR: u32 = 27;
pub const READDIR: u32 = 28;
pub const RELEASEDIR: u32 = 29;
pub const ACCESS: u32 = 34;
pub const INTERRUPT: u32 = 36;
pub const DESTROY: u32 = 38;
pub const BATCH_FORGET: u32 = 42;

/// Protocol version this server speaks (the kernel uses the lower minor).
pub const MAJOR: u32 = 7;
pub const MINOR: u32 = 31;
/// `fuse_open_out.open_flags`: bypass the page cache (no secret pages).
pub const FOPEN_DIRECT_IO: u32 = 1;
/// `fuse_getattr_in.getattr_flags`: `fh` is valid.
pub const GETATTR_FH: u32 = 1;
pub const MAX_WRITE: u32 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InHeader {
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// One request read from /dev/fuse → (header, body).
pub fn parse(req: &[u8]) -> Option<(InHeader, &[u8])> {
    let len = u32_at(req, 0)? as usize;
    if len < HEADER_LEN || len > req.len() {
        return None;
    }
    let h = InHeader {
        opcode: u32_at(req, 4)?,
        unique: u64_at(req, 8)?,
        nodeid: u64_at(req, 16)?,
        uid: u32_at(req, 24)?,
        gid: u32_at(req, 28)?,
        pid: u32_at(req, 32)?,
    };
    Some((h, &req[HEADER_LEN..len]))
}

/// `fuse_out_header` + body; `error` is 0 or a negative errno.
pub fn reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend(((16 + body.len()) as u32).to_le_bytes());
    out.extend(error.to_le_bytes());
    out.extend(unique.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// `fuse_init_in` → `fuse_init_out` body, or the errno to fail with.
pub fn init(body: &[u8]) -> Result<Vec<u8>, i32> {
    let (major, minor) = (
        u32_at(body, 0).ok_or(libc::EINVAL)?,
        u32_at(body, 4).unwrap_or(0),
    );
    let max_readahead = u32_at(body, 8).unwrap_or(0);
    let mut out = Vec::with_capacity(64);
    if major > MAJOR {
        // The kernel retries with our major.
        out.extend(MAJOR.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.resize(64, 0);
        return Ok(out);
    }
    if major < MAJOR {
        return Err(libc::EPROTO);
    }
    out.extend(MAJOR.to_le_bytes());
    out.extend(MINOR.to_le_bytes());
    out.extend(max_readahead.to_le_bytes());
    out.extend(0u32.to_le_bytes()); // flags: none
    out.extend(1u16.to_le_bytes()); // max_background
    out.extend(1u16.to_le_bytes()); // congestion_threshold
    out.extend(MAX_WRITE.to_le_bytes());
    out.extend(1u32.to_le_bytes()); // time_gran
                                    // max_pages, map_alignment, flags2, unused: zero.
    out.resize(if minor < 23 { 24 } else { 64 }, 0);
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub time: u64,
}

/// `fuse_attr` (88 bytes).
fn attr(a: &Attr, out: &mut Vec<u8>) {
    for v in [a.ino, a.size, a.size.div_ceil(512), a.time, a.time, a.time] {
        out.extend(v.to_le_bytes());
    }
    for v in [0, 0, 0, a.mode, a.nlink, a.uid, a.gid, 0, 4096, 0u32] {
        out.extend(v.to_le_bytes());
    }
}

/// `fuse_entry_out` for LOOKUP (cached for a second; attributes not cached).
pub fn entry_out(a: &Attr) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    for v in [a.ino, 0, 1, 0] {
        out.extend(v.to_le_bytes()); // nodeid, generation, entry_valid, attr_valid
    }
    out.extend([0u8; 8]); // nsecs
    attr(a, &mut out);
    out
}

/// `fuse_attr_out` for GETATTR (not cached).
pub fn attr_out(a: &Attr) -> Vec<u8> {
    let mut out = vec![0u8; 16];
    attr(a, &mut out);
    out
}

/// `fuse_open_out`.
pub fn open_out(fh: u64, open_flags: u32) -> Vec<u8> {
    let mut out = fh.to_le_bytes().to_vec();
    out.extend(open_flags.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out
}

/// `fuse_open_in.flags`.
pub fn open_flags(body: &[u8]) -> Option<u32> {
    u32_at(body, 0)
}

/// `fuse_getattr_in` → (getattr_flags, fh).
pub fn getattr_in(body: &[u8]) -> (u32, u64) {
    (u32_at(body, 0).unwrap_or(0), u64_at(body, 8).unwrap_or(0))
}

/// `fuse_read_in` → (fh, offset, size).
pub fn read_in(body: &[u8]) -> Option<(u64, u64, u32)> {
    Some((u64_at(body, 0)?, u64_at(body, 8)?, u32_at(body, 16)?))
}

/// `fuse_release_in.fh`.
pub fn release_fh(body: &[u8]) -> Option<u64> {
    u64_at(body, 0)
}

/// LOOKUP's NUL-terminated name.
pub fn lookup_name(body: &[u8]) -> &[u8] {
    body.split(|b| *b == 0).next().unwrap_or(&[])
}

/// One `fuse_dirent`, padded to 8 bytes; false when it does not fit `max`.
pub fn dirent(out: &mut Vec<u8>, max: usize, ino: u64, next: u64, dtype: u32, name: &str) -> bool {
    let len = (24 + name.len()).div_ceil(8) * 8;
    if out.len() + len > max {
        return false;
    }
    out.extend(ino.to_le_bytes());
    out.extend(next.to_le_bytes());
    out.extend((name.len() as u32).to_le_bytes());
    out.extend(dtype.to_le_bytes());
    out.extend(name.as_bytes());
    out.resize(out.len() + len - 24 - name.len(), 0);
    true
}

/// `fuse_statfs_out` for a tiny read-only filesystem.
pub fn statfs_out(files: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    for v in [0u64, 0, 0, files, 0] {
        out.extend(v.to_le_bytes());
    }
    for v in [4096u32, 255, 4096, 0] {
        out.extend(v.to_le_bytes()); // bsize, namelen, frsize, padding
    }
    out.resize(80, 0);
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A request as the kernel writes it.
    pub fn request(
        opcode: u32,
        unique: u64,
        nodeid: u64,
        uid: u32,
        pid: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut r = ((HEADER_LEN + body.len()) as u32).to_le_bytes().to_vec();
        r.extend(opcode.to_le_bytes());
        r.extend(unique.to_le_bytes());
        r.extend(nodeid.to_le_bytes());
        r.extend(uid.to_le_bytes());
        r.extend(uid.to_le_bytes()); // gid
        r.extend(pid.to_le_bytes());
        r.extend([0u8; 4]);
        r.extend_from_slice(body);
        r
    }

    /// FUSE_INIT from a 7.38 kernel (Linux 6.x): fuse_init_in with flags2.
    pub const INIT_7_38: &str = "680000001a000000\
        0200000000000000 0000000000000000 e8030000e8030000 d204000000000000\
        07000000260000000000020000000000 00000000\
        0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    pub fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn init_fixture_negotiates_7_31() {
        let req = unhex(INIT_7_38);
        assert_eq!(req.len(), 104);
        let (h, body) = parse(&req).unwrap();
        assert_eq!((h.opcode, h.unique, h.uid, h.pid), (INIT, 2, 1000, 1234));
        let out = init(body).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(u32_at(&out, 0), Some(7));
        assert_eq!(u32_at(&out, 4), Some(31));
        assert_eq!(u32_at(&out, 8), Some(0x20000), "max_readahead echoed");
        assert_eq!(u32_at(&out, 20), Some(MAX_WRITE));
        let r = reply(h.unique, 0, &out);
        assert_eq!(&r[..16], unhex("50000000 00000000 0200000000000000"));
        // A newer major: answer with ours only; an older one: refuse.
        let mut v8 = body.to_vec();
        v8[0] = 8;
        assert_eq!(u32_at(&init(&v8).unwrap(), 4), Some(0));
        let mut v6 = body.to_vec();
        v6[0] = 6;
        assert_eq!(init(&v6), Err(libc::EPROTO));
        // Kernels before 7.23 get the short reply.
        let mut v22 = body.to_vec();
        v22[4] = 22;
        assert_eq!(init(&v22).unwrap().len(), 24);
    }

    #[test]
    fn struct_sizes_match_the_kernel() {
        let a = Attr {
            ino: 2,
            size: 513,
            mode: libc::S_IFREG | 0o400,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            time: 7,
        };
        assert_eq!(entry_out(&a).len(), 128);
        assert_eq!(attr_out(&a).len(), 104);
        let e = entry_out(&a);
        assert_eq!(u64_at(&e, 0), Some(2), "nodeid");
        assert_eq!(u64_at(&e, 40 + 8), Some(513), "size");
        assert_eq!(u64_at(&e, 40 + 16), Some(2), "blocks");
        assert_eq!(u32_at(&e, 40 + 60), Some(libc::S_IFREG | 0o400), "mode");
        assert_eq!(u32_at(&e, 40 + 68), Some(1000), "uid");
        assert_eq!(
            open_out(9, FOPEN_DIRECT_IO),
            unhex("0900000000000000 01000000 00000000")
        );
        assert_eq!(statfs_out(3).len(), 80);
        let mut d = Vec::new();
        assert!(dirent(&mut d, 4096, 2, 3, 8, ".env"));
        assert_eq!(d.len(), 32);
        assert_eq!(&d[24..28], b".env");
        assert!(!dirent(&mut d, 40, 3, 4, 8, "x"));
        assert_eq!(lookup_name(b".env\0"), b".env");
        let read = unhex("0500000000000000 0a00000000000000 00100000 00000000 0000000000000000 00000000 00000000");
        assert_eq!(read_in(&read), Some((5, 10, 4096)));
        assert!(parse(&[1, 0, 0, 0]).is_none());
    }
}
