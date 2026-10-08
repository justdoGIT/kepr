// exe_digest.rs — executable identities for binary-identity bindings
// (T10.09), shared by `kepr set --exe` (which records them) and the
// daemon's Get gate (which checks the peer's /proc/<pid>/exe).
//
// An identity is a string:
//
//   sha256:<64 hex>          SHA-256 of the file's contents
//   verity-sha256:<64 hex>   the fs-verity file digest (FS_IOC_MEASURE_VERITY)
//   verity-sha512:<128 hex>
//
// Recording always takes the SHA-256 and adds the fs-verity digest when the
// file has verity enabled. Checking uses the fs-verity digest when the file
// has one (the kernel vouches for every page, and nothing is read) and
// falls back to hashing the contents otherwise.

use std::fs::File;
use std::io::{self, Read};

use sha2::{Digest, Sha256};

/// At most this many identities per credential.
pub const MAX_ENTRIES: usize = 16;

/// True for a well-formed identity string.
pub fn is_valid(entry: &str) -> bool {
    let hexlen = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    match entry.split_once(':') {
        Some(("sha256" | "verity-sha256", h)) => hexlen(h, 64),
        Some(("verity-sha512", h)) => hexlen(h, 128),
        _ => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `sha256:<hex>` of everything readable from `f` (from its current offset).
pub fn sha256_of(mut f: &File) -> io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex(&h.finalize())))
}

/// The fs-verity digest, or `None` when the file or its filesystem has no
/// verity (ENODATA, ENOTTY, EOPNOTSUPP, …).
#[cfg(target_os = "linux")]
pub fn verity_of(f: &File) -> Option<String> {
    use std::os::fd::AsRawFd;
    // FS_IOC_MEASURE_VERITY = _IOWR('f', 134, struct fsverity_digest).
    const FS_IOC_MEASURE_VERITY: libc::c_ulong = 0xc004_6686;
    const MAX: usize = 64;
    // struct fsverity_digest { u16 algorithm; u16 size; u8 digest[]; }
    let mut buf = [0u8; 4 + MAX];
    buf[2..4].copy_from_slice(&(MAX as u16).to_ne_bytes());
    // SAFETY: `buf` is a valid, writable fsverity_digest with room for
    // `MAX` digest bytes, as announced in its size field.
    let r = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_MEASURE_VERITY as _, buf.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    let alg = u16::from_ne_bytes([buf[0], buf[1]]);
    let size = u16::from_ne_bytes([buf[2], buf[3]]) as usize;
    let name = match (alg, size) {
        (1, 32) => "verity-sha256",
        (2, 64) => "verity-sha512",
        _ => return None,
    };
    Some(format!("{name}:{}", hex(&buf[4..4 + size])))
}

#[cfg(not(target_os = "linux"))]
pub fn verity_of(_f: &File) -> Option<String> {
    None
}

/// The identities to record for `f`: its SHA-256, plus its fs-verity
/// digest when it has one.
pub fn entries_of(f: &File) -> io::Result<Vec<String>> {
    let mut out = vec![sha256_of(f)?];
    out.extend(verity_of(f));
    Ok(out)
}

/// Does a file with this fs-verity digest (if any) match `allowed`?
/// `sha256` is called only when verity can't decide, so a verity-enabled
/// binary is never read.
pub fn matches(
    allowed: &[String],
    verity: Option<String>,
    sha256: impl FnOnce() -> io::Result<String>,
) -> bool {
    if verity.is_some_and(|v| allowed.contains(&v)) {
        return true;
    }
    if !allowed.iter().any(|e| e.starts_with("sha256:")) {
        return false;
    }
    sha256().is_ok_and(|d| allowed.contains(&d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_strings() {
        let h64 = "a".repeat(64);
        assert!(is_valid(&format!("sha256:{h64}")));
        assert!(is_valid(&format!("verity-sha256:{h64}")));
        assert!(is_valid(&format!("verity-sha512:{}", "0".repeat(128))));
        for bad in [
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha512:{h64}"),
            format!("verity-sha512:{h64}"),
            h64.clone(),
            String::new(),
        ] {
            assert!(!is_valid(&bad), "{bad}");
        }
    }

    #[test]
    fn sha256_of_a_file() {
        let dir = std::env::temp_dir().join(format!("kepr-exe-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"abc").unwrap();
        let f = File::open(&p).unwrap();
        let e = entries_of(&f).unwrap();
        assert_eq!(
            e[0],
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(e.iter().all(|x| is_valid(x)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verity_first_then_sha256() {
        let sha = format!("sha256:{}", "1".repeat(64));
        let ver = format!("verity-sha256:{}", "2".repeat(64));
        let both = [sha.clone(), ver.clone()];
        let never = || -> io::Result<String> { panic!("hashed a verity-enabled file") };
        assert!(matches(&both, Some(ver.clone()), never));
        // No verity on this filesystem: falls back to the contents.
        assert!(matches(&both, None, || Ok(sha.clone())));
        // Verity present but different (e.g. rebuilt): SHA-256 still decides.
        let other = format!("verity-sha256:{}", "3".repeat(64));
        assert!(matches(&both, Some(other.clone()), || Ok(sha.clone())));
        assert!(!matches(&both, Some(other), || Ok(format!(
            "sha256:{}",
            "4".repeat(64)
        ))));
        // Only a verity identity recorded and the file has none: refused.
        assert!(!matches(&[ver], None, || Ok(sha.clone())));
        // A read error is a refusal.
        assert!(!matches(&[sha], None, || Err(io::Error::other("x"))));
    }
}
