// cli_clip/x11_auth.rs — which local X display, and the user's own
// MIT-MAGIC-COOKIE-1 for it (T12.48), from `$XAUTHORITY` or
// `~/.Xauthority`. The cookie stays in wiped memory and is never printed.

use zeroize::Zeroizing;

pub const AUTH_NAME: &[u8] = b"MIT-MAGIC-COOKIE-1";
const FAMILY_LOCAL: u16 = 256;
const FAMILY_WILD: u16 = 65535;

/// The display number of a local display: `:N[.S]` or `unix:N[.S]`.
/// Anything else (a TCP or forwarded display) is refused.
pub fn display_number(display: &str) -> Result<u32, String> {
    let rest = display
        .strip_prefix("unix:")
        .or_else(|| display.strip_prefix(':'))
        .ok_or("not a local X display")?;
    let n = rest.split('.').next().unwrap_or("");
    n.parse().map_err(|_| "not a local X display".to_string())
}

/// The MIT-MAGIC-COOKIE-1 for `display` in an Xauthority file: an entry
/// of family Local whose address is `host`, or Wild, with that number.
/// Fields are big-endian length-prefixed byte strings.
pub fn xauth_cookie(file: &[u8], host: &str, display: u32) -> Option<Zeroizing<Vec<u8>>> {
    let want = display.to_string();
    let word = |at: usize| Some(u16::from_be_bytes([*file.get(at)?, *file.get(at + 1)?]));
    let field = |at: &mut usize| -> Option<&[u8]> {
        let len = word(*at)? as usize;
        let f = file.get(*at + 2..*at + 2 + len)?;
        *at += 2 + len;
        Some(f)
    };
    let mut at = 0;
    while at < file.len() {
        let family = word(at)?;
        at += 2;
        let (addr, num) = (field(&mut at)?, field(&mut at)?);
        let (name, data) = (field(&mut at)?, field(&mut at)?);
        let host_ok = family == FAMILY_WILD || (family == FAMILY_LOCAL && addr == host.as_bytes());
        if host_ok && num == want.as_bytes() && name == AUTH_NAME {
            return Some(Zeroizing::new(data.to_vec()));
        }
    }
    None
}

/// The cookie for local display `n`, if the user's Xauthority has one.
pub fn cookie(n: u32) -> Option<Zeroizing<Vec<u8>>> {
    let file = std::env::var_os("XAUTHORITY")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".Xauthority"))
        })?;
    // fs::read sizes the buffer from the file: no reallocation copies.
    let file = Zeroizing::new(std::fs::read(file).ok()?);
    xauth_cookie(&file, &hostname(), n)
}

fn hostname() -> String {
    let mut b = [0u8; 256];
    // SAFETY: gethostname writes at most b.len() bytes into a stack buffer.
    if unsafe { libc::gethostname(b.as_mut_ptr() as *mut _, b.len()) } != 0 {
        return String::new();
    }
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(family: u16, addr: &[u8], num: &[u8], name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut e = family.to_be_bytes().to_vec();
        for f in [addr, num, name, data] {
            e.extend((f.len() as u16).to_be_bytes());
            e.extend(f);
        }
        e
    }

    fn found(f: &[u8], host: &str, n: u32) -> Option<Vec<u8>> {
        xauth_cookie(f, host, n).map(|c| c.to_vec())
    }

    #[test]
    fn xauthority_picks_the_matching_entry() {
        let mut f = entry(FAMILY_LOCAL, b"otherhost", b"0", AUTH_NAME, &[1; 16]);
        f.extend(entry(FAMILY_LOCAL, b"myhost", b"0", AUTH_NAME, &[2; 16]));
        assert_eq!(found(&f, "myhost", 0), Some(vec![2; 16]));
        assert_eq!(found(&f, "otherhost", 0), Some(vec![1; 16]));
        assert_eq!(found(&f, "myhost", 1), None);
        let w = entry(FAMILY_WILD, b"", b"3", AUTH_NAME, &[3; 16]);
        assert_eq!(found(&w, "any", 3), Some(vec![3; 16]));
        let other = entry(
            FAMILY_LOCAL,
            b"myhost",
            b"0",
            b"XDM-AUTHORIZATION-1",
            &[4; 16],
        );
        assert_eq!(found(&other, "myhost", 0), None);
        assert_eq!(found(&f[..f.len() - 3], "myhost", 0), None); // truncated
    }

    #[test]
    fn local_displays_only() {
        assert_eq!(display_number(":0"), Ok(0));
        assert_eq!(display_number(":12.1"), Ok(12));
        assert_eq!(display_number("unix:3"), Ok(3));
        for d in ["localhost:0", "10.0.0.1:0.0", "", ":x", "host/unix:0"] {
            assert!(display_number(d).is_err(), "{d}");
        }
    }
}
