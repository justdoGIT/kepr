//! MySQL protocol pieces shared by the gate's MySQL proxy (T7.02) and the
//! CLI's MySQL clients (`kepr agent rotate-db`, `kepr mcp` db_query):
//! packet framing, length-encoded integers, OK / ERR packets and the
//! two password scrambles (the handshake packets are in mysql_handshake).
//! No IO, no TLS.

use sha1::Sha1;
use sha2::{Digest, Sha256};

pub use crate::mysql_handshake::{auth_switch, Greeting, HandshakeResponse};

/// Largest payload of one packet.
pub const MAX_PACKET: usize = (1 << 24) - 1;
pub const NATIVE: &str = "mysql_native_password";
pub const CACHING_SHA2: &str = "caching_sha2_password";
/// ER_ACCESS_DENIED_ERROR.
pub const ACCESS_DENIED: u16 = 1045;

/// Capability flags this module and its users care about.
pub mod caps {
    pub const LONG_PASSWORD: u32 = 1;
    pub const CONNECT_WITH_DB: u32 = 1 << 3;
    pub const COMPRESS: u32 = 1 << 5;
    pub const PROTOCOL_41: u32 = 1 << 9;
    pub const SSL: u32 = 1 << 11;
    pub const TRANSACTIONS: u32 = 1 << 13;
    pub const SECURE_CONNECTION: u32 = 1 << 15;
    pub const MULTI_RESULTS: u32 = 1 << 17;
    pub const PLUGIN_AUTH: u32 = 1 << 19;
    pub const CONNECT_ATTRS: u32 = 1 << 20;
    pub const PLUGIN_AUTH_LENENC: u32 = 1 << 21;
    pub const DEPRECATE_EOF: u32 = 1 << 24;
    pub const ZSTD: u32 = 1 << 26;
    pub const MULTI_FACTOR: u32 = 1 << 28;
}

/// `len (3 bytes LE) | seq | payload`.
pub fn packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes()[..3].to_vec();
    out.push(seq);
    out.extend_from_slice(payload);
    out
}

/// (payload length, sequence id) of a packet header.
pub fn header(h: [u8; 4]) -> (usize, u8) {
    (u32::from_le_bytes([h[0], h[1], h[2], 0]) as usize, h[3])
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

/// `mysql_native_password`: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw))).
pub fn native_scramble(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let s1 = Sha1::digest(password);
    let s2 = Sha1::digest(s1);
    let s3 = Sha1::new().chain_update(nonce).chain_update(s2).finalize();
    xor(&s1, &s3)
}

/// `caching_sha2_password` fast auth:
/// SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + nonce).
pub fn sha2_scramble(password: &[u8], nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let d1 = Sha256::digest(password);
    let d2 = Sha256::digest(d1);
    let d3 = Sha256::new()
        .chain_update(d2)
        .chain_update(nonce)
        .finalize();
    xor(&d1, &d3)
}

/// The scramble `plugin` expects; `None` for a plugin we can't answer.
pub fn scramble_for(plugin: &str, password: &[u8], nonce: &[u8]) -> Option<Vec<u8>> {
    match plugin {
        NATIVE => Some(native_scramble(password, nonce)),
        CACHING_SHA2 => Some(sha2_scramble(password, nonce)),
        _ => None,
    }
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn put_lenenc(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=250 => out.push(n as u8),
        251..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = (b.get(..n)?, b.get(n..)?);
    *b = rest;
    Some(head)
}

pub fn take_lenenc(b: &mut &[u8]) -> Option<u64> {
    let first = *take(b, 1)?.first()?;
    let width = match first {
        0..=250 => return Some(first as u64),
        0xfc => 2,
        0xfd => 3,
        0xfe => 8,
        _ => return None,
    };
    let mut v = [0u8; 8];
    v[..width].copy_from_slice(take(b, width)?);
    Some(u64::from_le_bytes(v))
}

/// Bytes up to a NUL (consumed); the rest when there is none.
pub fn take_nul<'a>(b: &mut &'a [u8]) -> &'a [u8] {
    match b.iter().position(|c| *c == 0) {
        Some(i) => {
            let s = &b[..i];
            *b = &b[i + 1..];
            s
        }
        None => std::mem::take(b),
    }
}

pub(crate) fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// An ERR packet payload.
pub fn err_packet(code: u16, sql_state: &str, msg: &str) -> Vec<u8> {
    let mut out = vec![0xff];
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    out.extend_from_slice(sql_state.as_bytes());
    out.extend_from_slice(msg.as_bytes());
    out
}

/// (code, message) of an ERR payload.
pub fn parse_err(p: &[u8]) -> Option<(u16, String)> {
    let mut b = p.strip_prefix(&[0xff])?;
    let code = u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?);
    if b.first() == Some(&b'#') {
        take(&mut b, 6)?;
    }
    Some((code, text(b)))
}

/// A plain OK payload (nothing affected, no warnings).
pub fn ok_packet(status: u16) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// The user name `kepr agent rotate-db` logs in through the gate with to
/// ask for a password rotation (T7.04).
pub const ROTATE_USER: &str = "kepr_rotate";

/// Append `s` to `out` as a string literal: single quotes, `'` doubled.
/// A backslash or NUL is refused (`false`, nothing appended): what a
/// backslash means depends on the server's NO_BACKSLASH_ESCAPES mode.
pub fn quote(out: &mut Vec<u8>, s: &str) -> bool {
    if s.bytes().any(|b| b == b'\\' || b == 0) {
        return false;
    }
    out.push(b'\'');
    for b in s.bytes() {
        if b == b'\'' {
            out.push(b'\'');
        }
        out.push(b);
    }
    out.push(b'\'');
    true
}

/// COM_QUERY payload `ALTER USER CURRENT_USER() IDENTIFIED BY '<pw>'`
/// (T7.04), in a buffer wiped on drop (sized up front, so never moved);
/// `None` if `pw` can't be quoted.
pub fn alter_password(pw: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    const SQL: &[u8] = b"ALTER USER CURRENT_USER() IDENTIFIED BY ";
    let mut q = zeroize::Zeroizing::new(Vec::with_capacity(1 + SQL.len() + 2 * pw.len() + 2));
    q.push(0x03);
    q.extend_from_slice(SQL);
    quote(&mut q, pw).then_some(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: [u8; 20] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn scrambles_match_the_reference_vectors() {
        // Computed independently (Python hashlib) from the documented
        // formulas for password "secret" and nonce 0x01..0x14.
        assert_eq!(
            hex(&native_scramble(b"secret", &NONCE)),
            "b32bb3a583e1340c0a1108d58b1be49781ad8c2f"
        );
        assert_eq!(
            hex(&sha2_scramble(b"secret", &NONCE)),
            "746ebe205d56a0707acb3e796e834e0dd7b1d61743b26bd5202c7a623230c7c9"
        );
        assert!(native_scramble(b"", &NONCE).is_empty());
        assert!(scramble_for("sha256_password", b"x", &NONCE).is_none());
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
    }

    #[test]
    fn packets_and_lenenc() {
        let p = packet(3, b"abc");
        assert_eq!(header(p[..4].try_into().unwrap()), (3, 3));
        for n in [0u64, 250, 251, 65_535, 65_536, 1 << 24, u64::MAX] {
            let mut out = Vec::new();
            put_lenenc(&mut out, n);
            assert_eq!(take_lenenc(&mut out.as_slice()), Some(n), "{n}");
        }
        let e = err_packet(ACCESS_DENIED, "28000", "no");
        assert_eq!(parse_err(&e), Some((ACCESS_DENIED, "no".into())));
        assert_eq!(ok_packet(2)[0], 0);
    }

    fn quoted(s: &str) -> Option<String> {
        let mut out = b"x=".to_vec();
        quote(&mut out, s).then(|| String::from_utf8(out).unwrap())
    }

    #[test]
    fn string_literals_double_quotes_and_refuse_backslash_and_nul() {
        assert_eq!(quoted("abc").as_deref(), Some("x='abc'"));
        assert_eq!(quoted("it's").as_deref(), Some("x='it''s'"));
        assert_eq!(
            quoted("'; DROP USER x; --").as_deref(),
            Some("x='''; DROP USER x; --'")
        );
        assert_eq!(quoted("").as_deref(), Some("x=''"));
        // A backslash's meaning depends on NO_BACKSLASH_ESCAPES: refused.
        assert_eq!(quoted("a\\' OR 1=1"), None);
        assert_eq!(quoted("a\0b"), None);
        let mut out = b"x=".to_vec();
        assert!(!quote(&mut out, "\\"));
        assert_eq!(out, b"x=", "nothing appended on refusal");
    }

    #[test]
    fn alter_password_statement() {
        let q = alter_password("Abc123xyz").unwrap();
        assert_eq!(
            &q[..],
            b"\x03ALTER USER CURRENT_USER() IDENTIFIED BY 'Abc123xyz'"
        );
        assert_eq!(
            &alter_password("o'k").unwrap()[1..],
            b"ALTER USER CURRENT_USER() IDENTIFIED BY 'o''k'"
        );
        assert!(alter_password("bad\\").is_none());
    }
}
