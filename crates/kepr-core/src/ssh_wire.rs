//! OpenSSH wire formats for kepr's SSH agent (agent vault P2.4): the
//! length-prefixed `string` encoding, Ed25519 public-key and signature
//! blobs, `ssh-ed25519 AAAA… comment` lines, and parsing of unencrypted
//! `openssh-key-v1` Ed25519 and ECDSA P-256 private keys (for `kepr ssh
//! import`; the ECDSA encodings are in ssh_wire_ecdsa.rs, T12.11).
//! No cryptography here: signing happens in the daemon.

use base64::Engine;

use crate::ssh_wire_ecdsa;

pub const ED25519: &str = "ssh-ed25519";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn put_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Read one `string` from the front of `buf`, advancing it.
pub fn take_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    if buf.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes(buf[..4].try_into().ok()?) as usize;
    if buf.len() < 4 + n {
        return None;
    }
    let (s, rest) = buf[4..].split_at(n);
    *buf = rest;
    Some(s)
}

pub fn take_u32(buf: &mut &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        return None;
    }
    let v = u32::from_be_bytes(buf[..4].try_into().ok()?);
    *buf = &buf[4..];
    Some(v)
}

pub fn ed25519_public_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(51);
    put_string(&mut b, ED25519.as_bytes());
    put_string(&mut b, pk);
    b
}

pub fn ed25519_signature_blob(sig: &[u8; 64]) -> Vec<u8> {
    let mut b = Vec::with_capacity(83);
    put_string(&mut b, ED25519.as_bytes());
    put_string(&mut b, sig);
    b
}

/// `ssh-ed25519 AAAA… comment`, as in authorized_keys.
pub fn public_line(pk: &[u8; 32], comment: &str) -> String {
    let line = format!(
        "{ED25519} {} {comment}",
        B64.encode(ed25519_public_blob(pk))
    );
    line.trim_end().to_string()
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s.trim()).ok()
}

/// The secret half of a key parsed from an OpenSSH private key file.
pub enum KeyKind {
    Ed25519 {
        seed: zeroize::Zeroizing<[u8; 32]>,
    },
    /// T12.11: the scalar and the file's uncompressed public point.
    EcdsaP256 {
        scalar: zeroize::Zeroizing<[u8; 32]>,
        q: [u8; 65],
    },
}

/// A key parsed from an unencrypted OpenSSH private key file.
pub struct OpensshKey {
    pub kind: KeyKind,
    pub comment: String,
}

/// The Ed25519 fields after the key type: `string pk ‖ string (seed ‖ pk)`.
fn take_ed25519(sec: &mut &[u8]) -> Option<(zeroize::Zeroizing<[u8; 32]>, [u8; 32])> {
    let pk: [u8; 32] = take_string(sec)?.try_into().ok()?;
    let sk = take_string(sec).filter(|s| s.len() == 64)?;
    if sk[32..] != pk {
        return None;
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&sk[..32]);
    Some((seed, pk))
}

/// Parse `-----BEGIN OPENSSH PRIVATE KEY-----` (unencrypted Ed25519 or,
/// since T12.11, ECDSA P-256).
pub fn parse_openssh_private(pem: &str) -> Result<OpensshKey, String> {
    const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const END: &str = "-----END OPENSSH PRIVATE KEY-----";
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(b, _)| b.split_whitespace().collect::<String>())
        .ok_or("not an OpenSSH private key")?;
    let raw = zeroize::Zeroizing::new(B64.decode(body).map_err(|_| "bad base64 in key")?);
    let mut buf: &[u8] = raw
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or("not openssh-key-v1")?;
    let bad = || "malformed OpenSSH key".to_string();
    let cipher = take_string(&mut buf).ok_or_else(bad)?;
    let _kdf = take_string(&mut buf).ok_or_else(bad)?;
    let _kdf_opts = take_string(&mut buf).ok_or_else(bad)?;
    if cipher != b"none" {
        return Err("encrypted keys are not supported: decrypt first (ssh-keygen -p -N '' -f KEY on a copy)".into());
    }
    if take_u32(&mut buf) != Some(1) {
        return Err("only single-key files are supported".into());
    }
    let pub_blob = take_string(&mut buf).ok_or_else(bad)?;
    let mut sec: &[u8] = take_string(&mut buf).ok_or_else(bad)?;
    let (c1, c2) = (take_u32(&mut sec), take_u32(&mut sec));
    if c1.is_none() || c1 != c2 {
        return Err(bad());
    }
    let key_type = take_string(&mut sec);
    // Each arm also checks that the public section names the same key.
    let kind = if key_type == Some(ED25519.as_bytes()) {
        let (seed, pk) = take_ed25519(&mut sec).ok_or_else(bad)?;
        if pub_blob != ed25519_public_blob(&pk) {
            return Err(bad());
        }
        KeyKind::Ed25519 { seed }
    } else if key_type == Some(ssh_wire_ecdsa::ECDSA_P256.as_bytes()) {
        let (scalar, q) = ssh_wire_ecdsa::take_private(&mut sec).ok_or_else(bad)?;
        if pub_blob != ssh_wire_ecdsa::public_blob(&q) {
            return Err(bad());
        }
        KeyKind::EcdsaP256 { scalar, q }
    } else {
        return Err("only ssh-ed25519 and ecdsa-sha2-nistp256 keys are supported".into());
    };
    let comment = take_string(&mut sec)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .unwrap_or_default();
    Ok(OpensshKey { kind, comment })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an unencrypted openssh-key-v1 file the way ssh-keygen does.
    fn fake_key(seed: [u8; 32], pk: [u8; 32], cipher: &str) -> String {
        let mut sec = Vec::new();
        sec.extend_from_slice(&7u32.to_be_bytes());
        sec.extend_from_slice(&7u32.to_be_bytes());
        put_string(&mut sec, ED25519.as_bytes());
        put_string(&mut sec, &pk);
        let mut sk = seed.to_vec();
        sk.extend_from_slice(&pk);
        put_string(&mut sec, &sk);
        put_string(&mut sec, b"me@host");
        let mut raw = b"openssh-key-v1\0".to_vec();
        put_string(&mut raw, cipher.as_bytes());
        put_string(&mut raw, b"none");
        put_string(&mut raw, b"");
        raw.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut raw, &ed25519_public_blob(&pk));
        put_string(&mut raw, &sec);
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            B64.encode(raw)
        )
    }

    #[test]
    fn strings_round_trip() {
        let mut b = Vec::new();
        put_string(&mut b, b"abc");
        put_string(&mut b, b"");
        let mut s: &[u8] = &b;
        assert_eq!(take_string(&mut s), Some(&b"abc"[..]));
        assert_eq!(take_string(&mut s), Some(&b""[..]));
        assert_eq!(take_string(&mut s), None);
        let mut short: &[u8] = &[0, 0, 0, 9, 1];
        assert_eq!(take_string(&mut short), None);
    }

    #[test]
    fn parses_unencrypted_ed25519_and_rejects_encrypted() {
        let k = parse_openssh_private(&fake_key([1; 32], [2; 32], "none")).unwrap();
        assert_eq!(k.comment, "me@host");
        match k.kind {
            KeyKind::Ed25519 { seed } => assert_eq!(*seed, [1; 32]),
            KeyKind::EcdsaP256 { .. } => panic!("parsed as ECDSA"),
        }
        let e = parse_openssh_private(&fake_key([1; 32], [2; 32], "aes256-ctr"))
            .err()
            .unwrap();
        assert!(e.contains("encrypted"));
        assert!(parse_openssh_private("garbage").is_err());
    }

    #[test]
    fn public_line_shape() {
        let l = public_line(&[0; 32], "c");
        assert!(l.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5") && l.ends_with(" c"));
    }
}
