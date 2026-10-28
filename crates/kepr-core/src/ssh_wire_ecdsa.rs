//! ECDSA P-256 in OpenSSH's wire formats (RFC 5656 §3.1, T12.11): the
//! `ecdsa-sha2-nistp256` public-key and signature blobs, RFC 4251 mpints,
//! and the key fields of an unencrypted `openssh-key-v1` private key.
//! No cryptography here: signing and the point check happen in the daemon.

use zeroize::Zeroizing;

use crate::ssh_wire::{self, put_string, take_string};

pub const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const CURVE: &str = "nistp256";

/// `string "ecdsa-sha2-nistp256" ‖ string "nistp256" ‖ string Q`, where
/// Q is the uncompressed point `0x04 ‖ x ‖ y`.
pub fn public_blob(q: &[u8; 65]) -> Vec<u8> {
    let mut b = Vec::with_capacity(104);
    put_string(&mut b, ECDSA_P256.as_bytes());
    put_string(&mut b, CURVE.as_bytes());
    put_string(&mut b, q);
    b
}

/// An RFC 4251 mpint of the unsigned big-endian `v`: leading zero bytes
/// stripped, a `0x00` prefix when the top bit is set (zero is empty).
pub fn put_mpint(out: &mut Vec<u8>, v: &[u8]) {
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let v = &v[start..];
    let pad = v.first().is_some_and(|&b| b & 0x80 != 0);
    out.extend_from_slice(&((v.len() + usize::from(pad)) as u32).to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

/// `string "ecdsa-sha2-nistp256" ‖ string(mpint r ‖ mpint s)`.
pub fn signature_blob(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(74);
    put_mpint(&mut inner, r);
    put_mpint(&mut inner, s);
    let mut b = Vec::with_capacity(97);
    put_string(&mut b, ECDSA_P256.as_bytes());
    put_string(&mut b, &inner);
    b
}

/// `ecdsa-sha2-nistp256 AAAA… comment`, as in authorized_keys.
pub fn public_line(q: &[u8; 65], comment: &str) -> String {
    let line = format!("{ECDSA_P256} {} {comment}", ssh_wire::b64(&public_blob(q)));
    line.trim_end().to_string()
}

/// The key type a public-key or signature blob starts with.
pub fn blob_type(blob: &[u8]) -> Option<&str> {
    let mut b = blob;
    std::str::from_utf8(take_string(&mut b)?).ok()
}

/// The authorized_keys type word for a stored public blob (base64):
/// ECDSA when the blob says so, else Ed25519 (every key before T12.11).
pub fn type_of_b64(public_b64: &str) -> &'static str {
    match ssh_wire::unb64(public_b64).as_deref().and_then(blob_type) {
        Some(ECDSA_P256) => ECDSA_P256,
        _ => ssh_wire::ED25519,
    }
}

/// A non-negative mpint of at most 32 bytes, left-padded into `out`.
fn take_mpint32(buf: &mut &[u8], out: &mut [u8; 32]) -> Option<()> {
    let raw = take_string(buf)?;
    if raw.first().is_some_and(|&b| b & 0x80 != 0) {
        return None; // negative
    }
    let start = raw.iter().position(|&b| b != 0).unwrap_or(raw.len());
    let v = &raw[start..];
    if v.len() > 32 {
        return None;
    }
    out.fill(0);
    out[32 - v.len()..].copy_from_slice(v);
    Some(())
}

/// The private section's fields after the key type: `string "nistp256"
/// ‖ string Q ‖ mpint d`. Returns (d, Q); whether d belongs to Q is the
/// daemon's check (it has the curve arithmetic).
pub fn take_private(sec: &mut &[u8]) -> Option<(Zeroizing<[u8; 32]>, [u8; 65])> {
    if take_string(sec)? != CURVE.as_bytes() {
        return None;
    }
    let q: [u8; 65] = take_string(sec)?.try_into().ok()?;
    if q[0] != 0x04 {
        return None; // only uncompressed points, as OpenSSH writes them
    }
    let mut d = Zeroizing::new([0u8; 32]);
    take_mpint32(sec, &mut d)?;
    Some((d, q))
}

/// (r, s) from an `ecdsa-sha2-nistp256` signature blob.
pub fn parse_signature_blob(blob: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut b = blob;
    if take_string(&mut b)? != ECDSA_P256.as_bytes() {
        return None;
    }
    let mut inner = take_string(&mut b)?;
    let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
    take_mpint32(&mut inner, &mut r)?;
    take_mpint32(&mut inner, &mut s)?;
    (inner.is_empty() && b.is_empty()).then_some((r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ssh-keygen -t ecdsa -b 256 -N '' -C fixture@kepr` (OpenSSH 9.6),
    /// test-only, shared with the daemon's tests. The PEM armour is added
    /// at run time, as in github_app.rs, so the tree holds no private-key
    /// block. Its scalar has the top bit set (a 33-byte mpint).
    const FIXTURE_B64: &str =
        include_str!("../../../src/daemon_ssh/testdata/ecdsa-p256-test-only.b64");
    /// The fixture's `.pub` line, as ssh-keygen wrote it.
    const FIXTURE_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzd\
        HAyNTYAAABBBOMNoAg49EaERM72g2AhPFDX2DoGcFAWQLENAmYrxBatdOfAXh5yBrhspI4XCb1tvy5E31k+BVIzbf0Eaq1ZPJo= fixture@kepr";
    const FIXTURE_Q: &str = "04e30da00838f4468444cef68360213c50d7d83a0670501640b10d02662bc416ad\
        74e7c05e1e7206b86ca48e1709bd6dbf2e44df593e0552336dfd046aad593c9a";
    const FIXTURE_D: &str = "b919416088b282f6ad06dbe52550609d1360f31917721494d115597e0857b169";
    /// The signature blob inside `ssh-keygen -Y sign -f fixture -n file`
    /// of "kepr ecdsa vector": r has its top bit set, s does not.
    const KEYGEN_SIG: &str = "0000001365636473612d736861322d6e69737470323536000000490000002100\
        866bfc0051daa60570af7a750d5565a043ff50e85763b866b32eaa5e55025cc6000000203f415ba68fe2b8b5bb5d\
        96d03da0ef82875657dfe2a67117dc1f7107722d3d69";

    fn pem(b64: &str) -> String {
        let label = "OPENSSH PRIVATE KEY";
        format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n")
    }

    fn unhex(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tohex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        unhex(h).try_into().unwrap()
    }

    #[test]
    fn public_line_matches_ssh_keygen() {
        let q = arr::<65>(FIXTURE_Q);
        assert_eq!(public_line(&q, "fixture@kepr"), FIXTURE_PUB);
        let blob = public_blob(&q);
        assert_eq!(blob_type(&blob), Some(ECDSA_P256));
        assert_eq!(type_of_b64(&ssh_wire::b64(&blob)), ECDSA_P256);
        let ed = ssh_wire::ed25519_public_blob(&[1; 32]);
        assert_eq!(type_of_b64(&ssh_wire::b64(&ed)), ssh_wire::ED25519);
        assert_eq!(type_of_b64("!!"), ssh_wire::ED25519);
        assert_eq!(blob_type(&[0, 0, 0, 9, 1]), None);
    }

    #[test]
    fn signature_blob_matches_ssh_keygen() {
        let want = unhex(KEYGEN_SIG);
        let (r, s) = parse_signature_blob(&want).unwrap();
        assert_eq!(tohex(&r).get(..6), Some("866bfc"));
        assert_eq!(signature_blob(&r, &s), want);
        assert_eq!(blob_type(&want), Some(ECDSA_P256));
    }

    #[test]
    fn mpint_padding_and_stripping() {
        let enc = |v: &[u8]| {
            let mut o = Vec::new();
            put_mpint(&mut o, v);
            o
        };
        assert_eq!(
            enc(&[0x80, 1]),
            vec![0, 0, 0, 3, 0, 0x80, 1],
            "top bit: 0x00"
        );
        assert_eq!(enc(&[0, 0, 0x7f, 2]), vec![0, 0, 0, 2, 0x7f, 2], "stripped");
        assert_eq!(
            enc(&[0, 0x80]),
            vec![0, 0, 0, 2, 0, 0x80],
            "stripped, then 0x00"
        );
        assert_eq!(enc(&[0, 0]), vec![0, 0, 0, 0], "zero is empty");
        let mut r = [0u8; 32];
        r[0] = 0x80;
        let mut s = [0u8; 32];
        s[1] = 0x01;
        let blob = signature_blob(&r, &s);
        let mut b: &[u8] = &blob;
        assert_eq!(take_string(&mut b), Some(ECDSA_P256.as_bytes()));
        let inner = take_string(&mut b).unwrap();
        assert_eq!(inner.len(), 4 + 33 + 4 + 31);
        assert_eq!(&inner[..6], &[0, 0, 0, 33, 0, 0x80]);
        assert_eq!(&inner[37..42], &[0, 0, 0, 31, 0x01]);
        assert_eq!(parse_signature_blob(&blob), Some((r, s)));
    }

    #[test]
    fn negative_or_long_mpints_are_refused() {
        let blob = |inner: &[u8]| {
            let mut b = Vec::new();
            put_string(&mut b, ECDSA_P256.as_bytes());
            put_string(&mut b, inner);
            b
        };
        let mut neg = Vec::new();
        put_string(&mut neg, &[0x80; 32]);
        put_string(&mut neg, &[1]);
        assert_eq!(parse_signature_blob(&blob(&neg)), None);
        let mut long = Vec::new();
        put_string(&mut long, &[1; 33]);
        put_string(&mut long, &[1]);
        assert_eq!(parse_signature_blob(&blob(&long)), None);
        let ed = ssh_wire::ed25519_signature_blob(&[1; 64]);
        assert_eq!(parse_signature_blob(&ed), None);
    }

    #[test]
    fn parses_the_ssh_keygen_fixture() {
        let k = ssh_wire::parse_openssh_private(&pem(FIXTURE_B64)).unwrap();
        assert_eq!(k.comment, "fixture@kepr");
        match k.kind {
            ssh_wire::KeyKind::EcdsaP256 { scalar, q } => {
                assert_eq!(tohex(&*scalar), FIXTURE_D);
                assert_eq!(q, arr::<65>(FIXTURE_Q));
            }
            ssh_wire::KeyKind::Ed25519 { .. } => panic!("parsed as Ed25519"),
        }
    }

    #[test]
    fn a_public_section_that_disagrees_is_malformed() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut raw = b64.decode(FIXTURE_B64.replace('\n', "")).unwrap();
        let q = arr::<65>(FIXTURE_Q);
        // The first copy of Q is the public section's.
        let at = raw.windows(65).position(|w| w == q).unwrap();
        raw[at + 64] ^= 1;
        let e = ssh_wire::parse_openssh_private(&pem(&b64.encode(&raw)));
        assert_eq!(e.err().as_deref(), Some("malformed OpenSSH key"));
    }

    #[test]
    fn other_key_types_are_refused() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut raw = b64.decode(FIXTURE_B64.replace('\n', "")).unwrap();
        // Same length, so every length prefix stays right.
        let needle = b"ecdsa-sha2-nistp256";
        while let Some(p) = raw.windows(needle.len()).position(|w| w == needle) {
            raw[p..p + needle.len()].copy_from_slice(b"ecdsa-sha2-nistp384");
        }
        let e = ssh_wire::parse_openssh_private(&pem(&b64.encode(&raw)));
        assert_eq!(
            e.err().as_deref(),
            Some("only ssh-ed25519 and ecdsa-sha2-nistp256 keys are supported")
        );
    }
}
