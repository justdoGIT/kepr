// cli_platform/kdbx.rs — `kepr import vault.kdbx` (T10.02): KeePass KDBX 4.
//
// Container: outer header (cipher, compression, master seed, IV, KDF
// parameters as a variant dictionary), its SHA-256 and HMAC, then the
// HMAC-SHA256 block stream. Keys come from kdbx_keys.rs (Argon2d/Argon2id
// key schedule). The payload
// (AES-256-CBC or ChaCha20, optionally gzip) holds an inner header with the
// protected-value stream key, then the XML that kdbx_xml.rs reads.
//
// Key files, AES-KDF and KDBX 3.x are refused with a plain message. The
// password is the only input that unlocks; a wrong one fails the header
// HMAC before anything is decrypted.

use std::collections::HashMap;
use std::io::Read;

use hmac::Mac;
use kepr_core::protocol::Response;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::kdbx_keys::{block_key, hmac, Keys};

use crate::cli_import::Opts;
use crate::cli_import_parse::Entry;

const MAGIC: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
const AES256: &str = "31c1f2e6bf714350be5805216afc5aff";
const CHACHA20: &str = "d6038a2b8b6f4cb5a524339a31dbb59a";
/// Decompressed payload limit (a KeePass database is rarely over a few MB).
const MAX_PAYLOAD: u64 = 256 << 20;

pub const WRONG_PASSWORD: &str =
    "wrong password (or the database also needs a key file, which kepr import does not read)";

/// Is this import a KeePass database?
pub fn wants(file: &str, format: &str) -> bool {
    match format {
        "kdbx" => true,
        "auto" => {
            file.to_ascii_lowercase().ends_with(".kdbx")
                || std::fs::File::open(file)
                    .and_then(|mut f| {
                        let mut m = [0u8; 8];
                        f.read_exact(&mut m).map(|_| m == MAGIC)
                    })
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// The `kepr import` hook: `Some` when `file` is a KeePass database.
pub fn cmd_import(file: &str, o: &Opts) -> Option<Response> {
    if !wants(file, o.format) {
        return None;
    }
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => return Some(Response::fail(format!("{file}: {e}"))),
    };
    if let Err(e) = version(&bytes) {
        return Some(Response::fail(e));
    }
    let pw = crate::cli_input::read_masked(&format!("Password for {file} (input hidden): "));
    Some(match open(&bytes, pw.as_str().as_bytes()) {
        // No "delete the export" hint: the database stays encrypted.
        Ok(entries) => crate::cli_import::import_entries(entries, o, None),
        Err(e) => Response::fail(e),
    })
}

/// The entries of a KDBX 4 database.
pub fn open(bytes: &[u8], password: &[u8]) -> Result<Vec<Entry>, String> {
    let h = header(bytes)?;
    let Keys {
        cipher: key,
        hmac_base,
    } = Keys::derive(&h.kdf, &h.seed, password)?;
    let (head, rest) = bytes.split_at(h.end);
    let (sha, rest) = split(rest, 32)?;
    if Sha256::digest(head).as_slice() != sha {
        return Err("the database file is damaged (header checksum)".into());
    }
    let (tag, rest) = split(rest, 32)?;
    if hmac(&block_key(&hmac_base, u64::MAX), &[head])
        .verify_slice(tag)
        .is_err()
    {
        return Err(WRONG_PASSWORD.into());
    }
    let ct = blocks(rest, &hmac_base)?;
    let mut plain = decrypt(&h, &key, &ct)?;
    if h.gzip {
        plain = gunzip(&plain)?;
    }
    let (stream_key, xml) = inner_header(&plain)?;
    super::kdbx_xml::entries(xml, &stream_key)
}

/// KDBX 4.x only.
pub fn version(b: &[u8]) -> Result<(), String> {
    if b.len() < 12 || b[..8] != MAGIC {
        return Err("not a KeePass database".into());
    }
    let (minor, major) = (u16le(&b[8..]), u16le(&b[10..]));
    if major != 4 {
        return Err(format!(
            "unsupported version: KDBX {major}.{minor}; kepr reads KDBX 4 \
             (in KeePassXC: Database > Database Security > Encryption Settings, format KDBX 4)"
        ));
    }
    Ok(())
}

pub struct Header {
    chacha: bool,
    gzip: bool,
    seed: Vec<u8>,
    iv: Vec<u8>,
    kdf: HashMap<String, Vec<u8>>,
    /// Offset just past the end-of-header field.
    end: usize,
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn split(b: &[u8], n: usize) -> Result<(&[u8], &[u8]), String> {
    (b.len() >= n)
        .then(|| b.split_at(n))
        .ok_or_else(|| "the database file is truncated".to_string())
}

pub fn header(b: &[u8]) -> Result<Header, String> {
    version(b)?;
    let mut fields: HashMap<u8, &[u8]> = HashMap::new();
    let mut rest = &b[12..];
    loop {
        let (id_len, r) = split(rest, 5)?;
        let (data, r) = split(r, u32le(&id_len[1..]) as usize)?;
        rest = r;
        if id_len[0] == 0 {
            break;
        }
        fields.insert(id_len[0], data);
    }
    let field = |id: u8, what: &str| {
        fields
            .get(&id)
            .copied()
            .ok_or_else(|| format!("the database header has no {what}"))
    };
    let cipher = hex::encode(field(2, "cipher")?);
    let chacha = match cipher.as_str() {
        AES256 => false,
        CHACHA20 => true,
        _ => return Err("unsupported cipher (kepr reads AES-256 and ChaCha20 databases)".into()),
    };
    let gzip = match field(3, "compression flag")? {
        [0, 0, 0, 0] => false,
        [1, 0, 0, 0] => true,
        _ => return Err("unsupported compression".into()),
    };
    Ok(Header {
        chacha,
        gzip,
        seed: field(4, "master seed")?.to_vec(),
        iv: field(7, "IV")?.to_vec(),
        kdf: super::kdbx_keys::variant_dict(field(11, "KDF parameters")?)?,
        end: b.len() - rest.len(),
    })
}

/// The HMAC block stream, checked block by block → ciphertext.
pub fn blocks(mut b: &[u8], base: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for i in 0u64.. {
        let (tag, r) = split(b, 32)?;
        let (size, r) = split(r, 4)?;
        let (data, r) = split(r, u32le(size) as usize)?;
        let ok = hmac(&block_key(base, i), &[&i.to_le_bytes(), size, data]).verify_slice(tag);
        if ok.is_err() {
            return Err(format!("the database file is damaged (block {i})"));
        }
        if data.is_empty() {
            break;
        }
        out.extend_from_slice(data);
        b = r;
    }
    Ok(out)
}

fn decrypt(h: &Header, key: &[u8; 32], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit, StreamCipher};
    let bad = || "the database file is damaged (payload)".to_string();
    if h.chacha {
        let iv: [u8; 12] = h.iv.as_slice().try_into().map_err(|_| bad())?;
        let mut buf = Zeroizing::new(ct.to_vec());
        chacha20::ChaCha20::new(key.into(), &iv.into()).apply_keystream(&mut buf);
        Ok(buf)
    } else {
        let iv: [u8; 16] = h.iv.as_slice().try_into().map_err(|_| bad())?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let n = cbc::Decryptor::<aes::Aes256>::new(key.into(), &iv.into())
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(|_| bad())?
            .len();
        buf.truncate(n);
        Ok(buf)
    }
}

fn gunzip(b: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(b)
        .take(MAX_PAYLOAD + 1)
        .read_to_end(&mut out)
        .map_err(|_| "the database file is damaged (compression)".to_string())?;
    if out.len() as u64 > MAX_PAYLOAD {
        return Err("the database is too large".into());
    }
    Ok(out)
}

/// Inner header → (protected-value stream key, XML).
fn inner_header(b: &[u8]) -> Result<(Zeroizing<Vec<u8>>, &[u8]), String> {
    let (mut chacha, mut key, mut rest) = (false, Zeroizing::new(Vec::new()), b);
    loop {
        let (id_len, r) = split(rest, 5)?;
        let (data, r) = split(r, u32le(&id_len[1..]) as usize)?;
        rest = r;
        match id_len[0] {
            0 => break,
            1 => chacha = data == [3, 0, 0, 0],
            2 => key.extend_from_slice(data),
            _ => {} // attachments
        }
    }
    if !chacha || key.is_empty() {
        return Err("unsupported protected-value stream (kepr reads ChaCha20)".into());
    }
    Ok((key, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with pykeepass 4.2.0 (no KeePassXC binary on the build host):
    // create_database(path, password="kepr-fixture-pw"), Argon2 M = 1 MiB,
    // I = 2, P = 2 to keep the test fast; groups Root/Work; GitHub (alice,
    // with a history entry holding the old password), AWS prod (bob, a
    // protected "API Key" and an unprotected "Region" field), Database (db,
    // otp), and "Old thing" moved to the recycle bin.
    const AES_ARGON2D_GZIP: &[u8] =
        include_bytes!("../../tests/fixtures/kdbx/aes-argon2d-gzip.kdbx");
    const CHACHA20_ARGON2ID: &[u8] =
        include_bytes!("../../tests/fixtures/kdbx/chacha20-argon2id.kdbx");
    const PASSWORD: &[u8] = b"kepr-fixture-pw";

    fn pairs(e: &[Entry]) -> Vec<(String, String)> {
        e.iter()
            .map(|e| (e.name.clone(), e.value.as_str().to_string()))
            .collect()
    }

    #[test]
    fn fixtures_import_three_entries() {
        let want: Vec<(String, String)> = [
            ("GITHUB", "gh-pass-1b"),
            ("GITHUB_USERNAME", "alice"),
            ("AWS_PROD", "aws-secret-2"),
            ("AWS_PROD_USERNAME", "bob"),
            ("AWS_PROD_API_KEY", "aws-api-key-<&>"),
            ("DATABASE", "db-pass-3"),
            ("DATABASE_USERNAME", "db"),
            ("DATABASE_TOTP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        for (what, db) in [
            ("AES-256 + Argon2d + gzip", AES_ARGON2D_GZIP),
            ("ChaCha20 + Argon2id", CHACHA20_ARGON2ID),
        ] {
            let got = pairs(&open(db, PASSWORD).unwrap_or_else(|e| panic!("{what}: {e}")));
            assert_eq!(got, want, "{what}");
            let titles: std::collections::HashSet<&str> = got
                .iter()
                .map(|(n, _)| n.split('_').next().unwrap())
                .collect();
            assert_eq!(titles.len(), 3, "{what}: three entries");
        }
        assert!(!header(AES_ARGON2D_GZIP).unwrap().chacha);
        assert!(header(CHACHA20_ARGON2ID).unwrap().chacha);
    }

    #[test]
    fn wrong_password_refused() {
        for db in [AES_ARGON2D_GZIP, CHACHA20_ARGON2ID] {
            assert_eq!(open(db, b"not it").err().as_deref(), Some(WRONG_PASSWORD));
        }
    }

    #[test]
    fn kdbx3_and_damage_are_reported() {
        // A KDBX 3.1 file starts like this (version 0x00030001).
        let mut v31 = MAGIC.to_vec();
        v31.extend([0x01, 0x00, 0x03, 0x00, 0x02, 0x10, 0x00]);
        let e = open(&v31, PASSWORD).err().unwrap();
        assert!(e.starts_with("unsupported version: KDBX 3.1"), "{e}");
        assert_eq!(
            open(b"PK\x03\x04 zip", PASSWORD).err().unwrap(),
            "not a KeePass database"
        );
        // A flipped payload byte fails its block HMAC; a truncated file fails cleanly.
        let mut bad = CHACHA20_ARGON2ID.to_vec();
        let n = bad.len() - 100;
        bad[n] ^= 1;
        assert!(open(&bad, PASSWORD)
            .err()
            .unwrap()
            .contains("damaged (block 0)"));
        let cut = &CHACHA20_ARGON2ID[..CHACHA20_ARGON2ID.len() - 40];
        assert!(open(cut, PASSWORD).is_err());
        for n in [12, 40, 200] {
            assert!(open(&AES_ARGON2D_GZIP[..n], PASSWORD).is_err());
        }
    }

    #[test]
    fn detection() {
        assert!(wants("x.KDBX", "auto"));
        assert!(wants("anything", "kdbx"));
        assert!(!wants("x.csv", "auto"));
        assert!(!wants("x.kdbx", "csv"));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vault.bin");
        std::fs::write(&p, CHACHA20_ARGON2ID).unwrap();
        assert!(wants(p.to_str().unwrap(), "auto"));
    }
}
