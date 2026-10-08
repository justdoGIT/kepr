// cli_platform/kdbx_keys.rs — the KDBX 4 key schedule (T10.02).
//
// composite = SHA-256(SHA-256(password)); transformed = Argon2d or Argon2id
// (`argon2`, RustCrypto, already a dependency) over it with the header's
// salt, memory, iterations and lanes; cipher key = SHA-256(seed ||
// transformed); HMAC base = SHA-512(seed || transformed || 1); the key for
// block i (u64::MAX for the header) = SHA-512(i || base). Every key lives in
// a zeroizing buffer.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::kdbx::{split, u32le};

const ARGON2D: &str = "ef636ddf8c29444b91f7a9a403e30a0c";
const ARGON2ID: &str = "9e298b1956db4773b23dfc3ec6f0a1e6";
const AES_KDF: &str = "c9d9f39a628a4460bf740d08c18a4fea";
const MAX_ARGON2_KIB: u64 = 4 << 20; // 4 GiB

/// A KeePass VariantDictionary: name → raw value bytes.
pub fn variant_dict(b: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    let bad = || "the database header is damaged (KDF parameters)".to_string();
    let (ver, mut rest) = split(b, 2).map_err(|_| bad())?;
    if ver[1] != 1 {
        return Err(bad());
    }
    let mut out = HashMap::new();
    loop {
        let (t, r) = split(rest, 1).map_err(|_| bad())?;
        if t[0] == 0 {
            return Ok(out);
        }
        let (n, r) = split(r, 4).map_err(|_| bad())?;
        let (name, r) = split(r, u32le(n) as usize).map_err(|_| bad())?;
        let (n, r) = split(r, 4).map_err(|_| bad())?;
        let (value, r) = split(r, u32le(n) as usize).map_err(|_| bad())?;
        out.insert(String::from_utf8_lossy(name).into_owned(), value.to_vec());
        rest = r;
    }
}

fn kdf_u64(kdf: &HashMap<String, Vec<u8>>, k: &str) -> Result<u64, String> {
    match kdf.get(k).map(Vec::as_slice) {
        Some(v) if v.len() == 4 => Ok(u64::from(u32le(v))),
        Some(v) if v.len() == 8 => Ok(u64::from_le_bytes(v[..8].try_into().unwrap_or([0; 8]))),
        _ => Err(format!("the database header has no KDF parameter {k}")),
    }
}

/// The payload key and the HMAC base key of a database.
pub struct Keys {
    pub cipher: Zeroizing<[u8; 32]>,
    pub hmac_base: Zeroizing<[u8; 64]>,
}

impl Keys {
    /// Argon2 over the composite key, then the KDBX 4 key schedule.
    pub fn derive(
        kdf: &HashMap<String, Vec<u8>>,
        seed: &[u8],
        password: &[u8],
    ) -> Result<Self, String> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let alg = match kdf.get("$UUID").map(hex::encode).as_deref() {
            Some(ARGON2D) => Algorithm::Argon2d,
            Some(ARGON2ID) => Algorithm::Argon2id,
            Some(AES_KDF) => {
                return Err(
                    "unsupported key derivation (AES-KDF); switch the database to \
                        Argon2 in KeePassXC's Encryption Settings"
                        .into(),
                )
            }
            _ => return Err("unsupported key derivation".into()),
        };
        if kdf.contains_key("K") || kdf.contains_key("A") {
            return Err("unsupported Argon2 secret / associated data".into());
        }
        let salt = kdf.get("S").ok_or("the database header has no KDF salt")?;
        let m_kib = kdf_u64(kdf, "M")? / 1024;
        let (t, p) = (kdf_u64(kdf, "I")?, kdf_u64(kdf, "P")?);
        let version = match kdf_u64(kdf, "V")? {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            _ => return Err("unsupported Argon2 version".into()),
        };
        let too_big = || "the database's Argon2 settings are out of range".to_string();
        if m_kib > MAX_ARGON2_KIB {
            return Err(too_big());
        }
        let n = |v: u64| u32::try_from(v).map_err(|_| too_big());
        let params = Params::new(n(m_kib)?, n(t)?, n(p)?, Some(32)).map_err(|_| too_big())?;
        let composite = Zeroizing::new(Sha256::digest(Sha256::digest(password)));
        let mut transformed = Zeroizing::new([0u8; 32]);
        Argon2::new(alg, version, params)
            .hash_password_into(composite.as_slice(), salt, transformed.as_mut())
            .map_err(|_| too_big())?;
        let key = Sha256::new()
            .chain_update(seed)
            .chain_update(transformed.as_ref())
            .finalize();
        let base = Sha512::new()
            .chain_update(seed)
            .chain_update(transformed.as_ref())
            .chain_update([1u8])
            .finalize();
        let mut out = Self {
            cipher: Zeroizing::new([0u8; 32]),
            hmac_base: Zeroizing::new([0u8; 64]),
        };
        out.cipher.copy_from_slice(&key);
        out.hmac_base.copy_from_slice(&base);
        Ok(out)
    }
}

pub fn block_key(base: &[u8; 64], index: u64) -> Zeroizing<[u8; 64]> {
    let mut k = Zeroizing::new([0u8; 64]);
    let d = Sha512::new()
        .chain_update(index.to_le_bytes())
        .chain_update(base)
        .finalize();
    k.copy_from_slice(&d);
    k
}

pub fn hmac(key: &[u8; 64], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m
}
