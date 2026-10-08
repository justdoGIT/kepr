// daemon_syncx/bundle.rs — T6.09 encrypted bundle format, shared with
// multi-device sync (T6.10).
//
//   kepr_bundle1\n
//   {"kdf":"argon2id","m":65536,"t":3,"p":1,"salt":"…","nonce":"…"}\n
//   AES-256-GCM(JSON body), AAD = the two lines above
//
// The body carries each exported credential (value, a few meta fields,
// earlier values, attachments) and lists, by name only, the ones left
// out (`"omitted":"sealed"`, …). Sealed, SSH and share-key values never
// enter a body: export.rs never decrypts them. The KDF parameters a
// bundle names are bounded before use, so a crafted file can't make the
// daemon allocate more than the store passphrase's own 64 MiB.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use kepr_core::generate::ZeroString;
use kepr_core::protocol_syncx::{BundleOmitted, BUNDLE_MAGIC, MAX_BUNDLE_BYTES};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::daemon_eco::cipher::{self, NONCE_LEN};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
/// The shortest bundle passphrase accepted for a new bundle.
pub const MIN_PASSPHRASE: usize = 10;
/// Room kept for the header lines and the tag inside MAX_BUNDLE_BYTES.
pub const HEADER_ROOM: usize = 4096;
const OPEN_FAILED: &str = "wrong passphrase or damaged bundle";

/// Argon2id cost (KiB, passes, lanes).
struct Kdf(u32, u32, u32);
/// What new bundles use: the store passphrase's 64 MiB, 3 passes.
#[cfg(not(test))]
const KDF: Kdf = Kdf(64 * 1024, 3, 1);
#[cfg(test)]
const KDF: Kdf = Kdf(256, 1, 1);
/// Bounds a bundle's own parameters must stay inside.
const MIN_M: u32 = if cfg!(test) { 256 } else { 8 * 1024 };
const MAX_M: u32 = 64 * 1024;
const MAX_T: u32 = 10;
const MAX_P: u32 = 4;

#[derive(Serialize, Deserialize)]
struct Header {
    kdf: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
    nonce: String,
}

/// The plaintext of a bundle.
#[derive(Default, Serialize, Deserialize)]
pub struct Body {
    pub created: u64,
    #[serde(default)]
    pub items: Vec<Item>,
    #[serde(default)]
    pub omitted: Vec<BundleOmitted>,
}

#[derive(Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    pub value: ZeroString,
    #[serde(default)]
    pub meta: ItemMeta,
    /// Earlier values, oldest first (never one saved while sealed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<ZeroString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<File>,
}

/// The `.meta` fields a bundle carries. Policy that only makes sense on
/// the machine that set it (consent, FIDO2, seals, bindings) never does.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_reauth: Option<bool>,
}

/// One attachment: its name and its bytes as base64.
#[derive(Serialize, Deserialize)]
pub struct File {
    pub file: String,
    pub data: ZeroString,
}

impl Item {
    /// Roughly what this item adds to a body's JSON.
    pub fn weight(&self) -> usize {
        let files: usize = self.files.iter().map(|f| f.file.len() + f.data.len()).sum();
        let history: usize = self.history.iter().map(|h| h.len() + 8).sum();
        self.name.len() + self.value.len() + history + files + 256
    }
}

fn derive(passphrase: &[u8], salt: &[u8], k: &Kdf) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = Params::new(k.0, k.1, k.2, Some(KEY_LEN))
        .map_err(|_| "unsupported bundle parameters".to_string())?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| "bundle key derivation failed".to_string())?;
    Ok(key)
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(b)
}

/// Encrypt `body` under `passphrase`.
pub fn seal(body: &Body, passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if passphrase.len() < MIN_PASSPHRASE {
        return Err(format!(
            "the bundle passphrase must be at least {MIN_PASSPHRASE} characters"
        ));
    }
    let plain = Zeroizing::new(serde_json::to_vec(body).map_err(|e| e.to_string())?);
    if plain.len() > MAX_BUNDLE_BYTES - HEADER_ROOM {
        return Err("the bundle would be over 16 MiB".into());
    }
    let (salt, nonce) = (random::<SALT_LEN>()?, random::<NONCE_LEN>()?);
    let header = Header {
        kdf: "argon2id".into(),
        m: KDF.0,
        t: KDF.1,
        p: KDF.2,
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
    };
    let mut out = BUNDLE_MAGIC.to_vec();
    out.extend(serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    out.push(b'\n');
    let key = derive(passphrase, &salt, &KDF)?;
    let ct = cipher::seal(key.as_ref(), &nonce, &out, &plain)
        .map_err(|_| "bundle encryption failed".to_string())?;
    out.extend(ct);
    Ok(out)
}

/// Decrypt a bundle; any wrong passphrase or tampering gives one error.
pub fn open(bytes: &[u8], passphrase: &[u8]) -> Result<Body, String> {
    let rest = bytes
        .strip_prefix(BUNDLE_MAGIC)
        .ok_or("not a kepr bundle")?;
    let line = rest.iter().position(|b| *b == b'\n').ok_or(OPEN_FAILED)?;
    let h: Header = serde_json::from_slice(&rest[..line]).map_err(|_| OPEN_FAILED)?;
    let bounded =
        (MIN_M..=MAX_M).contains(&h.m) && (1..=MAX_T).contains(&h.t) && (1..=MAX_P).contains(&h.p);
    if h.kdf != "argon2id" || !bounded {
        return Err("unsupported bundle parameters".into());
    }
    let salt = B64.decode(&h.salt).map_err(|_| OPEN_FAILED)?;
    let nonce: [u8; NONCE_LEN] = B64
        .decode(&h.nonce)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or(OPEN_FAILED)?;
    if salt.len() < 8 {
        return Err(OPEN_FAILED.into());
    }
    let aad_len = BUNDLE_MAGIC.len() + line + 1;
    let key = derive(passphrase, &salt, &Kdf(h.m, h.t, h.p))?;
    let plain = cipher::open(key.as_ref(), &nonce, &bytes[..aad_len], &bytes[aad_len..])
        .map_err(|_| OPEN_FAILED)?;
    serde_json::from_slice(&plain).map_err(|_| "malformed bundle".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery";

    fn body() -> Body {
        Body {
            created: 7,
            items: vec![Item {
                name: "API".into(),
                value: "s3cret-value".into(),
                meta: ItemMeta {
                    tags: Some(vec!["work".into()]),
                    ..Default::default()
                },
                history: vec!["old".into()],
                files: vec![File {
                    file: "a.txt".into(),
                    data: "aGk=".into(),
                }],
            }],
            omitted: vec![BundleOmitted {
                name: "SEALED".into(),
                omitted: "sealed".into(),
            }],
        }
    }

    #[test]
    fn round_trip() {
        let bytes = seal(&body(), PASS).unwrap();
        assert!(bytes.starts_with(BUNDLE_MAGIC));
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("s3cret-value") && !text.contains("API"));
        let back = open(&bytes, PASS).unwrap();
        assert_eq!(back.created, 7);
        let item = &back.items[0];
        assert_eq!(
            (item.name.as_str(), item.value.as_str()),
            ("API", "s3cret-value")
        );
        assert_eq!(item.meta.tags.as_deref(), Some(&["work".to_string()][..]));
        assert_eq!(item.history[0].as_str(), "old");
        assert_eq!(item.files[0].data.as_str(), "aGk=");
        assert_eq!(back.omitted, body().omitted);
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_refused_alike() {
        let bytes = seal(&body(), PASS).unwrap();
        assert_eq!(
            open(&bytes, b"wrong horse battery").err().unwrap(),
            OPEN_FAILED
        );
        let mut ct = bytes.clone();
        *ct.last_mut().unwrap() ^= 1;
        assert_eq!(open(&ct, PASS).err().unwrap(), OPEN_FAILED);
        // The header is authenticated too: a changed salt or cost fails.
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let t = text.replacen("\"t\":1", "\"t\":2", 1);
        assert_eq!(open(t.as_bytes(), PASS).err(), Some(OPEN_FAILED.into()));
        assert_eq!(
            open(b"kepr_pw1\n", PASS).err().unwrap(),
            "not a kepr bundle"
        );
    }

    #[test]
    fn short_passphrases_and_unbounded_costs_are_refused() {
        assert!(seal(&body(), b"short").unwrap_err().contains("at least"));
        let bytes = seal(&body(), PASS).unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for (from, to) in [("\"m\":256", "\"m\":1048576"), ("\"p\":1", "\"p\":64")] {
            let t = text.replacen(from, to, 1);
            assert_eq!(
                open(t.as_bytes(), PASS).err().unwrap(),
                "unsupported bundle parameters"
            );
        }
    }

    #[test]
    fn oversized_bodies_are_refused() {
        let mut b = body();
        b.items[0].value = ZeroString::from_string("x".repeat(MAX_BUNDLE_BYTES));
        assert!(seal(&b, PASS).unwrap_err().contains("16 MiB"));
    }
}
