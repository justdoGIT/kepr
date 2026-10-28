// daemon_sharing/kem.rs — share envelopes (P6.1 v1, T6.01 v2).
//
//   v1  kepr-pub1-<x25519_pub>             kepr-share1-<eph ‖ nonce ‖ gcm>
//       key = HKDF-SHA256(salt = eph ‖ to, X25519 ss, "kepr-share-v1")
//   v2  kepr-pk2-<x25519_pub ‖ mlkem_ek>   kepr-share2-<eph ‖ mlkem_ct ‖ nonce ‖ gcm>
//       key = HKDF-SHA256(salt = SHA-256(eph ‖ mlkem_ct),
//                         ikm  = x25519_ss ‖ mlkem_ss,
//                         info = "kepr-share-v2" ‖ x25519_pub ‖ mlkem_ek)
//
// v2 is a hybrid: an attacker has to break both X25519 and ML-KEM-768
// (FIPS 203) to read a share, so envelopes recorded today stay closed
// against a future quantum computer. v1 keys and envelopes keep working:
// a v1 public key gets a v1 envelope, and both versions are received.
//
// The secret share key record holds `base64(x25519_sk ‖ mlkem_seed)`
// (96 bytes); a v1 record holds only the 32-byte X25519 key and is
// upgraded in place (same X25519 key, new ML-KEM seed) by `kepr share key`.

use base64::Engine;
use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::daemon_eco::cipher;

pub const PUB1: &str = "kepr-pub1-";
pub const PUB2: &str = "kepr-pk2-";
pub const ENV1: &str = "kepr-share1-";
pub const ENV2: &str = "kepr-share2-";
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const SEED_LEN: usize = 64;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn rand<const N: usize>() -> Result<Zeroizing<[u8; N]>, String> {
    let mut b = Zeroizing::new([0u8; N]);
    cipher::fill_random(b.as_mut()).map_err(|_| "CSPRNG failure".to_string())?;
    Ok(b)
}

/// A recipient's public key, as parsed from its text form.
pub enum Recipient {
    V1([u8; 32]),
    V2 { x: [u8; 32], ek: Vec<u8> },
}

impl Recipient {
    pub fn x25519(&self) -> &[u8; 32] {
        match self {
            Recipient::V1(x) | Recipient::V2 { x, .. } => x,
        }
    }

    /// The canonical text form (what `parse` reads back).
    pub fn text(&self) -> String {
        match self {
            Recipient::V1(x) => format!("{PUB1}{}", B64.encode(x)),
            Recipient::V2 { x, ek } => format!("{PUB2}{}", B64.encode([&x[..], ek].concat())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim();
        let decode = |p: &str| t.strip_prefix(p).and_then(|b| B64.decode(b).ok());
        if let Some(raw) = decode(PUB1) {
            let x = raw.try_into().map_err(|_| "not a kepr public key")?;
            return Ok(Recipient::V1(x));
        }
        if let Some(raw) = decode(PUB2).filter(|r| r.len() == 32 + EK_LEN) {
            EncapsulationKey::new_from_slice(&raw[32..]).map_err(|_| "not a kepr public key")?;
            let x = raw[..32].try_into().expect("32-byte slice");
            return Ok(Recipient::V2 {
                x,
                ek: raw[32..].to_vec(),
            });
        }
        Err("not a kepr public key (kepr-pk2-… or kepr-pub1-…)".into())
    }
}

/// This user's secret share key: X25519, plus an ML-KEM-768 seed since T6.01.
pub struct ShareSecret {
    pub x: StaticSecret,
    pub mlkem_seed: Option<Zeroizing<[u8; SEED_LEN]>>,
}

impl ShareSecret {
    pub fn generate() -> Result<Self, String> {
        Ok(Self {
            x: StaticSecret::from(*rand::<32>()?),
            mlkem_seed: Some(rand::<SEED_LEN>()?),
        })
    }

    /// Add an ML-KEM key to a v1-only secret. Returns whether it changed.
    pub fn upgrade(&mut self) -> Result<bool, String> {
        if self.mlkem_seed.is_some() {
            return Ok(false);
        }
        self.mlkem_seed = Some(rand::<SEED_LEN>()?);
        Ok(true)
    }

    pub fn encode(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(self.x.to_bytes().to_vec());
        if let Some(s) = &self.mlkem_seed {
            raw.extend_from_slice(s.as_ref());
        }
        Zeroizing::new(B64.encode(raw.as_slice()))
    }

    pub fn decode(text: &str) -> Result<Self, String> {
        let raw = Zeroizing::new(B64.decode(text).map_err(|_| "share key is damaged")?);
        let x: [u8; 32] = raw
            .get(..32)
            .and_then(|b| b.try_into().ok())
            .ok_or("share key is damaged")?;
        let mlkem_seed = match raw.len() {
            32 => None,
            96 => {
                let mut s = Zeroizing::new([0u8; SEED_LEN]);
                s.copy_from_slice(&raw[32..]);
                Some(s)
            }
            _ => return Err("share key is damaged".into()),
        };
        Ok(Self {
            x: StaticSecret::from(x),
            mlkem_seed,
        })
    }

    fn dk(&self) -> Option<DecapsulationKey> {
        let seed = self.mlkem_seed.as_ref()?;
        Some(DecapsulationKey::from_seed((**seed).into()))
    }

    /// Our public key: v2 when we hold an ML-KEM key, else v1.
    pub fn recipient(&self) -> Recipient {
        let x = PublicKey::from(&self.x).to_bytes();
        match self.dk() {
            Some(dk) => Recipient::V2 {
                x,
                ek: dk.encapsulation_key().to_bytes().to_vec(),
            },
            None => Recipient::V1(x),
        }
    }
}

fn kdf1(shared: &[u8; 32], eph: &[u8; 32], to: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let salt = [&eph[..], to].concat();
    cipher::hkdf_sha256(Some(&salt), shared, &[b"kepr-share-v1"])
}

fn kdf2(
    x_ss: &[u8; 32],
    k_ss: &[u8],
    eph: &[u8; 32],
    ct: &[u8],
    to: &Recipient,
) -> Zeroizing<[u8; 32]> {
    let Recipient::V2 { x, ek } = to else {
        unreachable!("kdf2 is only used with v2 recipients")
    };
    let salt = cipher::sha256(&[eph, ct]);
    let ikm = Zeroizing::new([&x_ss[..], k_ss].concat());
    cipher::hkdf_sha256(Some(&salt), &ikm, &[b"kepr-share-v2", x, ek])
}

fn gcm_seal(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = *rand::<12>()?;
    let ct = cipher::seal(key, &nonce, aad, msg).map_err(|_| "encryption failed")?;
    Ok([&nonce[..], &ct].concat())
}

fn gcm_open(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let nonce: [u8; 12] = body
        .get(..12)
        .and_then(|n| n.try_into().ok())
        .ok_or(NOT_YOURS)?;
    cipher::open(key, &nonce, aad, &body[12..]).map_err(|_| NOT_YOURS.into())
}

const NOT_YOURS: &str = "this share is not for you, or it was altered";

/// Encrypt `payload` to `to`: a v1 envelope for a v1 key, else v2.
pub fn seal(to: &Recipient, payload: &[u8]) -> Result<String, String> {
    let eph = StaticSecret::from(*rand::<32>()?);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let x_ss = Zeroizing::new(
        eph.diffie_hellman(&PublicKey::from(*to.x25519()))
            .to_bytes(),
    );
    match to {
        Recipient::V1(x) => {
            let key = kdf1(&x_ss, &eph_pub, x);
            let body = gcm_seal(&key, &[ENV1.as_bytes(), x].concat(), payload)?;
            Ok(format!(
                "{ENV1}{}",
                B64.encode([&eph_pub[..], &body].concat())
            ))
        }
        Recipient::V2 { x, ek } => {
            let ek = EncapsulationKey::new_from_slice(ek).map_err(|_| "not a kepr public key")?;
            let (ct, k_ss) = ek.encapsulate();
            let key = kdf2(&x_ss, k_ss.as_slice(), &eph_pub, ct.as_slice(), to);
            let body = gcm_seal(&key, &[ENV2.as_bytes(), x].concat(), payload)?;
            let raw = [&eph_pub[..], ct.as_slice(), &body].concat();
            Ok(format!("{ENV2}{}", B64.encode(raw)))
        }
    }
}

/// Decrypt a v1 or v2 envelope with our secret key.
pub fn open(me: &ShareSecret, envelope: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let t = envelope.trim();
    let decode = |p: &str| t.strip_prefix(p).and_then(|b| B64.decode(b).ok());
    let my_x = PublicKey::from(&me.x).to_bytes();
    if let Some(raw) = decode(ENV1).filter(|r| r.len() > 32 + 12 + 16) {
        let eph: [u8; 32] = raw[..32].try_into().expect("32-byte slice");
        let x_ss = Zeroizing::new(me.x.diffie_hellman(&PublicKey::from(eph)).to_bytes());
        let key = kdf1(&x_ss, &eph, &my_x);
        return gcm_open(&key, &[ENV1.as_bytes(), &my_x].concat(), &raw[32..]);
    }
    if let Some(raw) = decode(ENV2).filter(|r| r.len() > 32 + CT_LEN + 12 + 16) {
        let dk = me
            .dk()
            .ok_or("this share needs a post-quantum share key: run `kepr share key`, then ask for it again")?;
        let eph: [u8; 32] = raw[..32].try_into().expect("32-byte slice");
        let ct = &raw[32..32 + CT_LEN];
        let k_ss = dk.decapsulate_slice(ct).map_err(|_| NOT_YOURS)?;
        let x_ss = Zeroizing::new(me.x.diffie_hellman(&PublicKey::from(eph)).to_bytes());
        let key = kdf2(&x_ss, k_ss.as_slice(), &eph, ct, &me.recipient());
        return gcm_open(
            &key,
            &[ENV2.as_bytes(), &my_x].concat(),
            &raw[32 + CT_LEN..],
        );
    }
    Err("not a kepr share (kepr-share2-… or kepr-share1-…)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(env: &str, prefix: &str) -> Vec<u8> {
        B64.decode(env.strip_prefix(prefix).unwrap()).unwrap()
    }

    #[test]
    fn v2_round_trip_for_one_recipient_only() {
        let bob = ShareSecret::generate().unwrap();
        let eve = ShareSecret::generate().unwrap();
        let to = Recipient::parse(&bob.recipient().text()).unwrap();
        assert!(bob.recipient().text().starts_with(PUB2));
        let env = seal(&to, b"hello").unwrap();
        assert!(env.starts_with(ENV2));
        assert_eq!(&**open(&bob, &env).unwrap(), b"hello");
        assert!(open(&eve, &env).is_err());
        assert_ne!(env, seal(&to, b"hello").unwrap());
        // A flipped byte anywhere fails.
        let r = raw(&env, ENV2);
        for i in [0, 40, 32 + CT_LEN + 3, r.len() - 1] {
            let mut m = r.clone();
            m[i] ^= 1;
            assert!(open(&bob, &format!("{ENV2}{}", B64.encode(m))).is_err());
        }
    }

    #[test]
    fn v2_with_a_swapped_mlkem_ciphertext_fails() {
        let bob = ShareSecret::generate().unwrap();
        let to = bob.recipient();
        let a = raw(&seal(&to, b"one").unwrap(), ENV2);
        let b = raw(&seal(&to, b"one").unwrap(), ENV2);
        let mut swapped = a.clone();
        swapped[32..32 + CT_LEN].copy_from_slice(&b[32..32 + CT_LEN]);
        let env = format!("{ENV2}{}", B64.encode(swapped));
        assert!(open(&bob, &env).is_err());
    }

    #[test]
    fn v1_envelopes_are_still_received_and_v1_keys_get_v1() {
        let bob = ShareSecret::generate().unwrap();
        let v1 = Recipient::V1(PublicKey::from(&bob.x).to_bytes());
        let v1_text = v1.text();
        assert!(v1_text.starts_with(PUB1));
        let to = Recipient::parse(&v1_text).unwrap();
        assert!(matches!(to, Recipient::V1(_)));
        let env = seal(&to, b"old").unwrap();
        assert!(env.starts_with(ENV1));
        assert_eq!(&**open(&bob, &env).unwrap(), b"old");
    }

    #[test]
    fn a_v1_only_secret_is_upgraded_in_place() {
        let mut old = ShareSecret::decode(&B64.encode([5u8; 32])).unwrap();
        assert!(matches!(old.recipient(), Recipient::V1(_)));
        let v1_env = seal(&old.recipient(), b"x").unwrap();
        // A v2 envelope can't reach a v1-only key (it only has v1 text).
        assert!(old.upgrade().unwrap());
        assert!(!old.upgrade().unwrap());
        let back = ShareSecret::decode(&old.encode()).unwrap();
        assert_eq!(back.x.to_bytes(), [5u8; 32]);
        assert!(matches!(back.recipient(), Recipient::V2 { .. }));
        // Same X25519 key: shares sent to the old v1 key still open.
        assert_eq!(&**open(&back, &v1_env).unwrap(), b"x");
        assert_eq!(
            &**open(&back, &seal(&back.recipient(), b"y").unwrap()).unwrap(),
            b"y"
        );
    }

    #[test]
    fn v2_envelope_to_a_v1_only_key_holder_says_upgrade() {
        let v2 = ShareSecret::generate().unwrap();
        let env = seal(&v2.recipient(), b"x").unwrap();
        let v1_only = ShareSecret {
            x: StaticSecret::from(v2.x.to_bytes()),
            mlkem_seed: None,
        };
        assert!(open(&v1_only, &env).unwrap_err().contains("kepr share key"));
    }

    #[test]
    fn public_key_text() {
        let s = ShareSecret::generate().unwrap();
        let text = s.recipient().text();
        assert_eq!(Recipient::parse(&text).unwrap().text(), text);
        assert!(Recipient::parse("kepr-pub1-AAAA").is_err());
        assert!(Recipient::parse("kepr-pk2-AAAA").is_err());
        assert!(Recipient::parse("ssh-ed25519 AAAA").is_err());
        assert!(ShareSecret::decode("AAAA").is_err());
    }

    fn fixed_secret() -> ShareSecret {
        ShareSecret {
            x: StaticSecret::from([5u8; 32]),
            mlkem_seed: Some(Zeroizing::new([6u8; SEED_LEN])),
        }
    }

    // Written by the code before it moved onto the cipher seam (T12.41):
    // either crypto build must still open them.
    #[test]
    fn envelopes_written_by_the_old_code_still_open() {
        let me = fixed_secret();
        let v1 = "kepr-share1-EKk9GVDOiF8r0afrBKWwAGCxa2y_t7hkuEaBRLqQvkLdSpSONnhIPuwPdDAsHLIuc3C1r6pJDjJT0lUZ7jt2j2zVqJO0";
        let v2 = "kepr-share2-Rm52-uD4ap0dErGd_NuXUlM2u6fCraFL6Kek3-l9qxGLfDpOU60MCNo1RHwvVKk32I6AX7yT0eBQrAcx5dWEsQYzPvOrNSsf-5sZ6jwxSz5WdTPge6bn3UVwHEfEGenCp99ynJKrCflh9_QGFIosG3Ymz9q4KeoKjHiuVn26AIrnF0R2qrBYznZKwopLKtjh1_Xcjr0sftu28B2DFdM6LfmRIsvq7IUWgpo8cKg_LGYhSHiz1hi_Ueg-sbAsMYmmDHzKSE5gCw1CFV3xGoW7AlcPvhL5gYWjK3Maw99jPgWXNYmjkmpd-7mt31bSPa8EB-pvB1fCwyLrEy4eB0n__5cE9Dg8Z9IY7Zh9MG-AViHG7g3nOg1QChhkS50Sb7sB95Xkwgq1HYBtsb57vwdONqoUokpB6Z_WY6iaxpHEDLwMAfP5Do1XQHLe7WlePxh0PCmlUyU_DfbuZVbpsHS7suv7qtKoN7OQWi9cbkqF8FghG5buFQVaojjK45JailYuzPi3SYAqxDTZdUF7QO_Z0fTB6RTBC0Ar7ZYLLyxcCbEz90oJC3cZYhHJLnlqWWY4rVyKf9HBYSh-Z-S4a3dXYWEdG3mKmsJSXDS8WPzFDvgOUSn4w8VNueHzZuP7z7jYY4_HBZ5pCytXHCISaZnZ3N0BBclgNUmnBLaZz1IJDRYo5D1XpvEnWSC579XLTNfphveoE-VQgAL8MkzWckyBNQ9bjdG4uwL5bqOb0BTQnlxmdgIRj2iu_mi3ePr6kcSew8R5SmCvvNli8aPjWfg8KPg6VaxFQYd60oWc4ld4OPF1kIbtiP5rhMJzGyNu4xddnVAugcVI0GfZwHTnmnDkg-U-a1LkGvhyvRxhKfxiT93VHqgunwnlzC29J73GMgyASpNDGHZ5uGVDGYPIXt7mucyheChBeQJFOIsnjSSXbOvobF4rjT6csbBu5FOLKfBn7iKkeHc-hpMTVxMD6d9MJsG-2oj_jyrUU4C1R_sDr_K9EeFfTLzCJmf9AUcfNhBFL6d6HlQKVeV_KJ__QzYqNlR-RCDAtUOv_JVQkMrmEqcAftfst3BXrD7liM6v-VxmeRA1RXSzeufsNbtJFDpJRNfyiQ34yJoUJle7WA58iLiyBnL6bHJw5s6soYi3Z2rjZJ-OeJ9dRpkwho02IVb1WSlzkgMyPhSuAdiftasvypojFVBI4iH6cShNdSwoEDCCcZ82Wvukoy85rb9m0-ubxWwcSJI1id3YZEDtA8-m8njXJGfD2dHITsWpG_H1-5ahNiFOJWPqEAgio7WPhZ6zprSmMlc7o56O0NBhFZWNsfMQiKWqKhh5VLqFKeNakUBkBUprdDI45Y0Rw5HmN96bso_nY4e9H5jcgK8khGOWtQ78boW2OdNnkg9nE7RXgkXwfmLT-cpH6CQzU8jsz-JMifFQE-WMBQBb1DE4Vpr7SbS7iPIa01PAfdHrBtIn_YO0gCbGE8_TJPA-SI2DOWHX-ehhmVr2dQiaPqUhcYh11JHMoSa8OpdFkwOcJ5wJSUu3KcGug4Q";
        assert_eq!(&**open(&me, v1).unwrap(), b"pinned v1");
        assert_eq!(&**open(&me, v2).unwrap(), b"pinned v2");
    }
}
