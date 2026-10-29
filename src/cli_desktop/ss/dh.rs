// cli_desktop/ss/dh.rs — the Secret Service session algorithm
// `dh-ietf1024-sha256-aes128-cbc-pkcs7`.
//
//   keys      Diffie-Hellman in the 1024-bit MODP group of RFC 2409 §6.2
//             (Oakley group 2, generator 2); public keys are big-endian,
//             the shared secret is left-padded to 128 bytes
//   key       HKDF-SHA256 of the shared secret, no salt, no info, 16 bytes
//   secrets   AES-128-CBC with PKCS#7 padding under a fresh 16-byte IV
//
// The 1024-bit arithmetic is a Montgomery multiplication on 32 words of
// 32 bits; the exponentiation squares and multiplies on every bit and
// picks the result with a mask, so its timing does not follow the private
// exponent. Nothing here protects against an observer who can read the
// process; it keeps secrets off the bus in the clear.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PUBLIC_LEN: usize = 128;
pub const ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

const N: usize = 32;
type Big = [u32; N];

/// RFC 2409 §6.2 prime, big endian.
const PRIME: [u8; PUBLIC_LEN] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

fn from_be(b: &[u8]) -> Big {
    let mut x = [0u32; N];
    for (i, byte) in b.iter().rev().enumerate() {
        x[i / 4] |= u32::from(*byte) << (8 * (i % 4));
    }
    x
}

fn to_be(x: &Big) -> [u8; PUBLIC_LEN] {
    let mut out = [0u8; PUBLIC_LEN];
    for i in 0..PUBLIC_LEN {
        out[PUBLIC_LEN - 1 - i] = (x[i / 4] >> (8 * (i % 4))) as u8;
    }
    out
}

/// a - b into `r`; the final borrow (1 if a < b).
fn sub(a: &Big, b: &Big, r: &mut Big) -> u32 {
    let mut borrow = 0i64;
    for i in 0..N {
        let d = i64::from(a[i]) - i64::from(b[i]) - borrow;
        r[i] = d as u32;
        borrow = i64::from(d < 0);
    }
    borrow as u32
}

/// `if take { b } else { a }`, without a branch.
fn select(take: u32, a: &Big, b: &Big) -> Big {
    let mask = 0u32.wrapping_sub(take & 1);
    let mut r = [0u32; N];
    for i in 0..N {
        r[i] = (a[i] & !mask) | (b[i] & mask);
    }
    r
}

struct Mont {
    n: Big,
    n0inv: u32,
    r2: Big,
}

impl Mont {
    fn new() -> Mont {
        let n = from_be(&PRIME);
        // -n^-1 mod 2^32 by Newton iteration.
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        // R^2 mod n for R = 2^1024: start at 1 and double 2048 times.
        let mut x = [0u32; N];
        x[0] = 1;
        for _ in 0..2 * 32 * N {
            let mut carry = 0u32;
            for w in x.iter_mut() {
                let c = *w >> 31;
                *w = (*w << 1) | carry;
                carry = c;
            }
            let mut t = [0u32; N];
            let borrow = sub(&x, &n, &mut t);
            // Subtract when the doubling overflowed or x >= n.
            x = select(carry | (borrow ^ 1), &x, &t);
        }
        Mont {
            n,
            n0inv: inv.wrapping_neg(),
            r2: x,
        }
    }

    /// a * b / R mod n (CIOS).
    #[allow(clippy::needless_range_loop)] // the textbook CIOS indices
    fn mul(&self, a: &Big, b: &Big) -> Big {
        let mut t = [0u32; N + 2];
        for i in 0..N {
            let mut carry = 0u64;
            for j in 0..N {
                let cur = u64::from(t[j]) + u64::from(a[j]) * u64::from(b[i]) + carry;
                t[j] = cur as u32;
                carry = cur >> 32;
            }
            let cur = u64::from(t[N]) + carry;
            t[N] = cur as u32;
            t[N + 1] = (cur >> 32) as u32;
            let m = t[0].wrapping_mul(self.n0inv);
            let cur = u64::from(t[0]) + u64::from(m) * u64::from(self.n[0]);
            let mut carry = cur >> 32;
            for j in 1..N {
                let cur = u64::from(t[j]) + u64::from(m) * u64::from(self.n[j]) + carry;
                t[j - 1] = cur as u32;
                carry = cur >> 32;
            }
            let cur = u64::from(t[N]) + carry;
            t[N - 1] = cur as u32;
            t[N] = t[N + 1] + (cur >> 32) as u32;
            t[N + 1] = 0;
        }
        let mut r = [0u32; N];
        r.copy_from_slice(&t[..N]);
        let mut s = [0u32; N];
        let borrow = sub(&r, &self.n, &mut s);
        // Keep the difference if there was a top word or r >= n.
        select(t[N] | (borrow ^ 1), &r, &s)
    }

    /// base^exp mod n for a 1024-bit big-endian exponent.
    fn pow(&self, base: &Big, exp: &[u8; PUBLIC_LEN]) -> Big {
        let mut one = [0u32; N];
        one[0] = 1;
        let base_m = self.mul(base, &self.r2);
        let mut r = self.mul(&one, &self.r2);
        for byte in exp {
            for bit in (0..8).rev() {
                r = self.mul(&r, &r);
                let t = self.mul(&r, &base_m);
                r = select(u32::from((byte >> bit) & 1), &r, &t);
            }
        }
        self.mul(&r, &one)
    }
}

/// `2^private mod p`.
pub fn public_from(private: &[u8; PUBLIC_LEN]) -> [u8; PUBLIC_LEN] {
    let mut two = [0u32; N];
    two[0] = 2;
    to_be(&Mont::new().pow(&two, private))
}

/// A fresh key pair: (private, public).
pub fn keypair() -> Result<(Zeroizing<[u8; PUBLIC_LEN]>, [u8; PUBLIC_LEN]), String> {
    let mut private = Zeroizing::new([0u8; PUBLIC_LEN]);
    getrandom::fill(private.as_mut()).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let public = public_from(&private);
    Ok((private, public))
}

/// The AES key both sides derive. Refuses a peer key that would make the
/// secret trivial (0, 1, p - 1, or not below p).
pub fn session_key(
    private: &[u8; PUBLIC_LEN],
    theirs: &[u8],
) -> Result<Zeroizing<[u8; 16]>, String> {
    if theirs.is_empty() || theirs.len() > PUBLIC_LEN {
        return Err("the public key has the wrong length".into());
    }
    let y = from_be(theirs);
    let p = from_be(&PRIME);
    let mut p_minus_1 = [0u32; N];
    let mut one = [0u32; N];
    one[0] = 1;
    sub(&p, &one, &mut p_minus_1);
    let mut t = [0u32; N];
    let below_p = sub(&y, &p, &mut t) == 1;
    if !below_p || y == [0u32; N] || y == one || y == p_minus_1 {
        return Err("the public key is not acceptable".into());
    }
    let shared = Zeroizing::new(to_be(&Mont::new().pow(&y, private)));
    let mut key = Zeroizing::new([0u8; 16]);
    Hkdf::<Sha256>::new(None, shared.as_ref())
        .expand(&[], key.as_mut())
        .map_err(|_| "key derivation failed".to_string())?;
    Ok(key)
}

/// Encrypt under a fresh IV: (iv, ciphertext).
pub fn encrypt(key: &[u8; 16], plain: &[u8]) -> Result<([u8; 16], Vec<u8>), String> {
    use cbc::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).map_err(|e| format!("CSPRNG failure: {e}"))?;
    // Room for a whole block of padding; the plaintext copy is wiped.
    let mut buf = Zeroizing::new(vec![0u8; plain.len() + 16]);
    buf[..plain.len()].copy_from_slice(plain);
    let n = cbc::Encryptor::<aes::Aes128>::new(key.into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, plain.len())
        .map_err(|_| "the secret could not be encrypted")?
        .len();
    Ok((iv, buf[..n].to_vec()))
}

pub fn decrypt(key: &[u8; 16], iv: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
    let iv: [u8; 16] = iv.try_into().map_err(|_| "the IV must be 16 bytes")?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let n = cbc::Decryptor::<aes::Aes128>::new(key.into(), &iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| "the secret could not be decrypted")?
        .len();
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Computed with Python's pow() and `cryptography`.
    fn priv_a() -> [u8; 128] {
        std::array::from_fn(|i| ((i * 7 + 3) % 256) as u8)
    }
    fn priv_b() -> [u8; 128] {
        std::array::from_fn(|i| ((i * 11 + 5) % 256) as u8)
    }
    const YA: &str = "7b1d7d3188d79522e49e1ef8a54a32403fa559965ff46561a8d12fc1f79273e70b2c6ea601992ec15910b87dffa610904bdbc2bdd35b13c95a0d7cb40a0d62720f4a904259982b507d9981f4eedb7371db1336d26e29d58e2d2da00d7928a64cadc4eb683c04df21ac4f5f71174805326a640a789679de2fc1b3ed28d2c9ba71";
    const YB: &str = "d3408fa3d029066a1fb0349fcb945b151ef6bc73ea7005d1764e21063ddbe06a41302230e76cc904880c7a834338dc99f48b4a2a9dca1ee0f63f126610de6f4ffb3c99aeaf9ff23d2073c6c3f82688a0869c43c9d6173c3774136ca5533af28e527067a6cfdd1720954c6f997df758206c5d39a268753bf8aabfade7bb7e1dca";
    const KEY: &str = "4e4fa98997927fe31c1c7a8eff2977a8";
    const CT: &str = "b265e8ae861bfea5db27789388e040cde5fd01d0c2b90623fcd4ae0ebd0f2995";

    #[test]
    fn the_prime_is_the_rfc_2409_group_2_prime() {
        // Starts and ends with 64 one bits, as the RFC's does.
        assert!(PRIME[..8].iter().all(|b| *b == 0xff) && PRIME[120..].iter().all(|b| *b == 0xff));
        assert_eq!(
            &PRIME[8..16],
            &[0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34]
        );
    }

    #[test]
    fn matches_python_for_public_keys_shared_key_and_ciphertext() {
        assert_eq!(hex::encode(public_from(&priv_a())), YA);
        assert_eq!(hex::encode(public_from(&priv_b())), YB);
        let ka = session_key(&priv_a(), &hex::decode(YB).unwrap()).unwrap();
        let kb = session_key(&priv_b(), &hex::decode(YA).unwrap()).unwrap();
        assert_eq!(hex::encode(ka.as_ref()), KEY);
        assert_eq!(ka.as_ref(), kb.as_ref());
        // Python's ciphertext of "correct horse battery staple" under IV 0..16.
        let iv: Vec<u8> = (0..16).collect();
        let plain = decrypt(&ka, &iv, &hex::decode(CT).unwrap()).unwrap();
        assert_eq!(&plain[..], b"correct horse battery staple");
    }

    #[test]
    fn a_peer_key_may_omit_leading_zeros() {
        let (priv_s, pub_s) = keypair().unwrap();
        let (priv_c, pub_c) = keypair().unwrap();
        let stripped: Vec<u8> = pub_c.iter().copied().skip_while(|b| *b == 0).collect();
        assert_eq!(
            session_key(&priv_s, &stripped).unwrap().as_ref(),
            session_key(&priv_c, &pub_s).unwrap().as_ref()
        );
    }

    #[test]
    fn trivial_and_out_of_range_peer_keys_are_refused() {
        let (k, _) = keypair().unwrap();
        let mut p_minus_1 = PRIME;
        p_minus_1[127] -= 1;
        for bad in [
            vec![],
            vec![0u8; 128],
            vec![1],
            PRIME.to_vec(),
            p_minus_1.to_vec(),
            vec![1u8; 129],
        ] {
            assert!(
                session_key(&k, &bad).is_err(),
                "{} bytes accepted",
                bad.len()
            );
        }
        let mut above = PRIME;
        above[127] = 0xff; // p + 0xff-ish, not below p
        assert!(session_key(&k, &above).is_err());
        assert!(session_key(&k, &[2]).is_ok());
    }

    #[test]
    fn secrets_round_trip_and_the_iv_is_fresh() {
        let key = [7u8; 16];
        let (iv1, ct1) = encrypt(&key, b"hunter2").unwrap();
        let (iv2, ct2) = encrypt(&key, b"hunter2").unwrap();
        assert_ne!(iv1, iv2);
        assert_ne!(ct1, ct2);
        assert_eq!(&decrypt(&key, &iv1, &ct1).unwrap()[..], b"hunter2");
        assert_eq!(ct1.len(), 16);
        let (iv, empty) = encrypt(&key, b"").unwrap();
        assert_eq!(empty.len(), 16);
        assert!(decrypt(&key, &iv, &empty).unwrap().is_empty());
        // Wrong key / short IV / damaged ciphertext are errors, not garbage.
        assert!(decrypt(&[8u8; 16], &iv1, &ct1).map_or(true, |p| &p[..] != b"hunter2"));
        assert!(decrypt(&key, &iv1[..8], &ct1).is_err());
        assert!(decrypt(&key, &iv1, &ct1[..15]).is_err());
    }
}
