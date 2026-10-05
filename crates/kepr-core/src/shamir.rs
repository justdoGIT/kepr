//! Shamir secret sharing over GF(2^8) for the recovery kit (agent vault
//! P6.3). Each byte of the secret is the constant term of its own random
//! polynomial of degree k-1; share `x` holds the polynomials' values at
//! `x`. Any k shares rebuild the secret by Lagrange interpolation at 0;
//! fewer reveal nothing about it.
//!
//! Field: AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b), generator 3.
//! Share text: `kepr1-<k>-<x>-<fingerprint16hex>-<value hex>`.

use zeroize::Zeroizing;

const fn tables() -> ([u8; 256], [u8; 255]) {
    let mut log = [0u8; 256];
    let mut exp = [0u8; 255];
    let mut v: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = v as u8;
        log[v as usize] = i as u8;
        // multiply by the generator 3 = x + 1
        v ^= v << 1;
        if v & 0x100 != 0 {
            v ^= 0x11b;
        }
        i += 1;
    }
    (log, exp)
}

const TABLES: ([u8; 256], [u8; 255]) = tables();

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (log, exp) = &TABLES;
    exp[(log[a as usize] as usize + log[b as usize] as usize) % 255]
}

fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let (log, exp) = &TABLES;
    exp[(log[a as usize] as usize + 255 - log[b as usize] as usize) % 255]
}

/// One share: its x coordinate (1..=255) and one y byte per secret byte.
#[derive(Clone)]
pub struct Share {
    pub threshold: u8,
    pub x: u8,
    pub y: Zeroizing<Vec<u8>>,
}

/// Split `secret` into `n` shares, any `k` of which rebuild it.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, String> {
    if !(2..=n).contains(&k) || n > 16 {
        return Err("need 2 <= threshold <= shares <= 16".into());
    }
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            threshold: k,
            x,
            y: Zeroizing::new(Vec::with_capacity(secret.len())),
        })
        .collect();
    let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
    for &byte in secret {
        coeffs[0] = byte;
        getrandom::fill(&mut coeffs[1..]).map_err(|e| format!("CSPRNG failure: {e}"))?;
        for s in &mut shares {
            // Horner: c0 + x(c1 + x(c2 + ...))
            let mut acc = 0u8;
            for &c in coeffs.iter().rev() {
                acc = mul(acc, s.x) ^ c;
            }
            s.y.push(acc);
        }
    }
    Ok(shares)
}

/// Rebuild the secret from at least `threshold` distinct shares.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, String> {
    let k = shares.first().ok_or("no shares given")?.threshold as usize;
    let len = shares[0].y.len();
    if shares.len() < k {
        return Err(format!("need {k} shares, got {}", shares.len()));
    }
    let used = &shares[..k];
    for (i, s) in used.iter().enumerate() {
        if s.y.len() != len || s.threshold as usize != k || s.x == 0 {
            return Err("shares come from different kits".into());
        }
        if used[..i].iter().any(|o| o.x == s.x) {
            return Err("the same share was given twice".into());
        }
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    for (i, si) in used.iter().enumerate() {
        // Lagrange basis at 0: prod_j x_j / (x_j - x_i); minus is xor.
        let mut basis = 1u8;
        for (j, sj) in used.iter().enumerate() {
            if i != j {
                basis = mul(basis, div(sj.x, sj.x ^ si.x));
            }
        }
        for (b, &y) in out.iter_mut().zip(si.y.iter()) {
            *b ^= mul(y, basis);
        }
    }
    Ok(out)
}

/// `kepr1-<k>-<x>-<fingerprint>-<hex>`.
pub fn encode(s: &Share, fingerprint: &str) -> Zeroizing<String> {
    let hex: String = s.y.iter().map(|b| format!("{b:02x}")).collect();
    Zeroizing::new(format!("kepr1-{}-{}-{fingerprint}-{hex}", s.threshold, s.x))
}

/// Parse a share and return it with its fingerprint.
pub fn decode(text: &str) -> Result<(Share, String), String> {
    let bad = || "not a kepr recovery share".to_string();
    let mut parts = text.trim().split('-');
    if parts.next() != Some("kepr1") {
        return Err(bad());
    }
    let mut num = || {
        parts
            .next()
            .and_then(|p| p.parse::<u8>().ok())
            .ok_or_else(bad)
    };
    let (threshold, x) = (num()?, num()?);
    let fp = parts
        .next()
        .filter(|f| f.len() == 16)
        .ok_or_else(bad)?
        .to_string();
    let hex = parts.next().ok_or_else(bad)?;
    // ASCII hex only: slicing below is by byte, and a multi-byte
    // character would split mid-char (a panic, and an abort in release).
    if parts.next().is_some()
        || hex.len() % 2 != 0
        || x == 0
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
        || !fp.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(bad());
    }
    let y = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| bad()))
        .collect::<Result<Vec<u8>, String>>()?;
    Ok((
        Share {
            threshold,
            x,
            y: Zeroizing::new(y),
        },
        fp,
    ))
}

#[cfg(test)]
mod tests {

    #[test]
    fn non_ascii_share_text_is_an_error_not_a_panic() {
        assert!(decode("kepr1-2-1-0123456789abcdef-a\u{e9}a").is_err());
        assert!(decode("kepr1-2-1-0123456789abcd\u{e9}-aa").is_err());
    }
    use super::*;

    #[test]
    fn field_inverse_and_generator_cover_the_field() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, div(1, a)), 1);
        }
        let (_, exp) = &TABLES;
        let mut seen = exp.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 255);
    }

    #[test]
    fn any_k_of_n_rebuilds_and_fewer_do_not() {
        let secret: Vec<u8> = (0..32).map(|i| i * 7 + 3).collect();
        let shares = split(&secret, 3, 5).unwrap();
        for a in 0..5 {
            for b in 0..5 {
                for c in 0..5 {
                    if a != b && b != c && a != c {
                        let pick = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                        assert_eq!(*combine(&pick).unwrap(), secret);
                    }
                }
            }
        }
        assert!(combine(&shares[..2]).is_err());
        // Two shares plus a forged third give garbage, not the secret.
        let mut forged = shares[2].clone();
        forged.y[0] ^= 1;
        let got = combine(&[shares[0].clone(), shares[1].clone(), forged]).unwrap();
        assert_ne!(*got, secret);
    }

    #[test]
    fn rejects_bad_parameters_and_duplicates() {
        assert!(split(b"x", 1, 3).is_err());
        assert!(split(b"x", 4, 3).is_err());
        assert!(split(b"x", 2, 17).is_err());
        let s = split(b"abc", 2, 3).unwrap();
        assert!(combine(&[s[0].clone(), s[0].clone()]).is_err());
    }

    #[test]
    fn text_round_trip() {
        let s = split(&[9u8; 32], 2, 3).unwrap();
        let t = encode(&s[1], "0123456789abcdef");
        assert!(t.starts_with("kepr1-2-2-0123456789abcdef-"));
        let (back, fp) = decode(&t).unwrap();
        assert_eq!(
            (back.x, back.threshold, fp.as_str()),
            (2, 2, "0123456789abcdef")
        );
        assert_eq!(*back.y, *s[1].y);
        for bad in [
            "",
            "kepr1-2-0-0123456789abcdef-00",
            "kepr2-2-1-0123456789abcdef-00",
            "kepr1-2-1-short-00",
            "kepr1-2-1-0123456789abcdef-0g",
        ] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }
}
