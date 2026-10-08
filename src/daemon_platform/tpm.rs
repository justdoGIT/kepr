// daemon_platform/tpm.rs — TPM2 quote checks for SVID issuance (T10.11).
//
// The CLI runs `tpm2_quote -c AK -l sha256:7 -q NONCE -g sha256` and sends
// the two files it writes: the TPMS_ATTEST message and the TPMT_SIGNATURE,
// both TSS-marshalled (big-endian). A quote passes when
//   * it is a TPM-generated quote (magic, type),
//   * its extraData is a nonce this daemon handed this uid in the last two
//     minutes (each nonce works once),
//   * it selects exactly PCR 7 of the SHA-256 bank and its PCR digest is
//     SHA-256 of the enrolled PCR 7 value,
//   * the ECDSA P-256 / SHA-256 signature verifies with the enrolled
//     attestation key.
// Parsing is bounds-checked on untrusted input; any failure is one of a few
// plain messages.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use kepr_core::pki::{TpmPolicy, TpmQuote};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const TPM_GENERATED: u32 = 0xff54_4347;
const ST_ATTEST_QUOTE: u16 = 0x8018;
const ALG_SHA256: u16 = 0x000b;
const ALG_ECDSA: u16 = 0x0018;
const NONCE_TTL: Duration = Duration::from_secs(120);
const MAX_NONCES: usize = 64;

static NONCES: Mutex<Vec<(u32, [u8; 32], Instant)>> = Mutex::new(Vec::new());

/// A fresh nonce for `uid` (hex).
pub fn new_nonce(uid: u32) -> Result<String, String> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| format!("CSPRNG failure: {e}"))?;
    let mut all = NONCES.lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|(_, _, t)| t.elapsed() < NONCE_TTL);
    if all.len() >= MAX_NONCES {
        all.remove(0);
    }
    all.push((uid, n, Instant::now()));
    Ok(hex::encode(n))
}

/// Remove `nonce` for `uid`; true when it was live.
fn take_nonce(uid: u32, nonce: &[u8]) -> bool {
    let mut all = NONCES.lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|(_, _, t)| t.elapsed() < NONCE_TTL);
    match all
        .iter()
        .position(|(u, n, _)| *u == uid && n[..] == *nonce)
    {
        Some(i) => {
            all.remove(i);
            true
        }
        None => false,
    }
}

/// A bounds-checked big-endian reader.
struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("TPM quote: truncated".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// What a quote attests: (extraData, PCR selection as (hash, bitmap), PCR digest).
pub struct Attest<'a> {
    pub nonce: &'a [u8],
    pub selection: Vec<(u16, &'a [u8])>,
    pub pcr_digest: &'a [u8],
}

pub fn parse_attest(b: &[u8]) -> Result<Attest<'_>, String> {
    let mut r = Rd(b);
    if r.u32()? != TPM_GENERATED || r.u16()? != ST_ATTEST_QUOTE {
        return Err("TPM quote: not a TPM-generated quote".into());
    }
    r.tpm2b()?; // qualifiedSigner
    let nonce = r.tpm2b()?;
    r.take(17 + 8)?; // clockInfo, firmwareVersion
    let count = r.u32()?;
    if count > 16 {
        return Err("TPM quote: bad PCR selection".into());
    }
    let mut selection = Vec::new();
    for _ in 0..count {
        let hash = r.u16()?;
        let n = r.u8()? as usize;
        selection.push((hash, r.take(n)?));
    }
    let pcr_digest = r.tpm2b()?;
    if !r.0.is_empty() {
        return Err("TPM quote: trailing data".into());
    }
    Ok(Attest {
        nonce,
        selection,
        pcr_digest,
    })
}

/// A TPMT_SIGNATURE with ECDSA over SHA-256.
pub fn parse_signature(b: &[u8]) -> Result<Signature, String> {
    let mut r = Rd(b);
    if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
        return Err("TPM quote: the signature must be ECDSA with SHA-256".into());
    }
    let mut scalar = || -> Result<[u8; 32], String> {
        let v = r.tpm2b()?;
        let v = &v[v.iter().take_while(|b| **b == 0).count()..];
        if v.len() > 32 {
            return Err("TPM quote: bad signature".into());
        }
        let mut out = [0u8; 32];
        out[32 - v.len()..].copy_from_slice(v);
        Ok(out)
    };
    let (rr, ss) = (scalar()?, scalar()?);
    if !r.0.is_empty() {
        return Err("TPM quote: trailing data".into());
    }
    Signature::from_scalars(rr, ss).map_err(|_| "TPM quote: bad signature".to_string())
}

/// Only PCR 7, SHA-256 bank.
fn selects_only_pcr7(sel: &[(u16, &[u8])]) -> bool {
    let mut pcr7 = false;
    for (hash, bits) in sel {
        for (i, b) in bits.iter().enumerate() {
            let want = if *hash == ALG_SHA256 && i == 0 {
                0x80
            } else {
                0
            };
            if *b != want {
                return false;
            }
            pcr7 |= want != 0;
        }
    }
    pcr7 && sel.len() == 1
}

/// A normalised policy: the AK on the curve, PCR 7 a SHA-256 value.
pub fn policy(ak_public: &str, pcr7: &str) -> Result<TpmPolicy, String> {
    let ak = hex::decode(ak_public.trim()).map_err(|_| "attestation key: not hex")?;
    VerifyingKey::from_sec1_bytes(&ak).map_err(|_| "attestation key: not a P-256 point")?;
    let pcr = hex::decode(pcr7.trim()).map_err(|_| "PCR 7: not hex")?;
    if pcr.len() != 32 {
        return Err("PCR 7: expected a SHA-256 value (32 bytes)".into());
    }
    Ok(TpmPolicy {
        ak_public: hex::encode(ak),
        pcr7: hex::encode(pcr),
    })
}

/// Check `q` against `p` and spend its nonce.
pub fn verify(uid: u32, p: &TpmPolicy, q: &TpmQuote) -> Result<(), String> {
    let hx = |s: &str| hex::decode(s.trim()).map_err(|_| "TPM quote: not hex".to_string());
    let (nonce, attest, sig) = (hx(&q.nonce)?, hx(&q.attest)?, hx(&q.signature)?);
    // Spent first: a quote that fails for any reason burns its nonce.
    if !take_nonce(uid, &nonce) {
        return Err("TPM quote: unknown or expired nonce; run the command again".into());
    }
    let a = parse_attest(&attest)?;
    if a.nonce != nonce.as_slice() {
        return Err("TPM quote: it was made over a different nonce".into());
    }
    if !selects_only_pcr7(&a.selection) {
        return Err("TPM quote: it must cover exactly PCR 7 (sha256:7)".into());
    }
    let ak = VerifyingKey::from_sec1_bytes(&hx(&p.ak_public)?)
        .map_err(|_| "the enrolled attestation key is damaged".to_string())?;
    ak.verify(&attest, &parse_signature(&sig)?)
        .map_err(|_| "TPM quote: the signature does not match the enrolled key".to_string())?;
    if a.pcr_digest != Sha256::digest(hx(&p.pcr7)?).as_slice() {
        return Err("TPM quote: PCR 7 differs from the enrolled value \
                    (Secure Boot state changed)"
            .into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    /// A TPMS_ATTEST as `tpm2_quote -l sha256:7` writes it (the clock,
    /// firmware and signer name are fixture values).
    pub fn attest_fixture(nonce: &[u8], pcr7: &[u8], bitmap: [u8; 3]) -> Vec<u8> {
        let mut b = hex::decode(
            "ff544347\
             8018\
             0022000b2a5ef1b1c4a2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c",
        )
        .unwrap();
        b.extend((nonce.len() as u16).to_be_bytes());
        b.extend(nonce);
        b.extend(hex::decode("000000001c9c3800000000020000000101").unwrap()); // clockInfo
        b.extend(hex::decode("2017041900120003").unwrap()); // firmwareVersion
        b.extend([0, 0, 0, 1, 0x00, 0x0b, 3]); // one selection, sha256, 3 bytes
        b.extend(bitmap);
        b.extend([0, 32]);
        b.extend(Sha256::digest(pcr7));
        b
    }

    /// TPMT_SIGNATURE (ECDSA, SHA-256) of `msg`; `high_s` flips s to n - s.
    pub fn sign_tss(ak: &SigningKey, msg: &[u8], high_s: bool) -> Vec<u8> {
        let sig: Signature = ak.sign(msg);
        let sig = if high_s {
            let (r, s) = sig.split_scalars();
            Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap()
        } else {
            sig
        };
        let (r, s) = (sig.r().to_bytes(), sig.s().to_bytes());
        let mut b = vec![0x00, 0x18, 0x00, 0x0b, 0, 32];
        b.extend(r.as_slice());
        b.extend([0, 32]);
        b.extend(s.as_slice());
        b
    }

    pub fn ak() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    pub fn ak_hex() -> String {
        hex::encode(super::super::pki_sign::public_point(&ak()))
    }

    /// A good quote over a fresh nonce for `uid`.
    pub fn quote(uid: u32, pcr7: &[u8]) -> TpmQuote {
        let nonce = new_nonce(uid).unwrap();
        let attest = attest_fixture(&hex::decode(&nonce).unwrap(), pcr7, [0x80, 0, 0]);
        TpmQuote {
            signature: hex::encode(sign_tss(&ak(), &attest, false)),
            attest: hex::encode(attest),
            nonce,
        }
    }

    #[test]
    fn a_good_quote_passes_once() {
        let pcr7 = [0x11u8; 32];
        let p = policy(&ak_hex(), &hex::encode(pcr7)).unwrap();
        let q = quote(9_001, &pcr7);
        assert_eq!(verify(9_001, &p, &q), Ok(()));
        let again = verify(9_001, &p, &q).unwrap_err();
        assert!(again.contains("nonce"), "{again}");
        // Another uid cannot spend this uid's nonce.
        let q = quote(9_001, &pcr7);
        assert!(verify(9_002, &p, &q).unwrap_err().contains("nonce"));
    }

    #[test]
    fn high_s_signatures_verify() {
        let pcr7 = [0x22u8; 32];
        let p = policy(&ak_hex(), &hex::encode(pcr7)).unwrap();
        let mut q = quote(9_003, &pcr7);
        let attest = hex::decode(&q.attest).unwrap();
        q.signature = hex::encode(sign_tss(&ak(), &attest, true));
        assert_eq!(verify(9_003, &p, &q), Ok(()));
    }

    #[test]
    fn bad_quotes_are_refused() {
        let uid = 9_004;
        let pcr7 = [0x33u8; 32];
        let p = policy(&ak_hex(), &hex::encode(pcr7)).unwrap();
        let fail = |q: TpmQuote, want: &str| {
            let e = verify(uid, &p, &q).unwrap_err();
            assert!(e.contains(want), "{e} (wanted {want})");
        };
        // PCR 7 changed (another Secure Boot state).
        fail(quote(uid, &[0x34u8; 32]), "PCR 7 differs");
        // Signed by another key.
        let mut q = quote(uid, &pcr7);
        let other = SigningKey::from_slice(&[8u8; 32]).unwrap();
        q.signature = hex::encode(sign_tss(&other, &hex::decode(&q.attest).unwrap(), false));
        fail(q, "does not match");
        // Message altered after signing.
        let mut q = quote(uid, &pcr7);
        q.attest = q.attest.replace("2017041900120003", "2017041900120004");
        fail(q, "does not match");
        // Quote over another nonce than the one presented.
        let mut q = quote(uid, &pcr7);
        let other_nonce = new_nonce(uid).unwrap();
        let attest = attest_fixture(&hex::decode(&other_nonce).unwrap(), &pcr7, [0x80, 0, 0]);
        q.signature = hex::encode(sign_tss(&ak(), &attest, false));
        q.attest = hex::encode(attest);
        fail(q, "different nonce");
        // PCRs 0 and 7 selected: refused even when signed.
        let nonce = new_nonce(uid).unwrap();
        let attest = attest_fixture(&hex::decode(&nonce).unwrap(), &pcr7, [0x81, 0, 0]);
        let q = TpmQuote {
            signature: hex::encode(sign_tss(&ak(), &attest, false)),
            attest: hex::encode(attest),
            nonce,
        };
        fail(q, "exactly PCR 7");
        // A nonce the daemon never issued.
        let mut q = quote(uid, &pcr7);
        q.nonce = hex::encode([0u8; 32]);
        fail(q, "unknown or expired");
    }

    #[test]
    fn parsers_refuse_malformed_input() {
        let a = attest_fixture(&[1, 2], &[0u8; 32], [0x80, 0, 0]);
        for n in 0..a.len() {
            assert!(parse_attest(&a[..n]).is_err(), "truncated at {n}");
        }
        let mut long = a.clone();
        long.push(0);
        assert!(parse_attest(&long).is_err());
        let mut wrong_type = a.clone();
        wrong_type[5] = 0x17; // TPM_ST_ATTEST_CERTIFY
        assert!(parse_attest(&wrong_type).is_err());
        let s = sign_tss(&ak(), b"m", false);
        assert!(parse_signature(&s).is_ok());
        let mut rsa = s.clone();
        rsa[1] = 0x14; // TPM_ALG_RSASSA
        assert!(parse_signature(&rsa).is_err());
        assert!(parse_signature(&s[..s.len() - 1]).is_err());
        assert!(policy("04", &"00".repeat(32)).is_err());
        assert!(policy(&ak_hex(), "00").is_err());
    }
}
