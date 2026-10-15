// daemon_seal/tpm_blob.rs — the sealed master key's file format for the
// TPM2 PIN / counter sealer (T4.08; moved out of tpm.rs unchanged).
//
// Blob: "kepr-tpm2-v1\n" | flags (1: PIN, 2: PCRs) | counter u64 | index
// u32 | pcrs (u8 len, `7,11`) | public (u16 len) | private (u16 len).

use super::tpm::SEAL_FAILED;

pub(super) const MAGIC: &[u8] = b"kepr-tpm2-v1\n";
pub(super) const FLAG_PIN: u8 = 1;
pub(super) const FLAG_PCRS: u8 = 2;

pub(super) struct Blob {
    pub flags: u8,
    pub counter: u64,
    pub index: u32,
    pub pcrs: String,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

fn put16(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    let n = u16::try_from(b.len()).map_err(|_| SEAL_FAILED)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

impl Blob {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = MAGIC.to_vec();
        out.push(self.flags);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.push(self.pcrs.len() as u8);
        out.extend_from_slice(self.pcrs.as_bytes());
        put16(&mut out, &self.public)?;
        put16(&mut out, &self.private)?;
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, String> {
        let bad =
            || "the master key was not sealed with the TPM2 PIN / counter options".to_string();
        let mut r = blob.strip_prefix(MAGIC).ok_or_else(bad)?;
        let mut take = |n: usize| -> Result<Vec<u8>, String> {
            if r.len() < n {
                return Err(bad());
            }
            let (a, b) = r.split_at(n);
            r = b;
            Ok(a.to_vec())
        };
        let flags = take(1)?[0];
        let counter = u64::from_be_bytes(take(8)?.try_into().map_err(|_| bad())?);
        let index = u32::from_be_bytes(take(4)?.try_into().map_err(|_| bad())?);
        let n = take(1)?[0];
        let pcrs = String::from_utf8(take(n.into())?).map_err(|_| bad())?;
        let n = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad())?);
        let public = take(n.into())?;
        let n = u16::from_be_bytes(take(2)?.try_into().map_err(|_| bad())?);
        let private = take(n.into())?;
        let pcrs_ok = pcrs.bytes().all(|b| b.is_ascii_digit() || b == b',');
        if !r.is_empty() || !pcrs_ok || (flags & FLAG_PCRS != 0) == pcrs.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            flags,
            counter,
            index,
            pcrs,
            public,
            private,
        })
    }
}
