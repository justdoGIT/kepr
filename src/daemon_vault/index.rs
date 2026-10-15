// daemon_vault/index.rs — the index and record payload encodings (T4.05).
//
// The index maps a record name to everything needed to find and open
// it: a random record id (placement), its own AES-256 key wrapped under
// the vault master key with AAD = id ‖ name, the epoch its pages were
// sealed in, and each page's slot and hash (the Merkle leaves). The
// whole index is sealed under the index key into index pages each
// commit (records.rs). A record's payload is its `.meta` JSON and its
// value, sealed page by page under the record's own key.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::header::Reader;
use super::merkle::Hash;

/// nonce (12) ‖ wrapped 32-byte key ‖ tag (16).
pub const WRAPPED: usize = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub record_id: [u8; 16],
    pub wrapped_key: [u8; WRAPPED],
    /// Epoch the record's pages were sealed in (their AAD).
    pub epoch: u64,
    /// Unix seconds of the last write.
    pub updated: u64,
    pub value_len: u32,
    pub has_value: bool,
    /// (slot, Merkle leaf) per page, in payload order.
    pub pages: Vec<(u32, Hash)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Index {
    pub entries: BTreeMap<String, Entry>,
}

impl Index {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (name, e) in &self.entries {
            b.extend_from_slice(&(name.len() as u16).to_le_bytes());
            b.extend_from_slice(name.as_bytes());
            b.extend_from_slice(&e.record_id);
            b.extend_from_slice(&e.wrapped_key);
            b.extend_from_slice(&e.epoch.to_le_bytes());
            b.extend_from_slice(&e.updated.to_le_bytes());
            b.extend_from_slice(&e.value_len.to_le_bytes());
            b.push(u8::from(e.has_value));
            b.extend_from_slice(&(e.pages.len() as u16).to_le_bytes());
            for (s, h) in &e.pages {
                b.extend_from_slice(&s.to_le_bytes());
                b.extend_from_slice(h);
            }
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader(b);
        let n = u32::from_le_bytes(r.take()?);
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let len = u16::from_le_bytes(r.take()?) as usize;
            let name = std::str::from_utf8(r.bytes(len)?)
                .map_err(|_| "vault index is malformed")?
                .to_string();
            let record_id = r.take()?;
            let wrapped_key = r.take()?;
            let epoch = u64::from_le_bytes(r.take()?);
            let updated = u64::from_le_bytes(r.take()?);
            let value_len = u32::from_le_bytes(r.take()?);
            let has_value = r.take::<1>()?[0] != 0;
            let np = u16::from_le_bytes(r.take()?);
            let pages = (0..np)
                .map(|_| Ok((u32::from_le_bytes(r.take()?), r.take()?)))
                .collect::<Result<Vec<_>, String>>()?;
            let e = Entry {
                record_id,
                wrapped_key,
                epoch,
                updated,
                value_len,
                has_value,
                pages,
            };
            entries.insert(name, e);
        }
        Ok(Self { entries })
    }

    /// Every slot the records use.
    pub fn record_slots(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries
            .values()
            .flat_map(|e| e.pages.iter().map(|p| p.0))
    }
}

/// A record as stored: its `.meta` JSON and its value, either optional.
pub struct Record {
    pub meta: Option<Vec<u8>>,
    pub value: Option<Zeroizing<Vec<u8>>>,
}

const HAS_VALUE: u8 = 1;
const HAS_META: u8 = 2;

/// flags u8 ‖ meta length u32 ‖ meta ‖ value
pub fn encode_payload(value: Option<&[u8]>, meta: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let (v, m) = (value.unwrap_or_default(), meta.unwrap_or_default());
    let mut b = Zeroizing::new(Vec::with_capacity(5 + m.len() + v.len()));
    let flags =
        if value.is_some() { HAS_VALUE } else { 0 } | if meta.is_some() { HAS_META } else { 0 };
    b.push(flags);
    b.extend_from_slice(&(m.len() as u32).to_le_bytes());
    b.extend_from_slice(m);
    b.extend_from_slice(v);
    b
}

pub fn decode_payload(b: &[u8]) -> Result<Record, String> {
    let mut r = Reader(b);
    let flags = r.take::<1>()?[0];
    let mlen = u32::from_le_bytes(r.take()?) as usize;
    let meta = r.bytes(mlen)?.to_vec();
    Ok(Record {
        meta: (flags & HAS_META != 0).then_some(meta),
        value: (flags & HAS_VALUE != 0).then(|| Zeroizing::new(r.0.to_vec())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(slot: u32) -> Entry {
        Entry {
            record_id: [1; 16],
            wrapped_key: [2; WRAPPED],
            epoch: 9,
            updated: 1_700_000_000,
            value_len: 5,
            has_value: true,
            pages: vec![(slot, [3; 32]), (slot + 1, [4; 32])],
        }
    }

    #[test]
    fn index_round_trips_and_rejects_truncation() {
        let mut ix = Index::default();
        ix.entries.insert("kepr-1000-a".into(), entry(10));
        ix.entries.insert("kepr-1000-b~1".into(), entry(20));
        let b = ix.encode();
        assert_eq!(Index::decode(&b).unwrap(), ix);
        assert!(Index::decode(&b[..b.len() - 1]).is_err());
        assert_eq!(ix.record_slots().count(), 4);
    }

    #[test]
    fn payload_keeps_value_and_meta_apart() {
        for (v, m) in [
            (Some(&b"v"[..]), Some(&b"{}"[..])),
            (None, Some(&b"{\"sealed\":true}"[..])),
            (Some(&b""[..]), None),
            (None, None),
        ] {
            let p = encode_payload(v, m);
            let r = decode_payload(&p).unwrap();
            assert_eq!(r.value.as_deref().map(|z| z.as_slice()), v);
            assert_eq!(r.meta.as_deref(), m);
        }
    }
}
