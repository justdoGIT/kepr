// daemon_vault/records.rs — record keys and crypto-shred delete (T4.05).
//
// Every write of a record draws a fresh random AES-256 key RK, seals the
// payload (meta + value) under RK into newly placed pages, wraps RK
// under the vault master key (AAD = "kepr-vi1 rk" ‖ record id ‖ name,
// so an index entry moved to another name no longer unwraps), and
// commits a new index sealed under the index key. A delete drops the
// entry, so RK is gone from the current image, and the commit scrubs
// the record's pages with noise and bumps the epoch: the current image
// holds neither the key nor the ciphertext. (An older copy of the image
// plus the master key can still open older values; see the plan's
// crypto-shred table.)

use std::collections::HashSet;

use zeroize::Zeroizing;

use super::header::{Header, MAX_INDEX_SLOTS};
use super::image::{SlotIo, VaultImage, SLOT};
use super::index::{decode_payload, encode_payload, Entry, Index, Record, WRAPPED};
use super::journal::Commit;
use super::keys::{gcm_open, gcm_seal, noise, Keys};
use super::merkle::{leaf, merkle_root, Hash};
use super::place::{Allocator, DECOYS};
use super::slot::{open_slot, seal_slot, PAYLOAD};

type Pages = Vec<(u32, Box<[u8; SLOT]>)>;

fn wrap_aad(record_id: &[u8; 16], name: &str) -> Vec<u8> {
    [&b"kepr-vi1 rk"[..], record_id, name.as_bytes()].concat()
}

/// The record key of `name`'s entry; fails if the entry isn't `name`'s.
pub fn unwrap_key(keys: &Keys, name: &str, e: &Entry) -> Result<Zeroizing<[u8; 32]>, String> {
    let rk = gcm_open(&keys.vmk, &wrap_aad(&e.record_id, name), &e.wrapped_key)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(rk.get(..32).ok_or("decryption failed: authentication")?);
    Ok(out)
}

fn now() -> u64 {
    crate::expiry::now_unix()
}

impl<I: SlotIo> VaultImage<I> {
    /// Decrypt the current index (empty on a fresh image).
    pub fn load_index(&self, keys: &Keys) -> Result<Index, String> {
        let h = &self.header;
        let mut blob = Zeroizing::new(Vec::with_capacity(h.index_len as usize));
        for &s in &h.index_slots {
            let page = self.read_slot(s)?;
            let part = open_slot(&keys.index, &h.image_id, s, h.epoch, &page)
                .map_err(|_| format!("vault index slot {s} does not authenticate"))?;
            blob.extend_from_slice(&part);
        }
        if h.index_slots.is_empty() {
            return Ok(Index::default());
        }
        blob.truncate(h.index_len as usize);
        Index::decode(&blob)
    }

    /// Open `name`'s record, checking every page against the index.
    pub fn read_record(
        &self,
        keys: &Keys,
        ix: &Index,
        name: &str,
    ) -> Result<Option<Record>, String> {
        let Some(e) = ix.entries.get(name) else {
            return Ok(None);
        };
        let rk = unwrap_key(keys, name, e)?;
        let mut payload = Zeroizing::new(Vec::new());
        for (s, want) in &e.pages {
            let page = self.read_slot(*s)?;
            if leaf(*s, &page) != *want {
                return Err(format!("decryption failed: vault slot {s} is damaged"));
            }
            payload.extend_from_slice(&open_slot(&rk, &self.header.image_id, *s, e.epoch, &page)?);
        }
        decode_payload(&payload).map(Some)
    }

    /// Every slot the current state uses.
    pub fn allocator(&self, ix: &Index) -> Allocator {
        let used = ix
            .record_slots()
            .chain(self.header.index_slots.iter().copied());
        Allocator::new(self.header.slot_count, used)
    }

    /// Write (or replace) `name` under a fresh record key.
    pub fn put_record(
        &mut self,
        keys: &Keys,
        name: &str,
        value: Option<&[u8]>,
        meta: Option<&[u8]>,
    ) -> Result<(), String> {
        let old = self.load_index(keys)?;
        let mut alloc = self.allocator(&old);
        let epoch = self.header.epoch + 1;
        let record_id = match old.entries.get(name) {
            Some(e) => e.record_id,
            None => {
                let mut id = [0u8; 16];
                noise(&mut id)?;
                id
            }
        };
        let mut rk = Zeroizing::new([0u8; 32]);
        noise(rk.as_mut())?;
        let payload = encode_payload(value, meta);
        let (mut writes, mut pages) = (Vec::new(), Vec::new());
        for (p, chunk) in payload.chunks(PAYLOAD).enumerate() {
            let s = alloc.place(&keys.place, &record_id, p as u32)?;
            let page = seal_slot(&rk, &self.header.image_id, s, epoch, chunk)?;
            pages.push((s, leaf(s, &page)));
            writes.push((s, page));
        }
        let wrapped = gcm_seal(&keys.vmk, &wrap_aad(&record_id, name), rk.as_ref())?;
        let entry = Entry {
            record_id,
            wrapped_key: wrapped.try_into().map_err(|_| "key wrap failed")?,
            epoch,
            updated: now(),
            value_len: value.map_or(0, |v| v.len() as u32),
            has_value: value.is_some(),
            pages,
        };
        let mut new = old.clone();
        new.entries.insert(name.to_string(), entry);
        self.commit_index(keys, &old, new, alloc, writes)
    }

    /// Crypto-shred `name`. False if there was no such record.
    pub fn remove_record(&mut self, keys: &Keys, name: &str) -> Result<bool, String> {
        let old = self.load_index(keys)?;
        if !old.entries.contains_key(name) {
            return Ok(false);
        }
        let alloc = self.allocator(&old);
        let mut new = old.clone();
        new.entries.remove(name);
        self.commit_index(keys, &old, new, alloc, Vec::new())?;
        Ok(true)
    }

    /// Seal `new` into fresh index pages and commit it with `writes`.
    pub(super) fn commit_index(
        &mut self,
        keys: &Keys,
        old: &Index,
        new: Index,
        mut alloc: Allocator,
        mut writes: Pages,
    ) -> Result<(), String> {
        let epoch = self.header.epoch + 1;
        let id = self.header.image_id;
        let blob = Zeroizing::new(new.encode());
        if blob.len().div_ceil(PAYLOAD) > MAX_INDEX_SLOTS {
            return Err("vault index is full".into());
        }
        let label = [&b"kepr-vi1 index"[..], &epoch.to_le_bytes()].concat();
        let mut index_slots = Vec::new();
        let mut leaves: Vec<(u32, Hash)> =
            new.entries.values().flat_map(|e| e.pages.clone()).collect();
        for (p, chunk) in blob.chunks(PAYLOAD).enumerate() {
            let s = alloc.place(&keys.place, &label, p as u32)?;
            let page = seal_slot(&keys.index, &id, s, epoch, chunk)?;
            leaves.push((s, leaf(s, &page)));
            index_slots.push(s);
            writes.push((s, page));
        }
        leaves.sort_unstable_by_key(|l| l.0);
        let in_use: HashSet<u32> = leaves.iter().map(|l| l.0).collect();
        let freed = old
            .record_slots()
            .chain(self.header.index_slots.iter().copied())
            .filter(|s| !in_use.contains(s))
            .collect();
        let header = Header {
            epoch,
            root: merkle_root(&leaves.iter().map(|l| l.1).collect::<Vec<_>>()),
            index_len: blob.len() as u32,
            index_slots,
            ..self.header.clone()
        };
        let decoys = alloc.decoys(DECOYS)?;
        self.commit(
            keys,
            Commit {
                header,
                writes,
                decoys,
                freed,
            },
        )
    }

    /// Check the index, every page's hash and the root. Returns
    /// (records, slots checked); an error names the damaged slots.
    pub fn verify_records(&self, keys: &Keys) -> Result<(usize, usize), String> {
        let ix = self.load_index(keys)?;
        let mut used: Vec<(u32, Option<Hash>)> = ix
            .entries
            .values()
            .flat_map(|e| e.pages.iter().map(|(s, h)| (*s, Some(*h))))
            .collect();
        used.extend(self.header.index_slots.iter().map(|s| (*s, None)));
        match self.verify(&used) {
            Ok(()) => Ok((ix.entries.len(), used.len())),
            Err(d) if d.slots.is_empty() => {
                Err("vault image check failed: the Merkle root does not match".into())
            }
            Err(d) => {
                let list: Vec<String> = d.slots.iter().map(|s| format!("slot {s}")).collect();
                Err(format!(
                    "vault image check failed: {} damaged",
                    list.join(", ")
                ))
            }
        }
    }
}

const _: () = assert!(WRAPPED == 12 + 32 + 16);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_vault::image::SLOT;
    use crate::daemon_vault::slot::open_slot;
    use crate::daemon_vault::testio::{Faulty, MemIo};

    const KEK: [u8; 32] = [7u8; 32];

    fn fresh() -> (VaultImage<MemIo>, Keys, MemIo) {
        let mem = MemIo::new(1 << 20);
        let img = VaultImage::format(mem.clone(), 256, &KEK).unwrap();
        let keys = img.keys(&KEK);
        (img, keys, mem)
    }

    fn value<I: SlotIo>(img: &VaultImage<I>, keys: &Keys, name: &str) -> Option<Vec<u8>> {
        let ix = img.load_index(keys).unwrap();
        img.read_record(keys, &ix, name)
            .unwrap()
            .and_then(|r| r.value.map(|v| v.to_vec()))
    }

    #[test]
    fn put_get_update_remove() {
        let (mut img, keys, mem) = fresh();
        assert!(img.load_index(&keys).unwrap().entries.is_empty());
        img.put_record(&keys, "A", Some(b"one"), Some(b"{\"m\":1}"))
            .unwrap();
        img.put_record(&keys, "B", Some(&[9u8; 10_000]), None)
            .unwrap();
        img.put_record(&keys, "A", Some(b"two"), Some(b"{\"m\":2}"))
            .unwrap();
        let again = VaultImage::load(mem.clone(), &KEK).unwrap();
        let ix = again.load_index(&keys).unwrap();
        assert_eq!(ix.entries.len(), 2);
        assert_eq!(ix.entries["B"].pages.len(), 3, "10 kB spans 3 pages");
        let a = again.read_record(&keys, &ix, "A").unwrap().unwrap();
        assert_eq!(a.value.unwrap().as_slice(), b"two");
        assert_eq!(a.meta.unwrap(), b"{\"m\":2}");
        assert_eq!(value(&again, &keys, "B").unwrap(), vec![9u8; 10_000]);
        assert!(again.read_record(&keys, &ix, "C").unwrap().is_none());
        assert!(img.remove_record(&keys, "A").unwrap());
        assert!(!img.remove_record(&keys, "A").unwrap());
        assert!(value(&img, &keys, "A").is_none());
        assert_eq!(img.header.epoch, 4);
    }

    #[test]
    fn delete_destroys_the_key_and_the_pages() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "KEEP", Some(b"other"), None).unwrap();
        img.put_record(&keys, "GONE", Some(b"secret"), None)
            .unwrap();
        let ix = img.load_index(&keys).unwrap();
        let gone = ix.entries["GONE"].clone();
        let captured: Vec<(u32, Box<[u8; SLOT]>)> = gone
            .pages
            .iter()
            .map(|(s, _)| (*s, img.read_slot(*s).unwrap()))
            .collect();
        let epoch = img.header.epoch;
        img.remove_record(&keys, "GONE").unwrap();
        assert_eq!(img.header.epoch, epoch + 1, "delete bumps the epoch");
        // The pages are noise now.
        for (s, bytes) in &captured {
            assert_ne!(img.read_slot(*s).unwrap()[..], bytes[..]);
        }
        // Even holding the VMK, no key left in the image opens the copy.
        let ix = img.load_index(&keys).unwrap();
        assert!(ix.entries.values().all(|e| e.record_id != gone.record_id));
        assert!(!ix.entries.is_empty());
        for (name, e) in &ix.entries {
            let rk = unwrap_key(&keys, name, e).unwrap();
            for (s, bytes) in &captured {
                assert!(open_slot(&rk, &img.header.image_id, *s, gone.epoch, bytes).is_err());
            }
        }
    }

    #[test]
    fn renaming_an_index_entry_fails_authentication() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "A", Some(b"secret"), None).unwrap();
        let old = img.load_index(&keys).unwrap();
        let mut ix = old.clone();
        let e = ix.entries.remove("A").unwrap();
        ix.entries.insert("B".into(), e);
        let alloc = img.allocator(&old);
        img.commit_index(&keys, &old, ix, alloc, Vec::new())
            .unwrap();
        let ix = img.load_index(&keys).unwrap();
        let err = img.read_record(&keys, &ix, "B").err().unwrap();
        assert!(err.contains("authentication"), "{err}");
    }

    #[test]
    fn a_flipped_page_is_named_by_verify_and_refused_on_read() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "A", Some(b"secret"), None).unwrap();
        let s = img.load_index(&keys).unwrap().entries["A"].pages[0].0;
        let mut page = img.read_slot(s).unwrap();
        page[77] ^= 1;
        img.write_slot(s, &page).unwrap();
        let err = img.verify_records(&keys).err().unwrap();
        assert!(err.contains(&format!("slot {s}")), "{err}");
        let ix = img.load_index(&keys).unwrap();
        assert!(img.read_record(&keys, &ix, "A").is_err());
    }

    #[test]
    fn a_full_image_refuses_a_write_and_stays_intact() {
        let (mut img, keys, mem) = fresh();
        let big = vec![1u8; 60_000];
        let mut n = 0;
        let err = loop {
            match img.put_record(&keys, &format!("R{n}"), Some(&big), None) {
                Ok(()) => n += 1,
                Err(e) => break e,
            }
        };
        assert!(err.contains("full"), "{err}");
        let again = VaultImage::load(mem, &KEK).unwrap();
        assert!(again.verify_records(&keys).is_ok());
        assert_eq!(again.load_index(&keys).unwrap().entries.len(), n);
    }

    #[test]
    fn a_crash_mid_put_or_remove_leaves_old_or_new_records() {
        let (mut img, keys, mem) = fresh();
        img.put_record(&keys, "X", Some(b"old"), None).unwrap();
        img.put_record(&keys, "Y", Some(b"y"), None).unwrap();
        let base = mem.bytes();
        type Op = fn(&mut VaultImage<Faulty>, &Keys);
        let ops: [(Op, Option<&[u8]>); 2] = [
            (
                |i, k| {
                    i.put_record(k, "X", Some(b"new"), None)
                        .map(drop)
                        .unwrap_or(())
                },
                Some(b"new"),
            ),
            (|i, k| i.remove_record(k, "X").map(drop).unwrap_or(()), None),
        ];
        for (op, new_x) in ops {
            for n in (0..48_000).step_by(307) {
                let disk = MemIo::from_bytes(base.clone());
                let mut img = VaultImage::load(Faulty::new(disk.clone(), n), &KEK).unwrap();
                op(&mut img, &keys);
                let after = VaultImage::load(disk, &KEK).unwrap();
                assert!(after.verify_records(&keys).is_ok(), "budget {n}");
                let x = value(&after, &keys, "X");
                assert!(
                    x.as_deref() == Some(&b"old"[..]) || x.as_deref() == new_x,
                    "budget {n}: {x:?}"
                );
                assert_eq!(value(&after, &keys, "Y").unwrap(), b"y", "budget {n}");
            }
        }
    }
}
