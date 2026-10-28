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
//
// A record and the index each take 1, 2, 4, 8, … pages (T12.28): the
// rest of the bucket is pages sealed over no data, placed, hashed and
// scrubbed like the others, so a diff of two images shows a size only to
// the power of two. Readers need nothing new: an empty page adds nothing
// to the payload or the index blob, and records written before padding
// read as they are.

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

/// Pages for `pages` of data: the next power of two, at most `cap`.
fn bucket(pages: usize, cap: usize) -> usize {
    pages.max(1).next_power_of_two().min(cap)
}

impl<I: SlotIo> VaultImage<I> {
    /// Decrypt the current index (empty on a fresh image).
    pub fn load_index(&self, keys: &Keys) -> Result<Index, String> {
        let h = &self.header;
        let mut blob = Zeroizing::new(Vec::with_capacity(h.index_len as usize));
        for &s in &h.index_slots {
            let page = self.read_slot(s)?;
            let part = open_slot(&keys.index, &h.image_id, s, h.epoch, &page)
                .map_err(|_| format!("decryption failed: vault index slot {s} is damaged"))?;
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
        self.put_record_at(keys, name, (value, meta), None)
    }

    /// [`put_record`](Self::put_record) keeping a given write time (a
    /// record copied into another image keeps its age; T13.11).
    pub fn put_record_at(
        &mut self,
        keys: &Keys,
        name: &str,
        (value, meta): (Option<&[u8]>, Option<&[u8]>),
        updated: Option<u64>,
    ) -> Result<(), String> {
        let old = self.load_index(keys)?;
        let mut alloc = self.allocator(&old);
        let (mut entry, writes) = self.seal_record(keys, &old, &mut alloc, name, (value, meta))?;
        if let Some(t) = updated {
            entry.updated = t;
        }
        let mut new = old.clone();
        new.entries.insert(name.to_string(), entry);
        self.commit_index(keys, &old, new, alloc, writes)
    }

    /// Move `from`'s record (value and meta) to `to`, replacing `to`, in
    /// one commit: re-sealed under a fresh record key and new pages, the
    /// old key and pages gone. False if there is no `from`.
    pub fn rename_record(&mut self, keys: &Keys, from: &str, to: &str) -> Result<bool, String> {
        let old = self.load_index(keys)?;
        let Some(rec) = self.read_record(keys, &old, from)? else {
            return Ok(false);
        };
        let mut alloc = self.allocator(&old);
        let value = rec.value.as_deref().map(Vec::as_slice);
        let (entry, writes) =
            self.seal_record(keys, &old, &mut alloc, to, (value, rec.meta.as_deref()))?;
        let mut new = old.clone();
        new.entries.remove(from);
        new.entries.insert(to.to_string(), entry);
        self.commit_index(keys, &old, new, alloc, writes)?;
        Ok(true)
    }

    /// Seal `name`'s payload under a fresh record key into newly placed
    /// pages for the next epoch: its index entry and the page writes.
    fn seal_record(
        &self,
        keys: &Keys,
        old: &Index,
        alloc: &mut Allocator,
        name: &str,
        (value, meta): (Option<&[u8]>, Option<&[u8]>),
    ) -> Result<(Entry, Pages), String> {
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
        let chunks: Vec<&[u8]> = payload.chunks(PAYLOAD).collect();
        let (mut writes, mut pages) = (Vec::new(), Vec::new());
        for p in 0..bucket(chunks.len(), usize::MAX) {
            let chunk = chunks.get(p).copied().unwrap_or_default();
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
        Ok((entry, writes))
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
        alloc: Allocator,
        writes: Pages,
    ) -> Result<(), String> {
        let c = self.prepare_index(keys, old, new, alloc, writes)?;
        self.commit(keys, c)
    }

    /// `commit_index` up to the commit itself: the index pages sealed and
    /// placed, the next header, the decoys and the freed slots.
    pub(super) fn prepare_index(
        &self,
        keys: &Keys,
        old: &Index,
        new: Index,
        mut alloc: Allocator,
        mut writes: Pages,
    ) -> Result<Commit, String> {
        let epoch = self.header.epoch + 1;
        let id = self.header.image_id;
        let blob = Zeroizing::new(new.encode());
        let chunks: Vec<&[u8]> = blob.chunks(PAYLOAD).collect();
        if chunks.len() > MAX_INDEX_SLOTS {
            return Err("vault index is full".into());
        }
        let label = [&b"kepr-vi1 index"[..], &epoch.to_le_bytes()].concat();
        let mut index_slots = Vec::new();
        let mut leaves: Vec<(u32, Hash)> =
            new.entries.values().flat_map(|e| e.pages.clone()).collect();
        for p in 0..bucket(chunks.len(), MAX_INDEX_SLOTS) {
            let chunk = chunks.get(p).copied().unwrap_or_default();
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
            // Each commit raises the anchor; the counter follows (T12.27).
            anchor: self.header.anchor.map(|(i, v)| (i, v + 1)),
            ..self.header.clone()
        };
        let decoys = alloc.decoys(DECOYS)?;
        Ok(Commit {
            header,
            writes,
            decoys,
            freed,
        })
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
        assert_eq!(
            ix.entries["B"].pages.len(),
            4,
            "10 kB: 3 pages, padded to 4"
        );
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
    fn bucket_rounds_up_to_a_power_of_two_under_the_cap() {
        let got: Vec<usize> = [0, 1, 2, 3, 4, 5, 9, 200, 253]
            .iter()
            .map(|n| bucket(*n, MAX_INDEX_SLOTS))
            .collect();
        assert_eq!(got, [1, 1, 2, 4, 4, 8, 16, 253, 253]);
        assert_eq!(bucket(1000, usize::MAX), 1024);
    }

    #[test]
    fn values_round_trip_at_page_edges() {
        let (mut img, keys, mem) = fresh();
        // The payload is 5 bytes of framing plus the value (no meta).
        for (len, pages) in [(1, 1), (PAYLOAD - 5, 1), (PAYLOAD, 2), (3 * PAYLOAD + 1, 4)] {
            let v: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            img.put_record(&keys, "EDGE", Some(&v), None).unwrap();
            let again = VaultImage::load(mem.clone(), &KEK).unwrap();
            let ix = again.load_index(&keys).unwrap();
            assert_eq!(ix.entries["EDGE"].pages.len(), pages, "len {len}");
            assert_eq!(value(&again, &keys, "EDGE").unwrap(), v, "len {len}");
            assert_eq!(ix.entries["EDGE"].value_len as usize, len);
        }
        assert!(img.verify_records(&keys).is_ok());
    }

    /// An index of `n` entries without pages: 4 + 108 n bytes.
    fn synthetic(n: u32) -> Index {
        let e = Entry {
            record_id: [1; 16],
            wrapped_key: [2; WRAPPED],
            epoch: 1,
            updated: 1,
            value_len: 0,
            has_value: false,
            pages: Vec::new(),
        };
        Index {
            entries: (0..n).map(|i| (format!("R{i:06}"), e.clone())).collect(),
        }
    }

    #[test]
    fn index_pages_are_a_power_of_two() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "A", Some(b"a"), None).unwrap();
        assert_eq!(img.header.index_slots.len(), 1);
        // 76 entries: 8212 bytes, 3 pages of index, padded to 4; 160: 5 → 8.
        for (n, want) in [(76, 4), (160, 8), (20, 1)] {
            let old = img.load_index(&keys).unwrap();
            let alloc = img.allocator(&old);
            img.commit_index(&keys, &old, synthetic(n), alloc, Vec::new())
                .unwrap();
            assert_eq!(img.header.index_slots.len(), want, "{n} entries");
            assert_eq!(img.load_index(&keys).unwrap(), synthetic(n));
            assert!(img.verify_records(&keys).is_ok());
        }
    }

    #[test]
    fn verify_covers_padding_pages() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "A", Some(&[3u8; 9000]), None)
            .unwrap();
        let pages = img.load_index(&keys).unwrap().entries["A"].pages.clone();
        assert_eq!(pages.len(), 4);
        let pad = pages[3].0;
        let mut page = img.read_slot(pad).unwrap();
        page[100] ^= 1;
        img.write_slot(pad, &page).unwrap();
        let err = img.verify_records(&keys).unwrap_err();
        assert!(err.contains(&format!("slot {pad}")), "{err}");
        let ix = img.load_index(&keys).unwrap();
        assert!(img.read_record(&keys, &ix, "A").is_err());
    }

    #[test]
    fn a_3_and_a_4_page_write_change_the_same_number_of_slots() {
        let (mut img, keys, mem) = fresh();
        img.put_record(&keys, "Y", Some(b"y"), None).unwrap();
        let base = mem.bytes();
        let changed = |len: usize| {
            let disk = MemIo::from_bytes(base.clone());
            let mut img = VaultImage::load(disk.clone(), &KEK).unwrap();
            img.put_record(&keys, "X", Some(&vec![1u8; len]), None)
                .unwrap();
            let after = disk.bytes();
            let n = (0..base.len() / SLOT)
                .filter(|s| base[s * SLOT..(s + 1) * SLOT] != after[s * SLOT..(s + 1) * SLOT])
                .count();
            (n, img.load_index(&keys).unwrap().entries["X"].pages.len())
        };
        let (three, p3) = changed(2 * PAYLOAD + 100);
        let (four, p4) = changed(4 * PAYLOAD - 100);
        assert_eq!((p3, p4), (4, 4));
        assert_eq!(three, four);
    }

    #[test]
    fn records_written_without_padding_still_read() {
        let (mut img, keys, _) = fresh();
        // A 3-page record as the code before T12.28 wrote it.
        let old = img.load_index(&keys).unwrap();
        let mut alloc = img.allocator(&old);
        let (epoch, record_id, rk) = (img.header.epoch + 1, [9u8; 16], [5u8; 32]);
        let v = vec![7u8; 3 * PAYLOAD - 100];
        let payload = encode_payload(Some(&v), Some(b"{}"));
        let (mut writes, mut pages) = (Vec::new(), Vec::new());
        for (p, chunk) in payload.chunks(PAYLOAD).enumerate() {
            let s = alloc.place(&keys.place, &record_id, p as u32).unwrap();
            let page = seal_slot(&rk, &img.header.image_id, s, epoch, chunk).unwrap();
            pages.push((s, leaf(s, &page)));
            writes.push((s, page));
        }
        let wrapped = gcm_seal(&keys.vmk, &wrap_aad(&record_id, "OLD"), &rk).unwrap();
        let entry = Entry {
            record_id,
            wrapped_key: wrapped.try_into().unwrap(),
            epoch,
            updated: 1,
            value_len: v.len() as u32,
            has_value: true,
            pages,
        };
        let mut new = old.clone();
        new.entries.insert("OLD".into(), entry);
        img.commit_index(&keys, &old, new, alloc, writes).unwrap();
        let ix = img.load_index(&keys).unwrap();
        assert_eq!(ix.entries["OLD"].pages.len(), 3);
        let rec = img.read_record(&keys, &ix, "OLD").unwrap().unwrap();
        assert_eq!(rec.value.unwrap().as_slice(), &v[..]);
        assert_eq!(rec.meta.unwrap(), b"{}");
        assert!(img.verify_records(&keys).is_ok());
        // Its next write pads it.
        img.put_record(&keys, "OLD", Some(&v), None).unwrap();
        assert_eq!(img.load_index(&keys).unwrap().entries["OLD"].pages.len(), 4);
        assert_eq!(value(&img, &keys, "OLD").unwrap(), v);
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
    fn rename_moves_value_and_meta_in_one_commit_under_a_new_key() {
        let (mut img, keys, _) = fresh();
        img.put_record(&keys, "A", Some(b"secret"), Some(b"{\"s\":1}"))
            .unwrap();
        img.put_record(&keys, "C", None, Some(b"{\"alias\":1}"))
            .unwrap();
        let before = img.load_index(&keys).unwrap().entries["A"].clone();
        let epoch = img.header.epoch;
        assert!(img.rename_record(&keys, "A", "B").unwrap());
        assert_eq!(img.header.epoch, epoch + 1, "one commit");
        let ix = img.load_index(&keys).unwrap();
        assert!(!ix.entries.contains_key("A"));
        let b = img.read_record(&keys, &ix, "B").unwrap().unwrap();
        assert_eq!(b.value.unwrap().as_slice(), b"secret");
        assert_eq!(b.meta.unwrap(), b"{\"s\":1}");
        // Re-keyed and re-placed: the old pages are noise, the old key gone.
        let after = &ix.entries["B"];
        assert_ne!(after.record_id, before.record_id);
        assert_ne!(after.wrapped_key, before.wrapped_key);
        for (s, h) in &before.pages {
            assert_ne!(
                crate::daemon_vault::merkle::leaf(*s, &img.read_slot(*s).unwrap()),
                *h
            );
        }
        // A meta-only record moves too, and replaces what `to` held.
        assert!(img.rename_record(&keys, "C", "B").unwrap());
        let ix = img.load_index(&keys).unwrap();
        let b = img.read_record(&keys, &ix, "B").unwrap().unwrap();
        assert!(b.value.is_none());
        assert_eq!(b.meta.unwrap(), b"{\"alias\":1}");
        assert_eq!(ix.entries.len(), 1);
        assert!(!img.rename_record(&keys, "NONE", "D").unwrap());
        assert!(img.verify_records(&keys).is_ok());
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
