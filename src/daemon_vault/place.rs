// daemon_vault/place.rs — where slots go, and decoy rewrites (T4.03).
//
// Part `p` of a record lands at HMAC(place key, record id ‖ p ‖ attempt)
// mod (data slots), trying attempt 0, 1, … until a free slot comes up.
// A slot in use by the current state is never reused within a commit,
// so new pages always go to free slots (copy-on-write): the old state
// stays intact until the header points at the new one (T4.04).
//
// Every write also rewrites `DECOYS` random free slots with fresh noise,
// so comparing two copies of the image shows more changed slots than a
// write needed, at positions that say nothing.

use std::collections::HashSet;

use crate::daemon_eco::cipher;

use super::image::{SlotIo, VaultImage, FIRST_DATA_SLOT, SLOT};
use super::keys::noise;

pub const DECOYS: usize = 3;

/// Hands out free slots for one commit.
pub struct Allocator {
    slot_count: u32,
    taken: HashSet<u32>,
}

impl Allocator {
    /// `in_use`: every slot the current state references.
    pub fn new(slot_count: u32, in_use: impl IntoIterator<Item = u32>) -> Self {
        Self {
            slot_count,
            taken: in_use.into_iter().collect(),
        }
    }

    fn data_slots(&self) -> u32 {
        self.slot_count.saturating_sub(FIRST_DATA_SLOT)
    }

    /// Free data slots left.
    pub fn free(&self) -> u32 {
        let used = self.taken.iter().filter(|s| **s >= FIRST_DATA_SLOT).count();
        self.data_slots().saturating_sub(used as u32)
    }

    fn is_free(&self, s: u32) -> bool {
        s >= FIRST_DATA_SLOT && s < self.slot_count && !self.taken.contains(&s)
    }

    /// Slot for part `part` of `record_id`, marked taken.
    pub fn place(&mut self, key: &[u8; 32], record_id: &[u8], part: u32) -> Result<u32, String> {
        if self.free() == 0 {
            return Err(FULL.into());
        }
        let n = u64::from(self.data_slots());
        let mut last = FIRST_DATA_SLOT;
        for attempt in 0..PROBES {
            let h = cipher::hmac_sha256(
                key,
                &[record_id, &part.to_le_bytes(), &attempt.to_le_bytes()],
            );
            let v = u64::from_le_bytes(h[..8].try_into().expect("8 bytes"));
            last = FIRST_DATA_SLOT + (v % n) as u32;
            if self.is_free(last) {
                return Ok(self.take(last));
            }
        }
        // A nearly full image: scan on from the last candidate.
        let s = self.scan_from(last).ok_or(FULL)?;
        Ok(self.take(s))
    }

    /// `k` distinct random free slots (fewer if the image is that full),
    /// marked taken.
    pub fn decoys(&mut self, k: usize) -> Result<Vec<u32>, String> {
        let mut out = Vec::with_capacity(k);
        while out.len() < k && self.free() > 0 {
            let mut r = [0u8; 4];
            noise(&mut r)?;
            let start = FIRST_DATA_SLOT + u32::from_le_bytes(r) % self.data_slots();
            let s = self.scan_from(start).expect("free() > 0");
            out.push(self.take(s));
        }
        Ok(out)
    }

    fn take(&mut self, s: u32) -> u32 {
        self.taken.insert(s);
        s
    }

    fn scan_from(&self, start: u32) -> Option<u32> {
        let n = self.data_slots();
        (0..n)
            .map(|i| FIRST_DATA_SLOT + (start - FIRST_DATA_SLOT + i) % n)
            .find(|s| self.is_free(*s))
    }
}

const FULL: &str = "vault image is full";
/// HMAC probes before falling back to a scan (a ~97% full image still
/// finds a slot this way with high probability).
const PROBES: u32 = 128;

impl<I: SlotIo> VaultImage<I> {
    /// Write sealed slots and fill `decoys` with fresh noise (no fsync).
    pub fn apply(
        &mut self,
        writes: &[(u32, Box<[u8; SLOT]>)],
        decoys: &[u32],
    ) -> Result<(), String> {
        for (idx, bytes) in writes {
            self.write_slot(*idx, bytes)?;
        }
        for d in decoys {
            self.scrub_slot(*d)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_vault::slot::seal_slot;

    const PK: [u8; 32] = [5u8; 32];
    const N: u32 = 256;

    #[test]
    fn placement_is_deterministic_for_a_key() {
        let a = Allocator::new(N, [9, 10])
            .place(&PK, b"record-1", 0)
            .unwrap();
        let b = Allocator::new(N, [9, 10])
            .place(&PK, b"record-1", 0)
            .unwrap();
        assert_eq!(a, b);
        assert!((FIRST_DATA_SLOT..N).contains(&a));
        let other_key: Vec<u32> = (0..20u8)
            .map(|i| {
                Allocator::new(N, [])
                    .place(&[i; 32], b"record-1", 0)
                    .unwrap()
            })
            .collect();
        assert!(other_key.iter().any(|s| *s != other_key[0]), "key matters");
    }

    #[test]
    fn probing_skips_taken_slots_deterministically() {
        let first = Allocator::new(N, []).place(&PK, b"r", 0).unwrap();
        let probed = Allocator::new(N, [first]).place(&PK, b"r", 0).unwrap();
        assert_ne!(first, probed);
        assert_eq!(
            probed,
            Allocator::new(N, [first]).place(&PK, b"r", 0).unwrap()
        );
    }

    #[test]
    fn two_records_never_share_a_slot() {
        let mut alloc = Allocator::new(N, []);
        let mut seen = HashSet::new();
        for i in 0..(N - FIRST_DATA_SLOT) {
            let s = alloc.place(&PK, &i.to_le_bytes(), 0).unwrap();
            assert!(seen.insert(s), "slot {s} handed out twice");
        }
        assert_eq!(alloc.free(), 0);
        assert!(alloc.place(&PK, b"one too many", 0).is_err());
    }

    #[test]
    fn decoys_are_distinct_free_slots() {
        let mut alloc = Allocator::new(N, [2, 3, 4]);
        let d = alloc.decoys(DECOYS).unwrap();
        assert_eq!(d.len(), DECOYS);
        let set: HashSet<u32> = d.iter().copied().collect();
        assert_eq!(set.len(), DECOYS);
        assert!(d.iter().all(|s| (5..N).contains(s)));
    }

    #[test]
    fn a_write_changes_exactly_one_plus_k_slots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.img");
        let mut img = VaultImage::create(&path, 1, &[7u8; 32]).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut alloc = Allocator::new(N, []);
        let s = alloc.place(&PK, b"record", 0).unwrap();
        let sealed = seal_slot(&[1u8; 32], &img.header.image_id, s, 1, b"v").unwrap();
        let decoys = alloc.decoys(DECOYS).unwrap();
        img.apply(&[(s, sealed)], &decoys).unwrap();
        let after = std::fs::read(&path).unwrap();
        let changed: Vec<u32> = (0..N)
            .filter(|&i| {
                let r = i as usize * SLOT..(i as usize + 1) * SLOT;
                before[r.clone()] != after[r]
            })
            .collect();
        assert_eq!(changed.len(), 1 + DECOYS, "{changed:?}");
        assert!(changed.contains(&s));
        assert!(!changed.contains(&0), "header untouched");
    }

    #[test]
    fn placement_is_pinned() {
        let mut alloc = Allocator::new(64, []);
        let slots: Vec<u32> = (0..4)
            .map(|part| alloc.place(&[3u8; 32], b"rec", part).unwrap())
            .collect();
        assert_eq!(slots, [50, 45, 52, 20]);
    }
}
