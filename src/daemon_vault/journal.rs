// daemon_vault/journal.rs — the journal slot and two-phase commit (T4.04).
//
// A commit never overwrites a slot the current state uses: new pages go
// to free slots (place.rs). The only in-place writes are the header and
// the scrubbing of slots the new state no longer needs. Slot 1 holds a
// journal that makes the header switch atomic:
//
//   1. journal ← seal(new header ‖ written slots ‖ their hash ‖ freed
//      slots) under the journal key, fsync
//   2. new pages, and decoy noise, into free slots; fsync
//   3. header ← new header; fsync
//   4. scrub the freed slots, journal ← noise; fsync
//
// On open, a journal that authenticates and is one epoch ahead of the
// header (or the header is torn) is rolled forward if every slot it
// lists is on disk exactly as hashed, i.e. the crash came after step 2,
// and dropped otherwise: step 2 only touched free slots, so the old
// state is intact. A journal at the header's epoch means step 4 didn't
// finish; recovery finishes it. A torn or cleared journal is noise and
// fails its tag. Either way the image opens as the old state or the
// new one, never a mix.
//
// The ticket's journal carried the new slots' ciphertext; carrying their
// hash instead keeps the journal to one slot and gives the same answer,
// because new pages only ever go to free slots.

use crate::daemon_eco::cipher;

use super::header::{Header, Reader, BODY_LEN};
use super::image::{SlotIo, VaultImage, FIRST_DATA_SLOT, SLOT};
use super::keys::{gcm_open, gcm_seal, Keys, NONCE, TAG};

pub const JOURNAL_SLOT: u32 = 1;
const JOURNAL_BODY: usize = SLOT - NONCE - TAG;
const AAD: &[u8] = b"kepr-vi1 journal";

struct Journal {
    header: Header,
    written: Vec<u32>,
    hash: [u8; 32],
    freed: Vec<u32>,
}

fn put_list(b: &mut Vec<u8>, list: &[u32]) {
    b.extend_from_slice(&(list.len() as u16).to_le_bytes());
    for s in list {
        b.extend_from_slice(&s.to_le_bytes());
    }
}

fn get_list(r: &mut Reader) -> Result<Vec<u32>, String> {
    let n = u16::from_le_bytes(r.take()?);
    (0..n).map(|_| r.take().map(u32::from_le_bytes)).collect()
}

impl Journal {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut b = self.header.encode()?;
        put_list(&mut b, &self.written);
        b.extend_from_slice(&self.hash);
        put_list(&mut b, &self.freed);
        if b.len() > JOURNAL_BODY {
            return Err("vault commit is too large".into());
        }
        b.resize(JOURNAL_BODY, 0);
        Ok(b)
    }

    fn decode(b: &[u8]) -> Result<Self, String> {
        let header = Header::decode(b.get(..BODY_LEN).ok_or("short journal")?)?;
        let mut r = Reader(&b[BODY_LEN..]);
        let written = get_list(&mut r)?;
        let hash = r.take()?;
        let freed = get_list(&mut r)?;
        Ok(Self {
            header,
            written,
            hash,
            freed,
        })
    }
}

fn batch_hash<'a>(slots: impl Iterator<Item = (u32, &'a [u8; SLOT])>) -> [u8; 32] {
    let slots: Vec<_> = slots.collect();
    let idx: Vec<[u8; 4]> = slots.iter().map(|(i, _)| i.to_le_bytes()).collect();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(slots.len() * 2);
    for (n, (_, s)) in slots.iter().enumerate() {
        parts.push(&idx[n]);
        parts.push(&s[..]);
    }
    cipher::sha256(&parts)
}

/// One state change: the new header and the pages behind it.
#[derive(Clone)]
pub struct Commit {
    /// Next epoch, new Merkle root, new index slots.
    pub header: Header,
    /// Sealed pages, all in slots the current state doesn't use.
    pub writes: Vec<(u32, Box<[u8; SLOT]>)>,
    /// Free slots to fill with fresh noise.
    pub decoys: Vec<u32>,
    /// Slots the current state uses and the new one doesn't.
    pub freed: Vec<u32>,
}

impl<I: SlotIo> VaultImage<I> {
    /// Apply `c` atomically (see the top of this file). After an error the
    /// on-disk state is the old or the new one; reopen the image to learn
    /// which before using it again.
    pub fn commit(&mut self, keys: &Keys, c: Commit) -> Result<(), String> {
        let (h, cur) = (&c.header, &self.header);
        if h.epoch != cur.epoch + 1 || h.image_id != cur.image_id || h.slot_count != cur.slot_count
        {
            return Err("vault commit does not follow the current state".into());
        }
        let data = |s: &u32| *s >= FIRST_DATA_SLOT;
        let all_data = c.writes.iter().all(|w| data(&w.0))
            && c.decoys.iter().all(data)
            && c.freed.iter().all(data);
        if !all_data {
            return Err("vault commit touches a reserved slot".into());
        }
        let j = Journal {
            header: c.header.clone(),
            written: c.writes.iter().map(|w| w.0).collect(),
            hash: batch_hash(c.writes.iter().map(|(i, s)| (*i, &**s))),
            freed: c.freed.clone(),
        };
        self.write_journal(keys, &j)?;
        self.sync()?;
        self.apply(&c.writes, &c.decoys)?;
        self.sync()?;
        let prev = std::mem::replace(&mut self.header, c.header);
        if let Err(e) = self.write_header(keys).and_then(|()| self.sync()) {
            self.header = prev;
            return Err(e);
        }
        self.finish(&j.freed)
    }

    /// Step 4: scrub what the new state freed, then clear the journal.
    fn finish(&mut self, freed: &[u32]) -> Result<(), String> {
        for s in freed {
            self.scrub_slot(*s)?;
        }
        self.scrub_slot(JOURNAL_SLOT)?;
        self.sync()
    }

    fn journal_aad(&self) -> Vec<u8> {
        [AAD, &self.salt()[..]].concat()
    }

    fn write_journal(&mut self, keys: &Keys, j: &Journal) -> Result<(), String> {
        let sealed = gcm_seal(&keys.journal, &self.journal_aad(), &j.encode()?)?;
        let mut slot = Box::new([0u8; SLOT]);
        slot.copy_from_slice(&sealed);
        self.write_slot(JOURNAL_SLOT, &slot)
    }

    fn read_journal(&self, keys: &Keys) -> Option<Journal> {
        let slot = self.read_slot(JOURNAL_SLOT).ok()?;
        let body = gcm_open(&keys.journal, &self.journal_aad(), &slot[..]).ok()?;
        Journal::decode(&body).ok()
    }

    /// Are the pages a journal lists on disk exactly as it hashed them?
    fn pages_landed(&self, j: &Journal) -> bool {
        let pages: Result<Vec<_>, _> = j.written.iter().map(|&i| self.read_slot(i)).collect();
        pages.is_ok_and(|p| {
            batch_hash(j.written.iter().copied().zip(p.iter().map(|b| &**b))) == j.hash
        })
    }

    /// Settle the header after a crash (called by `load`). `current` is
    /// slot 0 as decrypted, or why it didn't decrypt.
    pub(super) fn recover(
        &mut self,
        keys: &Keys,
        current: Result<Header, String>,
    ) -> Result<(), String> {
        let Some(j) = self.read_journal(keys) else {
            self.header = current?;
            return Ok(());
        };
        if let Ok(h) = &current {
            if j.header.epoch <= h.epoch {
                // The header already moved on; finish step 4 if it was this
                // commit's, otherwise just clear the stale journal.
                self.header = h.clone();
                let freed = if j.header.epoch == h.epoch {
                    j.freed
                } else {
                    Vec::new()
                };
                return self.finish(&freed);
            }
        }
        let follows = current.as_ref().map_or(true, |h| {
            j.header.epoch == h.epoch + 1
                && j.header.image_id == h.image_id
                && j.header.slot_count == h.slot_count
        });
        // Read the listed pages under the journal's geometry.
        let prev = std::mem::replace(&mut self.header, j.header.clone());
        if follows && self.pages_landed(&j) {
            self.write_header(keys)?;
            self.sync()?;
            return self.finish(&j.freed);
        }
        // Torn commit: the old header still describes an intact state.
        self.header = current.inspect_err(|_| self.header = prev)?;
        self.finish(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_vault::merkle::{leaf, merkle_root, Hash};
    use crate::daemon_vault::place::{Allocator, DECOYS};
    use crate::daemon_vault::slot::{open_slot, seal_slot};
    use crate::daemon_vault::testio::{Faulty, MemIo};

    const KEK: [u8; 32] = [7u8; 32];
    const PAGE_KEY: [u8; 32] = [1u8; 32];

    /// A commit that replaces whatever `old` used with one page `data`.
    fn next<I: SlotIo>(img: &VaultImage<I>, old: &[u32], data: &[u8]) -> (Commit, u32, Hash) {
        let epoch = img.header.epoch + 1;
        let mut alloc = Allocator::new(img.header.slot_count, old.iter().copied());
        let s = alloc.place(&[5u8; 32], data, 0).unwrap();
        let page = seal_slot(&PAGE_KEY, &img.header.image_id, s, epoch, data).unwrap();
        let l = leaf(s, &page);
        let header = Header {
            epoch,
            root: merkle_root(&[l]),
            ..img.header.clone()
        };
        let c = Commit {
            header,
            writes: vec![(s, page)],
            decoys: alloc.decoys(DECOYS).unwrap(),
            freed: old.to_vec(),
        };
        (c, s, l)
    }

    fn reads<I: SlotIo>(img: &VaultImage<I>, s: u32) -> Vec<u8> {
        let page = img.read_slot(s).unwrap();
        open_slot(&PAGE_KEY, &img.header.image_id, s, img.header.epoch, &page)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn commit_moves_to_the_next_epoch_and_survives_reopen() {
        let mem = MemIo::new(1 << 20);
        let mut img = VaultImage::format(mem.clone(), 256, &KEK).unwrap();
        let keys = img.keys(&KEK);
        let (c, s, l) = next(&img, &[], b"one");
        img.commit(&keys, c).unwrap();
        let (c2, s2, l2) = next(&img, &[s], b"two");
        img.commit(&keys, c2).unwrap();
        let again = VaultImage::load(mem, &KEK).unwrap();
        assert_eq!(again.header.epoch, 2);
        assert!(again.verify(&[(s2, Some(l2))]).is_ok());
        assert_eq!(reads(&again, s2), b"two");
        assert_ne!(again.read_slot(s).unwrap().as_ref(), &[0u8; SLOT]);
        assert_ne!(
            leaf(s, &again.read_slot(s).unwrap()),
            l,
            "freed slot scrubbed"
        );
    }

    #[test]
    fn a_commit_out_of_order_is_refused() {
        let mem = MemIo::new(1 << 20);
        let mut img = VaultImage::format(mem, 256, &KEK).unwrap();
        let keys = img.keys(&KEK);
        let (mut c, _, _) = next(&img, &[], b"x");
        c.header.epoch += 1;
        assert!(img.commit(&keys, c).is_err());
    }

    #[test]
    fn a_crash_after_any_byte_leaves_the_old_or_the_new_state() {
        // Old state: one committed page. New state: a different page.
        let mem = MemIo::new(1 << 20);
        let mut img = VaultImage::format(mem.clone(), 256, &KEK).unwrap();
        let keys = img.keys(&KEK);
        let (c, old_s, old_l) = next(&img, &[], b"old");
        img.commit(&keys, c).unwrap();
        let (commit, new_s, new_l) = next(&img, &[old_s], b"new");
        let base = mem.bytes();

        // How many bytes a full commit writes.
        let mut full = VaultImage::load(
            Faulty::new(MemIo::from_bytes(base.clone()), usize::MAX),
            &KEK,
        )
        .unwrap();
        full.commit(&keys, commit.clone()).unwrap();
        let total = full.io_ref().written;

        let mut budgets: Vec<usize> = (0..=total).step_by(61).collect();
        for b in (0..=total).step_by(SLOT) {
            budgets.extend([b.saturating_sub(1), b, b + 1]);
        }
        let (mut saw_old, mut saw_new) = (false, false);
        for n in budgets {
            let disk = MemIo::from_bytes(base.clone());
            let mut img = VaultImage::load(Faulty::new(disk.clone(), n), &KEK).unwrap();
            let _ = img.commit(&keys, commit.clone());
            let after = VaultImage::load(disk, &KEK)
                .unwrap_or_else(|e| panic!("budget {n}: reopen failed: {e}"));
            match after.header.epoch {
                1 => {
                    assert!(after.verify(&[(old_s, Some(old_l))]).is_ok(), "budget {n}");
                    assert_eq!(reads(&after, old_s), b"old", "budget {n}");
                    saw_old = true;
                }
                2 => {
                    assert!(after.verify(&[(new_s, Some(new_l))]).is_ok(), "budget {n}");
                    assert_eq!(reads(&after, new_s), b"new", "budget {n}");
                    saw_new = true;
                }
                e => panic!("budget {n}: epoch {e}"),
            }
            // Recovery leaves nothing to redo: a second open is the same.
            let twice = VaultImage::load(MemIo::from_bytes(after_bytes(&after)), &KEK).unwrap();
            assert_eq!(twice.header, after.header, "budget {n}");
        }
        assert!(saw_old && saw_new);
    }

    fn after_bytes(img: &VaultImage<MemIo>) -> Vec<u8> {
        img.io_ref().bytes()
    }

    #[test]
    fn batch_hash_is_pinned() {
        let (a, b) = ([0xaau8; SLOT], [0xbbu8; SLOT]);
        let h = batch_hash([(3u32, &a), (9u32, &b)].into_iter());
        assert_eq!(
            hex::encode(h),
            "8a53f14762d6cf496cd1ed49ad857b779a862cfe22091b63070e675bdcc5ed1b"
        );
    }
}
