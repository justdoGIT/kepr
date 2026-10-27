// daemon_vault/merkle.rs — the Merkle root in the header (T4.02).
//
// Leaves are SHA-256 over (slot index ‖ slot ciphertext) of every slot
// the current state uses (index and record pages; free slots are noise
// and carry nothing). Inner nodes hash their two children; an odd level
// duplicates its last node. The leaf count is hashed into the root so
// [a, b, c] and [a, b, c, c] can't share one. Domain bytes keep leaves,
// nodes and the root apart.

use sha2::{Digest, Sha256};

use super::image::{SlotIo, VaultImage, SLOT};

pub type Hash = [u8; 32];

pub fn leaf(idx: u32, slot: &[u8; SLOT]) -> Hash {
    Sha256::new()
        .chain_update([0u8])
        .chain_update(idx.to_le_bytes())
        .chain_update(slot)
        .finalize()
        .into()
}

pub fn merkle_root(leaves: &[Hash]) -> Hash {
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("non-empty"));
        }
        level = level
            .chunks(2)
            .map(|p| {
                Sha256::new()
                    .chain_update([1u8])
                    .chain_update(p[0])
                    .chain_update(p[1])
                    .finalize()
                    .into()
            })
            .collect();
    }
    let top = level.first().copied().unwrap_or([0u8; 32]);
    Sha256::new()
        .chain_update([2u8])
        .chain_update((leaves.len() as u64).to_le_bytes())
        .chain_update(top)
        .finalize()
        .into()
}

/// What `verify` found: slots whose bytes don't match what the index
/// says they should be, and whether the header's root still matches.
#[derive(Debug, PartialEq, Eq)]
pub struct Damage {
    pub slots: Vec<u32>,
    pub root_ok: bool,
}

impl<I: SlotIo> VaultImage<I> {
    /// Merkle root over `slots` as they are on disk (sorted by index).
    #[cfg(test)]
    pub fn root_of(&self, slots: &[u32]) -> Result<Hash, String> {
        let mut sorted = slots.to_vec();
        sorted.sort_unstable();
        let leaves = sorted
            .iter()
            .map(|&i| self.read_slot(i).map(|s| leaf(i, &s)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(merkle_root(&leaves))
    }

    /// Re-read every used slot, compare each with its expected leaf (if
    /// the caller has one) and recompute the root against the header.
    pub fn verify(&self, used: &[(u32, Option<Hash>)]) -> Result<(), Damage> {
        let mut sorted = used.to_vec();
        sorted.sort_unstable_by_key(|u| u.0);
        let (mut leaves, mut slots) = (Vec::with_capacity(sorted.len()), Vec::new());
        for (i, want) in sorted {
            match self.read_slot(i) {
                Ok(s) => {
                    let l = leaf(i, &s);
                    if want.is_some_and(|w| w != l) {
                        slots.push(i);
                    }
                    leaves.push(l);
                }
                Err(_) => slots.push(i),
            }
        }
        let root_ok = merkle_root(&leaves) == self.header.root;
        if slots.is_empty() && root_ok {
            Ok(())
        } else {
            Err(Damage { slots, root_ok })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    #[test]
    fn root_depends_on_every_leaf_and_their_order() {
        let base = merkle_root(&[h(1), h(2), h(3)]);
        assert_ne!(base, merkle_root(&[h(1), h(2), h(4)]));
        assert_ne!(base, merkle_root(&[h(2), h(1), h(3)]));
        assert_eq!(base, merkle_root(&[h(1), h(2), h(3)]));
    }

    #[test]
    fn duplicating_the_last_leaf_does_not_collide() {
        assert_ne!(
            merkle_root(&[h(1), h(2), h(3)]),
            merkle_root(&[h(1), h(2), h(3), h(3)])
        );
        assert_ne!(merkle_root(&[]), merkle_root(&[h(0)]));
    }

    #[test]
    fn verify_recomputes_the_root_and_names_a_flipped_slot() {
        use crate::daemon_vault::image::VaultImage;
        use crate::daemon_vault::slot::seal_slot;
        const KEK: [u8; 32] = [7u8; 32];
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.img");
        let mut img = VaultImage::create(&p, 1, &KEK).unwrap();
        assert!(img.verify(&[]).is_ok(), "a fresh image verifies");
        let keys = img.keys(&KEK);
        let id = img.header.image_id;
        let used = [7u32, 5, 6];
        for &i in &used {
            let s = seal_slot(&[1u8; 32], &id, i, 1, b"data").unwrap();
            img.write_slot(i, &s).unwrap();
        }
        let expected: Vec<(u32, Option<Hash>)> = used
            .iter()
            .map(|&i| (i, Some(leaf(i, &img.read_slot(i).unwrap()))))
            .collect();
        img.header.root = img.root_of(&used).unwrap();
        img.header.epoch = 1;
        img.write_header(&keys).unwrap();
        assert!(img.verify(&expected).is_ok());

        let before = img.root_of(&used).unwrap();
        let mut s6 = img.read_slot(6).unwrap();
        s6[2000] ^= 0x10;
        img.write_slot(6, &s6).unwrap();
        assert_ne!(before, img.root_of(&used).unwrap(), "root changes");
        let damage = img.verify(&expected).unwrap_err();
        assert_eq!(damage.slots, vec![6]);
        assert!(!damage.root_ok);
        // Index pages have no stored hash: the root alone catches them.
        let unnamed: Vec<_> = used.iter().map(|&i| (i, None)).collect();
        let reopened = VaultImage::open(&p, &KEK).unwrap();
        let damage = reopened.verify(&unnamed).unwrap_err();
        assert!(damage.slots.is_empty() && !damage.root_ok);
    }

    #[test]
    fn leaf_binds_the_slot_index() {
        let s = [5u8; SLOT];
        assert_ne!(leaf(1, &s), leaf(2, &s));
        let mut t = s;
        t[100] ^= 1;
        assert_ne!(leaf(1, &s), leaf(1, &t));
    }
}
