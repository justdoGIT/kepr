// daemon_vault/slot.rs — sealing one 4 KiB slot (T4.02).
//
//   slot = nonce (12) ‖ AES-256-GCM(key, len u32 ‖ data ‖ zero pad) ‖ tag (16)
//   AAD  = image id (16) ‖ slot index u32 ‖ write epoch u64
//
// Up to `PAYLOAD` (4064) bytes per slot. The AAD binds a slot to its
// image, its position and the epoch it was written in: a slot copied to
// another index, another image, or put back from an older epoch fails
// the tag. The caller picks the key: the index key for index pages, the
// record's own key for record pages (T4.05).

use zeroize::Zeroizing;

use super::image::SLOT;
use super::keys::{gcm_open, gcm_seal, NONCE, TAG};

/// Data bytes one slot carries.
pub const PAYLOAD: usize = SLOT - NONCE - TAG - 4;

fn aad(image_id: &[u8; 16], idx: u32, epoch: u64) -> [u8; 28] {
    let mut a = [0u8; 28];
    a[..16].copy_from_slice(image_id);
    a[16..20].copy_from_slice(&idx.to_le_bytes());
    a[20..].copy_from_slice(&epoch.to_le_bytes());
    a
}

pub fn seal_slot(
    key: &[u8; 32],
    image_id: &[u8; 16],
    idx: u32,
    epoch: u64,
    data: &[u8],
) -> Result<Box<[u8; SLOT]>, String> {
    if data.len() > PAYLOAD {
        return Err("vault slot payload too large".into());
    }
    let mut plain = Zeroizing::new(vec![0u8; 4 + PAYLOAD]);
    plain[..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    plain[4..4 + data.len()].copy_from_slice(data);
    let sealed = gcm_seal(key, &aad(image_id, idx, epoch), &plain)?;
    let mut slot = Box::new([0u8; SLOT]);
    slot.copy_from_slice(&sealed);
    Ok(slot)
}

pub fn open_slot(
    key: &[u8; 32],
    image_id: &[u8; 16],
    idx: u32,
    epoch: u64,
    slot: &[u8; SLOT],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut plain = gcm_open(key, &aad(image_id, idx, epoch), slot)?;
    let len = u32::from_le_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
    if len > PAYLOAD {
        return Err("decryption failed: bad slot length".into());
    }
    plain.copy_within(4..4 + len, 0);
    plain.truncate(len);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [3u8; 32];
    const ID: [u8; 16] = [9u8; 16];

    #[test]
    fn round_trip_any_length_up_to_the_payload() {
        for len in [0usize, 1, 100, PAYLOAD] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let s = seal_slot(&K, &ID, 5, 2, &data).unwrap();
            assert_eq!(open_slot(&K, &ID, 5, 2, &s).unwrap().as_slice(), &data[..]);
        }
        assert!(seal_slot(&K, &ID, 5, 2, &[0u8; PAYLOAD + 1]).is_err());
    }

    #[test]
    fn a_slot_moved_to_another_index_fails_to_open() {
        let s = seal_slot(&K, &ID, 5, 2, b"value").unwrap();
        assert!(open_slot(&K, &ID, 6, 2, &s).is_err());
    }

    #[test]
    fn a_slot_from_an_older_epoch_fails() {
        let s = seal_slot(&K, &ID, 5, 2, b"value").unwrap();
        assert!(open_slot(&K, &ID, 5, 3, &s).is_err());
    }

    #[test]
    fn another_image_or_key_fails() {
        let s = seal_slot(&K, &ID, 5, 2, b"value").unwrap();
        assert!(open_slot(&K, &[8u8; 16], 5, 2, &s).is_err());
        assert!(open_slot(&[4u8; 32], &ID, 5, 2, &s).is_err());
    }

    #[test]
    fn sealing_the_same_data_twice_differs() {
        let a = seal_slot(&K, &ID, 5, 2, b"value").unwrap();
        let b = seal_slot(&K, &ID, 5, 2, b"value").unwrap();
        assert_ne!(a[..], b[..]);
    }
}
