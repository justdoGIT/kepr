// daemon_vault/header.rs — the image header in slot 0 (T4.01).
//
//   0..8     magic `kepr_vi1`   (the only fixed bytes in the whole file)
//   8..40    KDF salt           (random per image)
//   40..52   nonce
//   52..     AES-256-GCM(header key, body), AAD = magic ‖ salt
//   rest     noise
//
//   body = version u16 | image id [16] | slot count u32 | epoch u64 |
//          Merkle root [32] | index length u32 | n u16 | n × slot u32,
//          zero-padded to a fixed length so n doesn't show
//
// The GCM tag is the header MAC. Version, slot count and epoch sit
// inside the ciphertext, so two images differ everywhere except the
// magic and a copy doesn't show how many writes the image has seen.
// A wrong key, a torn header or a flipped bit all fail the tag.

use super::image::SLOT;
use super::keys::{gcm_open, gcm_seal, noise, Keys, NONCE, SALT, TAG};

pub const MAGIC: &[u8; 8] = b"kepr_vi1";
pub const VERSION: u16 = 1;
/// Cap on index slots (1 MiB of index), so the header fits one slot.
pub const MAX_INDEX_SLOTS: usize = 256;
const BODY_FIXED: usize = 2 + 16 + 4 + 8 + 32 + 4 + 2;
/// Every header body is padded to this length before sealing.
pub const BODY_LEN: usize = BODY_FIXED + 4 * MAX_INDEX_SLOTS;
pub const SEALED_AT: usize = 8 + SALT;
const SEALED_LEN: usize = NONCE + BODY_LEN + TAG;

/// The decrypted header body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub image_id: [u8; 16],
    pub slot_count: u32,
    pub epoch: u64,
    pub root: [u8; 32],
    /// Length in bytes of the index blob spread over `index_slots`.
    pub index_len: u32,
    pub index_slots: Vec<u32>,
}

impl Header {
    /// The fixed-length body (`BODY_LEN` bytes).
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.index_slots.len() > MAX_INDEX_SLOTS {
            return Err("vault index is too large".into());
        }
        let mut b = Vec::with_capacity(BODY_LEN);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&self.image_id);
        b.extend_from_slice(&self.slot_count.to_le_bytes());
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&self.root);
        b.extend_from_slice(&self.index_len.to_le_bytes());
        b.extend_from_slice(&(self.index_slots.len() as u16).to_le_bytes());
        for s in &self.index_slots {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b.resize(BODY_LEN, 0);
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader(b);
        if u16::from_le_bytes(r.take()?) != VERSION {
            return Err("unsupported vault image version".into());
        }
        let image_id = r.take()?;
        let slot_count = u32::from_le_bytes(r.take()?);
        let epoch = u64::from_le_bytes(r.take()?);
        let root = r.take()?;
        let index_len = u32::from_le_bytes(r.take()?);
        let n = u16::from_le_bytes(r.take()?) as usize;
        if n > MAX_INDEX_SLOTS {
            return Err("vault image header is malformed".into());
        }
        let index_slots = (0..n)
            .map(|_| r.take().map(u32::from_le_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            image_id,
            slot_count,
            epoch,
            root,
            index_len,
            index_slots,
        })
    }
}

/// Little cursor over a byte slice; every read is bounds-checked.
pub(super) struct Reader<'a>(pub &'a [u8]);

impl Reader<'_> {
    pub fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.bytes(N)?.try_into().expect("N bytes"))
    }
    pub fn bytes(&mut self, n: usize) -> Result<&[u8], String> {
        if self.0.len() < n {
            return Err("vault image data is truncated".into());
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
}

fn header_aad(salt: &[u8; SALT]) -> Vec<u8> {
    [&MAGIC[..], salt].concat()
}

/// Slot 0's bytes for `header`.
pub fn seal_header(
    keys: &Keys,
    salt: &[u8; SALT],
    header: &Header,
) -> Result<Box<[u8; SLOT]>, String> {
    let sealed = gcm_seal(&keys.header, &header_aad(salt), &header.encode()?)?;
    let mut slot = Box::new([0u8; SLOT]);
    noise(&mut slot[..])?;
    slot[..8].copy_from_slice(MAGIC);
    slot[8..SEALED_AT].copy_from_slice(salt);
    slot[SEALED_AT..SEALED_AT + SEALED_LEN].copy_from_slice(&sealed);
    Ok(slot)
}

pub fn open_header(keys: &Keys, slot: &[u8; SLOT]) -> Result<Header, String> {
    let salt: &[u8; SALT] = slot[8..SEALED_AT].try_into().expect("salt");
    let sealed = &slot[SEALED_AT..SEALED_AT + SEALED_LEN];
    let body = gcm_open(&keys.header, &header_aad(salt), sealed).map_err(|_| {
        "vault image header does not authenticate (wrong key, or the image is damaged)"
    })?;
    Header::decode(&body)
}
