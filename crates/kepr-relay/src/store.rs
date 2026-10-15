// store.rs — the relay's blobs, in memory only. A blob is deleted on its
// first fetch or at its expiry, whichever comes first. A fetched id
// leaves a tombstone until the blob's expiry, so a status check can tell
// "opened" (410) from "never here or expired" (404). Clock is injected.

use std::collections::HashMap;

pub struct Limits {
    pub max_blob: usize,
    pub max_blobs: usize,
    pub max_bytes: usize,
    pub max_ttl: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob: 1 << 20,
            max_blobs: 10_000,
            max_bytes: 256 << 20,
            max_ttl: 7 * 86_400,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    Stored,
    Exists,
    TooBig,
    BadTtl,
    Full,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Present,
    Opened,
    Unknown,
}

struct Blob {
    data: Vec<u8>,
    expires: u64,
}

#[derive(Default)]
pub struct Store {
    blobs: HashMap<String, Blob>,
    /// Fetched ids, until their blob would have expired.
    opened: HashMap<String, u64>,
    bytes: usize,
}

/// 16 to 64 characters of `[A-Za-z0-9_-]`.
pub fn valid_id(id: &str) -> bool {
    (16..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Store {
    pub fn sweep(&mut self, now: u64) {
        let mut freed = 0;
        self.blobs.retain(|_, b| {
            let keep = b.expires > now;
            if !keep {
                freed += b.data.len();
            }
            keep
        });
        self.bytes -= freed;
        self.opened.retain(|_, exp| *exp > now);
    }

    pub fn put(&mut self, id: &str, data: Vec<u8>, ttl: u64, now: u64, l: &Limits) -> Put {
        self.sweep(now);
        if data.len() > l.max_blob {
            return Put::TooBig;
        }
        if ttl == 0 || ttl > l.max_ttl {
            return Put::BadTtl;
        }
        if self.blobs.contains_key(id) || self.opened.contains_key(id) {
            return Put::Exists;
        }
        if self.blobs.len() >= l.max_blobs || self.bytes + data.len() > l.max_bytes {
            return Put::Full;
        }
        self.bytes += data.len();
        let expires = now + ttl;
        self.blobs.insert(id.to_string(), Blob { data, expires });
        Put::Stored
    }

    /// Fetch-and-delete.
    pub fn take(&mut self, id: &str, now: u64) -> Option<Vec<u8>> {
        self.sweep(now);
        let b = self.blobs.remove(id)?;
        self.bytes -= b.data.len();
        self.opened.insert(id.to_string(), b.expires);
        Some(b.data)
    }

    pub fn status(&mut self, id: &str, now: u64) -> Status {
        self.sweep(now);
        if self.blobs.contains_key(id) {
            Status::Present
        } else if self.opened.contains_key(id) {
            Status::Opened
        } else {
            Status::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_blob_is_fetched_once() {
        let (mut s, l) = (Store::default(), Limits::default());
        assert_eq!(s.put(ID, b"blob".to_vec(), 60, 100, &l), Put::Stored);
        assert_eq!(s.put(ID, b"other".to_vec(), 60, 100, &l), Put::Exists);
        assert_eq!(s.status(ID, 101), Status::Present);
        assert_eq!(s.take(ID, 101).as_deref(), Some(&b"blob"[..]));
        assert_eq!(s.take(ID, 102), None);
        assert_eq!(s.status(ID, 102), Status::Opened);
        // An opened id can't be reused before it would have expired.
        assert_eq!(s.put(ID, b"x".to_vec(), 60, 103, &l), Put::Exists);
        assert_eq!(s.bytes, 0);
    }

    #[test]
    fn an_expired_blob_is_gone() {
        let (mut s, l) = (Store::default(), Limits::default());
        s.put(ID, b"blob".to_vec(), 60, 100, &l);
        assert_eq!(s.take(ID, 160), None);
        assert_eq!(s.status(ID, 160), Status::Unknown);
        assert_eq!(s.bytes, 0);
    }

    #[test]
    fn limits() {
        let l = Limits {
            max_blob: 4,
            max_blobs: 1,
            max_bytes: 10,
            max_ttl: 60,
        };
        let mut s = Store::default();
        assert_eq!(s.put(ID, vec![0; 5], 60, 1, &l), Put::TooBig);
        assert_eq!(s.put(ID, vec![0; 4], 61, 1, &l), Put::BadTtl);
        assert_eq!(s.put(ID, vec![0; 4], 0, 1, &l), Put::BadTtl);
        assert_eq!(s.put(ID, vec![0; 4], 60, 1, &l), Put::Stored);
        let other = "fedcba9876543210fedcba9876543210";
        assert_eq!(s.put(other, vec![0; 4], 60, 1, &l), Put::Full);
        assert!(valid_id(ID) && !valid_id("short") && !valid_id(&"a/".repeat(10)));
    }
}
