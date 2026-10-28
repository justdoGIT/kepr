// daemon_vault/listing.rs — what the store features (`daemon_store/`:
// trash, aliases, verify, delete-all) need from the image (T4.14): every
// record, not just the nameable credentials `list` shows. History slots
// (`NAME~N`), trash entries (`NAME~t<unix>`) and meta-only records
// (aliases) are records like any other; the per-file store has them as
// value files and `.meta` sidecars.

use super::backend::ImageBackend;

impl ImageBackend {
    /// Every record as (`kepr-<uid>-<name>[~…]`, holds a value), sorted.
    /// No image: empty. A locked store or an index that doesn't open is
    /// an error, so a check can't mistake it for an empty store.
    pub fn records(&self) -> Result<Vec<(String, bool)>, String> {
        let all = self.with_index(|_, _, ix| {
            Ok(ix
                .entries
                .iter()
                .map(|(k, e)| (k.clone(), e.has_value))
                .collect())
        })?;
        Ok(all.unwrap_or_default())
    }

    /// Last write of any record (meta-only ones included).
    pub fn updated(&self, record: &str) -> Option<u64> {
        self.with_index(|_, _, ix| Ok(ix.entries.get(record).map(|e| e.updated)))
            .ok()
            .flatten()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Backend;
    use crate::expiry::{CredMeta, MetaStore};
    use crate::store;
    use zeroize::Zeroizing;

    fn key() -> Result<Zeroizing<[u8; 32]>, String> {
        Ok(Zeroizing::new([0x42; 32]))
    }
    fn locked() -> Result<Zeroizing<[u8; 32]>, String> {
        Err("credential store is locked".into())
    }

    #[test]
    fn records_lists_slots_trash_entries_and_meta_only_records() {
        let d = tempfile::tempdir().unwrap();
        let b = ImageBackend::new(d.path().join("vault.img"), key, None).with_create_mib(2);
        assert_eq!(b.records(), Ok(Vec::new()), "no image: nothing");
        b.encrypt(7, "A", b"a").unwrap();
        b.encrypt(7, "A~0", b"old").unwrap();
        b.encrypt(7, "B~t17", b"trashed").unwrap();
        let alias = CredMeta {
            alias_of: Some("A".into()),
            ..Default::default()
        };
        let mp = d
            .path()
            .join(format!("{}.meta", store::to_cred_name(7, "L")));
        b.write_meta(&mp, &alias).unwrap();
        let want: Vec<(String, bool)> = [("A", true), ("A~0", true), ("B~t17", true), ("L", false)]
            .iter()
            .map(|(n, v)| (store::to_cred_name(7, n), *v))
            .collect();
        assert_eq!(b.records().unwrap(), want);
        assert!(b.updated(&store::to_cred_name(7, "L")).unwrap() > 1_700_000_000);
        assert_eq!(b.updated(&store::to_cred_name(7, "NONE")), None);
        let shut = ImageBackend::new(b.path().to_path_buf(), locked, None);
        assert!(shut.records().is_err());
    }
}
