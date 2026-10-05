// daemon_store/files.rs — raw store helpers shared by the trash, delete-
// all and verify: every file a uid owns (including the unnameable `~`
// entries: history slots `NAME~3`, trash entries `NAME~t<unix>` and their
// slots `NAME~t<unix>~3`), and moving a value from one name to another.
//
// A value's AEAD tag is bound to its exact name, so a "move" is decrypt +
// encrypt under the new name; the plaintext stays in a ZeroString.

use std::path::{Path, PathBuf};

use crate::crypto;
use crate::store::{self, CRED_PREFIX};

/// One stored value file: `(uid, canonical name)`. The canonical name is
/// the one it was encrypted under: the credential part upper-case with
/// `_`, the `~` suffixes as written (`~t<digits>`, `~<digit>`).
pub fn parse_file_name(file: &str) -> Option<(u32, String)> {
    if file.ends_with(".meta") || file.contains(".tmp") {
        return None;
    }
    let rest = file.strip_prefix(CRED_PREFIX)?.strip_prefix('-')?;
    let (uid, base) = rest.split_once('-')?;
    let uid: u32 = uid.parse().ok()?;
    let mut parts = base.split('~');
    let name = parts.next()?.to_uppercase().replace('-', "_");
    store::validate_name(&name).ok()?;
    let mut canonical = name;
    for p in parts {
        let ok = p.strip_prefix('t').unwrap_or(p);
        if ok.is_empty() || !ok.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        canonical.push('~');
        canonical.push_str(p);
    }
    (store::to_cred_name(uid, &canonical) == file).then_some((uid, canonical))
}

/// Every value file under `dir`: `(uid, canonical name, path)`.
pub fn all_in(dir: &Path) -> Vec<(u32, String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<_> = rd
        .flatten()
        .filter_map(|e| {
            let f = e.file_name().to_string_lossy().to_string();
            parse_file_name(&f).map(|(u, n)| (u, n, e.path()))
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Every value file of `uid` in the store: `(canonical name, path)`.
pub fn all_of(uid: u32) -> Vec<(String, PathBuf)> {
    all_in(&store::store_dir())
        .into_iter()
        .filter(|(u, _, _)| *u == uid)
        .map(|(_, n, p)| (n, p))
        .collect()
}

/// Re-encrypt `from`'s value under `to` (the caller deletes `from`).
pub fn copy_value(uid: u32, from: &str, to: &str) -> Result<(), String> {
    let v = crypto::default_backend().decrypt(uid, from)?;
    crypto::default_backend().encrypt(uid, to, v.as_bytes())
}

/// `from`'s history slots become `to`'s (best effort, like history
/// itself); slots that can't be moved are dropped.
pub fn move_history(uid: u32, from: &str, to: &str) {
    for s in 0..crate::daemon_history::DEPTH {
        let (src, dst) = (format!("{from}~{s}"), format!("{to}~{s}"));
        if !store::cred_path(uid, &src).exists() {
            continue;
        }
        if let Err(e) = copy_value(uid, &src, &dst) {
            eprintln!("[kepr-daemon] history move failed: {e}");
        }
        let _ = crypto::default_backend().delete(uid, &src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_slots_and_trash_entries() {
        let p = |f: &str| parse_file_name(f);
        assert_eq!(p("kepr-1000-foo-bar"), Some((1000, "FOO_BAR".into())));
        assert_eq!(p("kepr-1000-foo~3"), Some((1000, "FOO~3".into())));
        assert_eq!(
            p("kepr-7-foo~t1700000000"),
            Some((7, "FOO~t1700000000".into()))
        );
        assert_eq!(p("kepr-7-foo~t17~2"), Some((7, "FOO~t17~2".into())));
        for bad in [
            "kepr-1000-foo.meta",
            "kepr-1000-foo~3.meta",
            "kepr-1000-foo.tmp.1",
            "kepr-1000-foo~x",
            "kepr-1000-foo~",
            "kepr-x-foo",
            "other-1000-foo",
            "kepr-1000-FOO",
        ] {
            assert_eq!(p(bad), None, "{bad}");
        }
    }
}
