// daemon_store/files.rs — raw store helpers shared by the trash, delete-
// all and verify: every value a uid owns (including the unnameable `~`
// entries: history slots `NAME~3`, trash entries `NAME~t<unix>` and their
// slots `NAME~t<unix>~3`), every `.meta`, and moving history from one
// name to another. With `KEPR_STORE=image` the same entries are records
// in the vault image (T4.14); a move is the backend's `rename`.

use std::path::PathBuf;

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

/// The store's entries as (`kepr-<uid>-…` base name, holds a value): the
/// vault image's records when it is the active store (T4.14), else the
/// value files and `.meta` sidecars in the store directory.
fn entries() -> Vec<(String, bool)> {
    if let Some(image) = crate::daemon_vault::active() {
        return image.records().unwrap_or_default();
    }
    let Ok(rd) = std::fs::read_dir(store::store_dir()) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .map(|f| match f.strip_suffix(".meta") {
            Some(base) => (base.to_string(), false),
            None => (f, true),
        })
        .collect()
}

/// Every stored value of every uid: `(uid, canonical name, path)`.
pub fn all() -> Vec<(u32, String, PathBuf)> {
    let dir = store::store_dir();
    let mut out: Vec<_> = entries()
        .into_iter()
        .filter(|(_, value)| *value)
        .filter_map(|(f, _)| parse_file_name(&f).map(|(u, n)| (u, n, dir.join(&f))))
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Every stored value of `uid`: `(canonical name, path)`.
pub fn all_of(uid: u32) -> Vec<(String, PathBuf)> {
    all()
        .into_iter()
        .filter(|(u, _, _)| *u == uid)
        .map(|(_, n, p)| (n, p))
        .collect()
}

/// The `.meta` path of every entry of `uid` that may have one: every
/// sidecar file, or every image record (`read_meta` is `None` where a
/// record has no meta). Meta-only entries (aliases) are among them.
pub fn meta_paths_of(uid: u32) -> Vec<PathBuf> {
    let (dir, prefix) = (store::store_dir(), format!("{CRED_PREFIX}-{uid}-"));
    let image = crate::daemon_vault::active().is_some();
    let mut out: Vec<PathBuf> = entries()
        .into_iter()
        .filter(|(base, value)| base.starts_with(&prefix) && (image || !value))
        .map(|(base, _)| dir.join(format!("{base}.meta")))
        .collect();
    out.sort();
    out
}

/// Would a plain `get` return this value with no prompt? Only such
/// values may be opened for search or compared for duplicates: anything
/// else (sealed, SSH, share key, consent / FIDO2, expired) would turn
/// those features into an oracle on a value `get` protects.
pub fn readable_without_prompt(meta: &crate::expiry::CredMeta, now: u64) -> bool {
    meta.sealed != Some(true)
        && meta.ssh.is_none()
        && meta.share_key != Some(true)
        && meta.requires_consent != Some(true)
        && meta.requires_fido2 != Some(true)
        && meta.expires_at_unix.is_none_or(|t| now < t)
}

/// `from`'s history slots become `to`'s (best effort, like history
/// itself); slots that can't be moved are dropped.
pub fn move_history(uid: u32, from: &str, to: &str) {
    for s in 0..crate::daemon_history::DEPTH {
        let (src, dst) = (format!("{from}~{s}"), format!("{to}~{s}"));
        if !store::cred_exists(uid, &src) {
            continue;
        }
        if let Err(e) = crypto::default_backend().rename(uid, &src, &dst) {
            eprintln!("[kepr-daemon] history move failed: {e}");
            let _ = crypto::default_backend().delete(uid, &src);
        }
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
