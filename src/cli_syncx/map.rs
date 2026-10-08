// cli_syncx/map.rs — T11.17: `kepr sync push --map sync.toml [--dry-run]`.
//
//     # sync.toml: one credential per line, NAME = "SCHEME:PATH"
//     DB_PASS = "aws-sm:prod/db"
//     API_KEY = "vault:secret/app/api"
//
// Every target is checked before anything runs. For each credential the
// local value (a normal `get`: sealed, SSH and share keys are refused, so
// they are "skipped", never pushed) and the remote one are compared by
// SHA-256 only and the row says `create`, `update` or `unchanged`. Without
// --dry-run, `create` and `update` rows are pushed; neither value is
// ever printed, and no hash is shown either.

use kepr_core::generate::ZeroString;
use kepr_core::protocol::Response;
use kepr_core::protocol_syncx::{SyncRow, SyncxResponse};
use sha2::{Digest, Sha256};

use crate::sync::{pick_syncer, Syncer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Create,
    Update,
    Unchanged,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Create => "create",
            Change::Update => "update",
            Change::Unchanged => "unchanged",
        }
    }
}

/// Compare by hash only: `None` (no remote secret) is a create.
pub fn classify(local: &[u8], remote: Option<&[u8]>) -> Change {
    match remote {
        None => Change::Create,
        Some(r) if Sha256::digest(r) == Sha256::digest(local) => Change::Unchanged,
        Some(_) => Change::Update,
    }
}

/// `NAME = "SCHEME:PATH"` lines → `(NAME, url)`, in name order. Names
/// are uppercased and checked like `kepr set` does; every URL must name
/// a target `pick_syncer` accepts.
pub fn parse_map(text: &str) -> Result<Vec<(String, String)>, String> {
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| format!("sync map: {}", e.message()))?;
    let mut out = Vec::new();
    for (name, v) in table {
        let upper = name.to_uppercase();
        let ok = !upper.is_empty()
            && upper.len() <= 128
            && upper
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !ok {
            return Err(format!("sync map: {name:?} is not a credential name"));
        }
        let url = v
            .as_str()
            .ok_or_else(|| format!("sync map: {name} must be a \"SCHEME:PATH\" string"))?;
        pick_syncer(url).map_err(|e| format!("sync map: {name}: {e}"))?;
        out.push((upper, url.to_string()));
    }
    if out.is_empty() {
        return Err("sync map: no entries (NAME = \"SCHEME:PATH\")".into());
    }
    out.sort();
    Ok(out)
}

/// One row: classify, and (unless `dry_run`) push a create / update.
pub fn plan_row(
    (name, url): (&str, &str),
    local: Result<ZeroString, String>,
    remote: &dyn Syncer,
    dry_run: bool,
) -> SyncRow {
    let row = |change: &str, error: Option<String>| SyncRow {
        name: name.to_string(),
        url: url.to_string(),
        change: change.to_string(),
        error,
    };
    let local = match local {
        Ok(v) => v,
        Err(e) => return row("skipped", Some(e)),
    };
    let change = match remote.fetch() {
        Ok(r) => classify(local.as_bytes(), r.as_ref().map(|r| r.as_bytes())),
        Err(e) => return row("failed", Some(e)),
    };
    if dry_run || change == Change::Unchanged {
        return row(change.as_str(), None);
    }
    match remote.push(local.as_str()) {
        Ok(()) => row(change.as_str(), None),
        Err(e) => row("failed", Some(e)),
    }
}

pub fn cmd_push_map(path: &str, dry_run: bool) -> Response {
    use crate::cli_exec::CredFetcher;
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Response::fail(format!("{path}: {e}")),
    };
    let entries = match parse_map(&text) {
        Ok(e) => e,
        Err(e) => return Response::fail(e),
    };
    let mut rows = Vec::new();
    for (name, url) in &entries {
        let remote = match pick_syncer(url) {
            Ok(s) => s,
            Err(e) => return Response::fail(e), // checked by parse_map
        };
        let local = crate::cli_exec::DaemonFetcher.fetch(name);
        let row = plan_row((name, url), local, remote.as_ref(), dry_run);
        if !crate::cli_ui::json_mode() {
            let why = row.error.as_deref().map(|e| format!("  ({e})"));
            println!(
                "{:<9}  {name} → {url}{}",
                row.change,
                why.unwrap_or_default()
            );
        }
        rows.push(row);
    }
    let failed: Vec<String> = rows
        .iter()
        .filter(|r| r.change == "failed")
        .map(|r| format!("{}: {}", r.name, r.error.as_deref().unwrap_or("")))
        .collect();
    if !failed.is_empty() {
        return Response::fail(format!(
            "{} of {} failed: {}",
            failed.len(),
            rows.len(),
            failed.join("; ")
        ));
    }
    if dry_run && !crate::cli_ui::json_mode() {
        crate::cli_ui::info("dry run: nothing was pushed");
    }
    SyncxResponse::SyncPlan { dry_run, rows }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_syncx::json_file::JsonFileSyncer;

    #[test]
    fn maps_parse_names_and_targets() {
        let m = parse_map("# comment\nDB_PASS = \"aws-sm:prod/db\"\napi_key = 'json:s.json#a.b'\n")
            .unwrap();
        assert_eq!(
            m,
            [
                ("API_KEY".to_string(), "json:s.json#a.b".to_string()),
                ("DB_PASS".to_string(), "aws-sm:prod/db".to_string()),
            ]
        );
        for bad in [
            "",
            "A = 1",
            "\"A-B\" = \"vault:x/y\"",
            "A = \"s3:bucket/k\"",
            "A = \"json:nokey\"",
            "[t]\nA = \"vault:x/y\"",
            "A = ",
        ] {
            assert!(parse_map(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hashes_classify_create_update_unchanged() {
        assert_eq!(classify(b"v", None), Change::Create);
        assert_eq!(classify(b"v", Some(b"v")), Change::Unchanged);
        assert_eq!(classify(b"v", Some(b"w")), Change::Update);
        assert_eq!(classify(b"", Some(b"")), Change::Unchanged);
    }

    #[test]
    fn dry_run_classifies_without_pushing_and_a_real_run_pushes() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("remote.json");
        std::fs::write(&file, r#"{"same":"v1","old":"v0"}"#).unwrap();
        let t = |k: &str| JsonFileSyncer::from_path(&format!("{}#{k}", file.display())).unwrap();
        let v = |s: &str| Ok(ZeroString::from_string(s.into()));
        let before = std::fs::read(&file).unwrap();
        let rows: Vec<String> = [("same", "v1"), ("old", "v1"), ("new", "v1")]
            .iter()
            .map(|(k, val)| plan_row((k, "u"), v(val), &t(k), true).change)
            .collect();
        assert_eq!(rows, ["unchanged", "update", "create"]);
        assert_eq!(std::fs::read(&file).unwrap(), before, "dry run wrote");

        let r = plan_row(("old", "u"), v("v1"), &t("old"), false);
        assert_eq!((r.change.as_str(), r.error), ("update", None));
        let r = plan_row(("new", "u"), v("v2"), &t("new"), false);
        assert_eq!(r.change, "create");
        assert_eq!(t("old").pull().unwrap(), "v1");
        assert_eq!(t("new").pull().unwrap(), "v2");
        assert_eq!(
            plan_row(("old", "u"), v("v1"), &t("old"), true).change,
            "unchanged"
        );
    }

    #[test]
    fn an_unreadable_local_value_is_skipped_never_pushed() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("remote.json");
        let t = JsonFileSyncer::from_path(&format!("{}#k", file.display())).unwrap();
        let r = plan_row(
            ("SEALED", "u"),
            Err("credential unavailable".into()),
            &t,
            false,
        );
        assert_eq!(r.change, "skipped");
        assert_eq!(r.error.as_deref(), Some("credential unavailable"));
        assert!(!file.exists());
    }
}
