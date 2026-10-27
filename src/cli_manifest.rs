// cli_manifest.rs — `.kepr.toml` project manifest.
//
// Lets a project declare its required credentials once, in a file
// committed to the repo, so the user can run `kepr exec -- python
// train.py` (no `--env CSV`) and have the right keys provisioned.
// The manifest is walked up from `$PWD` to `/`, first match wins —
// the same convention `git`, `cargo`, and `direnv` use.
//
// Schema:
//
//   [env]
//   required = ["DB_PASS", "DB_USER", "OPENAI_API_KEY"]
//
//   [env.map]                       # T5.06: VAR = a kepr:// reference
//   DATABASE_URL = "kepr://DB/url"
//
// Future fields go under their own `[…]` table; the parser ignores
// unknown tables (so a Phase 1 binary reading a Phase 2 manifest
// doesn't fail on a config-format-newer-than-tool mismatch — it
// just loses the new functionality).
//
// Resolution precedence (highest wins):
//
//   1. `--env CSV` on the CLI (explicit user override)
//   2. `--manifest /path/to/.kepr.toml` (explicit pin)
//
// Ancestor auto-discovery is intentionally opt-in through
// `KEPR_AUTO_MANIFEST=1`; this prevents an untrusted checkout from
// supplying a manifest that injects credentials into a child process.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli_recordsx::stages::{self, EnvSet};

/// Default manifest filename. Hidden so it doesn't clutter `ls`,
/// dotted so it sorts adjacent to `.gitignore` / `.envrc` in the
/// places where users edit them.
pub const MANIFEST_FILENAME: &str = ".kepr.toml";

/// Parsed manifest: the `[env].required` list, the `[env.map]`
/// references and the `[env.<stage>]` sets (cli_recordsx/stages.rs);
/// future fields land here as additional `pub` members.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub env_required: Vec<String>,
    /// `VAR=kepr://…` entries from `[env.map]`, checked at load.
    pub env_map: Vec<String>,
    /// T5.02: `[env.<stage>]` tables by stage name.
    pub stages: BTreeMap<String, EnvSet>,
}

impl Manifest {
    /// What `kepr exec` / `kepr env` provision: names, then references;
    /// with `stage`, merged with that stage's set.
    pub fn entries(self, stage: Option<&str>) -> Result<Vec<String>, String> {
        let base = EnvSet {
            required: self.env_required,
            map: self.env_map,
        };
        stages::merge(base, self.stages, stage)
    }
}

/// Walk `start` upward toward `/`, returning the first ancestor
/// (or `start` itself) that contains a regular file named
/// `.kepr.toml`. Returns `None` if the walk hits the filesystem
/// root with no match.
///
/// Path-traversal is bounded by the depth of `start`, which is
/// fine for any realistic project layout (deep monorepos run
/// ~10-20 components).
pub fn find_manifest(start: &Path) -> Option<PathBuf> {
    let mut current: Option<&Path> = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(MANIFEST_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        current = dir.parent();
    }
    None
}

/// Parse a manifest from a string. Used directly by tests and
/// from `parse_file` after the I/O step. Errors carry the toml
/// crate's parse-position context so the user can find the line
/// they typo'd.
pub fn parse_str(text: &str) -> Result<Manifest, String> {
    // The schema is small enough to parse via `toml::Value` rather
    // than a derived struct — keeps the dep surface minimal and
    // makes "ignore unknown sections" trivially the default.
    let v: toml::Value = toml::from_str(text).map_err(|e| format!("parse manifest: {e}"))?;

    let mut m = Manifest::default();
    if let Some(env_table) = v.get("env").and_then(|t| t.as_table()) {
        let base = stages::env_set(env_table, "env")?;
        (m.env_required, m.env_map) = (base.required, base.map);
        m.stages = stages::stages(env_table)?;
    }
    Ok(m)
}

/// Read and parse a manifest file. Composes `parse_str` with a
/// single `fs::read_to_string`, surfacing both the file-IO and the
/// parse error with enough context to find the offending file.
pub fn parse_file(path: &Path) -> Result<Manifest, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("read manifest {}: {e}", path.display()))?;
    parse_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Resolve the effective list of required env vars, applying the
/// precedence: CLI `--env` > `--manifest path`. Auto-discovery is
/// intentionally disabled by this safe default because an untrusted
/// checkout can provide a `.kepr.toml` that causes secrets to be
/// injected into an arbitrary child process.
pub fn resolve(
    cli_env: &[String],
    explicit_manifest: Option<&Path>,
    auto_start: &Path,
    stage: Option<&str>,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    resolve_internal(cli_env, explicit_manifest, auto_start, false, stage)
}

/// Resolve credentials with ancestor manifest discovery explicitly enabled.
/// The CLI exposes this through `KEPR_AUTO_MANIFEST=1`.
pub fn resolve_with_auto_discovery(
    cli_env: &[String],
    explicit_manifest: Option<&Path>,
    auto_start: &Path,
    stage: Option<&str>,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    resolve_internal(cli_env, explicit_manifest, auto_start, true, stage)
}

fn resolve_internal(
    cli_env: &[String],
    explicit_manifest: Option<&Path>,
    auto_start: &Path,
    auto_discover: bool,
    stage: Option<&str>,
) -> Result<(Vec<String>, Option<PathBuf>), String> {
    if !cli_env.is_empty() {
        return Ok((cli_env.to_vec(), None));
    }
    if let Some(p) = explicit_manifest {
        let m = parse_file(p)?;
        return Ok((m.entries(stage)?, Some(p.to_path_buf())));
    }
    if auto_discover {
        if let Some(p) = find_manifest(auto_start) {
            let m = parse_file(&p)?;
            return Ok((m.entries(stage)?, Some(p)));
        }
    }
    Ok((Vec::new(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_str_empty_yields_empty_required() {
        let m = parse_str("").unwrap();
        assert!(m.env_required.is_empty());
    }

    #[test]
    fn parse_str_no_env_section_yields_empty_required() {
        // A manifest that only sets future fields should not error.
        let m = parse_str("[other]\nfoo = 1\n").unwrap();
        assert!(m.env_required.is_empty());
    }

    #[test]
    fn parse_str_reads_env_required_array() {
        let m = parse_str(
            r#"
            [env]
            required = ["DB_PASS", "DB_USER", "OPENAI_API_KEY"]
            "#,
        )
        .unwrap();
        assert_eq!(m.env_required, vec!["DB_PASS", "DB_USER", "OPENAI_API_KEY"]);
    }

    #[test]
    fn parse_str_reads_env_map_references() {
        let m = parse_str(
            "[env]\nrequired = [\"A\"]\n[env.map]\nDB_URL = \"kepr://DB/url\"\nPIN = 'kepr://R/custom_field/a\\/b[1]'\n",
        )
        .unwrap();
        assert_eq!(
            m.env_map,
            [
                r"DB_URL=kepr://DB/url",
                r"PIN=kepr://R/custom_field/a\/b[1]"
            ]
        );
        assert_eq!(m.entries(None).unwrap().len(), 3);
        for (bad, what) in [
            ("[env.map]\nX = 1\n", "kepr:// string"),
            ("[env.map]\nX = \"DB\"\n", "starts with kepr://"),
            (
                "[env.map]\nX = \"kepr://DB/url[\"\n",
                "`[env.map]` X: kepr://DB/url[: unclosed [ at column 14",
            ),
            (
                "[env.map]\n\"1X\" = \"kepr://DB\"\n",
                "environment variable",
            ),
            ("[env]\nmap = 3\n", "must be a table"),
        ] {
            let e = parse_str(bad).unwrap_err();
            assert!(e.contains(what), "{bad}: {e}");
        }
    }

    #[test]
    fn parse_str_rejects_non_array_required() {
        let err = parse_str(
            r#"
            [env]
            required = "DB_PASS"
            "#,
        )
        .expect_err("string should be an array");
        assert!(err.contains("must be an array"), "msg: {err}");
    }

    #[test]
    fn parse_str_rejects_non_string_entries() {
        let err = parse_str(
            r#"
            [env]
            required = ["DB_PASS", 42]
            "#,
        )
        .expect_err("integer entry should fail");
        assert!(err.contains("only strings"), "msg: {err}");
    }

    #[test]
    fn parse_str_rejects_empty_entries() {
        let err = parse_str(
            r#"
            [env]
            required = ["DB_PASS", ""]
            "#,
        )
        .expect_err("empty string entry should fail");
        assert!(err.contains("empty entry"), "msg: {err}");
    }

    #[test]
    fn parse_str_rejects_malformed_toml() {
        let err = parse_str("this is not toml ===").expect_err("bad TOML must fail");
        assert!(err.contains("parse manifest"), "msg: {err}");
    }

    #[test]
    fn find_manifest_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(find_manifest(dir.path()), None);
    }

    #[test]
    fn find_manifest_returns_path_when_in_start_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, "").unwrap();
        let canon_expect = fs::canonicalize(&path).unwrap();
        let canon_got = fs::canonicalize(find_manifest(dir.path()).unwrap()).unwrap();
        assert_eq!(canon_got, canon_expect);
    }

    #[test]
    fn find_manifest_walks_up_from_nested_dir() {
        // Layout:
        //   /tmp/<root>/.kepr.toml
        //   /tmp/<root>/a/b/c/  ← start here
        let root = tempfile::tempdir().unwrap();
        let manifest = root.path().join(MANIFEST_FILENAME);
        fs::write(&manifest, "").unwrap();
        let nested = root.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();
        let found = find_manifest(&nested).expect("must walk up");
        // Compare canonicalised paths to handle platforms whose
        // tempdir paths route through /private/tmp etc.
        assert_eq!(
            fs::canonicalize(found).unwrap(),
            fs::canonicalize(manifest).unwrap()
        );
    }

    #[test]
    fn find_manifest_prefers_nearest_ancestor() {
        // Layout:
        //   /tmp/<root>/.kepr.toml          ← outer
        //   /tmp/<root>/a/.kepr.toml        ← inner (must win)
        //   /tmp/<root>/a/b/                ← start here
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(MANIFEST_FILENAME), "outer = 1").unwrap();
        let inner_dir = root.path().join("a");
        fs::create_dir_all(&inner_dir).unwrap();
        let inner = inner_dir.join(MANIFEST_FILENAME);
        fs::write(&inner, "inner = 1").unwrap();
        let start = inner_dir.join("b");
        fs::create_dir_all(&start).unwrap();
        let found = find_manifest(&start).expect("must find one");
        assert_eq!(
            fs::canonicalize(found).unwrap(),
            fs::canonicalize(inner).unwrap()
        );
    }

    #[test]
    fn parse_file_round_trips_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, "[env]\nrequired = [\"FOO\", \"BAR\"]\n").unwrap();
        let m = parse_file(&path).unwrap();
        assert_eq!(m.env_required, vec!["FOO", "BAR"]);
    }

    #[test]
    fn parse_file_surfaces_path_in_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, "this is not toml").unwrap();
        let err = parse_file(&path).expect_err("must surface parse error");
        assert!(err.contains(MANIFEST_FILENAME), "msg: {err}");
    }

    #[test]
    fn resolve_prefers_cli_env_over_manifest() {
        // Layout: a manifest with FOO; CLI passes BAR. CLI wins.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, "[env]\nrequired = [\"FOO\"]\n").unwrap();
        let cli = vec!["BAR".to_string()];
        let (resolved, used) = resolve(&cli, None, dir.path(), None).unwrap();
        assert_eq!(resolved, vec!["BAR"]);
        assert!(used.is_none(), "manifest must not be reported as used");
    }

    #[test]
    fn resolve_prefers_explicit_manifest_over_auto() {
        // Layout: an auto-discoverable manifest with FOO; an explicit
        // pin to a different file with BAR. Explicit wins.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            "[env]\nrequired = [\"FOO\"]\n",
        )
        .unwrap();
        let pinned = dir.path().join("alt.toml");
        fs::write(&pinned, "[env]\nrequired = [\"BAR\"]\n").unwrap();
        let (resolved, used) = resolve(&[], Some(&pinned), dir.path(), None).unwrap();
        assert_eq!(resolved, vec!["BAR"]);
        assert_eq!(
            fs::canonicalize(used.unwrap()).unwrap(),
            fs::canonicalize(pinned).unwrap()
        );
    }

    #[test]
    fn resolve_adds_the_named_stage() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = dir.path().join("staged.toml");
        fs::write(
            &pinned,
            "[env]\nrequired = [\"A\"]\n[env.dev]\nrequired = [\"B\"]\n[env.dev.map]\nU = \"kepr://DB/url\"\n",
        )
        .unwrap();
        let (r, _) = resolve(&[], Some(&pinned), dir.path(), Some("dev")).unwrap();
        assert_eq!(r, ["A", "B", "U=kepr://DB/url"]);
        let (r, _) = resolve(&[], Some(&pinned), dir.path(), None).unwrap();
        assert_eq!(r, ["A"]);
        let e = resolve(&[], Some(&pinned), dir.path(), Some("prod")).unwrap_err();
        assert!(e.contains("known stages: dev"), "{e}");
        // An explicit --env list ignores stages.
        let (r, _) = resolve(&["X".into()], Some(&pinned), dir.path(), Some("prod")).unwrap();
        assert_eq!(r, ["X"]);
    }

    #[test]
    fn resolve_falls_through_to_auto_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, "[env]\nrequired = [\"FOO\"]\n").unwrap();
        let (resolved, used) = resolve_with_auto_discovery(&[], None, dir.path(), None).unwrap();
        assert_eq!(resolved, vec!["FOO"]);
        assert!(used.is_some(), "auto-discovered path must be reported");
    }

    #[test]
    fn resolve_does_not_auto_discover_by_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            "[env]\nrequired = [\"UNTRUSTED\"]\n",
        )
        .unwrap();
        let (resolved, used) = resolve(&[], None, dir.path(), None).unwrap();
        assert!(resolved.is_empty());
        assert!(used.is_none());
    }

    #[test]
    fn resolve_returns_empty_when_nothing_found() {
        let dir = tempfile::tempdir().unwrap();
        let (resolved, used) = resolve(&[], None, dir.path(), None).unwrap();
        assert!(resolved.is_empty());
        assert!(used.is_none());
    }
}
