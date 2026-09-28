// file_size_limit.rs — pins the 350-LOC-per-file rule.
//
// Background: by 2026-04 the codebase had grown several files over
// 300 lines of production code each, the original ceiling. The
// 300-line limit was tightened from anecdotal worst-files-in-tree;
// 350 is the project's settled-on number after weighing how many
// files were borderline-violators that didn't actually need a split.
// The point of the cap is reviewer load and concept-per-file focus,
// not arbitrary line count — 350 hits both targets without
// generating refactor pressure for files that read fine at 320.
//
// What counts as "production LOC":
//
//   - Every line in the file UP TO the first `#[cfg(test)]`
//     directive. The test module at the bottom of the file is
//     conventional in Rust and shouldn't be penalised — splitting
//     `super::*` tests out into a separate file harms locality.
//   - Module doc comments at the top of the file count. They're
//     written once and rarely-edited, but a 200-line module-doc
//     comment is still a 200-line read for the next maintainer.
//
// What's exempt:
//
//   - Integration test files under `tests/*.rs` (this file is one).
//     Sequential test cases scale poorly when split; e2e.sh and the
//     systemd-unit test pin the same precedent.
//   - Build outputs under `target/` and hidden dirs.
//
// Enforcement model:
//
//   - PROD_LOC_LIMIT (350) applies to every `.rs` file under `src/`
//     and `crates/*/src/`.
//   - ALLOWLIST grandfathers files that were over the limit when
//     the rule landed (now down to 2 after the 300 → 350 raise).
//     Each entry pins the file's current size; the test fails if
//     the file grows beyond the pin, AND fails if a non-allowlisted
//     file exceeds the limit.
//   - When a grandfathered file drops below 350 LOC, remove it
//     from ALLOWLIST in the same PR that did the refactor — the
//     test will still pass, but the allowlist gets cleaner.
//
// Refactor backlog: each entry below is a candidate for splitting
// in a future PR. Don't refactor by introducing two 200-line files
// that just depend on each other to satisfy the limit; the rule is
// about code locality, not arbitrary file count. Justify the split
// (separate concept per file) in the refactor PR's body.

use std::fs;
use std::path::{Path, PathBuf};

/// Maximum production LOC for any `.rs` file under `src/` or
/// `crates/*/src/`. Test modules (everything after the first
/// `#[cfg(test)]`) don't count toward this.
const PROD_LOC_LIMIT: usize = 350;

/// Files grandfathered above the limit at the time the rule
/// landed. Each entry pins its current production LOC. Refactor
/// backlog — graduate files out of this list as their size drops.
///
/// At 350-LOC the only remaining violators are the two handler
/// modules whose per-operation handlers are tightly coupled to
/// shared audit / cache / version-state primitives; splitting
/// either prematurely would just trade locality for a multi-file
/// hop. Both are within ~1.5% of the ceiling — refactor pressure
/// kicks in the moment they grow.
const ALLOWLIST: &[(&str, usize)] = &[
    // daemon.rs grew from 349 → 391 in PR #?? (Phase 2 η FIDO2
    // unlock). The additions: FIDO2 dispatch arms (Fido2Register,
    // Fido2List), the new `daemon_handlers_get` module declaration,
    // and the `fido2` module declaration. Refactor candidate: move
    // the per-request handler dispatch into its own module
    // (`daemon_dispatch.rs`) so daemon.rs stays focused on the
    // accept loop and setup.
    ("src/daemon.rs", 489),
    ("src/crypto_inproc.rs", 382),
    ("src/cli_cmds.rs", 463),
];

fn count_production_loc(path: &Path) -> usize {
    let text = fs::read_to_string(path).expect("read source file");
    let mut count = 0;
    for line in text.lines() {
        // Stop at the first `#[cfg(test)]` directive. Everything
        // after is test code (the conventional `mod tests` at the
        // bottom of a Rust source file) and is subject to its own
        // scaling characteristics.
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        count += 1;
    }
    count
}

/// Recursively collect `.rs` files under `root`, skipping common
/// build outputs and hidden directories.
fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    if !root.is_dir() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
            if name == "target" || name.starts_with('.') {
                continue;
            }
            walk_rs_files(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_source_file_exceeds_loc_limit() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources: Vec<PathBuf> = Vec::new();
    walk_rs_files(&manifest_dir.join("src"), &mut sources);
    walk_rs_files(&manifest_dir.join("crates"), &mut sources);

    let mut violations = Vec::new();
    let mut stale_allowlist = Vec::new();

    for path in &sources {
        let rel = path
            .strip_prefix(&manifest_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        let loc = count_production_loc(path);
        let pinned = ALLOWLIST.iter().find(|(p, _)| *p == rel).map(|(_, l)| *l);
        let limit = pinned.unwrap_or(PROD_LOC_LIMIT);

        if loc > limit {
            violations.push(format!(
                "{rel}: {loc} LOC > {limit} (allowlisted: {})",
                pinned.is_some()
            ));
        }

        // Detect stale allowlist entries: a file that was
        // refactored below the limit no longer needs grandfathering.
        if let Some(pinned_size) = pinned {
            if loc <= PROD_LOC_LIMIT && pinned_size != loc {
                // The file has dropped below the global limit —
                // remove it from ALLOWLIST in your refactor PR.
                stale_allowlist.push(format!(
                    "{rel}: now {loc} LOC, pinned at {pinned_size} — \
                     drop the allowlist entry"
                ));
            }
        }
    }

    let mut messages = Vec::new();
    if !violations.is_empty() {
        messages.push(format!(
            "{} file(s) over the {PROD_LOC_LIMIT}-LOC production-code limit:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    if !stale_allowlist.is_empty() {
        messages.push(format!(
            "{} stale allowlist entry/entries (file dropped below limit, remove from ALLOWLIST):\n  {}",
            stale_allowlist.len(),
            stale_allowlist.join("\n  ")
        ));
    }
    assert!(messages.is_empty(), "{}", messages.join("\n\n"));
}

#[test]
fn allowlist_paths_actually_exist() {
    // A typo in ALLOWLIST silently grants the limit to a path
    // that doesn't exist. Pin against that.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for (rel, _) in ALLOWLIST {
        if !manifest_dir.join(rel).is_file() {
            missing.push(*rel);
        }
    }
    assert!(
        missing.is_empty(),
        "ALLOWLIST contains paths that don't exist on disk: {missing:?}"
    );
}
