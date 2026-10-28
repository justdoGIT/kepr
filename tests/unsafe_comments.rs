// unsafe_comments.rs — every `unsafe {` block says why it is sound.
//
// A block needs a `SAFETY:` comment on its own line or in the two lines
// above it. ALLOWLIST holds the files that predate the rule, with the
// number of blocks still missing a comment; it only shrinks: a file may
// not gain a bare block, and an entry that is no longer needed must be
// removed (T13.23).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const ALLOWLIST: &[(&str, usize)] = &[
    ("crates/kepr-core/src/auth.rs", 3),
    ("crates/kepr-core/src/memfd.rs", 8),
    ("crates/kepr-core/src/seccomp.rs", 6),
    ("crates/kepr-core/src/secmem.rs", 2),
    ("crates/kepr-gate/src/service.rs", 2),
    ("crates/kepr-gate/src/session.rs", 2),
    ("crates/kepr-gate/src/vault.rs", 1),
    ("src/audit_chain.rs", 2),
    ("src/cli_aws/checkout.rs", 2),
    ("src/cli_clip/wl_wire.rs", 1),
    ("src/cli_doctor.rs", 4),
    ("src/cli_eco/tui_term.rs", 1),
    ("src/cli_exec.rs", 1),
    ("src/cli_input.rs", 2),
    ("src/cli_sandbox_seccomp.rs", 4),
    ("src/cli_sandbox_sys.rs", 1),
    ("src/cli_ssh_agent.rs", 1),
    ("src/daemon_memlock.rs", 1),
    ("src/daemon_singleton.rs", 1),
    ("src/daemon_socket.rs", 7),
];

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if !matches!(name, "target" | "fuzz") && !name.starts_with('.') {
                walk(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

fn is_unsafe_block(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("//") {
        return false;
    }
    let mut rest = line;
    while let Some(i) = rest.find("unsafe") {
        let before_ok = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric();
        let after = rest[i + 6..].trim_start();
        if before_ok && after.starts_with('{') {
            return true;
        }
        rest = &rest[i + 6..];
    }
    false
}

fn bare_blocks(text: &str) -> usize {
    let lines: Vec<&str> = text.lines().collect();
    (0..lines.len())
        .filter(|&i| is_unsafe_block(lines[i]))
        .filter(|&i| !lines[i.saturating_sub(2)..=i].iter().any(|l| l.contains("SAFETY:")))
        .count()
}

#[test]
fn every_unsafe_block_has_a_safety_comment() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    walk(&root.join("crates"), &mut files);
    let allow: BTreeMap<&str, usize> = ALLOWLIST.iter().copied().collect();
    let mut problems = Vec::new();
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        let n = bare_blocks(&fs::read_to_string(&f).unwrap());
        let allowed = allow.get(rel.as_str()).copied().unwrap_or(0);
        if n > allowed {
            problems.push(format!("{rel}: {n} unsafe block(s) without SAFETY: (allowed {allowed})"));
        } else if n < allowed {
            problems.push(format!("{rel}: only {n} left; lower its ALLOWLIST entry from {allowed}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_lint_sees_bare_and_commented_blocks() {
    assert_eq!(bare_blocks("fn f() {\n    unsafe { g() }\n}"), 1);
    assert_eq!(bare_blocks("// SAFETY: g is fine\nunsafe { g() }"), 0);
    assert_eq!(bare_blocks("let x = unsafe { g() }; // SAFETY: ok"), 0);
    assert_eq!(bare_blocks("// unsafe { not code }"), 0);
    assert_eq!(bare_blocks("unsafe fn f() {}"), 0);
}
