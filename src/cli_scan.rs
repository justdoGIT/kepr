// cli_scan.rs — `kepr scan [PATH...] [--staged]` (agent vault P6.4).
// Looks for API keys and private keys in files (the same shapes the
// gate's prompt DLP blocks, kepr_core::leak). Prints file:line:kind with
// the match masked, and fails when anything is found, so it works as a
// pre-commit hook:  printf 'kepr scan --staged\n' > .git/hooks/pre-commit
//
// Skips .git, target, node_modules, binary files and files over 2 MiB.

use std::path::{Path, PathBuf};
use std::process::Command;

use kepr_core::protocol::Response;

const MAX_FILE: u64 = 2 * 1024 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
];

pub struct Finding {
    pub path: PathBuf,
    pub line: usize,
    pub kind: &'static str,
    pub masked: String,
}

fn mask(s: &[u8]) -> String {
    let s = String::from_utf8_lossy(s);
    let keep: String = s.chars().take(6).collect();
    format!("{keep}…")
}

pub fn scan_bytes(path: &Path, data: &[u8]) -> Vec<Finding> {
    if data.contains(&0) {
        return Vec::new(); // binary
    }
    kepr_core::leak::find_all(data)
        .into_iter()
        .map(|h| Finding {
            path: path.to_path_buf(),
            line: 1 + data[..h.offset].iter().filter(|b| **b == b'\n').count(),
            kind: h.kind,
            masked: mask(&data[h.offset..h.offset + h.len]),
        })
        .collect()
}

fn walk(p: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return;
    };
    if meta.is_file() {
        if meta.len() <= MAX_FILE {
            out.push(p.to_path_buf());
        }
    } else if meta.is_dir() {
        let skip = p
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| SKIP_DIRS.contains(&n));
        if skip {
            return;
        }
        if let Ok(rd) = std::fs::read_dir(p) {
            let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                walk(&e, out);
            }
        }
    }
}

fn staged_files() -> Result<Vec<PathBuf>, String> {
    let out = Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"])
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err("not a git repository (or git failed)".into());
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| PathBuf::from(String::from_utf8_lossy(s).to_string()))
        .collect())
}

/// Staged files are scanned as staged (the index), not as in the worktree.
fn staged_content(path: &Path) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("show")
        .arg(format!(":{}", path.display()))
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

pub fn cmd_scan(paths: &[String], staged: bool) -> Response {
    let mut findings = Vec::new();
    if staged {
        let files = match staged_files() {
            Ok(f) => f,
            Err(e) => return Response::fail(e),
        };
        for f in files {
            if let Some(data) = staged_content(&f) {
                findings.extend(scan_bytes(&f, &data));
            }
        }
    } else {
        let roots: Vec<PathBuf> = if paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            paths.iter().map(PathBuf::from).collect()
        };
        let mut files = Vec::new();
        for r in &roots {
            walk(r, &mut files);
        }
        for f in files {
            if let Ok(data) = std::fs::read(&f) {
                findings.extend(scan_bytes(&f, &data));
            }
        }
    }
    for f in &findings {
        println!("{}:{}: {} ({})", f.path.display(), f.line, f.kind, f.masked);
    }
    if findings.is_empty() {
        crate::cli_ui::ok("no keys found");
        Response::Pong
    } else {
        Response::fail(format!(
            "{} possible secret(s) found; move them into kepr (`kepr agent adopt` / `kepr set`)",
            findings.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_masks_with_line_numbers() {
        let data = b"a=1\nkey = \"sk-ant-api03-abcdefghijklmnopqrstu\"\n";
        let f = scan_bytes(Path::new("x.env"), data);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].line, f[0].kind), (2, "Anthropic API key"));
        assert_eq!(f[0].masked, "sk-ant…");
        assert!(scan_bytes(Path::new("b"), b"\0sk-ant-api03-abcdefghijklmnopqrstu").is_empty());
    }

    #[test]
    fn walk_skips_vendored_dirs() {
        let d = std::env::temp_dir().join(format!("kepr-scan-{}", std::process::id()));
        std::fs::create_dir_all(d.join("node_modules")).unwrap();
        std::fs::write(d.join("node_modules/x"), "AKIAABCDEFGHIJKLMNOP").unwrap();
        std::fs::write(d.join("a.txt"), "fine").unwrap();
        let mut files = Vec::new();
        walk(&d, &mut files);
        assert_eq!(files, vec![d.join("a.txt")]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
