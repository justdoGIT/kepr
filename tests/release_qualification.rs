//! SEC-012: fail if qualification can be bypassed before signing a release.
//! These hermetic checks inspect the workflow graph; CI execution is separate.

use std::fs;
use std::path::Path;

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

fn job(workflow: &str, name: &str) -> String {
    let key = format!("  {name}:");
    let mut lines = workflow.lines().skip_while(|line| *line != key);
    assert!(lines.next().is_some(), "missing job {name}");
    lines
        .take_while(|line| {
            !(line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim_start().starts_with('#'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn dependencies(job: &str) -> Vec<&str> {
    job.lines()
        .find_map(|line| line.strip_prefix("    needs:"))
        .map(|value| {
            value
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(str::trim)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn qualification_is_required_before_build_sign_and_publish() {
    let workflow = read(".github/workflows/release.yml");
    let qualify = job(&workflow, "qualify");
    for name in ["build", "sign", "release"] {
        let block = job(&workflow, name);
        assert!(
            dependencies(&block).contains(&"qualify"),
            "{name} bypasses qualification"
        );
    }
    for command in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo test --workspace --all-targets --locked",
        "cargo test --manifest-path crates/kepr-pam/Cargo.toml --locked",
        "cargo audit --file Cargo.lock",
        "cargo audit --file crates/kepr-pam/Cargo.lock",
        "cargo deny check",
    ] {
        assert!(
            qualify.contains(command),
            "qualification is missing {command}"
        );
    }
    assert!(!qualify.lines().any(|l| l.starts_with("    if:")));
    assert!(
        !qualify.contains("continue-on-error:") || qualify.contains("continue-on-error: false")
    );
    assert!(!qualify.contains("id-token:") && !qualify.contains("attestations:"));
    assert!(!qualify.contains("rust-cache"));
}

#[test]
fn qualified_and_packaged_sources_use_the_same_immutable_tag_commit() {
    let workflow = read(".github/workflows/release.yml");
    let tag = job(&workflow, "tag-check");
    assert!(tag.contains("commit: ${{ steps.resolve.outputs.commit }}"));
    assert!(tag.contains("git rev-parse --verify \"refs/tags/$TAG^{commit}\""));
    assert!(tag.contains("git merge-base --is-ancestor \"$COMMIT\" refs/remotes/origin/main"));
    for name in ["qualify", "build", "changelog"] {
        let block = job(&workflow, name);
        assert!(
            block.contains("ref: ${{ needs.tag-check.outputs.commit }}"),
            "{name} follows a mutable ref"
        );
        assert!(
            block.contains("persist-credentials: false"),
            "{name} retains checkout credentials"
        );
    }
}

#[test]
fn normal_rust_ci_checks_every_workspace_member() {
    let workflow = read(".github/workflows/ci.yml");
    let rust = job(&workflow, "rust");
    assert!(rust.contains("cargo test --release --workspace --all-targets --locked"));
    assert!(rust
        .contains("cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"));
}

#[test]
fn pull_requests_cannot_select_persistent_runners() {
    for path in [
        ".github/workflows/ci.yml",
        ".github/workflows/security.yml",
        ".github/workflows/pr-reviewer.yml",
        ".github/workflows/performance.yml",
    ] {
        let workflow = read(path);
        for line in workflow
            .lines()
            .filter(|line| line.trim_start().starts_with("runs-on:"))
        {
            if line.contains("vars.") {
                assert!(
                    line.contains(
                        "fromJSON(github.event_name == 'pull_request' && '\"ubuntu-latest\"' ||"
                    ),
                    "PR runner selection is unsafe: {line}"
                );
            }
        }
    }
}

#[test]
fn code_execution_jobs_do_not_persist_checkout_credentials() {
    for path in [
        ".github/workflows/ci.yml",
        ".github/workflows/security.yml",
        ".github/workflows/pr-reviewer.yml",
        ".github/workflows/performance.yml",
    ] {
        let workflow = read(path);
        let lines: Vec<_> = workflow.lines().collect();
        for (i, _) in lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim_start().starts_with("- uses: actions/checkout@"))
        {
            let options = lines[i + 1..]
                .iter()
                .take_while(|line| !line.trim_start().starts_with("- "))
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                options.contains("persist-credentials: false"),
                "checkout retains credentials in {path}"
            );
        }
    }
}

#[test]
fn pull_request_benchmarks_do_not_require_cluster_tools_or_update_baselines() {
    let workflow = read(".github/workflows/performance.yml");
    for name in [
        "Use the cluster toolchain (devsetup-stable)",
        "Run the benchmarks",
    ] {
        let marker = format!("      - name: {name}");
        let block = workflow
            .lines()
            .skip_while(|line| *line != marker)
            .skip(1)
            .take_while(|line| !line.starts_with("      - "))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            block.contains("if: github.event_name != 'pull_request'"),
            "cluster-only step is available to a PR: {name}"
        );
    }
    assert!(workflow.contains("if: github.event_name == 'pull_request'"));
    assert!(workflow.contains("cargo bench --locked -p kepr-core --bench core"));
}

#[test]
fn scheduled_parser_fuzzing_is_pinned_bounded_and_unprivileged() {
    let workflow = read(".github/workflows/security.yml");
    let fuzz = job(&workflow, "parser-fuzz");
    assert!(fuzz.contains("github.event_name == 'schedule'"));
    assert!(fuzz.contains("runs-on: ubuntu-latest"));
    assert!(fuzz.contains("timeout-minutes: 30"));
    assert!(fuzz.contains("toolchain: nightly-2025-06-26"));
    assert!(fuzz.contains("cargo install cargo-fuzz --locked --version 0.13.1"));
    for limit in [
        "-max_total_time=60",
        "-timeout=5",
        "-rss_limit_mb=512",
        "-max_len=65536",
    ] {
        assert!(fuzz.contains(limit), "fuzzing is missing {limit}");
    }
    assert!(!fuzz.contains("id-token:") && !fuzz.contains("attestations:"));
    let manifest = read("crates/kepr-core/fuzz/Cargo.toml");
    for line in manifest
        .lines()
        .filter(|line| line.starts_with("path = \"fuzz_targets/"))
    {
        let target = line
            .strip_prefix("path = \"fuzz_targets/")
            .unwrap()
            .trim_end_matches(".rs\"");
        assert!(fuzz.contains(target), "scheduled fuzzing omits {target}");
    }
}
