// release_workflow.rs — pin how the release `build` job builds (T12.38).
//
// The SLSA provenance the release publishes says the artefacts came from
// this workflow; it only means "hermetic" if the build job builds from
// locked, pre-fetched sources with a pinned toolchain, no shared cache and
// no network. GitHub Actions can't run in the test suite, so, like
// `systemd_unit.rs` for the unit file, this checks the job's text.

use std::fs;
use std::path::PathBuf;

fn workflow() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    fs::read_to_string(p).expect("read release.yml")
}

/// A job: from `  NAME:` to the next job key at the same indent.
fn job(name: &str) -> Vec<String> {
    let wf = workflow();
    let key = format!("  {name}:");
    let mut lines = wf.lines().skip_while(|l| *l != key);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("{name} job"))
        .to_string();
    let rest = lines.take_while(|l| {
        let top = l.starts_with("  ") && !l.starts_with("   ");
        !(top && l.trim_end().ends_with(':') && !l.trim_start().starts_with('#'))
    });
    std::iter::once(first)
        .chain(rest.map(str::to_string))
        .collect()
}

/// The `build` job.
fn build_job() -> Vec<String> {
    job("build")
}

/// Shell lines of the job with `\` continuations joined, step names and
/// comments left out (a step called "cargo build" is not a build).
fn commands() -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for l in build_job() {
        let t = l.trim();
        if t.starts_with('#') || t.starts_with("- name:") || t.starts_with("name:") {
            continue;
        }
        match t.strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(t);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    out
}

#[test]
fn a_no_shared_cache() {
    for l in build_job() {
        assert!(!l.contains("rust-cache"), "build job uses a cache: {l}");
    }
}

#[test]
fn b_toolchain_is_an_exact_version() {
    let job = build_job();
    let at = job
        .iter()
        .position(|l| l.contains("dtolnay/rust-toolchain@"))
        .expect("rust-toolchain step");
    let input = job[at + 1..]
        .iter()
        .take_while(|l| !l.trim_start().starts_with("- "))
        .find_map(|l| l.trim().strip_prefix("toolchain:"))
        .expect("toolchain input")
        .trim()
        .trim_matches('"')
        .to_string();
    let parts: Vec<&str> = input.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "toolchain must be X.Y.Z, got {input:?}"
    );
}

#[test]
fn c_sources_are_fetched_locked_before_the_build() {
    let cmds = commands();
    let fetch = cmds
        .iter()
        .position(|c| c.contains("cargo fetch --locked"))
        .expect("a `cargo fetch --locked` step");
    let build = cmds
        .iter()
        .position(|c| c.contains("cargo build"))
        .expect("a cargo build");
    assert!(fetch < build, "cargo fetch must come before the build");
}

#[test]
fn d_every_build_is_frozen_and_offline() {
    let builds: Vec<String> = commands()
        .into_iter()
        .filter(|c| c.contains("cargo build"))
        .collect();
    assert!(!builds.is_empty(), "no cargo build in the build job");
    for c in &builds {
        assert!(c.contains("unshare --net"), "not network-isolated: {c}");
        // The probe must fail inside the namespace, before any build.
        let probe = c
            .find("! curl")
            .unwrap_or_else(|| panic!("no failing probe: {c}"));
        for seg in c.split("cargo build").skip(1) {
            let one = seg.split("&&").next().unwrap_or(seg);
            assert!(
                one.contains("--frozen"),
                "cargo build without --frozen: {c}"
            );
        }
        assert!(
            probe < c.find("cargo build").unwrap(),
            "probe after build: {c}"
        );
    }
}

#[test]
fn e_installs_are_locked_and_pinned() {
    for c in commands().iter().filter(|c| c.contains("cargo install")) {
        assert!(
            c.contains("--locked"),
            "cargo install without --locked: {c}"
        );
        let v = c
            .split_whitespace()
            .skip_while(|w| *w != "--version")
            .nth(1)
            .unwrap_or_else(|| panic!("cargo install without --version: {c}"));
        assert!(
            v.split('.').count() == 3 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
            "--version must be exact: {c}"
        );
    }
}

/// The ticket's rules: actions stay pinned by commit SHA in the jobs that
/// build and sign, and only the signing job holds `id-token: write`.
#[test]
fn actions_stay_pinned_and_only_the_signing_job_has_the_token() {
    for name in ["build", "sign"] {
        for l in job(name)
            .iter()
            .filter(|l| l.trim_start().starts_with("- uses:"))
        {
            let rev = l.split('@').nth(1).unwrap_or("").split_whitespace().next();
            let rev = rev.unwrap_or("");
            assert!(
                rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()),
                "action not pinned by SHA: {l}"
            );
        }
    }
    let has = |j: &[String], key: &str| {
        j.iter()
            .any(|l| l.trim().starts_with(key) && l.contains("write"))
    };
    let sign = job("sign");
    assert!(has(&sign, "id-token:") && has(&sign, "attestations:"));
    assert!(!has(&build_job(), "id-token:"), "build compiles code");
    assert!(!has(&build_job(), "attestations:"), "build compiles code");
}

/// Nothing that compiles third-party code runs where the OIDC token is.
#[test]
fn the_signing_job_runs_no_compiler() {
    for l in job("sign") {
        let t = l.trim();
        if t.starts_with('#') {
            continue;
        }
        for banned in ["cargo ", "rustc", "rust-toolchain", "make ", "npm ", "pip "] {
            assert!(!t.contains(banned), "sign job runs `{banned}`: {t}");
        }
    }
}

/// Build scripts run as the runner user, who has sudo and docker: the
/// isolated step must drop groups and capabilities and forbid new
/// privileges, and must not step back into sudo.
#[test]
fn e2_the_isolated_build_cannot_climb_back_out() {
    let builds: Vec<String> = commands()
        .into_iter()
        .filter(|c| c.contains("cargo build"))
        .collect();
    for c in &builds {
        for need in [
            "setpriv",
            "--clear-groups",
            "--no-new-privs",
            "--bounding-set=-all",
        ] {
            assert!(c.contains(need), "isolated build lacks {need}: {c}");
        }
        assert!(
            !c.contains("sudo -u") && !c.contains("su "),
            "the build must not switch users through sudo: {c}"
        );
        // `sudo` may appear only as the namespace's entry and as the check
        // that it no longer works.
        assert!(
            c.contains("! sudo -n true"),
            "no check that sudo is dead: {c}"
        );
        assert_eq!(c.matches("sudo").count(), 2, "{c}");
    }
}

/// The isolated build's output is checked before anything un-isolated runs:
/// nothing but target/ changed, no cargo config appeared, and the binaries
/// are hashed and verified again right before packaging.
#[test]
fn f_the_isolated_build_is_checked_before_packaging() {
    let job = build_job().join("\n");
    let at = |needle: &str| {
        job.find(needle)
            .unwrap_or_else(|| panic!("build job lacks {needle}"))
    };
    let build = at("cargo build --release --frozen");
    let check = at("git status --porcelain --ignored");
    let hashed = at("sha256sum target/release/kepr");
    let install = at("cargo install cargo-deb");
    let verify = at("sha256sum --check --strict");
    let deb = at("cargo deb --no-build");
    assert!(build < check && check < hashed && hashed < install);
    assert!(install < verify && verify < deb);
    assert!(job.contains(".cargo/config"), "no cargo config check");
}
