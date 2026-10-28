// packaging_assets.rs — pin what the .deb, .rpm and release tarball ship.
//
// `cargo deb` and `cargo generate-rpm` read the asset maps in Cargo.toml;
// neither tool runs in the test suite, so this checks their inputs: the
// asset tables, the maintainer scripts and the tarball step of the release
// workflow. A package that silently drops a file install.sh installs fails
// here instead of on a user's machine.

use std::fs;
use std::path::PathBuf;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn text(rel: &str) -> String {
    fs::read_to_string(repo(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn manifest() -> toml::Table {
    text("Cargo.toml").parse().expect("Cargo.toml parses")
}

fn metadata<'a>(m: &'a toml::Table, tool: &str) -> &'a toml::Table {
    m["package"]["metadata"][tool]
        .as_table()
        .unwrap_or_else(|| panic!("[package.metadata.{tool}] missing"))
}

/// `(source, dest)` of every `[package.metadata.deb]` asset
/// (`[source, dest, mode]` arrays).
fn deb_assets(m: &toml::Table) -> Vec<(String, String)> {
    deb_assets_with_mode(m)
        .into_iter()
        .map(|(s, d, _)| (s, d))
        .collect()
}

fn deb_assets_with_mode(m: &toml::Table) -> Vec<(String, String, String)> {
    metadata(m, "deb")["assets"]
        .as_array()
        .expect("deb assets")
        .iter()
        .map(|a| {
            let a = a.as_array().expect("deb asset is an array");
            let s = |i: usize| a[i].as_str().expect("asset field").to_string();
            (s(0), s(1), s(2))
        })
        .collect()
}

/// Every `[package.metadata.generate-rpm]` asset table.
fn rpm_assets(m: &toml::Table) -> Vec<toml::Table> {
    metadata(m, "generate-rpm")["assets"]
        .as_array()
        .expect("rpm assets")
        .iter()
        .map(|a| a.as_table().expect("rpm asset is a table").clone())
        .collect()
}

fn rpm_script(m: &toml::Table, key: &str) -> String {
    metadata(m, "generate-rpm")[key]
        .as_str()
        .unwrap_or_else(|| panic!("rpm {key} missing"))
        .to_string()
}

const PROFILE: &str = "packaging/apparmor/kepr";
const PROFILE_DEST: &str = "/etc/apparmor.d/kepr";

/// T12.34: the agent sandbox's AppArmor profile is in both packages,
/// as a config file in the rpm.
#[test]
fn apparmor_profile_is_packaged() {
    let m = manifest();
    assert!(
        deb_assets(&m).contains(&(PROFILE.into(), PROFILE_DEST.into())),
        "deb assets must install {PROFILE} to {PROFILE_DEST}"
    );
    let rpm = rpm_assets(&m);
    let a = rpm
        .iter()
        .find(|a| a["dest"].as_str() == Some(PROFILE_DEST))
        .expect("rpm asset for the AppArmor profile");
    assert_eq!(a["source"].as_str(), Some(PROFILE));
    assert_eq!(a.get("config").and_then(|c| c.as_bool()), Some(true));
}

/// T12.34: both post-install scripts load the profile, only where AppArmor
/// runs, and never fail the install over it.
#[test]
fn post_install_loads_the_profile() {
    let m = manifest();
    for (what, s) in [
        (
            "packaging/debian/postinst",
            text("packaging/debian/postinst"),
        ),
        (
            "rpm post_install_script",
            rpm_script(&m, "post_install_script"),
        ),
    ] {
        let line = s
            .lines()
            .find(|l| l.contains("apparmor_parser -r"))
            .unwrap_or_else(|| panic!("{what} must run apparmor_parser -r"));
        assert!(line.contains("|| true"), "{what}: {line}");
        assert!(
            s.contains("command -v apparmor_parser") && s.contains("/sys/kernel/security/apparmor"),
            "{what} must check AppArmor is present first"
        );
    }
}

/// T12.34: the tarball carries the profile where install.sh looks for it.
#[test]
fn tarball_carries_the_profile() {
    let wf = text(".github/workflows/release.yml");
    assert!(
        text("install.sh").contains(PROFILE),
        "install.sh reads the profile from {PROFILE}"
    );
    assert!(
        wf.lines().any(|l| l.trim_start().starts_with("cp ")
            && l.contains(PROFILE)
            && l.contains("${STAGE}/packaging/apparmor")),
        "release.yml's tarball step must copy {PROFILE} into the stage"
    );
}

/// Runs a maintainer script with every tool it calls replaced by a stub
/// that logs its argv and fails (`getent` and `ps` excepted, so the script
/// gets past group creation and the rpm's systemd check). The host paths
/// the scripts test are swapped for temp dirs, so both branches run here.
fn run_script(body: &str, args: &[&str], systemd: bool, apparmor: bool) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let log = dir.path().join("log");
    let stub = |name: &str, tail: &str| {
        let p = bin.join(name);
        let s = format!("#!/bin/sh\necho \"{name} $*\" >> \"$LOG\"\n{tail}\n");
        fs::write(&p, s).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub("getent", "exit 0");
    stub("ps", "echo systemd");
    for t in [
        "addgroup",
        "groupadd",
        "deb-systemd-helper",
        "systemctl",
        "apparmor_parser",
    ] {
        stub(t, "exit 1");
    }
    let fake = |name: &str, present: bool| {
        let p = dir.path().join(name);
        if present {
            fs::create_dir(&p).unwrap();
        }
        p.display().to_string()
    };
    let script = body
        .replace("/run/systemd/system", &fake("systemd", systemd))
        .replace("/sys/kernel/security/apparmor", &fake("apparmor", apparmor));
    let path = dir.path().join("script");
    fs::write(&path, script).unwrap();
    let ok = std::process::Command::new("/bin/sh")
        .arg(&path)
        .args(args)
        .env_clear()
        .env("PATH", &bin)
        .env("LOG", &log)
        .status()
        .expect("run /bin/sh")
        .success();
    (ok, fs::read_to_string(&log).unwrap_or_default())
}

/// T12.34: a failing or missing AppArmor never fails the install, and the
/// profile is loaded only where AppArmor runs.
#[test]
fn post_install_survives_apparmor() {
    let m = manifest();
    for (what, s) in [
        ("postinst", text("packaging/debian/postinst")),
        ("rpm post", rpm_script(&m, "post_install_script")),
    ] {
        for apparmor in [false, true] {
            let (ok, log) = run_script(&s, &["configure"], true, apparmor);
            assert!(ok, "{what} failed (apparmor={apparmor}): {log}");
            let loaded = log.contains("apparmor_parser -r -W /etc/apparmor.d/kepr");
            assert_eq!(loaded, apparmor, "{what}: {log}");
        }
    }
}

/// T12.37: `(source, dest, mode)` the packages must install: what install.sh
/// installs (binaries, units, polkit action, AppArmor profile) plus docs.
const EXPECTED: &[(&str, &str, &str)] = &[
    ("target/release/kepr", "/usr/local/bin/kepr", "0755"),
    (
        "target/release/kepr-daemon",
        "/usr/local/bin/kepr-daemon",
        "0755",
    ),
    (
        "target/release/docker-credential-kepr",
        "/usr/local/bin/docker-credential-kepr",
        "0755",
    ),
    (
        "target/release/git-credential-kepr",
        "/usr/local/bin/git-credential-kepr",
        "0755",
    ),
    // The daemon's default gate path (daemon_gatex/spawn.rs).
    (
        "target/release/kepr-gate",
        "/usr/local/bin/kepr-gate",
        "0755",
    ),
    (
        "systemd/kepr.service",
        "/lib/systemd/system/kepr.service",
        "0644",
    ),
    (
        "systemd/kepr-gate.service",
        "/lib/systemd/system/kepr-gate.service",
        "0644",
    ),
    (
        "systemd/polkit/io.kepr.policy",
        "/usr/share/polkit-1/actions/io.kepr.policy",
        "0644",
    ),
    (PROFILE, PROFILE_DEST, "0644"),
    (
        "completions/kepr.bash",
        "/usr/share/bash-completion/completions/kepr",
        "0644",
    ),
    ("README.md", "/usr/share/doc/kepr/README.md", "0644"),
    ("SECURITY.md", "/usr/share/doc/kepr/SECURITY.md", "0644"),
    ("LICENSE-MIT", "/usr/share/doc/kepr/LICENSE-MIT", "0644"),
    (
        "LICENSE-APACHE",
        "/usr/share/doc/kepr/LICENSE-APACHE",
        "0644",
    ),
];

/// T12.37: both packages ship everything install.sh installs.
#[test]
fn packages_ship_what_install_sh_installs() {
    let m = manifest();
    let deb = deb_assets_with_mode(&m);
    let rpm: Vec<(String, String, String)> = rpm_assets(&m)
        .iter()
        .map(|a| {
            let s = |k: &str| a[k].as_str().expect("rpm asset field").to_string();
            (s("source"), s("dest"), s("mode"))
        })
        .collect();
    for (src, dest, mode) in EXPECTED {
        let want = (src.to_string(), dest.to_string(), mode.to_string());
        assert!(deb.contains(&want), "deb assets miss {want:?}");
        assert!(rpm.contains(&want), "rpm assets miss {want:?}");
    }
}

/// T12.37: every asset source exists, or is a release binary this
/// workspace builds (a root `[[bin]]`, or kepr-gate), or is the PAM
/// module the release job builds from `crates/kepr-pam` into `target/pam`
/// (T13.27; `tests/desktop_packaging.rs` pins that build step).
#[test]
fn every_asset_source_exists_or_is_built() {
    let m = manifest();
    let mut bins: Vec<String> = m["bin"]
        .as_array()
        .expect("[[bin]]")
        .iter()
        .map(|b| b["name"].as_str().expect("bin name").to_string())
        .collect();
    bins.push("kepr-gate".into());
    let rpm = rpm_assets(&m);
    let sources = deb_assets(&m).into_iter().map(|(s, _)| s).chain(
        rpm.iter()
            .map(|a| a["source"].as_str().expect("source").to_string()),
    );
    for src in sources {
        if let Some(lib) = src.strip_prefix("target/pam/release/") {
            assert_eq!(lib, "libpam_kepr.so", "{src} is not built by the PAM crate");
            continue;
        }
        match src.strip_prefix("target/release/") {
            Some(bin) => assert!(bins.iter().any(|b| b == bin), "{src} is not built here"),
            None => assert!(repo(&src).is_file(), "{src} is missing"),
        }
    }
}

/// The `build` job's text, from its key to the next job.
fn build_job() -> String {
    let wf = text(".github/workflows/release.yml");
    let start = wf.find("\n  build:\n").expect("build job");
    let rest = &wf[start + 1..];
    let end = rest[1..]
        .find("\n  # ─── 2b.")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// T12.37: the release builds kepr-gate and the tarball carries the gate,
/// both credential helpers and the gate's unit.
#[test]
fn release_builds_and_ships_the_gate() {
    let job = build_job();
    assert!(
        job.lines()
            .any(|l| l.contains("cargo build") && l.contains("-p kepr-gate")),
        "release.yml must build kepr-gate"
    );
    let tarball = &job[job.find("name: Build tarball").expect("tarball step")..];
    let tarball = &tarball[..tarball[1..]
        .find("- name:")
        .map_or(tarball.len(), |i| i + 1)];
    for f in [
        "target/release/kepr-gate",
        "target/release/git-credential-kepr",
        "target/release/docker-credential-kepr",
        "systemd/kepr-gate.service",
        "systemd/polkit/io.kepr.policy",
    ] {
        assert!(
            tarball
                .lines()
                .any(|l| l.trim_start().starts_with("cp ") && l.contains(f)),
            "the tarball step must copy {f}"
        );
    }
}

/// An upgrade reloads the units and restarts only running ones: it never
/// enables or starts what the administrator turned off.
#[test]
fn upgrades_restart_running_units_and_enable_nothing() {
    let m = manifest();
    for (what, s, args) in [
        (
            "postinst",
            text("packaging/debian/postinst"),
            vec!["configure", "0.3.0"],
        ),
        ("rpm post", rpm_script(&m, "post_install_script"), vec!["2"]),
    ] {
        let (ok, log) = run_script(&s, &args, true, false);
        assert!(ok, "{what}: {log}");
        for unit in ["kepr.service", "kepr-gate.service"] {
            assert!(
                log.contains(&format!("try-restart {unit}")),
                "{what}: {log}"
            );
        }
        assert!(
            !log.contains("enable") && !log.contains(" restart "),
            "{what} enables or force-restarts on upgrade: {log}"
        );
    }
}

/// T12.37: the package starts the gate service after daemon-reload, and
/// stops it on removal only; a failing systemctl never fails either.
#[test]
fn maintainer_scripts_manage_the_gate_service() {
    let m = manifest();
    for (what, s) in [
        ("postinst", text("packaging/debian/postinst")),
        ("rpm post", rpm_script(&m, "post_install_script")),
    ] {
        let (ok, log) = run_script(&s, &["configure"], true, false);
        assert!(ok, "{what}: {log}");
        let lines: Vec<&str> = log.lines().collect();
        let at = |pat: &str| {
            lines
                .iter()
                .position(|l| l.starts_with("systemctl ") && l.contains(pat))
                .unwrap_or_else(|| panic!("{what}: no systemctl {pat}: {log}"))
        };
        assert!(
            at("daemon-reload") < at("enable kepr-gate.service"),
            "{what}: enable after daemon-reload: {log}"
        );
        assert!(log.contains("restart kepr-gate.service"), "{what}: {log}");
    }
    let prerm = text("packaging/debian/prerm");
    let (ok, log) = run_script(&prerm, &["remove"], true, false);
    assert!(ok, "{log}");
    assert!(log.contains("stop kepr-gate.service"), "{log}");
    assert!(log.contains("disable kepr-gate.service"), "{log}");
    let (ok, log) = run_script(&prerm, &["upgrade"], true, false);
    assert!(
        ok && !log.contains("kepr-gate"),
        "upgrade keeps the gate: {log}"
    );

    let pre = rpm_script(&m, "pre_uninstall_script");
    let (ok, log) = run_script(&pre, &["0"], true, false);
    assert!(ok, "{log}");
    assert!(log.contains("disable --now kepr-gate.service"), "{log}");
    let (ok, log) = run_script(&pre, &["1"], true, false);
    assert!(
        ok && !log.contains("kepr-gate"),
        "upgrade keeps the gate: {log}"
    );
}
