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
    metadata(m, "deb")["assets"]
        .as_array()
        .expect("deb assets")
        .iter()
        .map(|a| {
            let a = a.as_array().expect("deb asset is an array");
            let s = |i: usize| a[i].as_str().expect("asset field").to_string();
            (s(0), s(1))
        })
        .collect()
}

/// `(source, dest)` of every `[package.metadata.generate-rpm]` asset.
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
