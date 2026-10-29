// packaging_assets.rs — pin what the .deb, the .rpm and the release tarball
// ship for unlock at login and the desktop Secret Service (T13.27, T13.28).
// Building a package needs the release pipeline; these checks keep its
// inputs from drifting: every file a package names exists, the two package
// lists agree, every user unit in the tree is shipped, and the release
// workflow builds, hashes and archives the PAM module.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn text(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn manifest() -> toml::Table {
    text("Cargo.toml").parse().expect("Cargo.toml parses")
}

/// (source, destination) pairs of the .deb.
fn deb_assets() -> Vec<(String, String)> {
    let m = manifest();
    m["package"]["metadata"]["deb"]["assets"]
        .as_array()
        .expect("deb assets")
        .iter()
        .map(|a| {
            let a = a.as_array().expect("an asset is [src, dest, mode]");
            (
                a[0].as_str().unwrap().to_string(),
                a[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// (source, destination) pairs of the .rpm.
fn rpm_assets() -> Vec<(String, String)> {
    let m = manifest();
    m["package"]["metadata"]["generate-rpm"]["assets"]
        .as_array()
        .expect("rpm assets")
        .iter()
        .map(|a| {
            (
                a["source"].as_str().unwrap().to_string(),
                a["dest"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn sources(v: &[(String, String)]) -> BTreeSet<String> {
    v.iter().map(|(s, _)| s.clone()).collect()
}

#[test]
fn every_file_a_package_names_exists_unless_the_build_makes_it() {
    for (kind, list) in [("deb", deb_assets()), ("rpm", rpm_assets())] {
        for (src, _) in list {
            if src.starts_with("target/") {
                continue;
            }
            assert!(root().join(&src).is_file(), "{kind} asset {src} is missing");
        }
    }
}

#[test]
fn the_deb_and_the_rpm_ship_the_same_files() {
    // pam-auth-update is Debian's; the rpm leaves the stacks to authselect.
    let mut deb = sources(&deb_assets());
    assert!(deb.remove("packaging/pam-configs/kepr"));
    let rpm = sources(&rpm_assets());
    assert_eq!(
        deb,
        rpm,
        "only in deb: {:?}; only in rpm: {:?}",
        deb.difference(&rpm).collect::<Vec<_>>(),
        rpm.difference(&deb).collect::<Vec<_>>()
    );
}

#[test]
fn every_user_unit_in_the_tree_is_shipped_to_the_user_unit_directory() {
    let mut units = Vec::new();
    for e in fs::read_dir(root().join("systemd/user")).unwrap().flatten() {
        units.push(e.file_name().to_string_lossy().into_owned());
    }
    assert!(
        units.iter().any(|u| u == "kepr-secret-service.service"),
        "{units:?}"
    );
    for (kind, list) in [("deb", deb_assets()), ("rpm", rpm_assets())] {
        for u in &units {
            let want = (
                format!("systemd/user/{u}"),
                format!("/usr/lib/systemd/user/{u}"),
            );
            assert!(
                list.contains(&want),
                "{kind} does not ship {u} to /usr/lib/systemd/user"
            );
        }
    }
}

#[test]
fn the_pam_module_goes_where_each_family_keeps_pam_modules() {
    let so = "target/pam/release/libpam_kepr.so";
    let dest =
        |list: &[(String, String)]| list.iter().find(|(s, _)| s == so).map(|(_, d)| d.clone());
    assert_eq!(
        dest(&deb_assets()).as_deref(),
        Some("/usr/lib/x86_64-linux-gnu/security/pam_kepr.so")
    );
    assert_eq!(
        dest(&rpm_assets()).as_deref(),
        Some("/usr/lib64/security/pam_kepr.so")
    );
    assert!(deb_assets().contains(&(
        "packaging/pam-configs/kepr".into(),
        "/usr/share/pam-configs/kepr".into()
    )));
}

#[test]
fn the_debian_scripts_register_and_unregister_the_pam_profile() {
    let post = text("packaging/debian/postinst");
    assert!(
        post.contains("pam-auth-update --package"),
        "postinst does not register the profile"
    );
    let code: String = post
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("--enable"),
        "installing the package must not switch login unlock on"
    );
    let rm = text("packaging/debian/postrm");
    assert!(rm.contains("pam-auth-update --package --remove kepr"));
    assert!(rm.contains("remove") && rm.contains("purge"));
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(root().join("packaging/debian/postrm"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "postrm must be executable");
}

#[test]
fn the_release_workflow_builds_hashes_and_archives_the_pam_module() {
    let w = text(".github/workflows/release.yml");
    let build = "cargo build --release --frozen --manifest-path crates/kepr-pam/Cargo.toml --target-dir target/pam";
    assert!(
        w.contains(build),
        "the isolated build does not build pam_kepr.so inside target/"
    );
    assert!(
        w.contains("cargo fetch --locked --manifest-path crates/kepr-pam/Cargo.toml"),
        "its sources are not fetched before the network goes"
    );
    let hashed = w
        .split("sha256sum target/release/kepr ")
        .nth(1)
        .expect("the binaries are hashed");
    assert!(
        hashed.contains("target/pam/release/libpam_kepr.so"),
        "the module is not in the hash list"
    );
    assert!(
        w.contains("dist/${STAGE}/pam_kepr.so") && w.contains("systemd/user/*.service"),
        "the tarball lacks the module or the units"
    );
}

#[test]
fn the_secret_service_unit_is_a_bus_service_that_reloads_its_policy() {
    let u = text("systemd/user/kepr-secret-service.service");
    let lines: Vec<&str> = u
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    for want in [
        "Type=dbus",
        "BusName=org.freedesktop.secrets",
        "ExecStart=/usr/local/bin/kepr secret-service run",
        "ExecReload=/bin/kill -HUP $MAINPID",
        "NoNewPrivileges=yes",
        "UMask=0077",
    ] {
        assert!(
            lines.contains(&want),
            "kepr-secret-service.service lost {want}"
        );
    }
    assert!(
        !lines.iter().any(|l| l.starts_with("[Install]")),
        "nothing may start it at login but the bus"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("PrivateTmp")),
        "the unlock dialog needs the X11 socket in /tmp"
    );
}
