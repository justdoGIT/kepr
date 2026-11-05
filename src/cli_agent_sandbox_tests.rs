// Protected harness filesystem and network isolation regressions.
use super::*;

#[test]
fn codex_auth_cache_is_masked_without_reading_it() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("auth.json");
    std::fs::write(&cache, "synthetic-auth-sentinel").unwrap();
    let env = vec![("CODEX_HOME".into(), dir.path().display().to_string())];
    let plan = Plan::new(&["true".into()], env, 7000, false).unwrap();
    assert!(
        plan.hide_files
            .iter()
            .any(|p| p.as_bytes() == cache.as_os_str().as_encoded_bytes()),
        "the sandbox must cover the auth cache"
    );
}

#[test]
fn nested_hidden_dirs_are_dropped() {
    let p = |s: &str| PathBuf::from(s);
    assert_eq!(
        outermost(vec![
            p("/s/kepr/runtime/kepr"),
            p("/r/kepr/profiles/work"),
            p("/s/kepr"),
            p("/r/kepr"),
            p("/r/kepr2"),
            p("/r/kepr"),
        ]),
        [p("/r/kepr"), p("/r/kepr2"), p("/s/kepr")]
    );
}

#[test]
fn kepr_mount_points_are_hidden_too() {
    // T12.20: a `kepr mount` directory gets the same empty tmpfs.
    let dir = std::env::temp_dir().join(format!("kepr hide {}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let escaped = dir.display().to_string().replace(' ', "\\040");
    let mi = format!("40 22 0:35 / {escaped} ro,nosuid - fuse.kepr kepr ro\n");
    let gone = dir.join("missing");
    let mi = format!(
        "{mi}41 22 0:36 / {} ro - fuse.kepr kepr ro\n",
        gone.display()
    );
    let hidden = hide_dirs_with(&mi);
    assert!(hidden.contains(&dir), "{hidden:?}");
    assert!(!hidden.contains(&gone), "only existing directories");
    assert!(!hide_dirs_with("").contains(&dir));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn hide_dirs_only_existing_and_include_socket_dir_when_present() {
    for d in hide_dirs() {
        assert!(d.is_dir(), "{}", d.display());
    }
}

#[test]
fn relays_the_gate_port_then_database_and_tunnel_ports() {
    let mut plan = Plan::new(&["true".into()], vec![], 7000, true).unwrap();
    assert_eq!(plan.relay_ports(), vec![7000]);
    plan.extra_ports = vec![7001, 7002];
    assert_eq!(plan.relay_ports(), vec![7000, 7001, 7002]);
}

#[test]
fn ns_flags_add_net_only_when_isolating() {
    assert_eq!(ns_flags(true) & libc::CLONE_NEWNET, libc::CLONE_NEWNET);
    assert_eq!(ns_flags(false) & libc::CLONE_NEWNET, 0);
    assert_ne!(ns_flags(false) & libc::CLONE_NEWPID, 0);
}
