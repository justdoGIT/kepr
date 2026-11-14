use super::*;
use std::path::PathBuf;

#[test]
fn workspace_policy_rejects_ambient_roots_and_requires_landlock() {
    assert!(WorkspaceLayout::new(PathBuf::from("/")).is_err());
    assert!(WorkspaceLayout::new(PathBuf::from("relative/session")).is_err());
    assert!(WorkspaceLayout::new(PathBuf::from("/tmp/session/../outside")).is_err());
    let layout = WorkspaceLayout::new(PathBuf::from("/tmp/private-session")).unwrap();
    for forbidden in ["/", "/etc", "/home/operator", "/etc/credstore.encrypted"] {
        assert!(FilesystemPolicy::new(layout.clone(), vec![PathBuf::from(forbidden)]).is_err());
    }
    assert_eq!(capability().required_landlock_abi, 3);
}

#[test]
fn derived_private_paths_are_distinct_and_never_grant_the_parent() {
    let layout = WorkspaceLayout::new(PathBuf::from("/tmp/private-session")).unwrap();
    assert_eq!(
        layout.home(),
        std::path::Path::new("/tmp/private-session/home")
    );
    assert_eq!(
        layout.workspace(),
        std::path::Path::new("/tmp/private-session/workspace")
    );
    assert_eq!(
        layout.tmp(),
        std::path::Path::new("/tmp/private-session/tmp")
    );
    assert_eq!(
        layout.config(),
        std::path::Path::new("/tmp/private-session/config")
    );
    let policy = FilesystemPolicy::new(layout, vec![PathBuf::from("/usr")]).unwrap();
    assert!(policy
        .runtime()
        .iter()
        .all(|path| path != std::path::Path::new("/")));
}

#[cfg(target_os = "linux")]
#[test]
fn scoped_filesystem_denies_outside_reads_and_symlink_escapes() {
    use std::os::unix::fs::{symlink, DirBuilderExt};
    if crate::landlock::abi() < 3 {
        eprintln!("skip: scoped workspace requires Landlock ABI 3");
        return;
    }
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("kepr-scope-{}-{unique}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .unwrap();
    let session = base.join("session");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&session)
        .unwrap();
    let layout = WorkspaceLayout::new(session.canonicalize().unwrap()).unwrap();
    for directory in [
        layout.home(),
        layout.workspace(),
        layout.tmp(),
        layout.config(),
    ] {
        std::fs::create_dir(directory).unwrap();
    }
    let inside = layout.workspace().join("inside");
    let outside = base.join("outside");
    let escape = layout.workspace().join("escape");
    let readonly = layout.config().join("config");
    std::fs::write(&inside, "inside").unwrap();
    std::fs::write(&outside, "outside").unwrap();
    std::fs::write(&readonly, "config").unwrap();
    symlink(&outside, &escape).unwrap();
    let policy = FilesystemPolicy::new(layout, vec![]).unwrap();
    // SAFETY: this child only installs restrictions, uses fixtures and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let allowed = restrict_filesystem(&policy).is_ok()
            && std::fs::read(&inside).is_ok()
            && std::fs::read(&readonly).is_ok()
            && std::fs::write(policy.layout().workspace().join("new"), "allowed").is_ok()
            && std::fs::read(&outside).is_err()
            && std::fs::read(&escape).is_err()
            && std::fs::hard_link(
                &readonly,
                policy.layout().workspace().join("mutable-config"),
            )
            .is_err()
            && std::fs::write(&outside, "denied").is_err()
            && std::fs::write(&readonly, "denied").is_err();
        // SAFETY: skip destructors in the restricted forked child.
        unsafe { libc::_exit(i32::from(!allowed)) };
    }
    let mut status = 0;
    // SAFETY: wait for our own child and inspect its status.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    std::fs::remove_dir_all(&base).unwrap();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
