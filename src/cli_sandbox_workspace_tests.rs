use super::*;

    #[test]
    fn source_reopen_keeps_renamed_inode_and_refuses_deleted_replacements() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input");
        let moved = root.path().join("moved");
        std::fs::write(&path, "original").unwrap();
        let pinned = File::open(&path).unwrap();
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        let local = namespace_source(pinned.as_raw_fd()).unwrap();
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{}", local.as_raw_fd())).unwrap(),
            b"original"
        );
        std::fs::remove_file(&moved).unwrap();
        std::fs::write(&moved, "replacement").unwrap();
        assert!(namespace_source(pinned.as_raw_fd()).is_err());
    }

    #[test]
    fn top_level_runtime_roots_reopen_from_the_filesystem_root() {
        use std::os::unix::fs::OpenOptionsExt;
        // `/usr` is a runtime mount root, so its parent is `/`, which scoped
        // path validation rejects; the reopen must still reach it.
        let pinned = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/usr")
            .unwrap();
        let local = namespace_source(pinned.as_raw_fd()).unwrap();
        let original = std::fs::metadata("/usr").unwrap();
        let reopened = local.metadata().unwrap();
        assert_eq!(
            (original.dev(), original.ino()),
            (reopened.dev(), reopened.ino())
        );
    }

    fn enter_namespace() -> Result<(), std::io::Error> {
        // SAFETY: this runs only in a forked test child; IDs have no failure mode.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // SAFETY: unshare takes only namespace flags.
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        crate::cli_sandbox_sys::write_id_maps(uid, gid).unwrap();
        Ok(())
    }

    fn flags(path: &Path) -> libc::c_ulong {
        let path = cpath(path).unwrap();
        let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: path is terminated and info points to writable storage.
        assert_eq!(
            unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) },
            0
        );
        // SAFETY: statvfs initialized info on success.
        unsafe { info.assume_init().f_flag }
    }

    fn mount_regression(root: &Path) {
        match enter_namespace() {
            Ok(()) => {}
            Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)) => {
                eprintln!("skip mount regression: user namespaces unavailable: {error}");
                return;
            }
            Err(error) => panic!("user namespace setup failed: {error}"),
        }
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .unwrap();
        let source = root.join("source");
        let readonly = root.join("readonly");
        let writable = root.join("writable");
        for path in [&source, &readonly, &writable] {
            mkdir(path).unwrap();
        }
        let fs = c"tmpfs".to_owned();
        let inherited = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOATIME;
        mount(Some(&fs), &source, Some(&fs), inherited, None).unwrap();
        std::fs::write(source.join("input"), "original").unwrap();
        let pinned = File::open(&source).unwrap();
        let null = File::open("/dev/null").unwrap();
        let null_flags = flags(Path::new("/dev/null"));
        bind(pinned.as_raw_fd(), &readonly, true, true).unwrap();
        assert_eq!(std::fs::read(readonly.join("input")).unwrap(), b"original");
        assert_eq!(
            std::fs::write(readonly.join("input"), "forbidden")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        let expected =
            libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC | libc::ST_NOATIME | libc::ST_RDONLY;
        assert_eq!(flags(&readonly) & expected, expected);
        bind(pinned.as_raw_fd(), &writable, false, true).unwrap();
        std::fs::write(writable.join("input"), "changed").unwrap();
        assert_eq!(std::fs::read(source.join("input")).unwrap(), b"changed");
        let device = root.join("null");
        File::create(&device).unwrap();
        bind(null.as_raw_fd(), &device, false, false).unwrap();
        std::fs::write(&device, "discarded").unwrap();
        let restrictions = libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC | libc::ST_NOATIME;
        assert_eq!(
            flags(&device) & null_flags & restrictions,
            null_flags & restrictions
        );
        // A descriptor pinned before this namespace cannot be re-imported: the
        // kernel renders such an fd as the nearest directory visible here, so a
        // bind would hand the harness this namespace's own root (or a sibling
        // tree) instead of the pinned inode. The reopen must fail closed.
        let escape = root.join("escape");
        mkdir(&escape).unwrap();
        let before = std::fs::metadata(&source).unwrap();
        let nested = enter_namespace();
        if let Err(error) = nested {
            assert!(
                matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOSYS)),
                "nested namespace setup failed: {error}"
            );
            return;
        }
        let refused = bind(pinned.as_raw_fd(), &escape, true, true);
        assert!(
            refused.is_err(),
            "a namespace-local fd must not be re-imported"
        );
        let after = std::fs::metadata(&source).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(std::fs::read_dir(&escape).unwrap().count(), 0);
    }
    #[test]
    fn cross_namespace_mounts_preserve_writes_readonly_and_locked_flags() {
        let root = tempfile::tempdir().unwrap();
        // SAFETY: the child owns its namespaces and exits without unwinding into
        // the test runner; the parent owns the temporary directory and waits.
        unsafe {
            let child = libc::fork();
            assert!(child >= 0);
            if child == 0 {
                let result = std::panic::catch_unwind(|| mount_regression(root.path()));
                libc::_exit(if result.is_ok() { 0 } else { 1 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
