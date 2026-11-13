//! Private root assembly. Control/baseline directories never enter this root.

use crate::cli_sandbox_runtime::{self, RuntimeMount};
use crate::cli_workspace::io::Dir;
use kepr_core::workspace_policy::{FilesystemPolicy, WorkspaceLayout};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) const VIRTUAL_ROOT: &str = "/session/private";
pub(crate) const WORKSPACE: &str = "/session/private/workspace";

pub(crate) struct WorkspaceMounts {
    stage: PathBuf,
    // Directory descriptors pin copies, even if host names change later.
    private: Vec<(&'static str, Dir)>,
    runtime: Vec<RuntimeMount>,
}

impl WorkspaceMounts {
    pub(crate) fn new(root: &Path, stage: PathBuf) -> Result<Self, &'static str> {
        let source = Dir::absolute(root, false, true)?;
        let private = ["home", "workspace", "tmp", "config"]
            .into_iter()
            .map(|name| Ok((name, source.child(name, false, true)?)))
            .collect::<Result<_, &'static str>>()?;
        Dir::absolute(&stage, false, true)?;
        Ok(Self {
            stage,
            private,
            runtime: cli_sandbox_runtime::mounts()?,
        })
    }
}

fn cpath(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "private workspace mount path invalid".into())
}

fn mount(
    source: Option<&CString>,
    target: &Path,
    fs: Option<&CString>,
    flags: libc::c_ulong,
    data: Option<&CString>,
) -> Result<(), String> {
    let target = cpath(target)?;
    let ptr = |s: Option<&CString>| s.map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: all supplied strings outlive mount, and omitted fields are NULL.
    if unsafe {
        libc::mount(
            ptr(source),
            target.as_ptr(),
            ptr(fs),
            flags,
            ptr(data).cast(),
        )
    } != 0
    {
        return Err(format!(
            "private workspace mount refused at {} (flags {flags:#x}): {}",
            target.to_string_lossy(),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn namespace_source(fd: i32) -> Result<File, String> {
    let descriptor = format!("/proc/self/fd/{fd}");
    let path =
        std::fs::read_link(&descriptor).map_err(|_| "private workspace source unavailable")?;
    let file_name = path.file_name().ok_or("private workspace source invalid")?;
    let name = cpath(Path::new(file_name))?;
    // Reopen relative to the root so top-level runtime roots (`/usr`) are
    // reachable; `path` was validated absolute before this descriptor existed.
    let parent = if path.parent() == Some(Path::new("/")) {
        Dir::root().map_err(str::to_owned)?
    } else {
        Dir::absolute(
            path.parent().ok_or("private workspace source invalid")?,
            false,
            false,
        )
        .map_err(str::to_owned)?
    };
    // The original FD pins an inode on the old mount namespace. Reopen it through
    // the new namespace without following links, then verify its pinned identity.
    // SAFETY: parent owns a directory FD and name is one NUL-terminated component.
    let local = unsafe {
        libc::openat(
            parent.fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if local < 0 {
        return Err("private workspace source reopen refused".into());
    }
    // SAFETY: openat returned a new owned descriptor.
    let local = unsafe { File::from_raw_fd(local) };
    let original =
        std::fs::metadata(descriptor).map_err(|_| "private workspace source unavailable")?;
    let reopened = local
        .metadata()
        .map_err(|_| "private workspace source unavailable")?;
    if (original.dev(), original.ino(), original.mode())
        != (reopened.dev(), reopened.ino(), reopened.mode())
    {
        return Err("private workspace source identity changed".into());
    }
    Ok(local)
}

fn bind(fd: i32, target: &Path, readonly: bool, nodev: bool) -> Result<(), String> {
    let local = namespace_source(fd)?;
    let source =
        CString::new(format!("/proc/self/fd/{}", local.as_raw_fd())).expect("numeric FD path");
    // Deliberately nonrecursive: host submounts are not imported.
    mount(Some(&source), target, None, libc::MS_BIND, None)?;
    let mut attributes = libc::mount_attr {
        attr_set: libc::MOUNT_ATTR_NOSUID,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    if readonly {
        attributes.attr_set |= libc::MOUNT_ATTR_RDONLY;
    }
    if nodev {
        attributes.attr_set |= libc::MOUNT_ATTR_NODEV;
    }
    let target = cpath(target)?;
    // Only add restrictions. A legacy bind remount clears inherited flags such
    // as /dev's noexec, which are locked in a less-privileged mount namespace.
    // SAFETY: target and attributes are live; size matches the kernel ABI.
    if unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            0u32,
            &attributes,
            std::mem::size_of::<libc::mount_attr>(),
        )
    } != 0
    {
        return Err(format!(
            "private workspace mount restrictions refused: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn mkdir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| "private workspace directory creation failed".into())
}

fn target(stage: &Path, relative: &str, directory: bool) -> Result<PathBuf, String> {
    let path = stage.join(relative.trim_start_matches('/'));
    mkdir(
        path.parent()
            .ok_or("private workspace mount target invalid")?,
    )?;
    if directory {
        mkdir(&path)?;
    } else {
        std::fs::File::create(&path).map_err(|_| "private workspace file creation failed")?;
    }
    Ok(path)
}

fn devices(stage: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    for (name, minor) in [("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)] {
        let path = Path::new("/dev").join(name);
        let source = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "private workspace device unavailable")?;
        let m = source
            .metadata()
            .map_err(|_| "private workspace device unavailable")?;
        if m.mode() & libc::S_IFMT != libc::S_IFCHR
            || libc::major(m.rdev()) != 1
            || libc::minor(m.rdev()) != minor
        {
            return Err("private workspace device identity invalid".into());
        }
        bind(
            source.as_raw_fd(),
            &target(stage, &format!("dev/{name}"), false)?,
            false,
            false,
        )?;
    }
    std::os::unix::fs::symlink("/proc/self/fd", stage.join("dev/fd"))
        .map_err(|_| "private workspace FD path creation failed")?;
    Ok(())
}

fn local_identity(stage: &Path) -> Result<Vec<PathBuf>, String> {
    // SAFETY: getuid/getgid have no arguments or failure mode.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let files = [
        (
            "etc/passwd",
            format!("agent:x:{uid}:{gid}::/session/private/home:/bin/sh\n"),
        ),
        ("etc/group", format!("agent:x:{gid}:\n")),
        (
            "etc/nsswitch.conf",
            "passwd: files\ngroup: files\nhosts: files\n".into(),
        ),
    ];
    for (name, bytes) in &files {
        let file = target(stage, name, false)?;
        std::fs::write(file, bytes).map_err(|_| "private workspace identity creation failed")?;
    }
    Ok(files
        .iter()
        .map(|(name, _)| Path::new("/").join(name))
        .collect())
}

/// Must run as PID 1 after user, mount, PID and network namespaces exist.
pub(crate) fn setup(plan: &WorkspaceMounts) -> Result<FilesystemPolicy, String> {
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    let fs = c"tmpfs".to_owned();
    let data = c"size=8m,mode=0700".to_owned();
    mount(
        Some(&fs),
        &plan.stage,
        Some(&fs),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&data),
    )?;
    for (name, source) in &plan.private {
        let destination = target(&plan.stage, &format!("session/private/{name}"), true)?;
        bind(source.fd(), &destination, *name == "config", true)?;
    }
    let mut runtime = Vec::new();
    for input in &plan.runtime {
        bind(
            input.source.as_raw_fd(),
            &target(&plan.stage, input.target, input.directory)?,
            true,
            true,
        )?;
        runtime.push(PathBuf::from(input.target));
    }
    runtime.extend(local_identity(&plan.stage)?);
    devices(&plan.stage)?;
    target(&plan.stage, "proc", true)?;
    std::os::unix::fs::symlink("/session/private/tmp", plan.stage.join("tmp"))
        .map_err(|_| "private workspace tmp path creation failed")?;
    target(&plan.stage, ".old-root", true)?;
    std::env::set_current_dir(&plan.stage).map_err(|_| "private workspace root entry failed")?;
    // SAFETY: the current directory is a fresh mount; .old-root is beneath it.
    if unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old-root".as_ptr()) } != 0 {
        return Err(format!(
            "private workspace root isolation refused: {}",
            std::io::Error::last_os_error()
        ));
    }
    std::env::set_current_dir("/").map_err(|_| "private workspace root entry failed")?;
    // SAFETY: the detached old root is our private mount-namespace reference.
    if unsafe { libc::umount2(c"/.old-root".as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err("private workspace old root detach failed".into());
    }
    std::fs::remove_dir("/.old-root").map_err(|_| "private workspace old root removal failed")?;
    let procfs = c"proc".to_owned();
    let options = c"hidepid=2,subset=pid".to_owned();
    mount(
        Some(&procfs),
        Path::new("/proc"),
        Some(&procfs),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
        Some(&options),
    )?;
    // The root is immutable; writable copied inputs are separate bind mounts.
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        Some(&data),
    )?;
    std::env::set_current_dir(WORKSPACE).map_err(|_| "private workspace cwd unavailable")?;
    let layout = WorkspaceLayout::new(PathBuf::from(VIRTUAL_ROOT)).map_err(String::from)?;
    FilesystemPolicy::new(layout, runtime).map_err(String::from)
}

pub(crate) fn restrict(policy: &FilesystemPolicy) -> Result<(), String> {
    kepr_core::workspace_policy::restrict_private_filesystem(policy)
}

#[cfg(test)]
mod tests {
    include!("cli_sandbox_workspace_tests.rs");
}
