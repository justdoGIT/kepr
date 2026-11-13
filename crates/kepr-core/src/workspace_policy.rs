//! Contracts shared with the CLI private workspace launcher
//! (`src/cli_workspace/`, `src/cli_sandbox_workspace.rs`). Filesystem
//! restriction alone does not establish private mounts, snapshots, or brokered
//! export; the launcher supplies those. Landlock content rules do not hide host
//! metadata from stat/readlink.

use std::path::{Component, Path, PathBuf};

const REQUIRED_ABI: i32 = 3;
const MAX_RUNTIME_ROOTS: usize = 16;

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Separate session-owned directories. The launcher must create a fresh,
/// owner-only root and populate workspace/config by copying approved inputs.
#[derive(Clone, Debug)]
pub struct WorkspaceLayout {
    root: PathBuf,
    home: PathBuf,
    workspace: PathBuf,
    tmp: PathBuf,
    config: PathBuf,
}

impl WorkspaceLayout {
    pub fn new(root: PathBuf) -> Result<Self, &'static str> {
        if !normalized_absolute(&root) || root.components().count() < 3 {
            return Err("workspace session root must be a scoped absolute path");
        }
        Ok(Self {
            home: root.join("home"),
            workspace: root.join("workspace"),
            tmp: root.join("tmp"),
            config: root.join("config"),
            root,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn home(&self) -> &Path {
        &self.home
    }
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
    pub fn tmp(&self) -> &Path {
        &self.tmp
    }
    pub fn config(&self) -> &Path {
        &self.config
    }
}

fn approved_runtime(path: &Path) -> bool {
    normalized_absolute(path)
        && (["/usr", "/bin", "/sbin", "/lib", "/lib64"]
            .iter()
            .any(|root| path.starts_with(root))
            || [
                "/etc/ld.so.cache",
                "/etc/nsswitch.conf",
                "/etc/passwd",
                "/etc/group",
                "/etc/localtime",
                "/etc/ssl/cert.pem",
                "/etc/ssl/certs",
            ]
            .iter()
            .any(|allowed| path == Path::new(allowed)))
}

/// Read/write access is limited to private home/tmp and a copied workspace.
/// The original workspace and host configuration are never write grants.
#[derive(Clone, Debug)]
pub struct FilesystemPolicy {
    layout: WorkspaceLayout,
    runtime: Vec<PathBuf>,
}

impl FilesystemPolicy {
    pub fn new(layout: WorkspaceLayout, runtime: Vec<PathBuf>) -> Result<Self, &'static str> {
        if runtime.len() > MAX_RUNTIME_ROOTS || runtime.iter().any(|path| !approved_runtime(path)) {
            return Err("workspace runtime roots must be bounded trusted system paths");
        }
        Ok(Self { layout, runtime })
    }

    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }
    pub fn runtime(&self) -> &[PathBuf] {
        &self.runtime
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub landlock_abi: i32,
    pub required_landlock_abi: i32,
    pub filesystem_restriction_available: bool,
}

pub fn capability() -> Capability {
    #[cfg(target_os = "linux")]
    let abi = crate::landlock::abi();
    #[cfg(not(target_os = "linux"))]
    let abi = 0;
    Capability {
        landlock_abi: abi,
        required_landlock_abi: REQUIRED_ABI,
        filesystem_restriction_available: abi >= REQUIRED_ABI,
    }
}

/// Restrict this thread and descendants to prepared private directories and
/// explicit trusted runtime roots. Caller must first hide vault/keyring roots,
/// close inherited FDs, isolate mounts/network/processes, drop capabilities
/// and install seccomp. Imported files must be copies, never host hardlinks.
/// This function does not create a private root, copy files or export changes.
pub fn restrict_filesystem(policy: &FilesystemPolicy) -> Result<(), String> {
    restrict(policy, false)
}

/// For the CLI's detached private root only: adds the fresh PID namespace's
/// procfs and four explicitly mounted character devices. Never use on the host.
pub fn restrict_private_filesystem(policy: &FilesystemPolicy) -> Result<(), String> {
    restrict(policy, true)
}

fn restrict(policy: &FilesystemPolicy, private_kernel_runtime: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use crate::landlock::{self, Ruleset, EXECUTE, IOCTL_DEV, READ_DIR, READ_FILE};
        use std::os::unix::fs::MetadataExt;
        if landlock::abi() < REQUIRED_ABI {
            return Err("scoped workspace requires Landlock ABI 3 or newer".into());
        }
        let root = std::fs::symlink_metadata(policy.layout.root())
            .map_err(|_| "cannot inspect private workspace root")?;
        // SAFETY: getuid has no preconditions and cannot fail.
        if !root.is_dir() || root.uid() != unsafe { libc::getuid() } || root.mode() & 0o077 != 0 {
            return Err("workspace root must be an owner-only directory".into());
        }
        let paths = [
            policy.layout.home(),
            policy.layout.workspace(),
            policy.layout.tmp(),
            policy.layout.config(),
        ];
        for path in paths {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| "private workspace directory missing")?;
            if !metadata.is_dir() || std::fs::canonicalize(path).ok().as_deref() != Some(path) {
                return Err("private workspace paths must be real canonical directories".into());
            }
        }
        let handled = landlock::ruleset_attr_for_abi(landlock::abi()).handled_access_fs;
        let mut rules = Ruleset::create(handled)?.ok_or("Landlock unavailable")?;
        // Private writable directories can make ordinary files/sockets, but
        // cannot create device nodes or obtain device ioctl access.
        let writable = handled & !((1 << 6) | (1 << 11) | IOCTL_DEV);
        for path in [
            policy.layout.home(),
            policy.layout.workspace(),
            policy.layout.tmp(),
        ] {
            rules.allow(path, writable)?;
        }
        let readonly = EXECUTE | READ_DIR | READ_FILE;
        rules.allow(policy.layout.config(), readonly)?;
        for path in &policy.runtime {
            let canonical = std::fs::canonicalize(path).map_err(|_| "runtime root unavailable")?;
            if !approved_runtime(&canonical) {
                return Err("runtime root resolves outside trusted system paths".into());
            }
            rules.allow(&canonical, readonly)?;
        }
        if private_kernel_runtime {
            rules.allow(Path::new("/proc"), READ_DIR | READ_FILE)?;
            for device in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"] {
                rules.allow(Path::new(device), READ_FILE | landlock::WRITE_FILE)?;
            }
        }
        rules.restrict_self()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, private_kernel_runtime);
        Err("scoped workspace filesystem enforcement is Linux-only".into())
    }
}

#[cfg(test)]
#[path = "workspace_policy_tests.rs"]
mod tests;
