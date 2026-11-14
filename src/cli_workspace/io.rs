//! Directory-FD anchored IO. No user-controlled symbolic links are followed.

use super::paths;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub(super) const IO_ERROR: &str = "workspace filesystem operation refused";

pub(crate) struct Dir(pub(super) File);

pub(super) fn cstr(bytes: &[u8]) -> Result<CString, &'static str> {
    CString::new(bytes).map_err(|_| IO_ERROR)
}

pub(super) fn owned(m: &Metadata) -> bool {
    // SAFETY: geteuid has no arguments or failure mode.
    m.uid() == unsafe { libc::geteuid() }
}

fn directory(fd: libc::c_int, private: bool) -> Result<Dir, &'static str> {
    if fd < 0 {
        return Err(IO_ERROR);
    }
    // SAFETY: successful open/openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| IO_ERROR)?;
    if !m.is_dir() || (private && (!owned(&m) || m.mode() & 0o077 != 0)) {
        return Err("workspace directory must be owner-only and without links");
    }
    Ok(Dir(file))
}

impl Dir {
    pub(crate) fn absolute(path: &Path, create: bool, trusted: bool) -> Result<Self, &'static str> {
        paths::absolute(path)?;
        let mut dir = Self::root()?;
        for part in path.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            let name = cstr(name.as_encoded_bytes())?;
            if create {
                // SAFETY: dir owns a directory FD; name is one terminated component.
                let r = unsafe { libc::mkdirat(dir.fd(), name.as_ptr(), 0o700) };
                if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                    return Err(IO_ERROR);
                }
            }
            // SAFETY: path-only traversal does not enumerate unselected ancestors.
            let fd = unsafe {
                libc::openat(
                    dir.fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            dir = directory(fd, false)?;
            let m = dir.metadata()?;
            if trusted && m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
                return Err("workspace directory ancestors must be trusted");
            }
        }
        // SAFETY: reopen the pinned final directory, not a host ancestor.
        let fd = unsafe {
            libc::openat(
                dir.fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        directory(fd, false)
    }

    fn open_component(&self, name: &CString, private: bool) -> Result<Self, &'static str> {
        // SAFETY: owned directory FD and a live terminated single component.
        let fd = unsafe {
            libc::openat(
                self.fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        directory(fd, private)
    }

    pub(crate) fn child(
        &self,
        name: &str,
        create: bool,
        private: bool,
    ) -> Result<Self, &'static str> {
        paths::component(name)?;
        let name = cstr(name.as_bytes())?;
        if create {
            // SAFETY: the name is a single component relative to our owned FD.
            let r = unsafe { libc::mkdirat(self.fd(), name.as_ptr(), 0o700) };
            if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                return Err(IO_ERROR);
            }
            if r == 0 {
                self.sync()?;
            }
        }
        self.open_component(&name, private)
    }

    pub(crate) fn new_child(&self, name: &str) -> Result<Self, &'static str> {
        paths::component(name)?;
        let name = cstr(name.as_bytes())?;
        // SAFETY: one component relative to our owned directory FD.
        if unsafe { libc::mkdirat(self.fd(), name.as_ptr(), 0o700) } != 0 {
            return Err("workspace directory must be new");
        }
        self.sync()?;
        self.open_component(&name, true)
    }

    /// Anchor at the filesystem root so a caller that holds an already
    /// validated absolute path can reopen a top-level name (`/usr`) as
    /// `(root, name)` without relaxing scoped-path validation.
    pub(crate) fn root() -> Result<Self, &'static str> {
        // SAFETY: a static NUL-terminated path and valid open flags.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        directory(fd, false)
    }

    pub(crate) fn fd(&self) -> libc::c_int {
        self.0.as_raw_fd()
    }

    pub(super) fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd()))
    }

    pub(crate) fn metadata(&self) -> Result<Metadata, &'static str> {
        self.0.metadata().map_err(|_| IO_ERROR)
    }

    pub(super) fn parent(
        &self,
        path: &str,
        create: bool,
        private: bool,
    ) -> Result<(Self, String), &'static str> {
        paths::relative(path)?;
        let mut names: Vec<_> = path.split('/').collect();
        let name = names.pop().ok_or(IO_ERROR)?.to_string();
        let mut dir = Self(self.0.try_clone().map_err(|_| IO_ERROR)?);
        for part in names {
            dir = dir.child(part, create, private)?;
        }
        Ok((dir, name))
    }

    pub(super) fn sync(&self) -> Result<(), &'static str> {
        self.0.sync_all().map_err(|_| IO_ERROR)
    }

    pub(super) fn publish(&self, from: &str, to: &str) -> Result<(), &'static str> {
        paths::component(from)?;
        paths::component(to)?;
        let from = cstr(from.as_bytes())?;
        let to = cstr(to.as_bytes())?;
        // SAFETY: two anchored components; NOREPLACE prevents a racing overwrite.
        let r = unsafe {
            libc::renameat2(
                self.fd(),
                from.as_ptr(),
                self.fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if r != 0 {
            return Err("workspace export destination must be new");
        }
        self.sync()
    }
}

pub(super) fn random_id() -> Result<String, &'static str> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| "workspace random identifier unavailable")?;
    Ok(hex::encode(bytes))
}
