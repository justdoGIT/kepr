//! Bounded regular-file capture, durable writes, and session locks.

use super::{
    io::{cstr, owned, random_id, Dir, IO_ERROR},
    paths,
};
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use zeroize::Zeroizing;

const FILE_ERROR: &str =
    "workspace input must be a regular file without links or special permissions";

impl Dir {
    pub(super) fn read(
        &self,
        path: &str,
        limit: usize,
        private: bool,
    ) -> Result<(Zeroizing<Vec<u8>>, u32), &'static str> {
        let (dir, name) = self.parent(path, false, private)?;
        let name = cstr(name.as_bytes())?;
        // SAFETY: O_PATH pins the inode without opening a device or FIFO for IO.
        let fd = unsafe {
            libc::openat(
                dir.fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(FILE_ERROR);
        }
        // SAFETY: successful openat returned a new owned descriptor.
        let pinned = unsafe { File::from_raw_fd(fd) };
        let before = pinned.metadata().map_err(|_| FILE_ERROR)?;
        if !before.is_file()
            || before.nlink() != 1
            || before.mode() & 0o7000 != 0
            || (private && (!owned(&before) || before.mode() & 0o077 != 0))
        {
            return Err(FILE_ERROR);
        }
        if before.len() > limit as u64 {
            return Err("workspace file byte limit reached");
        }
        let descriptor = cstr(format!("/proc/self/fd/{fd}").as_bytes())?;
        // SAFETY: proc's FD link refers to our still-owned, verified regular inode.
        let readable = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                descriptor.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if readable < 0 {
            return Err(FILE_ERROR);
        }
        // SAFETY: successful openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(readable) };
        if signature(&file.metadata().map_err(|_| FILE_ERROR)?) != signature(&before) {
            return Err("workspace input changed while being captured");
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| FILE_ERROR)?;
        let after = file.metadata().map_err(|_| FILE_ERROR)?;
        if bytes.len() > limit {
            return Err("workspace file byte limit reached");
        }
        if bytes.len() as u64 != before.len() || signature(&before) != signature(&after) {
            return Err("workspace input changed while being captured");
        }
        Ok((bytes, before.mode() & 0o777))
    }

    pub(super) fn write(&self, path: &str, bytes: &[u8], mode: u32) -> Result<(), &'static str> {
        let (dir, name) = self.parent(path, true, true)?;
        dir.write_named(&name, bytes, mode)
    }

    /// Only launcher-generated configuration may use this unfiltered name path.
    pub(super) fn write_named(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), &'static str> {
        paths::component(name)?;
        let name = cstr(name.as_bytes())?;
        // SAFETY: anchored component; EXCL refuses existing files and symlinks.
        let fd = unsafe {
            libc::openat(
                self.fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(IO_ERROR);
        }
        // SAFETY: successful openat returned a new owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).map_err(|_| IO_ERROR)?;
        // SAFETY: owned file FD and an ordinary owner-only permission mode.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(IO_ERROR);
        }
        file.sync_all().map_err(|_| IO_ERROR)?;
        self.sync()
    }

    pub(super) fn atomic(&self, name: &str, bytes: &[u8]) -> Result<(), &'static str> {
        paths::component(name)?;
        let temp = format!(".pending-{}", random_id()?);
        self.write(&temp, bytes, 0o600)?;
        let from = cstr(temp.as_bytes())?;
        let to = cstr(name.as_bytes())?;
        // SAFETY: both single components are relative to our owned directory FD.
        let r = unsafe { libc::renameat(self.fd(), from.as_ptr(), self.fd(), to.as_ptr()) };
        if r != 0 {
            return Err(IO_ERROR);
        }
        self.sync()
    }

    pub(super) fn new_lock(&self) -> Result<File, &'static str> {
        // SAFETY: static single component, valid directory FD, restrictive mode.
        let fd = unsafe {
            libc::openat(
                self.fd(),
                c"lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(IO_ERROR);
        }
        // SAFETY: successful openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata().map_err(|_| IO_ERROR)?;
        if !m.is_file() || !owned(&m) || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err("workspace session lock is invalid");
        }
        // SAFETY: flock operates on our owned regular file; nonblocking.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("workspace session is running or in use");
        }
        Ok(file)
    }
}

fn signature(m: &Metadata) -> (u64, u64, u64, u64, i64, i64, i64, i64, u32) {
    (
        m.dev(),
        m.ino(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
    )
}
