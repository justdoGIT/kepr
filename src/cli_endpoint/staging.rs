//! Stage exactly one regular file; the scanner consumes this sealed inode.
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub const MAX_INPUT: usize = 64 * 1024 * 1024;
pub struct Staged {
    pub fd: OwnedFd,
    pub sha256: String,
    pub bytes: u64,
}

impl Staged {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "cannot open scanner input")?;
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect scanner input")?;
        if !metadata.is_file() || metadata.len() > MAX_INPUT as u64 {
            return Err("scanner input must be a regular file no larger than 64 MiB".into());
        }
        // Bound capacity up front so sensitive input is not copied into abandoned
        // allocations as read_to_end grows its buffer.
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(MAX_INPUT + 1));
        file.take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read scanner input")?;
        Self::from_bytes(&bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_INPUT {
            return Err("scanner input exceeds 64 MiB".into());
        }
        let sha256 = hex::encode(Sha256::digest(bytes));
        let fd = kepr_core::memfd::create_sealed_memfd_cloexec("endpoint_input", bytes)
            .map_err(|_| "immutable scanner staging is unavailable")?;
        Ok(Self {
            fd,
            sha256,
            bytes: bytes.len() as u64,
        })
    }
    #[cfg(test)]
    pub fn attach(&self, command: &mut Command) -> Result<(), String> {
        self.attach_inner(command, None)
    }

    pub fn attach_filtered(&self, command: &mut Command, filter: OwnedFd) -> Result<(), String> {
        self.attach_inner(command, Some(filter))
    }

    fn attach_inner(&self, command: &mut Command, filter: Option<OwnedFd>) -> Result<(), String> {
        let duplicate = |fd: i32| -> Result<OwnedFd, String> {
            // SAFETY: duplicates this owned descriptor above the reserved slots.
            let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
            if result < 0 {
                return Err("scanner descriptor setup failed".into());
            }
            // SAFETY: fcntl returned a new descriptor owned by this function.
            Ok(unsafe { OwnedFd::from_raw_fd(result) })
        };
        let input = duplicate(self.fd.as_raw_fd())?;
        let filter_copy = filter
            .as_ref()
            .map(|fd| duplicate(fd.as_raw_fd()))
            .transpose()?;
        // SAFETY: only async-signal-safe descriptor operations run in the child.
        // Owned source copies remain live in Command and never occupy slots 3/4.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(input.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(fd) = &filter_copy {
                    if libc::dup2(fd.as_raw_fd(), 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // Preserve the std spawn error pipe until exec; all other inherited
                // descriptors close at exec, including any pre-existing sockets.
                if libc::syscall(
                    libc::SYS_close_range,
                    if filter.is_some() { 5u32 } else { 4u32 },
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    #[test]
    fn pathname_replacement_does_not_change_staged_bytes_and_seals_reject_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        std::fs::write(&path, b"original fixture").unwrap();
        let staged = Staged::from_path(&path).unwrap();
        std::fs::rename(&path, dir.path().join("old")).unwrap();
        std::fs::write(&path, b"replaced fixture").unwrap();
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", "import os; print(os.read(3, 100).decode())"]);
        staged.attach(&mut command).unwrap();
        let output =
            super::super::process::run(&mut command, std::time::Duration::from_secs(2), 1024)
                .unwrap();
        assert_eq!(output.stdout.as_slice(), b"original fixture\n");
        let mut file = std::fs::File::from(staged.fd.try_clone().unwrap());
        assert!(file.write_all(b"changed").is_err());
    }

    #[test]
    fn symlinks_and_oversize_inputs_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        std::fs::write(&path, b"fixture").unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(Staged::from_path(&link).is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len((MAX_INPUT + 1) as u64)
            .unwrap();
        assert!(Staged::from_path(&path).is_err());
    }

    #[test]
    fn scanner_receives_only_staged_input_and_its_filter_descriptors() {
        let staged = Staged::from_bytes(b"input fixture").unwrap();
        let filter =
            kepr_core::memfd::create_sealed_memfd_cloexec("filter_fixture", b"filter fixture")
                .unwrap();
        let (_peer, socket) = std::os::unix::net::UnixStream::pair().unwrap();
        // SAFETY: creates an owned, deliberately inheritable synthetic socket.
        let extra = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD, 64) };
        assert!(extra >= 64);
        // SAFETY: this descriptor is newly allocated and owned by the test.
        let _extra = unsafe { OwnedFd::from_raw_fd(extra) };
        let mut command = Command::new("/usr/bin/python3");
        let script = format!("import os; print(os.read(3,100).decode()); print(os.read(4,100).decode())\ntry:\n os.fstat({extra}); print('unexpected descriptor')\nexcept OSError:\n print('extra descriptor closed')");
        command.args(["-c", &script]);
        staged.attach_filtered(&mut command, filter).unwrap();
        let result =
            super::super::process::run(&mut command, std::time::Duration::from_secs(2), 1024)
                .unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            result.stdout.as_slice(),
            b"input fixture\nfilter fixture\nextra descriptor closed\n"
        );
    }
}
