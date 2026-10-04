//! One file descriptor over a Unix socket (SCM_RIGHTS). Shared by the
//! agent sandbox's connection relay, the system daemon handing a session
//! channel to the gate service, and that service receiving it.

use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Send one fd over a Unix socket (SCM_RIGHTS).
pub fn send_fd(sock: &UnixStream, fd: RawFd) -> Result<(), String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut space = [0u8; 64];
    // SAFETY: msghdr/cmsg built per cmsg(3) in a 64-byte buffer, which is
    // larger than CMSG_SPACE(sizeof(int)); `fd` is open for the call.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr() as *mut _;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
        if libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(os_err("sendmsg"));
        }
    }
    Ok(())
}

/// Receive one fd sent with `send_fd`. `Ok(None)` on EOF.
pub fn recv_fd(sock: &UnixStream) -> Result<Option<RawFd>, String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut _,
        iov_len: 1,
    };
    let mut space = [0u8; 64];
    // SAFETY: mirror of send_fd; the received fd is checked before use
    // and MSG_CMSG_CLOEXEC keeps it out of any exec'd child.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr() as *mut _;
        msg.msg_controllen = space.len() as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n == 0 {
            return Ok(None);
        }
        if n < 0 {
            return Err(os_err("recvmsg"));
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_level != libc::SOL_SOCKET || (*c).cmsg_type != libc::SCM_RIGHTS
        {
            return Err("recvmsg: no fd".into());
        }
        Ok(Some(std::ptr::read_unaligned(
            libc::CMSG_DATA(c) as *const RawFd
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;

    #[test]
    fn fd_passing_round_trip() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut x, y) = UnixStream::pair().unwrap();
        send_fd(&a, y.as_raw_fd()).unwrap();
        drop(y);
        let fd = recv_fd(&b).unwrap().unwrap();
        // SAFETY: recv_fd just handed us ownership of this fd.
        let mut received = unsafe { UnixStream::from_raw_fd(fd) };
        x.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        received.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        drop(a);
        assert_eq!(recv_fd(&b).unwrap(), None);
    }
}
