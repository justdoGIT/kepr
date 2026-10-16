// cli_clip/wl_wire.rs — the Wayland wire format (T12.47): message
// encoding, argument decoding, and a connection that carries SCM_RIGHTS
// fds. No protocol logic; `wayland.rs` speaks the data-control protocol
// on top of it. Words are in the host's byte order, as Wayland requires.

use std::collections::VecDeque;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// One request or event argument (fds travel out of band).
pub enum Arg<'a> {
    Uint(u32),
    #[allow(dead_code)] // part of the wire format; no request kepr sends has one
    Int(i32),
    Str(&'a str),
    NewId(u32),
    Object(u32),
}

/// A message: object id, then `size << 16 | opcode`, then the arguments.
/// Strings carry a length (with the NUL), the bytes, the NUL, and padding
/// to 4 bytes.
pub fn encode(object: u32, opcode: u16, args: &[Arg]) -> Vec<u8> {
    let mut body = Vec::new();
    for a in args {
        match a {
            Arg::Uint(v) | Arg::NewId(v) | Arg::Object(v) => body.extend(v.to_ne_bytes()),
            Arg::Int(v) => body.extend(v.to_ne_bytes()),
            Arg::Str(s) => {
                body.extend((s.len() as u32 + 1).to_ne_bytes());
                body.extend(s.as_bytes());
                body.push(0);
                while !body.len().is_multiple_of(4) {
                    body.push(0);
                }
            }
        }
    }
    let size = (8 + body.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend(object.to_ne_bytes());
    out.extend((size << 16 | u32::from(opcode)).to_ne_bytes());
    out.extend(body);
    out
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    let w = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes([w[0], w[1], w[2], w[3]]))
}

/// The first complete message in `buf`: (object, opcode, arguments, bytes
/// used). None while the message is incomplete, or when its size field
/// is impossible (see `Conn::next`).
pub fn decode(buf: &[u8]) -> Option<(u32, u16, &[u8], usize)> {
    let (object, w) = (word(buf, 0)?, word(buf, 4)?);
    let size = (w >> 16) as usize;
    if size < 8 || !size.is_multiple_of(4) || buf.len() < size {
        return None;
    }
    Some((object, (w & 0xffff) as u16, &buf[8..size], size))
}

/// Reads arguments in order.
pub struct Args<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Args<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Args { b, at: 0 }
    }
    pub fn uint(&mut self) -> Option<u32> {
        let v = word(self.b, self.at)?;
        self.at += 4;
        Some(v)
    }
    #[allow(dead_code)] // as `Arg::Int`
    pub fn int(&mut self) -> Option<i32> {
        self.uint().map(|v| v as i32)
    }
    /// A string argument; a null string reads as "".
    pub fn string(&mut self) -> Option<&'a str> {
        let len = self.uint()? as usize;
        if len == 0 {
            return Some("");
        }
        let raw = self.b.get(self.at..self.at.checked_add(len)?)?;
        let (text, nul) = raw.split_at(len - 1);
        if nul != [0] {
            return None;
        }
        self.at += len.div_ceil(4) * 4;
        std::str::from_utf8(text).ok()
    }
}

/// A decoded message with its own copy of the arguments.
pub struct Msg {
    pub object: u32,
    pub opcode: u16,
    pub args: Vec<u8>,
}

/// A Wayland connection: buffered bytes plus the fds received with them,
/// kept in arrival order (a message's fd arguments are taken in order).
pub struct Conn {
    sock: UnixStream,
    buf: Vec<u8>,
    fds: VecDeque<OwnedFd>,
}

const MAX_FDS: usize = 8;

impl Conn {
    pub fn new(sock: UnixStream) -> Self {
        Conn {
            sock,
            buf: Vec::new(),
            fds: VecDeque::new(),
        }
    }

    /// Send one encoded message, passing `fds` with its first byte.
    pub fn send(&self, msg: &[u8], fds: &[RawFd]) -> std::io::Result<()> {
        let mut sent = 0;
        while sent < msg.len() {
            let fds = if sent == 0 { fds } else { &[] };
            sent += sendmsg(self.sock.as_raw_fd(), &msg[sent..], fds)?;
        }
        Ok(())
    }

    /// Wait until the socket is readable. False on timeout.
    pub fn readable(&self, timeout: Duration) -> std::io::Result<bool> {
        poll_fd(self.sock.as_raw_fd(), libc::POLLIN, timeout)
    }

    /// One read: append the bytes and fds that arrived. False on EOF.
    pub fn fill(&mut self) -> std::io::Result<bool> {
        let mut data = [0u8; 4096];
        let mut space = [0u64; 16]; // 128 bytes >= CMSG_SPACE(8 fds), aligned
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut _,
            iov_len: data.len(),
        };
        // SAFETY: msghdr points at stack buffers that outlive the call;
        // every cmsg is walked with CMSG_FIRSTHDR / CMSG_NXTHDR inside
        // msg_controllen, and each received fd is owned exactly once.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = space.as_mut_ptr() as *mut _;
            msg.msg_controllen =
                libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) as _;
            let n = loop {
                let n = libc::recvmsg(self.sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
                let e = std::io::Error::last_os_error();
                if n >= 0 || e.kind() != std::io::ErrorKind::Interrupted {
                    break if n < 0 { return Err(e) } else { n as usize };
                }
            };
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let p = libc::CMSG_DATA(c) as *const RawFd;
                    for i in 0..len / std::mem::size_of::<RawFd>() {
                        let fd = std::ptr::read_unaligned(p.add(i));
                        self.fds.push_back(OwnedFd::from_raw_fd(fd));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                return Err(std::io::Error::other("too many fds in one message"));
            }
            self.buf.extend_from_slice(&data[..n]);
            Ok(n > 0)
        }
    }

    /// The next complete message, if one is buffered.
    pub fn next(&mut self) -> Result<Option<Msg>, String> {
        if let Some(w) = word(&self.buf, 4) {
            let size = (w >> 16) as usize;
            if size < 8 || !size.is_multiple_of(4) {
                return Err("malformed message".into());
            }
        }
        let Some((object, opcode, args, used)) = decode(&self.buf) else {
            return Ok(None);
        };
        let m = Msg {
            object,
            opcode,
            args: args.to_vec(),
        };
        self.buf.drain(..used);
        Ok(Some(m))
    }

    /// The oldest fd not yet taken.
    pub fn take_fd(&mut self) -> Option<OwnedFd> {
        self.fds.pop_front()
    }
}

fn sendmsg(sock: RawFd, data: &[u8], fds: &[RawFd]) -> std::io::Result<usize> {
    if fds.len() > MAX_FDS {
        return Err(std::io::Error::other("too many fds"));
    }
    let mut space = [0u64; 16];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    // SAFETY: as in `fill`; the cmsg holds `fds.len()` ints inside a
    // 128-byte, 8-aligned buffer; the kernel only reads `data`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if !fds.is_empty() {
            let bytes = std::mem::size_of_val(fds) as u32;
            msg.msg_control = space.as_mut_ptr() as *mut _;
            msg.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(bytes) as _;
            let p = libc::CMSG_DATA(c) as *mut RawFd;
            for (i, fd) in fds.iter().enumerate() {
                std::ptr::write_unaligned(p.add(i), *fd);
            }
        }
        loop {
            let n = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

/// poll(2) one fd for `events`, retrying on EINTR. False on timeout.
pub fn poll_fd(fd: RawFd, events: libc::c_short, timeout: Duration) -> std::io::Result<bool> {
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut p = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        // SAFETY: one valid pollfd on the stack.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r >= 0 {
            return Ok(r > 0);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[cfg(target_endian = "little")]
    #[test]
    fn encodes_registry_bind() {
        let m = encode(
            2,
            0,
            &[
                Arg::Uint(7),
                Arg::Str("wl_seat"),
                Arg::Uint(8),
                Arg::NewId(5),
            ],
        );
        let want: &[u8] = &[
            2, 0, 0, 0, 0, 0, 32, 0, // object 2, size 32, opcode 0
            7, 0, 0, 0, // name
            8, 0, 0, 0, b'w', b'l', b'_', b's', b'e', b'a', b't', 0, // "wl_seat"
            8, 0, 0, 0, // version
            5, 0, 0, 0, // new id
        ];
        assert_eq!(m, want);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn decodes_a_global_event() {
        let mut fixture: Vec<u8> = vec![
            2, 0, 0, 0, 0, 0, 48, 0, // registry, size 48, opcode 0 (global)
            3, 0, 0, 0, // name
            28, 0, 0, 0, // length of "ext_data_control_manager_v1" + NUL
        ];
        fixture.extend(b"ext_data_control_manager_v1\0");
        fixture.extend([1, 0, 0, 0]); // version
        fixture.extend([9, 9]); // the start of the next message
        let (object, opcode, args, used) = decode(&fixture).unwrap();
        assert_eq!((object, opcode, used), (2, 0, 48));
        let mut a = Args::new(args);
        assert_eq!(a.uint(), Some(3));
        assert_eq!(a.string(), Some("ext_data_control_manager_v1"));
        assert_eq!(a.uint(), Some(1));
        assert!(decode(&fixture[..47]).is_none());
    }

    #[test]
    fn strings_round_trip_with_padding() {
        for s in ["", "a", "abc", "abcd", "text/plain;charset=utf-8"] {
            let m = encode(9, 3, &[Arg::Str(s), Arg::Int(-2), Arg::Object(4)]);
            assert_eq!(m.len() % 4, 0);
            let (o, op, args, used) = decode(&m).unwrap();
            assert_eq!((o, op, used), (9, 3, m.len()));
            let mut a = Args::new(args);
            assert_eq!(a.string(), Some(s));
            assert_eq!(a.int(), Some(-2));
            assert_eq!(a.uint(), Some(4));
            assert_eq!(a.uint(), None);
        }
    }

    fn pipe() -> (std::fs::File, std::fs::File) {
        let mut p = [0; 2];
        // SAFETY: pipe2 fills two fresh fds, each owned once below.
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe {
            (
                std::fs::File::from_raw_fd(p[0]),
                std::fs::File::from_raw_fd(p[1]),
            )
        }
    }

    #[test]
    fn fds_stay_in_order_across_two_messages() {
        let (a, b) = UnixStream::pair().unwrap();
        let (tx, mut rx) = (Conn::new(a), Conn::new(b));
        let (r0, w0) = pipe();
        let (r1, w1) = pipe();
        tx.send(&encode(6, 0, &[Arg::Uint(0)]), &[w0.as_raw_fd()])
            .unwrap();
        tx.send(&encode(6, 0, &[Arg::Uint(1)]), &[w1.as_raw_fd()])
            .unwrap();
        drop((w0, w1));
        let mut got = Vec::new();
        while got.len() < 2 {
            assert!(rx.fill().unwrap());
            while let Some(m) = rx.next().unwrap() {
                got.push((m, rx.take_fd().expect("an fd per message")));
            }
        }
        assert!(rx.take_fd().is_none());
        for (i, (m, fd)) in got.into_iter().enumerate() {
            assert_eq!(Args::new(&m.args).uint(), Some(i as u32));
            std::fs::File::from(fd)
                .write_all(format!("pipe{i}").as_bytes())
                .unwrap();
        }
        for (i, mut r) in [r0, r1].into_iter().enumerate() {
            let mut s = String::new();
            r.read_to_string(&mut s).unwrap();
            assert_eq!(s, format!("pipe{i}"));
        }
    }

    #[test]
    fn a_bad_size_is_an_error_not_a_stall() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut rx = Conn::new(b);
        std::io::Write::write_all(&mut &a, &[1, 0, 0, 0, 0, 0, 4, 0]).unwrap();
        assert!(rx.fill().unwrap());
        assert!(rx.next().is_err());
    }
}
