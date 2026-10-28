// cli_clip/x11_wire.rs — the X11 core protocol, as much as owning a
// selection needs (T12.48): the connection setup with an
// MIT-MAGIC-COOKIE-1 from the user's own Xauthority, request encoders,
// and reply / event / error framing. Local displays only (x11_auth.rs);
// anything else is refused and `kepr copy` falls back to xclip.
// Little-endian byte order is chosen at setup, so words are LE.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::x11_auth::{self, AUTH_NAME};

pub const CHANGE_PROPERTY: u8 = 18;
pub const SEND_EVENT: u8 = 25;
pub const SELECTION_CLEAR: u8 = 29;
pub const SELECTION_REQUEST: u8 = 30;
pub const SELECTION_NOTIFY: u8 = 31;
pub const ATOM_ATOM: u32 = 4;
const REPLY_WAIT: Duration = Duration::from_secs(5);

fn pad4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|w| u16::from_le_bytes([w[0], w[1]]))
}

pub fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// The connection setup request, little-endian, protocol 11.0.
pub fn setup_request(cookie: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let (name, data): (&[u8], &[u8]) = match cookie {
        Some(c) => (AUTH_NAME, c),
        None => (b"", b""),
    };
    let mut m = Zeroizing::new(Vec::with_capacity(12 + pad4(name.len()) + pad4(data.len())));
    m.extend_from_slice(&[b'l', 0]);
    m.extend_from_slice(&11u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&(data.len() as u16).to_le_bytes());
    m.extend_from_slice(&[0, 0]);
    for part in [name, data] {
        m.extend_from_slice(part);
        let padded = pad4(m.len());
        m.resize(padded, 0);
    }
    m
}

/// What `serve` needs from the setup reply.
#[derive(Debug, PartialEq, Eq)]
pub struct Setup {
    pub id_base: u32,
    pub id_mask: u32,
    pub max_request: usize, // bytes
    pub root: u32,
}

pub fn parse_setup(r: &[u8]) -> Result<Setup, String> {
    let bad = || "bad X11 setup reply".to_string();
    match r.first() {
        Some(1) => {}
        Some(_) => return Err("the X server refused the connection".into()),
        None => return Err(bad()),
    }
    let vendor = le16(r, 24).ok_or_else(bad)? as usize;
    let formats = *r.get(29).ok_or_else(bad)? as usize;
    Ok(Setup {
        id_base: le32(r, 12).ok_or_else(bad)?,
        id_mask: le32(r, 16).ok_or_else(bad)?,
        max_request: le16(r, 26).ok_or_else(bad)? as usize * 4,
        root: le32(r, 40 + pad4(vendor) + 8 * formats).ok_or_else(bad)?,
    })
}

/// A request header for a body of `body_len` bytes (padded by `pad`).
fn request(opcode: u8, data: u8, body_len: usize) -> Vec<u8> {
    let len = 4 + pad4(body_len);
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&[opcode, data]);
    m.extend_from_slice(&((len / 4) as u16).to_le_bytes());
    m
}

fn pad(mut m: Vec<u8>) -> Vec<u8> {
    m.resize(pad4(m.len()), 0);
    m
}

pub fn intern_atom(name: &str) -> Vec<u8> {
    let mut m = request(16, 0, 4 + name.len());
    m.extend_from_slice(&(name.len() as u16).to_le_bytes());
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(name.as_bytes());
    pad(m)
}

/// A 1x1 InputOnly window: something to own the selection with.
pub fn create_window(wid: u32, parent: u32) -> Vec<u8> {
    let mut m = request(1, 0, 28);
    for w in [wid, parent, 0, 1 | 1 << 16, 2 << 16, 0, 0] {
        m.extend_from_slice(&w.to_le_bytes()); // x,y=0; 1x1; border 0, InputOnly
    }
    m
}

pub fn set_selection_owner(owner: u32, selection: u32) -> Vec<u8> {
    let mut m = request(22, 0, 12);
    for w in [owner, selection, 0] {
        m.extend_from_slice(&w.to_le_bytes()); // time: CurrentTime
    }
    m
}

pub fn get_selection_owner(selection: u32) -> Vec<u8> {
    let mut m = request(23, 0, 4);
    m.extend_from_slice(&selection.to_le_bytes());
    m
}

/// ChangeProperty (Replace). `data` may be the value: wiped memory,
/// allocated once at its final size.
pub fn change_property(
    win: u32,
    prop: u32,
    ty: u32,
    format: u8,
    data: &[u8],
) -> Zeroizing<Vec<u8>> {
    let len = 24 + pad4(data.len());
    let mut m = Zeroizing::new(Vec::with_capacity(len));
    m.extend_from_slice(&[CHANGE_PROPERTY, 0]);
    m.extend_from_slice(&((len / 4) as u16).to_le_bytes());
    let units = (data.len() / (format as usize / 8).max(1)) as u32;
    for w in [win, prop, ty] {
        m.extend_from_slice(&w.to_le_bytes());
    }
    m.extend_from_slice(&[format, 0, 0, 0]);
    m.extend_from_slice(&units.to_le_bytes());
    m.extend_from_slice(data);
    m.resize(len, 0);
    m
}

/// SendEvent of a SelectionNotify (property 0 = None: refused).
pub fn selection_notify(time: u32, requestor: u32, sel: u32, target: u32, prop: u32) -> Vec<u8> {
    let mut m = request(SEND_EVENT, 0, 40);
    m.extend_from_slice(&requestor.to_le_bytes());
    m.extend_from_slice(&0u32.to_le_bytes()); // event mask: the owner client
    m.extend_from_slice(&[SELECTION_NOTIFY, 0, 0, 0]);
    for w in [time, requestor, sel, target, prop, 0, 0] {
        m.extend_from_slice(&w.to_le_bytes());
    }
    m
}

/// A connection after a successful setup.
pub struct Conn {
    sock: UnixStream,
    buf: Vec<u8>,
    seq: u16,
    next_id: u32,
    events: VecDeque<[u8; 32]>,
    pub setup: Setup,
}

/// Connect to a local display, authenticating with the user's cookie.
pub fn connect(display: &str) -> Result<Conn, String> {
    let n = x11_auth::display_number(display)?;
    let sock = UnixStream::connect(format!("/tmp/.X11-unix/X{n}")).map_err(|e| e.to_string())?;
    let cookie = x11_auth::cookie(n);
    connect_on(sock, cookie.as_deref().map(|c| &c[..]))
}

pub fn connect_on(mut sock: UnixStream, cookie: Option<&[u8]>) -> Result<Conn, String> {
    let io = |e: std::io::Error| e.to_string();
    sock.set_read_timeout(Some(REPLY_WAIT)).map_err(io)?;
    sock.write_all(&setup_request(cookie)).map_err(io)?;
    let mut head = [0u8; 8];
    sock.read_exact(&mut head).map_err(io)?;
    let mut reply = vec![0u8; 8 + le16(&head, 6).unwrap_or(0) as usize * 4];
    reply[..8].copy_from_slice(&head);
    sock.read_exact(&mut reply[8..]).map_err(io)?;
    sock.set_read_timeout(None).map_err(io)?;
    let setup = parse_setup(&reply)?;
    Ok(Conn {
        sock,
        buf: Vec::new(),
        seq: 0,
        next_id: 0,
        events: VecDeque::new(),
        setup,
    })
}

impl Conn {
    pub fn new_id(&mut self) -> u32 {
        self.next_id += 1;
        self.setup.id_base | (self.next_id & self.setup.id_mask)
    }

    /// Send one request; its sequence number.
    pub fn send(&mut self, req: &[u8]) -> Result<u16, String> {
        self.sock.write_all(req).map_err(|e| e.to_string())?;
        self.seq = self.seq.wrapping_add(1);
        Ok(self.seq)
    }

    /// The reply to request `seq`, queueing events that arrive first.
    pub fn reply(&mut self, seq: u16) -> Result<Vec<u8>, String> {
        let until = Instant::now() + REPLY_WAIT;
        loop {
            while let Some(used) = packet_len(&self.buf) {
                let p: Vec<u8> = self.buf.drain(..used).collect();
                match p[0] {
                    0 => check_error(&p)?,
                    1 if le16(&p, 2) == Some(seq) => return Ok(p),
                    1 => {} // a reply nobody waits for
                    _ => self.queue(&p),
                }
            }
            if !self.wait(until.saturating_duration_since(Instant::now()))? {
                return Err("the X server did not answer".into());
            }
        }
    }

    /// The next event within `timeout` (None on timeout).
    pub fn event(&mut self, timeout: Duration) -> Result<Option<[u8; 32]>, String> {
        let until = Instant::now() + timeout;
        loop {
            while let Some(used) = packet_len(&self.buf) {
                let p: Vec<u8> = self.buf.drain(..used).collect();
                match p[0] {
                    0 => check_error(&p)?,
                    1 => {}
                    _ => self.queue(&p),
                }
            }
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(e));
            }
            if !self.wait(until.saturating_duration_since(Instant::now()))? {
                return Ok(None);
            }
        }
    }

    fn queue(&mut self, p: &[u8]) {
        let mut e = [0u8; 32];
        e.copy_from_slice(&p[..32]);
        self.events.push_back(e);
    }

    /// Wait up to `timeout` for input and read it. False on timeout.
    fn wait(&mut self, timeout: Duration) -> Result<bool, String> {
        let fd = self.sock.as_raw_fd();
        if !super::wl_wire::poll_fd(fd, libc::POLLIN, timeout).map_err(|e| e.to_string())? {
            return Ok(false);
        }
        let mut b = [0u8; 4096];
        match self.sock.read(&mut b) {
            Ok(0) => Err("the X server closed the connection".into()),
            Ok(n) => {
                self.buf.extend_from_slice(&b[..n]);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The size of the whole packet at the start of `buf`, once it is all
/// there: replies are 32 bytes plus their length, errors and events 32.
fn packet_len(buf: &[u8]) -> Option<usize> {
    let size = match *buf.first()? {
        1 => 32 + le32(buf, 4)? as usize * 4,
        _ => 32,
    };
    (buf.len() >= size).then_some(size)
}

/// Errors caused by a requestor (a window gone before we answered) are
/// not ours; anything else ends the connection.
fn check_error(p: &[u8]) -> Result<(), String> {
    match p.get(10) {
        Some(&CHANGE_PROPERTY) | Some(&SEND_EVENT) => Ok(()),
        major => Err(format!(
            "X11 error {} for request {}",
            p.get(1).copied().unwrap_or(0),
            major.copied().unwrap_or(0)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_request_with_a_cookie() {
        let cookie: Vec<u8> = (1..=16).collect();
        let mut want = vec![b'l', 0, 11, 0, 0, 0, 18, 0, 16, 0, 0, 0];
        want.extend(b"MIT-MAGIC-COOKIE-1\0\0");
        want.extend(1..=16u8);
        assert_eq!(&setup_request(Some(&cookie))[..], &want[..]);
        assert_eq!(
            &setup_request(None)[..],
            &[b'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn request_encodings() {
        assert_eq!(
            intern_atom("TARGETS"),
            [16, 0, 4, 0, 7, 0, 0, 0, b'T', b'A', b'R', b'G', b'E', b'T', b'S', 0]
        );
        assert_eq!(get_selection_owner(9), [23, 0, 2, 0, 9, 0, 0, 0]);
        let p = change_property(5, 6, 7, 8, b"abcde");
        assert_eq!(p.len(), 32);
        assert_eq!(&p[..4], &[CHANGE_PROPERTY, 0, 8, 0]);
        assert_eq!(
            (le32(&p, 4), le32(&p, 8), le32(&p, 12)),
            (Some(5), Some(6), Some(7))
        );
        assert_eq!((p[16], le32(&p, 20)), (8, Some(5)));
        assert_eq!(&p[24..29], b"abcde");
        let atoms = change_property(5, 6, ATOM_ATOM, 32, &[0; 12]);
        assert_eq!(le32(&atoms, 20), Some(3));
        assert_eq!(create_window(1, 2).len(), 32);
        assert_eq!(selection_notify(1, 2, 3, 4, 0).len(), 44);
    }
}
