// cli_clip/wayland.rs — own the Wayland clipboard through a data-control
// protocol (T12.47): `ext_data_control_manager_v1`, else wlroots'
// `zwlr_data_control_manager_v1` (wlroots compositors, KWin). The value
// is offered as text plus `x-kde-passwordManagerHint` = `secret`, so
// clipboard managers that honour the hint don't store it. Served until
// the deadline, then the selection is dropped, unless another client
// took it first (`cancelled`: nothing of ours left to clear).

use std::os::unix::io::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;

use super::wl_wire::{poll_fd, Arg, Args, Conn, Msg};
use super::{HINT_MIME, HINT_VALUE, MAX_VALUE, TEXT_TYPES};

const DISPLAY: u32 = 1;
// wl_display requests: sync, get_registry; events: error, delete_id.
const SYNC: u16 = 0;
const GET_REGISTRY: u16 = 1;
const ERROR: u16 = 0;
// wl_registry: bind; event global. wl_callback event done.
const BIND: u16 = 0;
const GLOBAL: u16 = 0;
const DONE: u16 = 0;
// The two data-control managers share their opcodes.
const MANAGERS: [&str; 2] = [
    "ext_data_control_manager_v1",
    "zwlr_data_control_manager_v1",
];
const CREATE_DATA_SOURCE: u16 = 0;
const GET_DATA_DEVICE: u16 = 1;
const OFFER: u16 = 0; // source request
const SEND: u16 = 0; // source events
const CANCELLED: u16 = 1;
const SET_SELECTION: u16 = 0; // device request
const FINISHED: u16 = 2; // device event

const ROUNDTRIP: Duration = Duration::from_secs(5);
const WRITE_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub enum WlError {
    /// Neither data-control manager is advertised (GNOME / Mutter).
    NoDataControl,
    TooLarge,
    Protocol(String),
    Io(String),
}

impl std::fmt::Display for WlError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WlError::NoDataControl => write!(f, "the compositor has no data-control protocol"),
            WlError::TooLarge => write!(f, "value too large for the clipboard"),
            WlError::Protocol(e) | WlError::Io(e) => write!(f, "wayland: {e}"),
        }
    }
}

fn io(e: std::io::Error) -> WlError {
    WlError::Io(e.to_string())
}

/// `$WAYLAND_DISPLAY` (default `wayland-0`): an absolute path, or a name
/// under `$XDG_RUNTIME_DIR`.
fn socket_path(
    display: Option<std::ffi::OsString>,
    runtime: Option<std::ffi::OsString>,
) -> Result<PathBuf, WlError> {
    let d = PathBuf::from(display.unwrap_or_else(|| "wayland-0".into()));
    if d.is_absolute() {
        return Ok(d);
    }
    let r = runtime.ok_or_else(|| WlError::Io("XDG_RUNTIME_DIR is not set".into()))?;
    Ok(PathBuf::from(r).join(d))
}

/// Serve `value` on the session's clipboard for `secs` seconds; `ready`
/// runs once the selection is set.
pub fn serve(value: &ZeroString, secs: u64, ready: impl FnOnce()) -> Result<(), WlError> {
    let path = socket_path(
        std::env::var_os("WAYLAND_DISPLAY"),
        std::env::var_os("XDG_RUNTIME_DIR"),
    )?;
    let sock = UnixStream::connect(path).map_err(io)?;
    serve_on(sock, value, Duration::from_secs(secs), ready)
}

#[derive(PartialEq)]
enum Flow {
    Serving,
    /// Another client owns the selection now (or the seat went away).
    Lost,
}

struct Client<'v> {
    conn: Conn,
    next_id: u32,
    value: &'v [u8],
    registry: u32,
    source: u32,
    device: u32,
    globals: Vec<(u32, String, u32)>,
    /// The callback of the roundtrip in flight, and whether it is done.
    callback: u32,
    answered: bool,
}

pub(crate) fn serve_on(
    sock: UnixStream,
    value: &ZeroString,
    hold: Duration,
    ready: impl FnOnce(),
) -> Result<(), WlError> {
    if value.len() > MAX_VALUE {
        return Err(WlError::TooLarge);
    }
    let deadline = Instant::now()
        .checked_add(hold)
        .ok_or_else(|| WlError::Io("clear time out of range".into()))?;
    let mut c = Client {
        conn: Conn::new(sock),
        next_id: 2,
        value: value.as_bytes(),
        registry: 0,
        source: 0,
        device: 0,
        globals: Vec::new(),
        callback: 0,
        answered: false,
    };
    c.registry = c.new_id();
    c.send(DISPLAY, GET_REGISTRY, &[Arg::NewId(c.registry)])?;
    c.roundtrip()?;
    let seat = c.global(|i| i == "wl_seat");
    let manager = MANAGERS.iter().find_map(|m| c.global(|i| i == *m));
    let (Some((seat, _)), Some((manager, iface))) = (seat, manager) else {
        return Err(WlError::NoDataControl);
    };
    let seat = c.bind(seat, "wl_seat")?;
    let manager = c.bind(manager, &iface)?;
    c.source = c.new_id();
    c.send(manager, CREATE_DATA_SOURCE, &[Arg::NewId(c.source)])?;
    for mime in TEXT_TYPES.iter().chain([HINT_MIME].iter()) {
        c.send(c.source, OFFER, &[Arg::Str(mime)])?;
    }
    c.device = c.new_id();
    let device_args = [Arg::NewId(c.device), Arg::Object(seat)];
    c.send(manager, GET_DATA_DEVICE, &device_args)?;
    c.send(c.device, SET_SELECTION, &[Arg::Object(c.source)])?;
    if c.roundtrip()? == Flow::Lost {
        return Ok(());
    }
    ready();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if c.pump(deadline - now)? == Flow::Lost {
            return Ok(());
        }
    }
    // Whatever already arrived first: a selection another client took at
    // the last moment is not ours to clear.
    if c.pump(Duration::ZERO)? == Flow::Lost {
        return Ok(());
    }
    c.send(c.device, SET_SELECTION, &[Arg::Object(0)])?;
    let _ = c.roundtrip();
    Ok(())
}

impl Client<'_> {
    fn new_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id - 1
    }

    fn send(&self, object: u32, opcode: u16, args: &[Arg]) -> Result<(), WlError> {
        let m = super::wl_wire::encode(object, opcode, args);
        self.conn.send(&m, &[]).map_err(io)
    }

    /// The first advertised global whose interface matches.
    fn global(&self, want: impl Fn(&str) -> bool) -> Option<(u32, String)> {
        self.globals
            .iter()
            .find(|(_, i, _)| want(i))
            .map(|(n, i, _)| (*n, i.clone()))
    }

    /// Bind a global at version 1, which has every request we use.
    fn bind(&mut self, name: u32, iface: &str) -> Result<u32, WlError> {
        let id = self.new_id();
        let args = [
            Arg::Uint(name),
            Arg::Str(iface),
            Arg::Uint(1),
            Arg::NewId(id),
        ];
        self.send(self.registry, BIND, &args)?;
        Ok(id)
    }

    /// `wl_display.sync` and wait for its `done`, handling events.
    fn roundtrip(&mut self) -> Result<Flow, WlError> {
        self.callback = self.new_id();
        self.answered = false;
        self.send(DISPLAY, SYNC, &[Arg::NewId(self.callback)])?;
        let until = Instant::now() + ROUNDTRIP;
        let mut flow = Flow::Serving;
        while !self.answered {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(WlError::Io("the compositor did not answer".into()));
            }
            if self.pump(left)? == Flow::Lost {
                flow = Flow::Lost;
            }
        }
        Ok(flow)
    }

    /// Wait up to `timeout` for input, then handle every whole message.
    fn pump(&mut self, timeout: Duration) -> Result<Flow, WlError> {
        if !self.conn.readable(timeout).map_err(io)? {
            return Ok(Flow::Serving);
        }
        if !self.conn.fill().map_err(io)? {
            return Err(WlError::Io("the compositor closed the connection".into()));
        }
        let mut flow = Flow::Serving;
        while let Some(m) = self.conn.next().map_err(WlError::Protocol)? {
            if self.handle(m)? == Flow::Lost {
                flow = Flow::Lost;
            }
        }
        Ok(flow)
    }

    fn handle(&mut self, m: Msg) -> Result<Flow, WlError> {
        let mut a = Args::new(&m.args);
        match (m.object, m.opcode) {
            (DISPLAY, ERROR) => {
                let (obj, code) = (a.uint().unwrap_or(0), a.uint().unwrap_or(0));
                let text = a.string().unwrap_or("");
                return Err(WlError::Protocol(format!(
                    "error {code} on object {obj}: {text}"
                )));
            }
            (o, GLOBAL) if o == self.registry => {
                if let (Some(n), Some(i), Some(v)) = (a.uint(), a.string(), a.uint()) {
                    self.globals.push((n, i.to_string(), v));
                }
            }
            (o, SEND) if o == self.source && o != 0 => {
                let mime = a.string().unwrap_or("").to_string();
                if let Some(fd) = self.conn.take_fd() {
                    self.answer(&mime, fd);
                }
            }
            (o, CANCELLED) if o == self.source && o != 0 => return Ok(Flow::Lost),
            (o, FINISHED) if o == self.device && o != 0 => return Ok(Flow::Lost),
            (o, DONE) if o == self.callback => self.answered = true,
            _ => {} // delete_id, seat and offer events: nothing to do
        }
        Ok(Flow::Serving)
    }

    /// Write what `mime` stands for into the pipe the reader gave us,
    /// then close it. A reader that stops reading gets cut off.
    fn answer(&self, mime: &str, fd: OwnedFd) {
        let data: &[u8] = if mime == HINT_MIME {
            HINT_VALUE
        } else if TEXT_TYPES.contains(&mime) {
            self.value
        } else {
            &[]
        };
        let _ = write_within(&fd, data, WRITE_BUDGET);
    }
}

fn write_within(fd: &OwnedFd, mut data: &[u8], budget: Duration) -> std::io::Result<()> {
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl on an fd we own.
    unsafe {
        let fl = libc::fcntl(raw, libc::F_GETFL);
        libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let until = Instant::now() + budget;
    while !data.is_empty() {
        // SAFETY: writes from a live slice to an fd we own.
        let n = unsafe { libc::write(raw, data.as_ptr() as *const _, data.len()) };
        if n >= 0 {
            data = &data[n as usize..];
            continue;
        }
        let e = std::io::Error::last_os_error();
        match e.kind() {
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() || !poll_fd(raw, libc::POLLOUT, left)? {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
            }
            _ => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_clip::wl_wire::encode;
    use std::collections::HashMap;
    use std::io::Read;
    use std::os::unix::io::FromRawFd;
    use std::sync::mpsc;

    const SEAT_AND_EXT: &[(u32, &str, u32)] =
        &[(1, "wl_seat", 8), (2, "ext_data_control_manager_v1", 1)];

    #[derive(Debug, PartialEq)]
    enum Req {
        Bind(String, u32),
        Offer(String),
        SetSelection(u32),
        Sync,
        Other(String, u16),
    }

    /// A compositor that answers the registry and syncs and logs the rest.
    struct Fake {
        conn: Conn,
        globals: &'static [(u32, &'static str, u32)],
        ifaces: HashMap<u32, String>,
        log: Vec<Req>,
    }

    impl Fake {
        fn new(sock: UnixStream, globals: &'static [(u32, &'static str, u32)]) -> Self {
            let ifaces = HashMap::from([(DISPLAY, "wl_display".to_string())]);
            Fake {
                conn: Conn::new(sock),
                globals,
                ifaces,
                log: Vec::new(),
            }
        }

        fn event(&self, object: u32, opcode: u16, args: &[Arg], fds: &[i32]) {
            self.conn.send(&encode(object, opcode, args), fds).unwrap();
        }

        fn id_of(&self, iface: &str) -> u32 {
            *self
                .ifaces
                .iter()
                .find(|(_, i)| *i == iface)
                .expect(iface)
                .0
        }

        /// Handle requests until `until(log)` holds (true) or the client
        /// hangs up (false).
        fn pump(&mut self, until: impl Fn(&[Req]) -> bool) -> bool {
            loop {
                if until(&self.log) {
                    return true;
                }
                assert!(
                    self.conn.readable(Duration::from_secs(5)).unwrap(),
                    "client stalled"
                );
                if !self.conn.fill().unwrap() {
                    return false;
                }
                while let Some(m) = self.conn.next().unwrap() {
                    self.handle(m);
                }
            }
        }

        fn handle(&mut self, m: Msg) {
            let mut a = Args::new(&m.args);
            let iface = self.ifaces.get(&m.object).cloned().unwrap_or_default();
            let req = match (iface.as_str(), m.opcode) {
                ("wl_display", GET_REGISTRY) => {
                    let id = a.uint().unwrap();
                    self.ifaces.insert(id, "wl_registry".into());
                    for (n, i, v) in self.globals {
                        self.event(
                            id,
                            GLOBAL,
                            &[Arg::Uint(*n), Arg::Str(i), Arg::Uint(*v)],
                            &[],
                        );
                    }
                    return;
                }
                ("wl_display", SYNC) => {
                    self.event(a.uint().unwrap(), DONE, &[Arg::Uint(0)], &[]);
                    Req::Sync
                }
                ("wl_registry", BIND) => {
                    let (_, i, v, id) = (a.uint(), a.string().unwrap(), a.uint(), a.uint());
                    self.ifaces.insert(id.unwrap(), i.to_string());
                    Req::Bind(i.to_string(), v.unwrap())
                }
                (m_, CREATE_DATA_SOURCE) if MANAGERS.contains(&m_) => {
                    self.ifaces.insert(a.uint().unwrap(), "source".into());
                    return;
                }
                (m_, GET_DATA_DEVICE) if MANAGERS.contains(&m_) => {
                    self.ifaces.insert(a.uint().unwrap(), "device".into());
                    assert_eq!(a.uint(), Some(self.id_of("wl_seat")));
                    return;
                }
                ("source", OFFER) => Req::Offer(a.string().unwrap().to_string()),
                ("device", SET_SELECTION) => Req::SetSelection(a.uint().unwrap()),
                (i, op) => Req::Other(i.to_string(), op),
            };
            self.log.push(req);
        }

        fn selections(&self) -> Vec<u32> {
            let s = self.log.iter().filter_map(|r| match r {
                Req::SetSelection(s) => Some(*s),
                _ => None,
            });
            s.collect()
        }

        /// Ask for `mime` as the paste side would, and read the answer.
        fn paste(&self, mime: &str) -> Vec<u8> {
            let mut p = [0; 2];
            // SAFETY: pipe2 fills two fresh fds, each owned once below.
            assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let (mut r, w) = unsafe {
                (
                    std::fs::File::from_raw_fd(p[0]),
                    std::fs::File::from_raw_fd(p[1]),
                )
            };
            self.event(
                self.id_of("source"),
                SEND,
                &[Arg::Str(mime)],
                &[w.as_raw_fd()],
            );
            drop(w);
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            out
        }
    }

    type Served = std::thread::JoinHandle<Result<(), WlError>>;

    /// `serve_on` in a thread against a fake with `globals`; the receiver
    /// fires on `ready`.
    fn start(
        value: &str,
        hold: Duration,
        globals: &'static [(u32, &'static str, u32)],
    ) -> (Fake, Served, mpsc::Receiver<()>) {
        let (a, b) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel();
        let value = ZeroString::from(value);
        let t = std::thread::spawn(move || serve_on(a, &value, hold, move || tx.send(()).unwrap()));
        (Fake::new(b, globals), t, rx)
    }

    fn set_and_synced(log: &[Req]) -> bool {
        let at = log
            .iter()
            .position(|r| matches!(r, Req::SetSelection(s) if *s != 0));
        at.is_some_and(|i| log[i..].contains(&Req::Sync))
    }

    #[test]
    fn offers_text_and_the_hint_and_serves_both() {
        let (mut f, t, ready) = start("s3cr3t-value", Duration::from_secs(30), SEAT_AND_EXT);
        assert!(f.pump(set_and_synced));
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut offers: Vec<&str> = TEXT_TYPES.to_vec();
        offers.push(HINT_MIME);
        let got: Vec<&str> = f
            .log
            .iter()
            .filter_map(|r| match r {
                Req::Offer(m) => Some(m.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(got, offers);
        assert_eq!(f.selections(), [f.id_of("source")]);
        assert!(f
            .log
            .contains(&Req::Bind("ext_data_control_manager_v1".into(), 1)));
        assert_eq!(f.paste("text/plain;charset=utf-8"), b"s3cr3t-value");
        assert_eq!(f.paste("UTF8_STRING"), b"s3cr3t-value");
        assert_eq!(f.paste(HINT_MIME), b"secret");
        assert_eq!(f.paste("image/png"), b"");
        f.event(f.id_of("source"), CANCELLED, &[], &[]);
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        assert_eq!(f.selections().len(), 1);
    }

    #[test]
    fn the_deadline_drops_the_selection() {
        let (mut f, t, ready) = start("v", Duration::from_secs(1), SEAT_AND_EXT);
        assert!(f.pump(|l| l.contains(&Req::SetSelection(0))));
        ready.try_recv().unwrap();
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        assert_eq!(f.selections(), [f.id_of("source"), 0]);
    }

    #[test]
    fn cancelled_means_nothing_to_clear() {
        let started = Instant::now();
        let (mut f, t, ready) = start("v", Duration::from_secs(30), SEAT_AND_EXT);
        assert!(f.pump(set_and_synced));
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        f.event(f.id_of("source"), CANCELLED, &[], &[]);
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        assert!(!f.selections().contains(&0));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn wlroots_manager_is_the_fallback() {
        static G: &[(u32, &str, u32)] =
            &[(4, "zwlr_data_control_manager_v1", 2), (5, "wl_seat", 7)];
        let (mut f, t, _ready) = start("v", Duration::ZERO, G);
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        assert!(f
            .log
            .contains(&Req::Bind("zwlr_data_control_manager_v1".into(), 1)));
        assert_eq!(f.selections(), [f.id_of("source"), 0]);
    }

    #[test]
    fn no_data_control_global() {
        static G: &[(u32, &str, u32)] = &[(1, "wl_seat", 8), (2, "wl_data_device_manager", 3)];
        let (mut f, t, ready) = start("v", Duration::from_secs(30), G);
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Err(WlError::NoDataControl));
        assert!(ready.try_recv().is_err());
        assert!(f.selections().is_empty());
    }

    #[test]
    fn a_protocol_error_is_an_error() {
        let (mut f, t, _ready) = start("v", Duration::from_secs(30), SEAT_AND_EXT);
        assert!(f.pump(set_and_synced));
        let args = [Arg::Object(1), Arg::Uint(1), Arg::Str("bad request")];
        f.event(DISPLAY, ERROR, &args, &[]);
        let e = t.join().unwrap().unwrap_err();
        assert_eq!(
            e,
            WlError::Protocol("error 1 on object 1: bad request".into())
        );
    }

    #[test]
    fn a_value_over_the_limit_is_refused() {
        let (a, _b) = UnixStream::pair().unwrap();
        let big = ZeroString::from_string("x".repeat(MAX_VALUE + 1));
        let r = serve_on(a, &big, Duration::ZERO, || panic!("ready"));
        assert_eq!(r, Err(WlError::TooLarge));
    }

    #[test]
    fn socket_path_rules() {
        let p =
            |d: Option<&str>, r: Option<&str>| socket_path(d.map(Into::into), r.map(Into::into));
        assert_eq!(p(Some("/run/w.sock"), None), Ok("/run/w.sock".into()));
        assert_eq!(
            p(Some("wayland-1"), Some("/run/user/1")),
            Ok("/run/user/1/wayland-1".into())
        );
        assert_eq!(p(None, Some("/r")), Ok("/r/wayland-0".into()));
        assert!(p(Some("wayland-1"), None).is_err());
    }
}
