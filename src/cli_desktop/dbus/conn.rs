// cli_desktop/dbus/conn.rs — a connection to the bus.
//
// One reader thread decodes what the bus sends. Replies go to whoever
// `call`ed (matched by serial); method calls and signals go to the handler,
// which runs on the reader thread, so a handler that needs the bus itself
// (a `call`) must hand the work to another thread first. Writes from any
// thread are serialised. Every buffer that held a message is wiped.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use zeroize::Zeroizing;

use super::addr::{self, Endpoint};
use super::auth;
use super::msg::{Message, ERROR, METHOD_RETURN};
use super::value::Value;

pub type Handler = dyn Fn(&Arc<Conn>, Message) + Send + Sync + 'static;

pub const BUS: &str = "org.freedesktop.DBus";
pub const BUS_PATH: &str = "/org/freedesktop/DBus";
pub const CALL_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The peer answered with an error message.
    Remote { name: String, text: String },
    /// No answer: closed, write failure or timeout.
    Local(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Remote { name, text } => write!(f, "{name}: {text}"),
            CallError::Local(e) => f.write_str(e),
        }
    }
}

pub struct Conn {
    write: Mutex<UnixStream>,
    serial: AtomicU32,
    pending: Mutex<HashMap<u32, Sender<Message>>>,
    name: OnceLock<String>,
    closed: AtomicBool,
}

impl Conn {
    /// Connect to the first endpoint that answers, log in as `uid`, start
    /// reading and say Hello.
    pub fn connect(eps: &[Endpoint], uid: u32, handler: Arc<Handler>) -> Result<Arc<Conn>, String> {
        Self::start(addr::connect(eps)?, uid, handler)
    }

    pub fn start(mut s: UnixStream, uid: u32, handler: Arc<Handler>) -> Result<Arc<Conn>, String> {
        let io = |e: std::io::Error| format!("bus socket: {e}");
        s.set_read_timeout(Some(auth::TIMEOUT)).map_err(io)?;
        s.set_write_timeout(Some(auth::TIMEOUT)).map_err(io)?;
        auth::client(&mut s, uid)?;
        s.set_read_timeout(None).map_err(io)?;
        let reader = s.try_clone().map_err(io)?;
        let conn = Arc::new(Conn {
            write: Mutex::new(s),
            serial: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
            name: OnceLock::new(),
            closed: AtomicBool::new(false),
        });
        let c = Arc::clone(&conn);
        std::thread::Builder::new()
            .name("dbus-reader".into())
            .spawn(move || c.read_loop(reader, &handler))
            .map_err(|e| e.to_string())?;
        let hello = Message::call(BUS, BUS_PATH, BUS, "Hello", vec![]);
        let reply = conn
            .call(hello, auth::TIMEOUT)
            .map_err(|e| format!("Hello: {e}"))?;
        let name = reply
            .body
            .first()
            .and_then(Value::as_str)
            .ok_or("Hello returned no name")?;
        let _ = conn.name.set(name.to_string());
        Ok(conn)
    }

    /// The bus's name for this connection (`:1.42`).
    pub fn unique_name(&self) -> &str {
        self.name.get().map_or("", String::as_str)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(s) = self.write.lock() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    fn next_serial(&self) -> u32 {
        loop {
            let n = self.serial.fetch_add(1, Ordering::SeqCst);
            if n != 0 {
                return n;
            }
        }
    }

    /// Send `m`; returns the serial it went out under.
    pub fn send(&self, m: &Message) -> Result<u32, String> {
        if self.is_closed() {
            return Err("the bus connection is closed".into());
        }
        let serial = self.next_serial();
        let bytes = m.encode(serial)?;
        let mut w = self.write.lock().unwrap_or_else(|p| p.into_inner());
        w.write_all(&bytes).map_err(|e| format!("bus write: {e}"))?;
        Ok(serial)
    }

    /// Send a method call and wait for its return.
    pub fn call(&self, m: Message, timeout: Duration) -> Result<Message, CallError> {
        let (tx, rx) = channel();
        // The serial is known only once encoded; hold the lock across both.
        let serial;
        {
            let mut p = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            if self.is_closed() {
                return Err(CallError::Local("the bus connection is closed".into()));
            }
            serial = self.send(&m).map_err(CallError::Local)?;
            p.insert(serial, tx);
        }
        let reply = rx.recv_timeout(timeout);
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&serial);
        match reply {
            Ok(r) if r.kind == ERROR => Err(CallError::Remote {
                name: r.error_name.clone().unwrap_or_default(),
                text: r
                    .body
                    .first()
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            }),
            Ok(r) => Ok(r),
            Err(_) => Err(CallError::Local("no reply from the bus".into())),
        }
    }

    fn read_loop(self: Arc<Self>, mut s: UnixStream, handler: &Arc<Handler>) {
        loop {
            let mut head = [0u8; 16];
            if s.read_exact(&mut head).is_err() {
                break;
            }
            let Ok(total) = Message::total_len(&head) else {
                break;
            };
            let mut buf = Zeroizing::new(vec![0u8; total]);
            buf[..16].copy_from_slice(&head);
            if s.read_exact(&mut buf[16..]).is_err() {
                break;
            }
            // A message that does not decode is dropped; the stream is
            // still in step because its length was read.
            let Ok(m) = Message::decode(&buf) else {
                continue;
            };
            drop(buf);
            if m.kind == METHOD_RETURN || m.kind == ERROR {
                let tx = m.reply_serial.and_then(|r| {
                    self.pending
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&r)
                });
                if let Some(tx) = tx {
                    let _ = tx.send(m);
                }
            } else {
                handler(&self, m);
            }
        }
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A bus that answers Hello and echoes the first argument of anything
    /// else, in the other order of two quick calls.
    fn fake_bus(mut s: UnixStream) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut b = [0u8; 1];
            while !got.ends_with(b"BEGIN\r\n") {
                if s.read(&mut b).unwrap_or(0) == 0 {
                    return;
                }
                got.push(b[0]);
                if got.ends_with(b"\r\n")
                    && got.starts_with(b"\0AUTH")
                    && !got.ends_with(b"BEGIN\r\n")
                {
                    s.write_all(b"OK 00112233445566778899aabbccddeeff\r\n")
                        .unwrap();
                }
            }
            let mut serial = 100;
            loop {
                let mut head = [0u8; 16];
                if s.read_exact(&mut head).is_err() {
                    return;
                }
                let total = Message::total_len(&head).unwrap();
                let mut buf = vec![0u8; total];
                buf[..16].copy_from_slice(&head);
                s.read_exact(&mut buf[16..]).unwrap();
                let m = Message::decode(&buf).unwrap();
                serial += 1;
                let reply = match m.member.as_deref() {
                    Some("Hello") => Message {
                        reply_serial: Some(m.serial),
                        kind: METHOD_RETURN,
                        body: vec![Value::str(":1.5")],
                        ..Default::default()
                    },
                    Some("Fail") => Message {
                        kind: ERROR,
                        error_name: Some("a.b.Err".into()),
                        reply_serial: Some(m.serial),
                        body: vec![Value::str("nope")],
                        ..Default::default()
                    },
                    Some("Silent") => continue,
                    Some("Signal") => {
                        let sig = Message::signal("/p", "a.b", "Ping", vec![Value::U32(9)]);
                        s.write_all(&sig.encode(serial).unwrap()).unwrap();
                        Message {
                            reply_serial: Some(m.serial),
                            kind: METHOD_RETURN,
                            ..Default::default()
                        }
                    }
                    _ => Message {
                        reply_serial: Some(m.serial),
                        kind: METHOD_RETURN,
                        body: m.body.clone(),
                        ..Default::default()
                    },
                };
                s.write_all(&reply.encode(serial + 1000).unwrap()).unwrap();
            }
        })
    }

    fn connect() -> (Arc<Conn>, mpsc::Receiver<Message>) {
        let (a, b) = UnixStream::pair().unwrap();
        fake_bus(b);
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let h: Arc<Handler> = Arc::new(move |_, m| {
            let _ = tx.lock().unwrap().send(m);
        });
        (Conn::start(a, 1000, h).unwrap(), rx)
    }

    #[test]
    fn hello_names_the_connection_and_calls_get_their_own_replies() {
        let (c, _) = connect();
        assert_eq!(c.unique_name(), ":1.5");
        let echo = |n: u32| Message::call("x.y", "/p", "a.b", "Echo", vec![Value::U32(n)]);
        // From several threads at once: each gets its own answer.
        let hs: Vec<_> = (0..8)
            .map(|n| {
                let c = Arc::clone(&c);
                std::thread::spawn(move || {
                    c.call(echo(n), Duration::from_secs(5)).unwrap().body[0].as_u32()
                })
            })
            .collect();
        for (n, h) in hs.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), Some(n as u32));
        }
    }

    #[test]
    fn errors_timeouts_and_signals() {
        let (c, rx) = connect();
        let e = c
            .call(
                Message::call("x.y", "/p", "a.b", "Fail", vec![]),
                Duration::from_secs(5),
            )
            .unwrap_err();
        assert_eq!(
            e,
            CallError::Remote {
                name: "a.b.Err".into(),
                text: "nope".into()
            }
        );
        assert_eq!(e.to_string(), "a.b.Err: nope");
        let e = c
            .call(
                Message::call("x.y", "/p", "a.b", "Silent", vec![]),
                Duration::from_millis(100),
            )
            .unwrap_err();
        assert!(matches!(e, CallError::Local(_)));
        c.call(
            Message::call("x.y", "/p", "a.b", "Signal", vec![]),
            Duration::from_secs(5),
        )
        .unwrap();
        let sig = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            (sig.member.as_deref(), sig.body[0].as_u32()),
            (Some("Ping"), Some(9))
        );
    }

    #[test]
    fn closing_fails_waiting_and_later_calls() {
        let (c, _) = connect();
        let c2 = Arc::clone(&c);
        let waiter = std::thread::spawn(move || {
            c2.call(
                Message::call("x.y", "/p", "a.b", "Silent", vec![]),
                Duration::from_secs(20),
            )
        });
        std::thread::sleep(Duration::from_millis(100));
        c.close();
        assert!(waiter.join().unwrap().is_err());
        assert!(c.is_closed());
        assert!(c.send(&Message::signal("/p", "a.b", "X", vec![])).is_err());
        assert!(matches!(
            c.call(
                Message::call("x.y", "/p", "a.b", "Echo", vec![]),
                Duration::from_secs(1)
            ),
            Err(CallError::Local(_))
        ));
    }
}
