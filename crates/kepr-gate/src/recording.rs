//! Session recording (T7.09), gate side. Under `kepr agent run --record`
//! the gate keeps what the agent sends and receives: HTTP request bodies
//! (after the DLP check passed) and response bodies, and the byte streams
//! of database and tunnel connections after login. Only the agent's side
//! of the gate is recorded, so a placeholder stays a placeholder: nothing
//! the gate substituted is ever captured. Chunks go to the daemon in
//! batches over the private channel; the daemon stores them encrypted.
//! Nothing is written to disk here.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use zeroize::Zeroizing;

use crate::db::DbRoute;
use crate::proxy::{Body, State};
use crate::vault::Cache;
use kepr_core::gate_record::{GateRecord, RecChunk, FROM_AGENT, MAX_PIECE, TO_AGENT};
use kepr_core::generate::ZeroString;

/// Unsent bytes kept at most; beyond it chunks are counted as dropped
/// rather than slowing the agent down.
const MAX_PENDING: usize = 8 << 20;
const FLUSH_EVERY: Duration = Duration::from_millis(300);

#[derive(Default)]
struct Pending {
    chunks: Vec<RecChunk>,
    bytes: usize,
    dropped: u64,
}

pub struct Recorder {
    on: bool,
    start: Instant,
    next_conn: AtomicU64,
    pending: Mutex<Pending>,
    /// Held while a batch is on its way, so the final flush at session
    /// end waits for the flusher thread's.
    sending: Mutex<()>,
}

impl Recorder {
    pub fn new(on: bool) -> Self {
        Recorder {
            on,
            start: Instant::now(),
            next_conn: AtomicU64::new(1),
            pending: Mutex::default(),
            sending: Mutex::new(()),
        }
    }

    /// A number for a new connection or request.
    pub fn conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::SeqCst)
    }

    pub fn push(&self, conn: u64, route: &str, kind: &str, dir: &str, bytes: &[u8]) {
        if !self.on || bytes.is_empty() {
            return;
        }
        let t = self.start.elapsed().as_millis() as u64;
        let Ok(mut p) = self.pending.lock() else {
            return;
        };
        if p.bytes + bytes.len() > MAX_PENDING {
            p.dropped += bytes.len() as u64;
            return;
        }
        p.bytes += bytes.len();
        for piece in bytes.chunks(MAX_PIECE) {
            p.chunks
                .push(RecChunk::new(t, conn, route, kind, dir, piece));
        }
    }

    /// Everything pending, in frame-sized batches.
    pub(crate) fn take(&self) -> Vec<GateRecord> {
        let p = match self.pending.lock() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => return Vec::new(),
        };
        GateRecord::batches(p.chunks, p.dropped)
    }

    /// Send what is pending to the daemon.
    pub fn flush(&self, cache: &Cache) {
        let Ok(_sending) = self.sending.lock() else {
            return;
        };
        for batch in self.take() {
            if cache.record(batch).is_err() {
                break; // the daemon refused (store locked, size cap): stop
            }
        }
    }

    /// An HTTP request as the agent sent it (path without the query):
    /// returns its number for the response.
    pub fn http_request(&self, route: &str, method: &str, path: &str, body: &[u8]) -> u64 {
        let conn = self.conn();
        let line = format!("{method} {path}\n\n");
        self.push(conn, route, "http", FROM_AGENT, line.as_bytes());
        self.push(conn, route, "http", FROM_AGENT, body);
        conn
    }

    /// The response the agent receives: its status line, then the body
    /// as it streams, with this session's resolved values masked out.
    pub fn http_response(
        self: &Arc<Self>,
        conn: u64,
        route: &str,
        status: u16,
        b: Body,
        cache: &Cache,
    ) -> Body {
        if !self.on {
            return b;
        }
        let line = format!("HTTP {status}\n\n");
        self.push(conn, route, "http", TO_AGENT, line.as_bytes());
        let mut masked = Masked {
            rec: self.clone(),
            conn,
            route: route.to_string(),
            secrets: cache.values().into_iter().map(|(_, v)| v).collect(),
            carry: Zeroizing::default(),
        };
        b.map_frame(move |f| {
            if let Some(d) = f.data_ref() {
                masked.feed(d);
            }
            f
        })
        .boxed()
    }

    /// The agent's end of a relayed connection, recorded both ways.
    pub fn tap<'a, S>(&'a self, s: &'a mut S, route: &'a str, kind: &'a str) -> Tap<'a, S> {
        Tap {
            conn: self.conn(),
            inner: s,
            rec: self,
            route,
            kind,
        }
    }
}

/// A response body on its way into the recording. The agent's side holds
/// placeholders only, but an upstream may echo the key it was sent (an
/// error message quoting it): every value this session resolved is
/// overwritten with `*` before it is recorded. The last bytes wait for
/// the next frame, so a value split across two frames is caught too.
struct Masked {
    rec: Arc<Recorder>,
    conn: u64,
    route: String,
    secrets: Vec<ZeroString>,
    carry: Zeroizing<Vec<u8>>,
}

impl Masked {
    fn feed(&mut self, data: &[u8]) {
        let longest = self.secrets.iter().map(|s| s.as_str().len()).max();
        let keep = longest.unwrap_or(0).saturating_sub(1);
        let mut buf = Zeroizing::new([&self.carry[..], data].concat());
        mask(&mut buf, &self.secrets);
        let cut = buf.len().saturating_sub(keep);
        self.rec
            .push(self.conn, &self.route, "http", TO_AGENT, &buf[..cut]);
        self.carry = Zeroizing::new(buf[cut..].to_vec());
    }
}

impl Drop for Masked {
    fn drop(&mut self) {
        let rest = std::mem::take(&mut self.carry);
        self.rec
            .push(self.conn, &self.route, "http", TO_AGENT, &rest);
    }
}

fn mask(buf: &mut [u8], secrets: &[ZeroString]) {
    for s in secrets.iter().map(|s| s.as_str().as_bytes()) {
        let mut i = 0;
        while !s.is_empty() && i + s.len() <= buf.len() {
            if &buf[i..i + s.len()] == s {
                buf[i..i + s.len()].fill(b'*');
                i += s.len();
            } else {
                i += 1;
            }
        }
    }
}

/// Relay a logged-in database or tunnel connection, recording the
/// agent's side of it.
pub async fn relay<U>(state: &State, route: &DbRoute, client: &mut TcpStream, up: &mut U)
where
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut tap = state
        .recorder
        .tap(client, &route.key, route.target.kind.name());
    let _ = tokio::io::copy_bidirectional(&mut tap, up).await;
}

impl State {
    pub fn with_recorder(mut self, recorder: Arc<Recorder>) -> Self {
        self.recorder = recorder;
        self
    }
}

/// Flush on a thread of its own: the daemon channel is blocking.
pub fn spawn_flusher(rec: Arc<Recorder>, cache: Arc<Cache>) {
    if rec.on {
        std::thread::spawn(move || loop {
            std::thread::sleep(FLUSH_EVERY);
            rec.flush(&cache);
        });
    }
}

pub struct Tap<'a, S> {
    inner: &'a mut S,
    rec: &'a Recorder,
    conn: u64,
    route: &'a str,
    kind: &'a str,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut *self.inner).poll_read(cx, buf))?;
        let me = &*self;
        me.rec.push(
            me.conn,
            me.route,
            me.kind,
            FROM_AGENT,
            &buf.filled()[before..],
        );
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let n = ready!(Pin::new(&mut *self.inner).poll_write(cx, data))?;
        let me = &*self;
        me.rec
            .push(me.conn, me.route, me.kind, TO_AGENT, &data[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Resolve, DEFAULT_TTL};
    use kepr_core::binding::Inject;
    use kepr_core::generate::ZeroString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A daemon channel that keeps what it is sent.
    pub struct Sink(pub Arc<Mutex<Vec<GateRecord>>>);
    impl Resolve for Sink {
        fn generation(&self) -> Result<u64, String> {
            Ok(1)
        }
        fn resolve(&self, _: &str, _: &str, _: u16) -> Result<(ZeroString, Inject), String> {
            Err("none".into())
        }
        fn record(&self, r: GateRecord) -> Result<(), String> {
            self.0.lock().unwrap().push(r);
            Ok(())
        }
    }

    fn sink() -> (Cache, Arc<Mutex<Vec<GateRecord>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        (Cache::new(Box::new(Sink(got.clone())), DEFAULT_TTL), got)
    }

    fn all(got: &Arc<Mutex<Vec<GateRecord>>>) -> Vec<RecChunk> {
        got.lock()
            .unwrap()
            .iter()
            .flat_map(|r| r.chunks.clone())
            .collect()
    }

    #[test]
    fn off_records_nothing_and_on_keeps_order() {
        let (cache, got) = sink();
        let off = Recorder::new(false);
        off.push(1, "anthropic", "http", FROM_AGENT, b"x");
        off.flush(&cache);
        assert!(got.lock().unwrap().is_empty());

        let on = Recorder::new(true);
        let c = on.http_request("anthropic", "POST", "/v1/messages", b"{\"a\":1}");
        on.push(c, "anthropic", "http", TO_AGENT, &vec![b'y'; MAX_PIECE + 1]);
        on.flush(&cache);
        let chunks = all(&got);
        let text: Vec<Vec<u8>> = chunks.iter().map(RecChunk::bytes).collect();
        assert_eq!(text[0], b"POST /v1/messages\n\n");
        assert_eq!(text[1], b"{\"a\":1}");
        assert_eq!((text[2].len(), text[3].len()), (MAX_PIECE, 1), "split");
        assert!(chunks.iter().all(|ch| ch.conn == c));
    }

    #[test]
    fn a_value_split_across_frames_is_masked() {
        let rec = Arc::new(Recorder::new(true));
        let mut m = Masked {
            rec: rec.clone(),
            conn: 1,
            route: "anthropic".into(),
            secrets: vec![ZeroString::from_string("sk-abcdefgh".into())],
            carry: Zeroizing::default(),
        };
        for frame in ["key=sk-abc", "defgh ok", " and sk-abcdefgh"] {
            m.feed(frame.as_bytes());
        }
        drop(m);
        let text: Vec<u8> = rec
            .take()
            .into_iter()
            .flat_map(|b| b.chunks)
            .flat_map(|c| c.bytes())
            .collect();
        assert_eq!(text, b"key=*********** ok and ***********");
    }

    #[test]
    fn a_full_buffer_counts_dropped_bytes() {
        let (cache, got) = sink();
        let on = Recorder::new(true);
        let big = vec![0u8; MAX_PENDING];
        on.push(1, "db:A", "postgres", TO_AGENT, &big);
        on.push(1, "db:A", "postgres", TO_AGENT, b"lost");
        on.flush(&cache);
        assert_eq!(got.lock().unwrap()[0].dropped, 4);
    }

    #[tokio::test]
    async fn a_tap_records_both_directions_of_the_agent_side() {
        let (cache, got) = sink();
        let rec = Recorder::new(true);
        let (mut agent, mut gate_end) = tokio::io::duplex(1024);
        agent.write_all(b"Q select").await.unwrap();
        {
            let mut tap = rec.tap(&mut gate_end, "db:A", "postgres");
            let mut buf = [0u8; 8];
            tap.read_exact(&mut buf).await.unwrap();
            tap.write_all(b"rows").await.unwrap();
        }
        let mut back = [0u8; 4];
        agent.read_exact(&mut back).await.unwrap();
        rec.flush(&cache);
        let chunks = all(&got);
        assert_eq!(
            chunks
                .iter()
                .map(|c| (c.dir.as_str(), c.bytes()))
                .collect::<Vec<_>>(),
            vec![
                (FROM_AGENT, b"Q select".to_vec()),
                (TO_AGENT, b"rows".to_vec())
            ]
        );
        assert!(chunks
            .iter()
            .all(|c| c.route == "db:A" && c.kind == "postgres"));
    }

    #[tokio::test]
    async fn a_postgres_session_is_recorded_from_login_on_without_the_password() {
        use crate::db::testkit;
        use crate::pg::{message, read_msg};
        use kepr_core::gate_protocol::TargetKind;
        // A trust-auth server that answers every query with one row.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let len = s.read_u32().await.unwrap() as usize;
            let mut startup = vec![0u8; len - 4];
            s.read_exact(&mut startup).await.unwrap();
            let hello = [message(b'R', &0u32.to_be_bytes()), message(b'Z', b"I")];
            s.write_all(&hello.concat()).await.unwrap();
            while let Ok((b'Q', _)) = read_msg(&mut s).await {
                let row = message(b'D', &[0, 1, 0, 0, 0, 1, b'1']);
                let out = [row, message(b'C', b"SELECT 1\0"), message(b'Z', b"I")];
                s.write_all(&out.concat()).await.unwrap();
            }
        });
        let password = "s3cret-PW-only-the-gate-knows";
        let record = format!(
            r#"{{"user":"app","password":"{password}","database":"d","sslmode":"disable"}}"#
        );
        let rec = Arc::new(Recorder::new(true));
        let st = testkit::recording_state(&record, Inject::Postgres, rec.clone());
        let gate =
            testkit::listen(st, testkit::route(TargetKind::Postgres, "127.0.0.1", port)).await;

        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", gate))
            .await
            .unwrap();
        let mut body = 196_608u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0kepr\0\0");
        c.write_all(&[&((body.len() + 4) as u32).to_be_bytes()[..], &body].concat())
            .await
            .unwrap();
        assert_eq!(read_msg(&mut c).await.unwrap().0, b'R');
        let ph = testkit::placeholder(0);
        c.write_all(&message(b'p', format!("{ph}\0").as_bytes()))
            .await
            .unwrap();
        assert_eq!(read_msg(&mut c).await.unwrap().0, b'R'); // AuthenticationOk
        assert_eq!(read_msg(&mut c).await.unwrap().0, b'Z');
        c.write_all(&message(b'Q', b"SELECT 1\0")).await.unwrap();
        for want in *b"DCZ" {
            assert_eq!(read_msg(&mut c).await.unwrap().0, want);
        }
        drop(c);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let chunks: Vec<RecChunk> = rec.take().into_iter().flat_map(|b| b.chunks).collect();
        let sent: Vec<u8> = chunks
            .iter()
            .filter(|c| c.dir == FROM_AGENT)
            .flat_map(|c| c.bytes())
            .collect();
        let got: Vec<u8> = chunks
            .iter()
            .filter(|c| c.dir == TO_AGENT)
            .flat_map(|c| c.bytes())
            .collect();
        assert_eq!(sent, message(b'Q', b"SELECT 1\0"));
        assert_eq!(got[0], b'Z', "recording starts after AuthenticationOk");
        let all = [sent, got].concat();
        let has = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
        assert!(!has(password.as_bytes()));
        assert!(
            !has(ph.as_bytes()),
            "the login message is not recorded either"
        );
        assert!(chunks
            .iter()
            .all(|c| c.route == "db:TEST_DB" && c.kind == "postgres"));
    }
}
