// cli_clip/x11.rs — own the X11 CLIPBOARD selection (T12.48): offer
// TARGETS, the text targets and `x-kde-passwordManagerHint` = `secret`,
// answer requests until the deadline, then give the selection up if kepr
// still owns it. A SelectionClear (another client copied) ends serving
// with nothing to clear. No INCR: values over 64 KiB are refused and
// `kepr copy` uses xclip, which can send them in pieces.

use std::time::{Duration, Instant};

use kepr_core::generate::ZeroString;

use super::x11_wire::{self as wire, le32, Conn};
use super::{HINT_MIME, HINT_VALUE, TEXT_TYPES};

/// The largest value served in one ChangeProperty.
pub const MAX_X11_VALUE: usize = 64 * 1024;

/// Serve `value` on CLIPBOARD for `secs` seconds; `ready` runs once kepr
/// owns it.
pub fn serve(value: &ZeroString, secs: u64, ready: impl FnOnce()) -> Result<(), String> {
    if value.len() > MAX_X11_VALUE {
        return Err("value too large for an X11 selection".into());
    }
    let display = std::env::var("DISPLAY").map_err(|_| "DISPLAY is not set")?;
    let conn = wire::connect(&display)?;
    serve_on(conn, value, Duration::from_secs(secs), ready)
}

struct Atoms {
    clipboard: u32,
    targets: u32,
    text: Vec<u32>,
    utf8: u32,
    hint: u32,
}

pub(crate) fn serve_on(
    mut c: Conn,
    value: &ZeroString,
    hold: Duration,
    ready: impl FnOnce(),
) -> Result<(), String> {
    if value.len() > MAX_X11_VALUE || 24 + value.len() > c.setup.max_request {
        return Err("value too large for an X11 selection".into());
    }
    let deadline = Instant::now()
        .checked_add(hold)
        .ok_or("clear time out of range")?;
    let names: Vec<&str> = ["CLIPBOARD", "TARGETS"]
        .into_iter()
        .chain(TEXT_TYPES.iter().copied())
        .chain([HINT_MIME])
        .collect();
    let mut seqs = Vec::new();
    for n in &names {
        seqs.push(c.send(&wire::intern_atom(n))?);
    }
    let mut ids = Vec::new();
    for s in seqs {
        ids.push(le32(&c.reply(s)?, 8).ok_or("bad InternAtom reply")?);
    }
    let text = ids[2..2 + TEXT_TYPES.len()].to_vec();
    let a = Atoms {
        clipboard: ids[0],
        targets: ids[1],
        utf8: text[TEXT_TYPES
            .iter()
            .position(|t| *t == "UTF8_STRING")
            .unwrap_or(0)],
        text,
        hint: ids[ids.len() - 1],
    };
    let win = c.new_id();
    c.send(&wire::create_window(win, c.setup.root))?;
    c.send(&wire::set_selection_owner(win, a.clipboard))?;
    if owner(&mut c, a.clipboard)? != win {
        return Err("could not take the clipboard".into());
    }
    ready();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if let Some(e) = c.event(left)? {
            if handle(&mut c, &a, win, value, &e)? {
                return Ok(());
            }
        }
    }
    // Events that already arrived first: a SelectionClear means the
    // clipboard is someone else's now.
    while let Some(e) = c.event(Duration::ZERO)? {
        if handle(&mut c, &a, win, value, &e)? {
            return Ok(());
        }
    }
    if owner(&mut c, a.clipboard)? == win {
        c.send(&wire::set_selection_owner(0, a.clipboard))?;
        owner(&mut c, a.clipboard)?; // a round trip: the release is done
    }
    Ok(())
}

fn owner(c: &mut Conn, selection: u32) -> Result<u32, String> {
    let s = c.send(&wire::get_selection_owner(selection))?;
    le32(&c.reply(s)?, 8).ok_or_else(|| "bad GetSelectionOwner reply".into())
}

/// Answer one event. True when the selection was taken from us.
fn handle(
    c: &mut Conn,
    a: &Atoms,
    win: u32,
    value: &ZeroString,
    e: &[u8; 32],
) -> Result<bool, String> {
    let w = |at| le32(e, at).unwrap_or(0);
    match e[0] & 0x7f {
        wire::SELECTION_CLEAR => Ok(w(8) == win && w(12) == a.clipboard),
        wire::SELECTION_REQUEST => {
            let (time, requestor, sel, target, prop) = (w(4), w(12), w(16), w(20), w(24));
            let mut answered = 0;
            if sel == a.clipboard && w(8) == win && prop != 0 {
                if let Some(req) = property(a, requestor, prop, target, value) {
                    c.send(&req)?;
                    answered = prop;
                }
            }
            c.send(&wire::selection_notify(
                time, requestor, sel, target, answered,
            ))?;
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// The ChangeProperty answering `target`, or None to refuse it.
fn property(
    a: &Atoms,
    win: u32,
    prop: u32,
    target: u32,
    value: &ZeroString,
) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    if target == a.targets {
        let mut list = vec![a.targets];
        list.extend(&a.text);
        list.push(a.hint);
        let bytes: Vec<u8> = list.iter().flat_map(|t| t.to_le_bytes()).collect();
        return Some(wire::change_property(
            win,
            prop,
            wire::ATOM_ATOM,
            32,
            &bytes,
        ));
    }
    if target == a.hint {
        return Some(wire::change_property(win, prop, a.hint, 8, HINT_VALUE));
    }
    let i = a.text.iter().position(|t| *t == target)?;
    // TEXT asks the owner to pick a type: UTF8_STRING.
    let ty = if TEXT_TYPES[i] == "TEXT" {
        a.utf8
    } else {
        target
    };
    Some(wire::change_property(win, prop, ty, 8, value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    const ROOT: u32 = 0x1ab;
    const REQUESTOR: u32 = 0x60_0001;

    /// A fake X server: setup, InternAtom, GetSelectionOwner (tracking
    /// SetSelectionOwner), and a log of the rest.
    struct Fake {
        s: UnixStream,
        seq: u16,
        atoms: HashMap<String, u32>,
        owner: u32,
        log: Vec<(u8, Vec<u8>)>,
    }

    fn le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    impl Fake {
        fn start(s: UnixStream) -> Self {
            let mut f = Fake {
                s,
                seq: 0,
                atoms: HashMap::new(),
                owner: 0,
                log: Vec::new(),
            };
            let mut head = [0u8; 12];
            f.s.read_exact(&mut head).unwrap();
            let n = u16::from_le_bytes([head[6], head[7]]) as usize;
            let d = u16::from_le_bytes([head[8], head[9]]) as usize;
            let mut auth = vec![0u8; n.div_ceil(4) * 4 + d.div_ceil(4) * 4];
            f.s.read_exact(&mut auth).unwrap();
            let mut r = vec![1, 0, 11, 0, 0, 0, 19, 0];
            r.extend([0; 4]); // release
            r.extend(le(0x60_0000)); // id base
            r.extend(le(0x1f_ffff)); // id mask
            r.extend([0; 4]); // motion buffer
            r.extend([4, 0, 0xff, 0xff]); // vendor length 4, max request 65535
            r.extend([1, 0, 0, 0, 0, 0, 8, 255, 0, 0, 0, 0]); // 1 screen, 0 formats
            r.extend(b"fake");
            r.extend(le(ROOT));
            r.extend([0; 36]);
            assert_eq!(r.len(), 8 + 19 * 4);
            f.s.write_all(&r).unwrap();
            f
        }

        /// Handle requests until `until` holds; false when the client hung up.
        fn pump(&mut self, until: impl Fn(&Fake) -> bool) -> bool {
            self.s
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            while !until(self) {
                let mut h = [0u8; 4];
                match self.s.read(&mut h[..1]) {
                    Ok(0) => return false,
                    Ok(_) => {}
                    Err(e) => panic!("client stalled: {e}"),
                }
                self.s.read_exact(&mut h[1..]).unwrap();
                let len = u16::from_le_bytes([h[2], h[3]]) as usize * 4;
                let mut body = vec![0u8; len - 4];
                self.s.read_exact(&mut body).unwrap();
                self.seq += 1;
                self.request(h[0], body);
            }
            true
        }

        fn reply(&mut self, word: u32) {
            let mut r = vec![1, 0];
            r.extend(self.seq.to_le_bytes());
            r.extend([0; 4]);
            r.extend(le(word));
            r.extend([0; 20]);
            self.s.write_all(&r).unwrap();
        }

        fn request(&mut self, op: u8, body: Vec<u8>) {
            match op {
                16 => {
                    let n = u16::from_le_bytes([body[0], body[1]]) as usize;
                    let name = String::from_utf8(body[4..4 + n].to_vec()).unwrap();
                    let next = 100 + self.atoms.len() as u32;
                    let id = *self.atoms.entry(name).or_insert(next);
                    self.reply(id);
                }
                22 => self.owner = le32(&body, 0).unwrap(),
                23 => self.reply(self.owner),
                _ => {}
            }
            self.log.push((op, body));
        }

        fn atom(&self, n: &str) -> u32 {
            self.atoms[n]
        }

        fn owned(&self) -> bool {
            self.owner != 0 && self.log.iter().filter(|(op, _)| *op == 23).count() > 0
        }

        fn ops(&self, op: u8) -> Vec<&Vec<u8>> {
            self.log
                .iter()
                .filter(|(o, _)| *o == op)
                .map(|(_, b)| b)
                .collect()
        }

        fn event(&mut self, code: u8, words: [u32; 6]) {
            let mut e = vec![code, 0, 0, 0];
            for w in words {
                e.extend(le(w));
            }
            e.extend([0; 4]);
            self.s.write_all(&e).unwrap();
        }

        /// A SelectionRequest for `target` into property `prop`; the
        /// ChangeProperty (if any) and the SelectionNotify it answers with.
        fn request_target(&mut self, target: u32, prop: u32) -> (Option<Vec<u8>>, Vec<u8>) {
            let before = self.log.len();
            let words = [
                7,
                self.owner,
                REQUESTOR,
                self.atom("CLIPBOARD"),
                target,
                prop,
            ];
            self.event(wire::SELECTION_REQUEST, words);
            assert!(self.pump(|f| f.log[before..].iter().any(|(op, _)| *op == 25)));
            let new = &self.log[before..];
            let change = new.iter().find(|(op, _)| *op == 18).map(|(_, b)| b.clone());
            (
                change,
                new.iter().find(|(op, _)| *op == 25).unwrap().1.clone(),
            )
        }
    }

    type Served = std::thread::JoinHandle<Result<(), String>>;

    fn start(value: &str, hold: Duration) -> (Fake, Served, mpsc::Receiver<()>) {
        let (a, b) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel();
        let value = ZeroString::from(value);
        let t = std::thread::spawn(move || {
            let c = wire::connect_on(a, Some(&[7; 16]))?;
            serve_on(c, &value, hold, move || tx.send(()).unwrap())
        });
        let mut f = Fake::start(b);
        assert!(f.pump(Fake::owned));
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        (f, t, rx)
    }

    /// (property, notify property) of a SelectionNotify SendEvent body.
    fn notified(body: &[u8]) -> (u32, u32) {
        (le32(body, 0).unwrap(), le32(body, 28).unwrap())
    }

    #[test]
    fn targets_text_and_hint_answers() {
        let (mut f, t, _r) = start("x11-value", Duration::from_secs(30));
        let (change, notify) = f.request_target(f.atom("TARGETS"), 55);
        let change = change.unwrap();
        assert_eq!(
            (le32(&change, 8), change[12], le32(&change, 16)),
            (Some(wire::ATOM_ATOM), 32, Some(7))
        );
        let listed: Vec<u32> = (0..7).map(|i| le32(&change, 20 + 4 * i).unwrap()).collect();
        assert!(listed.contains(&f.atom(HINT_MIME)) && listed.contains(&f.atom("UTF8_STRING")));
        assert_eq!(notified(&notify), (REQUESTOR, 55));

        let (change, notify) = f.request_target(f.atom("UTF8_STRING"), 56);
        let change = change.unwrap();
        assert_eq!(
            (le32(&change, 0), le32(&change, 4)),
            (Some(REQUESTOR), Some(56))
        );
        assert_eq!((change[12], le32(&change, 16)), (8, Some(9)));
        assert_eq!(&change[20..29], b"x11-value");
        assert_eq!(notified(&notify), (REQUESTOR, 56));

        let (change, _) = f.request_target(f.atom(HINT_MIME), 57);
        assert_eq!(&change.unwrap()[20..26], b"secret");

        let (change, notify) = f.request_target(4242, 58);
        assert!(change.is_none());
        assert_eq!(notified(&notify), (REQUESTOR, 0));

        let (change, notify) = f.request_target(f.atom("STRING"), 0);
        assert!(change.is_none());
        assert_eq!(notified(&notify), (REQUESTOR, 0));

        let (owner, clip) = (f.owner, f.atom("CLIPBOARD"));
        f.event(wire::SELECTION_CLEAR, [9, owner, clip, 0, 0, 0]);
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        // SelectionClear: no SetSelectionOwner(None).
        assert!(f.ops(22).iter().all(|b| le32(b, 0) != Some(0)));
    }

    #[test]
    fn the_deadline_gives_the_selection_up() {
        let (mut f, t, _r) = start("v", Duration::from_secs(1));
        assert!(f.pump(|f| f.ops(22).iter().any(|b| le32(b, 0) == Some(0))));
        assert!(!f.pump(|_| false));
        assert_eq!(t.join().unwrap(), Ok(()));
        assert_eq!(f.owner, 0);
    }

    #[test]
    fn a_value_too_large_is_refused() {
        let (a, b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || Fake::start(b));
        let c = wire::connect_on(a, None).unwrap();
        let big = ZeroString::from_string("x".repeat(MAX_X11_VALUE + 1));
        assert!(serve_on(c, &big, Duration::ZERO, || panic!("ready")).is_err());
    }
}
