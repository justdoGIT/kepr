//! Responses to the agent without the session's secrets (T12.01).
//!
//! An upstream may echo what it was sent: an error message quoting the
//! key, a debug header. Before a response reaches the agent (and the
//! recording), every value this session resolved and every token it
//! minted is overwritten with `*` of the same length, in the headers and
//! in the body as it streams. Lengths never change, so `Content-Length`
//! stays right. Only the longest tail of a frame that could be the start
//! of a value waits for the next frame: a value split across frames is
//! caught, and a stream (SSE) is not delayed otherwise.

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use hyper::header::{HeaderMap, HeaderValue};
use kepr_core::generate::ZeroString;
use zeroize::Zeroizing;

use crate::dlp::MIN_SECRET_LEN;
use crate::proxy::Body;

/// The string fields of a JSON record that hold its secrets; any other
/// field (a user name, a database name) is left alone.
#[derive(serde::Deserialize)]
struct SecretFields {
    password: Option<serde_json::Value>,
    pending_password: Option<serde_json::Value>,
    secret_access_key: Option<serde_json::Value>,
    session_token: Option<serde_json::Value>,
    private_key: Option<serde_json::Value>,
    /// T12.09: a Google `authorized_user` file.
    client_secret: Option<serde_json::Value>,
    refresh_token: Option<serde_json::Value>,
    /// Cloudflare and Kubernetes structured logins.
    token: Option<serde_json::Value>,
}

/// The secret parts of one value: a JSON object's secret string fields,
/// or else the whole value.
fn secret_parts(value: &str) -> Vec<ZeroString> {
    if value.trim_start().starts_with('{') {
        if let Ok(f) = serde_json::from_str::<SecretFields>(value) {
            let fields = [
                f.password,
                f.pending_password,
                f.secret_access_key,
                f.session_token,
                f.private_key,
                f.client_secret,
                f.refresh_token,
                f.token,
            ];
            return (fields.into_iter().flatten())
                .filter_map(|v| match v {
                    serde_json::Value::String(s) => Some(ZeroString::from_string(s)),
                    _ => None,
                })
                .collect();
        }
    }
    vec![ZeroString::from(value)]
}

/// `v` as it reads inside a JSON string: `"`, `\` and control characters
/// escaped, and `/` too when `slash` (serializers differ on it).
fn json_escaped(v: &str, slash: bool) -> ZeroString {
    // Sized once so the secret is never copied by a reallocation.
    let mut s = String::with_capacity(v.len() * 6);
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '/' if slash => s.push_str("\\/"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    ZeroString::from_string(s)
}

/// Percent-encoding (RFC 3986 unreserved kept) and Base64 spellings of `v`.
fn encoded_forms(v: &str) -> Vec<ZeroString> {
    use base64::Engine;
    let mut pct = String::with_capacity(v.len() * 3);
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            pct.push(b as char);
        } else {
            pct.push_str(&format!("%{b:02X}"));
        }
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let mut out = vec![ZeroString::from_string(pct)];
    for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        out.push(ZeroString::from_string(e.encode(v.as_bytes())));
    }
    out
}

/// The needles one value contributes: its secret parts, each with its
/// JSON-escaped forms when they differ, none shorter than
/// `MIN_SECRET_LEN`.
pub fn forms(value: &str) -> Vec<ZeroString> {
    let mut out: Vec<ZeroString> = Vec::new();
    for part in secret_parts(value) {
        if part.len() < MIN_SECRET_LEN {
            continue;
        }
        for slash in [false, true] {
            let e = json_escaped(&part, slash);
            if e.as_str() != part.as_str() && !out.iter().any(|o| o.as_str() == e.as_str()) {
                out.push(e);
            }
        }
        // The forms the gate itself sends: URL-encoded, and Base64 of the
        // value alone (standard and URL alphabets, padded or not).
        for e in encoded_forms(&part) {
            if !out.iter().any(|o| o.as_str() == e.as_str()) && e.as_str() != part.as_str() {
                out.push(e);
            }
        }
        out.push(part);
    }
    out
}

fn usable(needles: &[ZeroString]) -> impl Iterator<Item = &[u8]> {
    (needles.iter().map(|n| n.as_bytes())).filter(|n| n.len() >= MIN_SECRET_LEN)
}

/// Mark every occurrence of every needle in `buf`, overlapping ones too,
/// all found in the unmasked bytes (so a needle that is a prefix of
/// another can't hide the rest of the longer one).
fn mark(buf: &[u8], needles: &[ZeroString], marks: &mut [bool]) -> bool {
    let mut any = false;
    for n in usable(needles) {
        let mut at = 0;
        while let Some(i) = memchr::memmem::find(&buf[at..], n) {
            marks[at + i..at + i + n.len()].fill(true);
            (any, at) = (true, at + i + 1);
        }
    }
    any
}

/// The length of the longest tail of `buf` that is a proper prefix of
/// some needle: the bytes that must wait for the next frame.
fn held_tail(buf: &[u8], needles: &[ZeroString]) -> usize {
    let mut best = 0;
    for n in usable(needles) {
        let (lo, hi) = (buf.len().saturating_sub(n.len() - 1), buf.len() - best);
        if lo >= hi {
            continue;
        }
        let mut starts = memchr::memchr_iter(n[0], &buf[lo..hi]).map(|i| lo + i);
        if let Some(s) = starts.find(|&s| n.starts_with(&buf[s..])) {
            best = buf.len() - s;
        }
    }
    best
}

fn masked_copy(buf: &[u8], marks: &[bool]) -> Bytes {
    let out: Vec<u8> = (buf.iter().zip(marks))
        .map(|(b, m)| if *m { b'*' } else { *b })
        .collect();
    Bytes::from(out)
}

/// Mask the needles in every header value; a changed value is rebuilt
/// and marked sensitive.
pub fn headers(h: &mut HeaderMap, needles: &[ZeroString]) {
    if needles.is_empty() {
        return;
    }
    for v in h.values_mut() {
        let mut marks = vec![false; v.len()];
        if !mark(v.as_bytes(), needles, &mut marks) {
            continue;
        }
        let out = masked_copy(v.as_bytes(), &marks);
        // `*` is a valid header byte wherever it lands; the fallback is
        // for form's sake.
        let mut nv =
            HeaderValue::from_maybe_shared(out).unwrap_or_else(|_| HeaderValue::from_static("*"));
        nv.set_sensitive(true);
        *v = nv;
    }
}

/// A response body with the needles masked as it streams.
pub struct MaskedBody {
    inner: Body,
    needles: Vec<ZeroString>,
    /// Held-back bytes as received, and which of them already belong to
    /// a match.
    carry: Zeroizing<Vec<u8>>,
    marks: Vec<bool>,
    /// Trailers waiting behind the flushed carry.
    trailers: Option<Frame<Bytes>>,
    ended: bool,
}

impl MaskedBody {
    /// Mask `carry + data`; what may go out now (`None`: all held back).
    fn feed(&mut self, data: Bytes) -> Option<Bytes> {
        let quick = self.carry.is_empty()
            && !usable(&self.needles).any(|n| memchr::memmem::find(&data, n).is_some())
            && held_tail(&data, &self.needles) == 0;
        if quick {
            return (!data.is_empty()).then_some(data);
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(self.carry.len() + data.len()));
        buf.extend_from_slice(&self.carry);
        buf.extend_from_slice(&data);
        let mut marks = std::mem::take(&mut self.marks);
        marks.resize(buf.len(), false);
        mark(&buf, &self.needles, &mut marks);
        let cut = buf.len() - held_tail(&buf, &self.needles);
        self.carry = Zeroizing::new(buf[cut..].to_vec());
        self.marks = marks.split_off(cut);
        (cut > 0).then(|| masked_copy(&buf[..cut], &marks))
    }

    /// The held-back bytes, at the end of the data.
    fn flush(&mut self) -> Option<Bytes> {
        if self.carry.is_empty() {
            return None;
        }
        let out = masked_copy(&self.carry, &self.marks);
        (self.carry, self.marks) = (Zeroizing::default(), Vec::new());
        Some(out)
    }
}

type Polled = Poll<Option<Result<Frame<Bytes>, hyper::Error>>>;

impl hyper::body::Body for MaskedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Polled {
        let me = self.get_mut();
        if let Some(t) = me.trailers.take() {
            return Poll::Ready(Some(Ok(t)));
        }
        while !me.ended {
            let frame = match ready!(Pin::new(&mut me.inner).poll_frame(cx)) {
                Some(Ok(f)) => f,
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    me.ended = true;
                    break;
                }
            };
            let other = match frame.into_data() {
                Ok(d) => match me.feed(d) {
                    Some(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
                    None => continue,
                },
                Err(other) => other,
            };
            let other = match other.into_trailers() {
                Ok(mut t) => {
                    headers(&mut t, &me.needles);
                    Frame::trailers(t)
                }
                Err(other) => other,
            };
            return Poll::Ready(Some(Ok(match me.flush() {
                Some(rest) => {
                    me.trailers = Some(other);
                    Frame::data(rest)
                }
                None => other,
            })));
        }
        Poll::Ready(me.flush().map(|rest| Ok(Frame::data(rest))))
    }

    fn is_end_stream(&self) -> bool {
        let inner_done = self.ended || self.inner.is_end_stream();
        inner_done && self.carry.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let (h, c) = (self.inner.size_hint(), self.carry.len() as u64);
        let mut out = SizeHint::new();
        if let Some(u) = h.upper() {
            out.set_upper(u + c);
        }
        out.set_lower(h.lower() + c);
        out
    }
}

/// `b` with `needles` masked; `b` itself when there are none to mask.
pub fn body(b: Body, needles: Vec<ZeroString>) -> Body {
    if usable(&needles).next().is_none() {
        return b;
    }
    let m = MaskedBody {
        inner: b,
        needles,
        carry: Zeroizing::default(),
        marks: Vec::new(),
        trailers: None,
        ended: false,
    };
    m.boxed()
}

#[cfg(test)]
#[path = "mask_tests.rs"]
mod tests;
