// Streaming response masking and secret encoding regressions.
use super::*;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use hyper::header::HeaderValue;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// A body that yields these steps; `None` is one `Pending` poll.
struct Steps(VecDeque<Option<Frame<Bytes>>>);
impl hyper::body::Body for Steps {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        match self.0.pop_front() {
            Some(Some(f)) => Poll::Ready(Some(Ok(f))),
            Some(None) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            None => Poll::Ready(None),
        }
    }
}

fn data(s: &str) -> Option<Frame<Bytes>> {
    Some(Frame::data(Bytes::copy_from_slice(s.as_bytes())))
}

fn masked(steps: Vec<Option<Frame<Bytes>>>, needles: &[&str]) -> Body {
    let n = needles.iter().map(|s| ZeroString::from(*s)).collect();
    body(Steps(steps.into()).boxed(), n)
}

/// Poll once, without a runtime.
fn poll(b: &mut Body) -> Poll<Option<Frame<Bytes>>> {
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(b)
        .poll_frame(&mut cx)
        .map(|o| o.map(|r| r.unwrap()))
}

fn next_data(b: &mut Body) -> Option<String> {
    loop {
        match poll(b) {
            Poll::Ready(Some(f)) => {
                let d = f.into_data().expect("a data frame");
                return Some(String::from_utf8(d.to_vec()).unwrap());
            }
            Poll::Ready(None) => return None,
            Poll::Pending => continue,
        }
    }
}

fn all(mut b: Body) -> String {
    let mut out = String::new();
    while let Some(d) = next_data(&mut b) {
        out.push_str(&d);
    }
    out
}

const REAL: &str = "real-key-1234567890";

#[test]
fn a_value_split_across_frames_is_masked() {
    let frames = ["key=sk-abc", "defgh ok", " and sk-abcdefgh"];
    let b = masked(frames.iter().map(|f| data(f)).collect(), &["sk-abcdefgh"]);
    assert_eq!(all(b), "key=*********** ok and ***********");
}

#[test]
fn an_sse_frame_with_no_partial_match_goes_out_whole_in_the_same_poll() {
    let event = "data: {\"type\":\"delta\",\"text\":\"hi\"}\n\n";
    let mut b = masked(vec![data(event), None, data(event)], &[REAL]);
    let Poll::Ready(Some(f)) = poll(&mut b) else {
        panic!("the event was delayed");
    };
    assert_eq!(f.into_data().unwrap(), event.as_bytes());
    assert!(poll(&mut b).is_pending(), "the inner body is pending");
    assert_eq!(next_data(&mut b).as_deref(), Some(event));
    assert!(next_data(&mut b).is_none());
}

#[test]
fn a_possible_start_is_held_back_then_released_unchanged() {
    let mut b = masked(vec![data("abc real-k"), data("zzz")], &[REAL]);
    assert_eq!(next_data(&mut b).as_deref(), Some("abc "));
    assert_eq!(next_data(&mut b).as_deref(), Some("real-kzzz"));
    assert!(next_data(&mut b).is_none());
}

#[test]
fn the_carry_is_flushed_at_end_of_stream_and_before_trailers() {
    let mut b = masked(vec![data("x real-key")], &[REAL]);
    assert_eq!(next_data(&mut b).as_deref(), Some("x "));
    assert_eq!(next_data(&mut b).as_deref(), Some("real-key"));
    assert!(next_data(&mut b).is_none());

    let mut t = HeaderMap::new();
    t.insert("x-echo", HeaderValue::from_static("k=real-key-1234567890"));
    let mut b = masked(vec![data("x real-key"), Some(Frame::trailers(t))], &[REAL]);
    assert_eq!(next_data(&mut b).as_deref(), Some("x "));
    assert_eq!(next_data(&mut b).as_deref(), Some("real-key"));
    let Poll::Ready(Some(f)) = poll(&mut b) else {
        panic!("trailers expected");
    };
    let t = f.into_trailers().expect("trailers");
    assert_eq!(t["x-echo"], "k=*******************");
    assert!(matches!(poll(&mut b), Poll::Ready(None)));
}

#[test]
fn a_needle_that_is_a_prefix_of_another_is_handled() {
    for needles in [["real-key-1234", REAL], [REAL, "real-key-1234"]] {
        let frames = vec![data("a real-key-1234"), data("567890 b real-key-1234 c")];
        assert_eq!(
            all(masked(frames, &needles)),
            "a ******************* b ************* c"
        );
    }
}

#[test]
fn a_json_escaped_occurrence_is_masked() {
    let n = forms("pa/ss\"word-1");
    let text = r#"raw=pa/ss"word-1 serde="pa/ss\"word-1" full="pa\/ss\"word-1""#;
    let b = body(Steps(vec![data(text)].into()).boxed(), n);
    assert_eq!(
        all(b),
        r#"raw=************ serde="*************" full="**************""#
    );
}

#[test]
fn a_seven_byte_value_is_not_masked() {
    assert!(forms("1234567").is_empty());
    let b = masked(vec![data("x 1234567 y")], &["1234567"]);
    assert_eq!(all(b), "x 1234567 y");
}

#[test]
fn json_records_contribute_their_secret_fields_only() {
    let aws = r#"{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"real/secret","session_token":"tok-1234567"}"#;
    let got: Vec<String> = forms(aws).iter().map(|z| z.to_owned_string()).collect();
    assert!(got.contains(&"real/secret".to_string()), "{}", got.len());
    assert!(got.contains(&r"real\/secret".to_string()));
    assert!(got.contains(&"tok-1234567".to_string()));
    assert!(!got.iter().any(|g| g.contains("AKIA")));
    // Not an object: the whole value.
    let plain: Vec<String> = forms("sk-live-abcdefgh")
        .iter()
        .map(|z| z.to_owned_string())
        .collect();
    // The value, plus its Base64 spellings (nothing to percent-encode).
    assert_eq!(plain.len(), 3);
    assert!(plain.contains(&"sk-live-abcdefgh".to_string()));
    assert!(plain.contains(&"c2stbGl2ZS1hYmNkZWZnaA==".to_string()));
    // T12.09: a Google authorized_user file's secrets.
    let user = r#"{"type":"authorized_user","client_id":"cid.apps.example","client_secret":"user-secret-1","refresh_token":"1//refresh-1"}"#;
    let got: Vec<String> = forms(user).iter().map(|z| z.to_owned_string()).collect();
    assert!(got.contains(&"user-secret-1".to_string()));
    assert!(got.contains(&"1//refresh-1".to_string()));
    assert!(!got.iter().any(|g| g.contains("cid.apps")));
}

#[test]
fn headers_are_masked_in_place_and_marked_sensitive() {
    let mut h = HeaderMap::new();
    h.insert(
        "x-debug",
        HeaderValue::from_str(&format!("got {REAL}")).unwrap(),
    );
    h.insert("x-other", HeaderValue::from_static("fine"));
    headers(&mut h, &[ZeroString::from(REAL)]);
    assert_eq!(h["x-debug"], "got *******************");
    assert!(h["x-debug"].is_sensitive());
    assert_eq!(h["x-other"], "fine");
    assert!(!h["x-other"].is_sensitive());
}

#[test]
fn the_size_hint_is_unchanged() {
    let full = http_body_util::Full::new(Bytes::from(format!("{{\"e\":\"{REAL}\"}}")));
    let n = full.size_hint().exact();
    let b = body(
        full.map_err(|e| match e {}).boxed(),
        vec![ZeroString::from(REAL)],
    );
    assert_eq!(b.size_hint().exact(), n);
    assert_eq!(all(b).len() as u64, n.unwrap());
}

#[test]
fn encoded_spellings_are_needles_too() {
    let f: Vec<String> = forms("s3cr3t/key+value=")
        .iter()
        .map(|z| z.as_str().to_string())
        .collect();
    for want in [
        "s3cr3t%2Fkey%2Bvalue%3D",
        "czNjcjN0L2tleSt2YWx1ZT0=",
        "czNjcjN0L2tleSt2YWx1ZT0",
    ] {
        assert!(f.iter().any(|x| x == want), "{want} not in {f:?}");
    }
}
